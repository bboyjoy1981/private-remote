using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.Extensions.DependencyInjection;
using PrivateRemote.Client;
using PrivateRemote.Protocol;
using PrivateRemote.Relay;
using PrivateRemote.Transport;

namespace PrivateRemote.Tests.Transport;

internal static class NativeHostIntegrationTests
{
    public static void NetworkHostsConnectDisconnectAndReconnect() => RunAsync().GetAwaiter().GetResult();

    private static async Task RunAsync()
    {
        var library = NativeNegotiationTests.FindLibrary();
        var root = Path.Combine(Path.GetTempPath(), "pr-network-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        Directory.CreateDirectory(Path.Combine(root, "left"));
        Directory.CreateDirectory(Path.Combine(root, "right"));
        try
        {
            using var leftIdentity = DeviceIdentity.Create();
            using var rightIdentity = DeviceIdentity.Create();
            var caps = SessionCapability.ScreenControl | SessionCapability.FileTransfer;
            var leftStore = new DeviceStore(Path.Combine(root, "left"));
            var rightStore = new DeviceStore(Path.Combine(root, "right"));
            leftStore.SaveApprovedDevice(new(rightIdentity.DeviceId, rightIdentity.PublicKey, "right", caps));
            rightStore.SaveApprovedDevice(new(leftIdentity.DeviceId, leftIdentity.PublicKey, "left", caps));
            var leftToken = Guid.NewGuid().ToString("N");
            var rightToken = Guid.NewGuid().ToString("N");
            var adminToken = Guid.NewGuid().ToString("N");
            using var tlsKey = System.Security.Cryptography.RSA.Create(2048);
            var tlsRequest = new System.Security.Cryptography.X509Certificates.CertificateRequest("CN=PrivateRemote-test", tlsKey,
                System.Security.Cryptography.HashAlgorithmName.SHA256, System.Security.Cryptography.RSASignaturePadding.Pkcs1);
            using var createdCertificate = tlsRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddHours(1));
            using var certificate = System.Security.Cryptography.X509Certificates.X509CertificateLoader.LoadPkcs12(createdCertificate.Export(System.Security.Cryptography.X509Certificates.X509ContentType.Pfx), null,
                System.Security.Cryptography.X509Certificates.X509KeyStorageFlags.UserKeySet);
            var certificatePin = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(certificate.RawData));
            await using var app = RelayServer.Build([
                "--environment", "Development",
                "--Logging:LogLevel:Default", "Warning",
                "--DevelopmentDevices:0:DeviceId", leftIdentity.DeviceId,
                "--DevelopmentDevices:0:BearerToken", leftToken,
                "--DevelopmentDevices:0:PublicKeyBase64", Convert.ToBase64String(leftIdentity.PublicKey),
                "--DevelopmentDevices:1:DeviceId", rightIdentity.DeviceId,
                "--DevelopmentDevices:1:BearerToken", rightToken,
                "--DevelopmentDevices:1:PublicKeyBase64", Convert.ToBase64String(rightIdentity.PublicKey),
                "--RelayAdmin:BearerToken", adminToken
            ], certificate, System.Net.IPAddress.Loopback, 0);
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(25));
            await app.StartAsync(timeout.Token);
            try
            {
                await using var left = new PeerSessionHost(new(leftStore, leftIdentity), library, "127.0.0.1");
                await using var right = new PeerSessionHost(new(rightStore, rightIdentity), library, "127.0.0.1");
                var address = app.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()!.Addresses.Single();
                var endpoint = new UriBuilder(address) { Scheme = "wss", Path = "/signal" }.Uri;
                await using (var wrongPin = new SignalingClient())
                {
                    try { await wrongPin.ConnectAsync(endpoint, leftIdentity.DeviceId, leftToken, timeout.Token, new string('0', 64)); throw new InvalidOperationException("Wrong certificate pin must fail."); }
                    catch (System.Net.WebSockets.WebSocketException) { }
                }
                await left.ConnectSignalingAsync(endpoint, leftToken, timeout.Token, certificatePin);
                await right.ConnectSignalingAsync(endpoint, rightToken, timeout.Token, certificatePin);
                var connected = app.Services.GetRequiredService<ConnectedDevices>();
                while (!connected.TryGet(leftIdentity.DeviceId, out _) || !connected.TryGet(rightIdentity.DeviceId, out _))
                    await Task.Delay(10, timeout.Token);
                Guid? previous = null;
                for (var round = 0; round < 2; round++)
                {
                    var peer = await left.ConnectDeviceAsync(rightIdentity.DeviceId, caps, timeout.Token);
                    while (right.Status.Phase != PeerHostPhase.Connected) await Task.Delay(10, timeout.Token);
                    TestAssert.True(peer.SessionId != previous, "Reconnect must use a fresh signed session identity.");
                    previous = peer.SessionId;
                    var bytes = System.Security.Cryptography.RandomNumberGenerator.GetBytes(64 * 1024);
                    await peer.SendAsync(PeerDataChannel.Bulk, bytes, timeout.Token);
                    var received = await right.ActivePeer!.ReadMessageAsync(timeout.Token);
                    TestAssert.SequenceEqual(bytes, received.Bytes, "Real WebSocket signaling must establish a working native encrypted channel.");
                    await right.ActivePeer.SendAsync(PeerDataChannel.Control, "network-control"u8.ToArray(), timeout.Token);
                    TestAssert.SequenceEqual("network-control"u8.ToArray(), (await peer.ReadMessageAsync(timeout.Token)).Bytes, "Control messages must work in the reverse direction.");
                    var inputs = new System.Collections.Concurrent.ConcurrentQueue<RemoteInputEvent>();
                    var released = 0;
                    var frameReady = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
                    var desktopBytes = System.Security.Cryptography.RandomNumberGenerator.GetBytes(160000);
                    await using (var viewer = new DesktopSession(peer, new FakeFrameSource(desktopBytes), _ => { }, () => { }))
                    await using (var controlled = new DesktopSession(right.ActivePeer, new FakeFrameSource(desktopBytes), inputs.Enqueue, () => Interlocked.Increment(ref released)))
                    {
                        viewer.FrameReceived += (_, bytes) => frameReady.TrySetResult(bytes);
                        TestAssert.Throws<InvalidOperationException>(() => viewer.SendInputAsync(new KeyEvent(65, true), timeout.Token).GetAwaiter().GetResult(), "Input requires an open remote view.");
                        await viewer.StartViewingAsync(timeout.Token);
                        TestAssert.SequenceEqual(desktopBytes, await frameReady.Task.WaitAsync(timeout.Token), "The desktop consumer must assemble a frame over the actual native channel.");
                        await viewer.SendInputAsync(new KeyEvent(65, true), timeout.Token);
                        await viewer.SendInputAsync(new KeyEvent(65, false), timeout.Token);
                        while (inputs.Count != 2) await Task.Delay(10, timeout.Token);
                        TestAssert.Equal(new KeyEvent(65, true), inputs.ToArray()[0], "Key down must precede key up.");
                        var sourcePath = Path.Combine(root, $"source-{round}.bin");
                        var contents = System.Security.Cryptography.RandomNumberGenerator.GetBytes(180000);
                        await File.WriteAllBytesAsync(sourcePath, contents, timeout.Token);
                        var destination = Path.Combine(root, $"received-{round}.bin");
                        var returned = Path.Combine(root, $"returned-{round}.bin");
                        controlled.Files!.ChooseDestinationAsync = (_, _) => Task.FromResult<string?>(destination);
                        viewer.Files!.ChooseDestinationAsync = (_, _) => Task.FromResult<string?>(returned);
                        await viewer.Files.SendFileAsync(sourcePath, timeout.Token);
                        TestAssert.SequenceEqual(contents, await File.ReadAllBytesAsync(destination, timeout.Token), "Approved native file transfer must verify and atomically save exact content.");
                        await controlled.Files.SendFileAsync(destination, timeout.Token);
                        TestAssert.SequenceEqual(contents, await File.ReadAllBytesAsync(returned, timeout.Token), "File content must transfer in the reverse direction while the desktop consumer remains active.");
                        controlled.Files.ChooseDestinationAsync = (_, _) => Task.FromResult<string?>(null);
                        try { await viewer.Files.SendFileAsync(sourcePath, timeout.Token); throw new InvalidOperationException("Rejected file offer must not send content."); }
                        catch (OperationCanceledException) { }
                        var emptyPath = Path.Combine(root, $"empty-{round}.bin"); await File.WriteAllBytesAsync(emptyPath, [], timeout.Token);
                        var emptyDestination = Path.Combine(root, $"empty-received-{round}.bin");
                        controlled.Files.ChooseDestinationAsync = (_, _) => Task.FromResult<string?>(emptyDestination);
                        await viewer.Files.SendFileAsync(emptyPath, timeout.Token);
                        TestAssert.Equal(0L, new FileInfo(emptyDestination).Length, "Zero-byte files must wait for an ordered end marker and hash validation.");
                        var cancelledPath = Path.Combine(root, $"cancel-source-{round}.bin");
                        await File.WriteAllBytesAsync(cancelledPath, new byte[4 * 1024 * 1024], timeout.Token);
                        var cancelledDestination = Path.Combine(root, $"cancel-received-{round}.bin");
                        controlled.Files.ChooseDestinationAsync = (_, _) => Task.FromResult<string?>(cancelledDestination);
                        controlled.Files.ProgressChanged += (_, progress) =>
                        {
                            if (progress.FileName == Path.GetFileName(cancelledPath) && progress.Completed >= 120000 && progress.Message == "正在接收")
                                _ = controlled.Files.CancelAsync();
                        };
                        try { await viewer.Files.SendFileAsync(cancelledPath, timeout.Token); throw new InvalidOperationException("Receiver cancellation must stop sender."); }
                        catch (OperationCanceledException) { }
                        TestAssert.True(!File.Exists(cancelledDestination) && !Directory.EnumerateFiles(root, "*.partial").Any(), "Cancelled files must leave neither completed output nor staging files.");
                        if (round == 0)
                        {
                            await viewer.StopViewingAsync(timeout.Token);
                            while (controlled.IsSharing || Volatile.Read(ref released) == 0) await Task.Delay(10, timeout.Token);
                        }
                        else
                        {
                            using var cancelled = new CancellationTokenSource(); cancelled.Cancel();
                            try { await viewer.StopViewingAsync(cancelled.Token); throw new InvalidOperationException("Cancelled stop must fail closed."); }
                            catch (OperationCanceledException) { }
                            TestAssert.True(!peer.PeerIdentityVerified, "Failed stop delivery must close the native session.");
                            while (controlled.IsSharing || Volatile.Read(ref released) == 0) await Task.Delay(10, timeout.Token);
                        }
                    }
                    await left.DisconnectDeviceAsync(timeout.Token);
                    while (right.ActivePeer is not null || left.ActivePeer is not null) await Task.Delay(10, timeout.Token);
                    TestAssert.Equal(PeerHostPhase.Available, right.Status.Phase, $"Signed disconnect must leave signaling available for reconnect. {right.Failure}");
                }
                await left.ConnectDeviceAsync(rightIdentity.DeviceId, caps, timeout.Token);
                while (right.Status.Phase != PeerHostPhase.Connected) await Task.Delay(10, timeout.Token);
                var incoming = right.ActivePeer!;
                using var handler = new HttpClientHandler { ServerCertificateCustomValidationCallback = (_, cert, _, _) => cert is not null && Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(cert.RawData)) == certificatePin };
                using var admin = new HttpClient(handler) { BaseAddress = new Uri(address) };
                admin.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", adminToken);
                using var response = await admin.PostAsync($"/admin/devices/{rightIdentity.DeviceId}/revoke", null, timeout.Token);
                TestAssert.Equal(System.Net.HttpStatusCode.NoContent, response.StatusCode, "Service revocation must succeed.");
                while (right.Status.Phase != PeerHostPhase.Failed || right.ActivePeer is not null || incoming.PeerIdentityVerified)
                    await Task.Delay(10, timeout.Token);
                TestAssert.True(!incoming.IsEndToEndEncrypted, "Loss of authorized signaling must close the active native session.");
            }
            finally { await app.StopAsync(CancellationToken.None); }
        }
        finally { Directory.Delete(root, true); }
    }

    private sealed class FakeFrameSource(byte[] frame) : IDesktopFrameSource
    {
        public Task<byte[]> CaptureAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested(); return Task.FromResult(frame);
        }
    }
}
