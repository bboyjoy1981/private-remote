using System.Security.Cryptography;
using PrivateRemote.Client;
using PrivateRemote.Protocol;
using PrivateRemote.Transport;

namespace PrivateRemote.Tests.Transport;

internal static class NativePeerLifecycleTests
{
    public static void RealManagedPeersTransferDataAndCloseOnRevocation() => RunAsync(true).GetAwaiter().GetResult();
    public static void ControlOnlyPeerRejectsBulkChannel() => RunAsync(false).GetAwaiter().GetResult();

    private static async Task RunAsync(bool includeBulk)
    {
        var library = NativeNegotiationTests.FindLibrary();
        var root = Path.Combine(Path.GetTempPath(), "private-remote-native-session-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(Path.Combine(root, "left"));
        Directory.CreateDirectory(Path.Combine(root, "right"));
        try
        {
            using var leftIdentity = DeviceIdentity.Create();
            using var rightIdentity = DeviceIdentity.Create();
            var capabilities = SessionCapability.ScreenControl | (includeBulk ? SessionCapability.FileTransfer : SessionCapability.None);
            var leftStore = new DeviceStore(Path.Combine(root, "left"));
            var rightStore = new DeviceStore(Path.Combine(root, "right"));
            leftStore.SaveApprovedDevice(new PairedDevice(rightIdentity.DeviceId, rightIdentity.PublicKey, "right", capabilities));
            rightStore.SaveApprovedDevice(new PairedDevice(leftIdentity.DeviceId, leftIdentity.PublicKey, "left", capabilities));
            var leftFactory = new DeviceSessionFactory(leftStore, leftIdentity);
            var rightFactory = new DeviceSessionFactory(rightStore, rightIdentity);
            using var lifetime = new CancellationTokenSource(TimeSpan.FromSeconds(20));
            await using var left = await leftFactory.BeginOutgoingNativeAsync(rightIdentity.DeviceId, capabilities, library, lifetime.Token, "127.0.0.1");
            var pending = new List<SignalingEnvelope>();
            var offer = await left.ReadOutgoingSignalAsync(lifetime.Token);
            while (offer.MessageType != "offer")
            {
                pending.Add(offer);
                offer = await left.ReadOutgoingSignalAsync(lifetime.Token);
            }

            await using var right = await rightFactory.AcceptIncomingNativeAsync(offer, library, lifetime.Token, "127.0.0.1");
            foreach (var signal in pending) right.ApplySignal(signal);
            var forward = PumpAsync(left, right, lifetime.Token);
            var backward = PumpAsync(right, left, lifetime.Token);
            try
            {
                var ready = Task.WhenAll(left.WaitForReadyAsync(lifetime.Token), right.WaitForReadyAsync(lifetime.Token));
                var first = await Task.WhenAny(ready, forward, backward);
                await first;
                await ready;
                TestAssert.True(left.PeerIdentityVerified && right.PeerIdentityVerified && left.IsEndToEndEncrypted && right.IsEndToEndEncrypted,
                    "Both actual native peers must verify signed identity and DTLS before data use.");
                TestAssert.Equal(PeerRouteKind.Direct, left.Route, "Loopback peers must report the actual direct candidate route.");
                var control = "managed-native-control"u8.ToArray();
                await left.SendAsync(PeerDataChannel.Control, control, lifetime.Token);
                var receivedControl = await right.ReadMessageAsync(lifetime.Token);
                TestAssert.Equal(PeerDataChannel.Control, receivedControl.Channel, "Control must use the dedicated ordered channel.");
                TestAssert.SequenceEqual(control, receivedControl.Bytes, "Control bytes must arrive unchanged.");
                if (includeBulk)
                {
                    var bulk = RandomNumberGenerator.GetBytes(64 * 1024);
                    await right.SendAsync(PeerDataChannel.Bulk, bulk, lifetime.Token);
                    var receivedBulk = await left.ReadMessageAsync(lifetime.Token);
                    TestAssert.Equal(PeerDataChannel.Bulk, receivedBulk.Channel, "Bulk traffic must use its dedicated channel.");
                    TestAssert.SequenceEqual(bulk, receivedBulk.Bytes, "A full-size native bulk chunk must arrive unchanged.");
                }
                else
                {
                    TestAssert.Throws<UnauthorizedAccessException>(() => left.SendAsync(PeerDataChannel.Bulk, control, lifetime.Token).GetAwaiter().GetResult(),
                        "A screen-only session must reject bulk use before sending bytes.");
                }

                new DeviceStore(Path.Combine(root, "left")).RevokeDevice(rightIdentity.DeviceId);
                try
                {
                    await left.Completion.WaitAsync(TimeSpan.FromSeconds(5));
                    throw new InvalidOperationException("Revocation did not terminate the native session.");
                }
                catch (PeerAuthenticationException) { }
                await left.DisposeAsync();
                TestAssert.True(!left.PeerIdentityVerified && !left.IsEndToEndEncrypted, "A disposed revoked session must report no active encrypted identity.");
                TestAssert.Throws<ObjectDisposedException>(() => left.SendAsync(PeerDataChannel.Control, control, CancellationToken.None).GetAwaiter().GetResult(),
                    "Revoked native sessions must stop all subsequent sends.");
            }
            finally
            {
                lifetime.Cancel();
                foreach (var pump in new[] { forward, backward })
                {
                    try { await pump; }
                    catch (Exception exception) when (exception is OperationCanceledException or ObjectDisposedException or PeerAuthenticationException or System.Threading.Channels.ChannelClosedException) { }
                }
            }
        }
        finally { Directory.Delete(root, recursive: true); }
    }

    private static async Task PumpAsync(NativeWebRtcPeer source, NativeWebRtcPeer target, CancellationToken cancellationToken)
    {
        while (true)
        {
            var envelope = await source.ReadOutgoingSignalAsync(cancellationToken);
            target.ApplySignal(envelope);
        }
    }
}
