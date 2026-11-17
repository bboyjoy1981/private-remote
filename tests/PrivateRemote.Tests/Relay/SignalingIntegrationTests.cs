using System.Net;
using System.Net.Http.Headers;
using System.Net.WebSockets;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.Extensions.DependencyInjection;
using PrivateRemote.Protocol;
using PrivateRemote.Relay;
using PrivateRemote.Transport;

namespace PrivateRemote.Tests.Relay;

internal static class SignalingIntegrationTests
{
    public static void TwoDevicesExchangeSignedMessagesAndRevocationClosesSocket() => RunAsync().GetAwaiter().GetResult();

    private static async Task RunAsync()
    {
        using var source = DeviceIdentity.Create();
        using var target = DeviceIdentity.Create();
        var sourceToken = Guid.NewGuid().ToString("N");
        var targetToken = Guid.NewGuid().ToString("N");
        var adminToken = Guid.NewGuid().ToString("N");
        await using var app = RelayServer.Build([
            "--environment", "Development", "--urls", "http://127.0.0.1:0",
            "--Logging:LogLevel:Default", "Warning",
            "--DevelopmentDevices:0:DeviceId", source.DeviceId,
            "--DevelopmentDevices:0:BearerToken", sourceToken,
            "--DevelopmentDevices:0:PublicKeyBase64", Convert.ToBase64String(source.PublicKey),
            "--DevelopmentDevices:1:DeviceId", target.DeviceId,
            "--DevelopmentDevices:1:BearerToken", targetToken,
            "--DevelopmentDevices:1:PublicKeyBase64", Convert.ToBase64String(target.PublicKey),
            "--RelayAdmin:BearerToken", adminToken
        ]);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        await app.StartAsync(timeout.Token);
        try
        {
            var address = app.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()!.Addresses.Single();
            var endpoint = new UriBuilder(address) { Scheme = "ws", Path = "/signal" }.Uri;
            await using var sender = new SignalingClient();
            await using var receiver = new SignalingClient();
            await sender.ConnectAsync(endpoint, source.DeviceId, sourceToken, timeout.Token);
            await receiver.ConnectAsync(endpoint, target.DeviceId, targetToken, timeout.Token);
            var sourceRecord = new PairedDevice(source.DeviceId, source.PublicKey, "source", SessionCapability.ScreenControl);
            var targetRecord = new PairedDevice(target.DeviceId, target.PublicKey, "target", SessionCapability.ScreenControl);
            var receiveInbox = new AuthenticatedSignalingInbox(target.DeviceId, id => id == source.DeviceId ? sourceRecord : null);
            var sendInbox = new AuthenticatedSignalingInbox(source.DeviceId, id => id == target.DeviceId ? targetRecord : null);
            var connected = app.Services.GetRequiredService<ConnectedDevices>();
            while (!connected.TryGet(source.DeviceId, out _) || !connected.TryGet(target.DeviceId, out _))
            {
                await Task.Delay(10, timeout.Token);
            }

            var messages = Enumerable.Range(0, 8).Select(index =>
                SignalingProtocol.CreateSigned(source, target.DeviceId, "ice", $"candidate-{index}", DateTimeOffset.UtcNow)).ToArray();
            await Task.WhenAll(messages.Select(message => sender.SendAsync(message, timeout.Token)));
            var receivedPayloads = new HashSet<string>();
            foreach (var _ in messages)
            {
                var received = (await receiver.ReceiveAuthenticatedAsync(receiveInbox, timeout.Token)).Envelope;
                TestAssert.True(SignalingProtocol.Verify(received, source.PublicKey, DateTimeOffset.UtcNow), "Forwarded messages must retain the source signature.");
                receivedPayloads.Add(received.Payload);
            }

            TestAssert.Equal(8, receivedPayloads.Count, "Concurrent sends must deliver each complete message exactly once.");
            await receiver.SendAsync(SignalingProtocol.CreateSigned(target, source.DeviceId, "answer", "peer-answer", DateTimeOffset.UtcNow), timeout.Token);
            TestAssert.Equal("peer-answer", (await sender.ReceiveAuthenticatedAsync(sendInbox, timeout.Token)).Envelope.Payload, "Signaling must work in both directions with paired-device authentication.");

            using var admin = new HttpClient { BaseAddress = new Uri(address) };
            admin.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", adminToken);
            using var response = await admin.PostAsync($"/admin/devices/{target.DeviceId}/revoke", null, timeout.Token);
            TestAssert.Equal(HttpStatusCode.NoContent, response.StatusCode, "Authorized revocation must succeed.");
            TestAssert.True(!connected.TryGet(target.DeviceId, out _), "Revocation must remove the active socket.");
            TestAssert.Throws<WebSocketException>(() => receiver.ReceiveAsync(timeout.Token).GetAwaiter().GetResult(), "A revoked peer must observe its socket closing.");
        }
        finally
        {
            await app.StopAsync(CancellationToken.None);
        }
    }
}
