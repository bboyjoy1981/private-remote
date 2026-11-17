using PrivateRemote.Protocol;
using PrivateRemote.Transport;

namespace PrivateRemote.Tests.Transport;

internal static class DirectConnectionTests
{
    public static void DirectFailureFallsBackToRelay()
    {
        using var local = DeviceIdentity.Create();
        var peer = new FakePeerConnection(route: PeerRouteKind.Relay);
        var connector = new FakePeerConnector((route, _) => route == PeerRouteKind.Direct
            ? Task.FromException<IPeerConnection>(new PeerRouteUnavailableException("Direct path unavailable."))
            : Task.FromResult<IPeerConnection>(peer));
        var coordinator = new DirectPeer(connector, TimeSpan.FromSeconds(2));

        var result = coordinator.ConnectAsync(CreateRequest(local), CancellationToken.None).GetAwaiter().GetResult();

        TestAssert.Equal(PeerRouteKind.Relay, result.Route, "A direct route failure should select the encrypted relay route.");
        TestAssert.Equal(2, connector.Attempts.Count, "The direct route and relay fallback must each be attempted once.");
        TestAssert.Equal(PeerRouteKind.Direct, connector.Attempts[0], "Direct must be attempted first.");
        TestAssert.Equal(PeerRouteKind.Relay, connector.Attempts[1], "Relay must be attempted after direct failure.");
    }

    public static void AuthenticationFailureDoesNotRetry()
    {
        using var local = DeviceIdentity.Create();
        var connector = new FakePeerConnector((_, _) => Task.FromException<IPeerConnection>(new PeerAuthenticationException("Peer identity mismatch.")));
        var coordinator = new DirectPeer(connector, TimeSpan.FromSeconds(2));

        TestAssert.Throws<PeerAuthenticationException>(
            () => coordinator.ConnectAsync(CreateRequest(local), CancellationToken.None).GetAwaiter().GetResult(),
            "A peer identity failure must be surfaced.");
        TestAssert.Equal(1, connector.Attempts.Count, "Authentication failure must not retry on relay.");
    }

    public static void TimeoutFallsBackAndCallerCancellationStops()
    {
        using var local = DeviceIdentity.Create();
        var peer = new FakePeerConnection(route: PeerRouteKind.Relay);
        var connector = new FakePeerConnector(async (route, cancellationToken) =>
        {
            if (route == PeerRouteKind.Direct)
            {
                await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
            }

            return peer;
        });
        var coordinator = new DirectPeer(connector, TimeSpan.FromMilliseconds(20));
        var result = coordinator.ConnectAsync(CreateRequest(local), CancellationToken.None).GetAwaiter().GetResult();
        TestAssert.Equal(PeerRouteKind.Relay, result.Route, "An internal direct-path timeout should proceed to relay.");

        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        TestAssert.Throws<OperationCanceledException>(
            () => coordinator.ConnectAsync(CreateRequest(local), cancellation.Token).GetAwaiter().GetResult(),
            "Caller cancellation must stop all route attempts.");
    }

    public static void UnverifiedPeersAreRejected()
    {
        using var local = DeviceIdentity.Create();
        var direct = new FakePeerConnector((_, _) => Task.FromResult<IPeerConnection>(new FakePeerConnection(verified: false)));
        var coordinator = new DirectPeer(direct, TimeSpan.FromSeconds(2));
        TestAssert.Throws<PeerAuthenticationException>(
            () => coordinator.ConnectAsync(CreateRequest(local), CancellationToken.None).GetAwaiter().GetResult(),
            "A connection must not be exposed before encryption and identity verification.");
        TestAssert.Equal(1, direct.Attempts.Count, "An insecure direct peer must not be retried as relay.");
    }

    private static PeerConnectRequest CreateRequest(DeviceIdentity identity) => new(
        identity.DeviceId,
        new string('a', 64),
        SessionCapability.ScreenControl,
        new Uri("wss://signaling.example.invalid/signal"),
        "short-lived-token");

    private sealed class FakePeerConnector(Func<PeerRouteKind, CancellationToken, Task<IPeerConnection>> connect) : IPeerConnector
    {
        public List<PeerRouteKind> Attempts { get; } = [];

        public Task<IPeerConnection> ConnectAsync(PeerConnectRequest request, PeerRouteKind route, CancellationToken cancellationToken)
        {
            Attempts.Add(route);
            return connect(route, cancellationToken);
        }
    }

    private sealed class FakePeerConnection(PeerRouteKind route = PeerRouteKind.Direct, bool verified = true) : IPeerConnection
    {
        public PeerRouteKind Route { get; } = route;
        public bool IsEndToEndEncrypted { get; } = verified;
        public bool PeerIdentityVerified { get; } = verified;
        public string PeerDeviceId { get; } = new('a', 64);
        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }
}
