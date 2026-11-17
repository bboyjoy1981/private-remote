namespace PrivateRemote.Transport;

public enum PeerRouteKind
{
    Direct,
    Relay
}

public enum PeerConnectionPhase
{
    Disconnected,
    ConnectingDirect,
    ConnectingRelay,
    Connected,
    Failed
}

public sealed record PeerRouteStatus(PeerConnectionPhase Phase, PeerRouteKind? Route, string Message)
{
    public static PeerRouteStatus Disconnected { get; } = new(PeerConnectionPhase.Disconnected, null, "未连接");
}

public sealed class PeerRouteUnavailableException(string message, Exception? innerException = null)
    : Exception(message, innerException);

public sealed class PeerAuthenticationException(string message, Exception? innerException = null)
    : Exception(message, innerException);

public sealed class PeerConnectionException(string message, Exception? innerException = null)
    : Exception(message, innerException);
