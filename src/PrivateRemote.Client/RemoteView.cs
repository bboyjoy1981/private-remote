using PrivateRemote.Protocol;

namespace PrivateRemote.Client;

public enum ConnectionRoute
{
    None,
    Direct,
    Relay
}

public sealed record SessionStatus(
    bool IsConnected,
    string? PeerName,
    string? PeerDeviceId,
    SessionCapability Capabilities,
    ConnectionRoute Route,
    string Message);

public interface IRemoteSession : IAsyncDisposable
{
    SessionStatus Status { get; }
    event EventHandler<SessionStatus>? StatusChanged;
    event EventHandler<ReadOnlyMemory<byte>>? VideoFrameReceived;
    Task ConnectAsync(string pairedDeviceId, SessionCapability capabilities, CancellationToken cancellationToken);
    Task SendInputAsync(RemoteInputEvent input, CancellationToken cancellationToken);
    Task DisconnectAsync(CancellationToken cancellationToken);
}

public abstract record RemoteInputEvent;
public sealed record MouseMoveEvent(double NormalizedX, double NormalizedY) : RemoteInputEvent;
public sealed record MouseButtonEvent(int Button, bool IsDown) : RemoteInputEvent;
public sealed record MouseWheelEvent(int Delta) : RemoteInputEvent;
public sealed record KeyEvent(ushort VirtualKey, bool IsDown) : RemoteInputEvent;
public sealed record TextInputEvent(string Text, bool Paste = false) : RemoteInputEvent;
public sealed record RemoteInputResult(bool Success, string Message);
