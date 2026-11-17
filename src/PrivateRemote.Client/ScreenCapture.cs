namespace PrivateRemote.Client;

public interface IScreenCapture : IAsyncDisposable
{
    event EventHandler<ReadOnlyMemory<byte>>? FrameAvailable;
    Task StartAsync(CancellationToken cancellationToken);
    Task StopAsync(CancellationToken cancellationToken);
}

public sealed class WindowsGraphicsCapture : IScreenCapture
{
    public event EventHandler<ReadOnlyMemory<byte>>? FrameAvailable
    {
        add { }
        remove { }
    }

    public Task StartAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        throw new PlatformNotSupportedException("Windows Graphics Capture is not connected yet. No screen data is captured.");
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    public ValueTask DisposeAsync() => ValueTask.CompletedTask;
}
