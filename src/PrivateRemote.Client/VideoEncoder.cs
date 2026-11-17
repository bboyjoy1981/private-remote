namespace PrivateRemote.Client;

public interface IVideoEncoder : IAsyncDisposable
{
    Task<ReadOnlyMemory<byte>> EncodeAsync(ReadOnlyMemory<byte> frame, CancellationToken cancellationToken);
}

public sealed class MediaFoundationH264Encoder : IVideoEncoder
{
    public Task<ReadOnlyMemory<byte>> EncodeAsync(ReadOnlyMemory<byte> frame, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        throw new PlatformNotSupportedException("The Media Foundation H.264 transform is not connected yet.");
    }

    public ValueTask DisposeAsync() => ValueTask.CompletedTask;
}
