using System.Security.Cryptography;

namespace PrivateRemote.Transfer;

public sealed record OutgoingFileMetadata(string FileName, long Length, byte[] Sha256);
public sealed record FileTransferProgress(long BytesSent, long TotalBytes);

public interface IEncryptedBulkDataChannel
{
    ValueTask SendAsync(ReadOnlyMemory<byte> chunk, CancellationToken cancellationToken);
}

public static class FileSender
{
    private const int ChunkSize = 64 * 1024;
    private const long MaximumTransferLength = 8L * 1024 * 1024 * 1024;

    public static async Task<OutgoingFileMetadata> SendAsync(
        string selectedFilePath,
        IEncryptedBulkDataChannel channel,
        IProgress<FileTransferProgress>? progress,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(selectedFilePath);
        ArgumentNullException.ThrowIfNull(channel);
        var fullPath = Path.GetFullPath(selectedFilePath);
        var metadata = await PrepareAsync(fullPath, cancellationToken).ConfigureAwait(false);
        try
        {
            await SendPreparedAsync(fullPath, metadata, channel, progress, cancellationToken).ConfigureAwait(false);
            return metadata;
        }
        catch
        {
            CryptographicOperations.ZeroMemory(metadata.Sha256);
            throw;
        }
    }

    public static async Task<OutgoingFileMetadata> PrepareAsync(string selectedFilePath, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(selectedFilePath);
        var fullPath = Path.GetFullPath(selectedFilePath);
        var fileInfo = new FileInfo(fullPath);
        if (!fileInfo.Exists)
        {
            throw new FileNotFoundException("The selected file no longer exists.", fullPath);
        }

        if (fileInfo.Length > MaximumTransferLength)
        {
            throw new InvalidDataException("The selected file exceeds the transfer size limit.");
        }

        var hash = await ComputeHashAsync(fullPath, cancellationToken).ConfigureAwait(false);
        try
        {
            return new OutgoingFileMetadata(Path.GetFileName(fullPath), fileInfo.Length, hash.ToArray());
        }
        finally
        {
            CryptographicOperations.ZeroMemory(hash);
        }
    }

    public static async Task SendPreparedAsync(
        string selectedFilePath,
        OutgoingFileMetadata metadata,
        IEncryptedBulkDataChannel channel,
        IProgress<FileTransferProgress>? progress,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(selectedFilePath);
        ArgumentNullException.ThrowIfNull(metadata);
        ArgumentNullException.ThrowIfNull(channel);
        var fullPath = Path.GetFullPath(selectedFilePath);
        if (metadata.FileName is null || !StringComparer.Ordinal.Equals(metadata.FileName, Path.GetFileName(fullPath)) ||
            metadata.Length < 0 || metadata.Length > MaximumTransferLength || metadata.Sha256 is null || metadata.Sha256.Length != 32)
        {
            throw new ArgumentException("The prepared metadata does not match a valid transfer.", nameof(metadata));
        }

        var fileInfo = new FileInfo(fullPath);
        if (!fileInfo.Exists)
        {
            throw new FileNotFoundException("The selected file no longer exists.", fullPath);
        }

        if (fileInfo.Length != metadata.Length)
        {
            throw new IOException("The selected file changed after its transfer metadata was prepared.");
        }

        var expectedHash = metadata.Sha256.ToArray();
        var buffer = new byte[ChunkSize];
        using var sentContentHash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        long sent = 0;
        try
        {
            await using var stream = new FileStream(fullPath, FileMode.Open, FileAccess.Read, FileShare.Read, ChunkSize, FileOptions.Asynchronous | FileOptions.SequentialScan);
            if (stream.Length != metadata.Length)
            {
                throw new IOException("The selected file changed after its transfer hash was calculated.");
            }

            int read;
            while ((read = await stream.ReadAsync(buffer.AsMemory(0, buffer.Length), cancellationToken).ConfigureAwait(false)) > 0)
            {
                cancellationToken.ThrowIfCancellationRequested();
                sentContentHash.AppendData(buffer, 0, read);
                await channel.SendAsync(buffer.AsMemory(0, read), cancellationToken).ConfigureAwait(false);
                sent += read;
                progress?.Report(new FileTransferProgress(sent, metadata.Length));
            }

            if (sent != metadata.Length)
            {
                throw new IOException("The selected file changed during transfer.");
            }

            var actualHash = sentContentHash.GetHashAndReset();
            try
            {
                if (!CryptographicOperations.FixedTimeEquals(actualHash, expectedHash))
                {
                    throw new IOException("The selected file content did not match the prepared transfer metadata.");
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(actualHash);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(buffer);
            CryptographicOperations.ZeroMemory(expectedHash);
        }
    }

    private static async Task<byte[]> ComputeHashAsync(string path, CancellationToken cancellationToken)
    {
        await using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, ChunkSize, FileOptions.Asynchronous | FileOptions.SequentialScan);
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var buffer = new byte[ChunkSize];
        try
        {
            int read;
            while ((read = await stream.ReadAsync(buffer.AsMemory(), cancellationToken).ConfigureAwait(false)) > 0)
            {
                hash.AppendData(buffer, 0, read);
            }

            return hash.GetHashAndReset();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(buffer);
        }
    }
}
