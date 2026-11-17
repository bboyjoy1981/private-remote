using System.Security.Cryptography;

namespace PrivateRemote.Transfer;

public sealed class FileReceiver : IDisposable
{
    private const long MaximumTransferLength = 8L * 1024 * 1024 * 1024;
    private readonly string _destinationDirectory;
    private readonly string _destinationPath;
    private readonly string _temporaryPath;
    private readonly long _expectedLength;
    private readonly byte[] _expectedHash;
    private readonly IncrementalHash _hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
    private FileStream? _stream;
    private long _receivedLength;
    private bool _completed;
    private bool _disposed;

    public FileReceiver(string selectedDirectory, string fileName, long expectedLength, byte[] expectedSha256)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(selectedDirectory);
        ArgumentException.ThrowIfNullOrWhiteSpace(fileName);
        ArgumentNullException.ThrowIfNull(expectedSha256);
        if (expectedLength < 0 || expectedLength > MaximumTransferLength)
        {
            throw new ArgumentOutOfRangeException(nameof(expectedLength), "The transfer length exceeds the allowed limit.");
        }

        if (expectedSha256.Length != 32)
        {
            throw new ArgumentException("The transfer hash must be a SHA-256 value.", nameof(expectedSha256));
        }

        ValidateFileName(fileName);
        _destinationDirectory = Path.GetFullPath(selectedDirectory);
        Directory.CreateDirectory(_destinationDirectory);
        _destinationPath = Path.Combine(_destinationDirectory, fileName);
        if (!StringComparer.OrdinalIgnoreCase.Equals(Path.GetDirectoryName(_destinationPath), _destinationDirectory))
        {
            throw new InvalidDataException("The received file path escaped the selected directory.");
        }

        if (File.Exists(_destinationPath) || Directory.Exists(_destinationPath))
        {
            throw new IOException("A file with this name already exists in the selected directory.");
        }

        _expectedLength = expectedLength;
        _expectedHash = expectedSha256.ToArray();
        _temporaryPath = Path.Combine(_destinationDirectory, $".private-remote-{Guid.NewGuid():N}.partial");
        _stream = new FileStream(_temporaryPath, FileMode.CreateNew, FileAccess.Write, FileShare.None, 64 * 1024, FileOptions.WriteThrough);
    }

    public long ReceivedLength => _receivedLength;

    public long ExpectedLength => _expectedLength;

    public void Write(ReadOnlySpan<byte> data)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (_completed)
        {
            throw new InvalidOperationException("The transfer is already complete.");
        }

        if (data.Length > _expectedLength - _receivedLength)
        {
            throw new InvalidDataException("The received data exceeds the declared file length.");
        }

        _stream!.Write(data);
        _hash.AppendData(data);
        _receivedLength += data.Length;
    }

    public string Complete()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (_completed)
        {
            throw new InvalidOperationException("The transfer is already complete.");
        }

        if (_receivedLength != _expectedLength)
        {
            throw new InvalidDataException("The received file length does not match the declared length.");
        }

        var actualHash = _hash.GetHashAndReset();
        try
        {
            if (!CryptographicOperations.FixedTimeEquals(actualHash, _expectedHash))
            {
                throw new InvalidDataException("The received file did not match the declared SHA-256 hash.");
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(actualHash);
        }

        _stream!.Flush(flushToDisk: true);
        _stream.Dispose();
        _stream = null;
        File.Move(_temporaryPath, _destinationPath);
        _completed = true;
        return _destinationPath;
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _stream?.Dispose();
        _hash.Dispose();
        CryptographicOperations.ZeroMemory(_expectedHash);
        if (!_completed && File.Exists(_temporaryPath))
        {
            File.Delete(_temporaryPath);
        }

        _disposed = true;
    }

    public static void ValidateFileName(string fileName)
    {
        if (fileName is "." or ".." || fileName.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0 ||
            fileName.Contains('/') || fileName.Contains('\\') || fileName.Contains(':') ||
            fileName.EndsWith(' ') || fileName.EndsWith('.') || IsReservedDeviceName(fileName))
        {
            throw new InvalidDataException("The received file name is not safe on Windows.");
        }
    }

    private static bool IsReservedDeviceName(string fileName)
    {
        var baseName = fileName.Split('.', 2)[0];
        if (baseName.Equals("CON", StringComparison.OrdinalIgnoreCase) ||
            baseName.Equals("PRN", StringComparison.OrdinalIgnoreCase) ||
            baseName.Equals("AUX", StringComparison.OrdinalIgnoreCase) ||
            baseName.Equals("NUL", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        return baseName.Length == 4 &&
               (baseName.StartsWith("COM", StringComparison.OrdinalIgnoreCase) || baseName.StartsWith("LPT", StringComparison.OrdinalIgnoreCase)) &&
               (baseName[3] is >= '1' and <= '9' or '¹' or '²' or '³');
    }
}

