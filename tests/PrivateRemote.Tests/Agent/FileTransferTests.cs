using System.Security.Cryptography;
using PrivateRemote.Transfer;
using PrivateRemote.Protocol;

namespace PrivateRemote.Tests.Agent;

internal static class FileTransferTests
{
    public static void CompletedFilesStayWithinSelectedDirectory()
    {
        var root = Path.Combine(Path.GetTempPath(), $"private-remote-tests-{Guid.NewGuid():N}");
        Directory.CreateDirectory(root);
        try
        {
            var payload = "transfer payload"u8.ToArray();
            using var receiver = new FileReceiver(root, "report.txt", payload.Length, SHA256.HashData(payload));
            receiver.Write(payload);
            var result = receiver.Complete();
            TestAssert.True(result.StartsWith(root, StringComparison.OrdinalIgnoreCase), "The finalized file must stay below the receiver-selected directory.");
            TestAssert.SequenceEqual(payload, File.ReadAllBytes(result), "The finalized file must match the verified payload.");
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    public static void InterruptedTransfersAreDiscarded()
    {
        var root = Path.Combine(Path.GetTempPath(), $"private-remote-tests-{Guid.NewGuid():N}");
        Directory.CreateDirectory(root);
        try
        {
            var receiver = new FileReceiver(root, "partial.bin", 8, SHA256.HashData(new byte[8]));
            receiver.Write(new byte[] { 1, 2, 3 });
            receiver.Dispose();
            TestAssert.Equal(0, Directory.GetFiles(root).Length, "An interrupted transfer must not be presented as a completed file.");
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    public static void WindowsSuperscriptDeviceNamesAreRejected()
    {
        var root = Path.Combine(Path.GetTempPath(), $"private-remote-tests-{Guid.NewGuid():N}");
        Directory.CreateDirectory(root);
        try
        {
            foreach (var name in new[] { "COM¹.txt", "COM².txt", "COM³.txt", "LPT¹.log", "LPT².log", "LPT³.log" })
            {
                TestAssert.Throws<InvalidDataException>(
                    () =>
                    {
                        using var receiver = new FileReceiver(root, name, 0, SHA256.HashData([]));
                    },
                    $"Windows reserved device name {name} must be rejected.");
            }
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    public static void DuplicateAndHashMismatchTransfersAreDiscarded()
    {
        var root = Path.Combine(Path.GetTempPath(), $"private-remote-tests-{Guid.NewGuid():N}");
        Directory.CreateDirectory(root);
        try
        {
            File.WriteAllText(Path.Combine(root, "existing.txt"), "keep");
            TestAssert.Throws<IOException>(
                () => new FileReceiver(root, "existing.txt", 0, SHA256.HashData([])),
                "An existing destination must never be overwritten.");

            var receiver = new FileReceiver(root, "mismatch.bin", 3, SHA256.HashData("yes"u8.ToArray()));
            receiver.Write("no!"u8);
            TestAssert.Throws<InvalidDataException>(() => receiver.Complete(), "A hash mismatch must fail finalization.");
            receiver.Dispose();
            TestAssert.True(!File.Exists(Path.Combine(root, "mismatch.bin")), "A hash mismatch must not create the destination file.");
            TestAssert.Equal(1, Directory.GetFiles(root).Length, "A failed transfer must remove its staging file.");
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    public static void InputRequiresScreenControl()
    {
        TestAssert.Throws<UnauthorizedAccessException>(
            () => CapabilityAuthorization.Require(SessionCapability.FileTransfer, SessionCapability.ScreenControl),
            "File-transfer permission must not authorize remote keyboard input.");
        CapabilityAuthorization.Require(SessionCapability.ScreenControl, SessionCapability.ScreenControl);
    }

    public static void SendingReportsProgressAndHonorsCancellation()
    {
        var root = Path.Combine(Path.GetTempPath(), $"private-remote-tests-{Guid.NewGuid():N}");
        Directory.CreateDirectory(root);
        var path = Path.Combine(root, "outgoing.bin");
        var payload = Enumerable.Range(0, 200_000).Select(value => (byte)(value % 251)).ToArray();
        File.WriteAllBytes(path, payload);
        try
        {
            var channel = new CollectingChannel();
            var progress = new List<FileTransferProgress>();
            var metadata = FileSender.SendAsync(path, channel, new InlineProgress<FileTransferProgress>(progress.Add), CancellationToken.None).GetAwaiter().GetResult();
            TestAssert.Equal("outgoing.bin", metadata.FileName, "Sender metadata must expose only the selected file name.");
            TestAssert.Equal((long)payload.Length, metadata.Length, "Sender metadata must carry the file length.");
            TestAssert.SequenceEqual(SHA256.HashData(payload), metadata.Sha256, "Sender metadata must include the verified file hash.");
            TestAssert.SequenceEqual(payload, channel.Bytes.ToArray(), "The encrypted channel must receive every selected byte in order.");
            TestAssert.Equal((long)payload.Length, progress[^1].BytesSent, "Progress must report the completed byte count.");

            using var cancellation = new CancellationTokenSource();
            var cancelChannel = new CollectingChannel(cancellation.Cancel);
            TestAssert.Throws<OperationCanceledException>(
                () => FileSender.SendAsync(path, cancelChannel, null, cancellation.Token).GetAwaiter().GetResult(),
                "Cancellation must stop an active send.");
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    public static void SenderCanPrepareMetadataBeforeStreaming()
    {
        var root = Path.Combine(Path.GetTempPath(), $"private-remote-tests-{Guid.NewGuid():N}");
        Directory.CreateDirectory(root);
        var path = Path.Combine(root, "prepared.bin");
        var payload = "metadata before bytes"u8.ToArray();
        File.WriteAllBytes(path, payload);
        try
        {
            var metadata = FileSender.PrepareAsync(path, CancellationToken.None).GetAwaiter().GetResult();
            TestAssert.Equal("prepared.bin", metadata.FileName, "The transfer header should be available before sending content.");
            TestAssert.Equal((long)payload.Length, metadata.Length, "Prepared metadata must include the exact length.");
            TestAssert.SequenceEqual(SHA256.HashData(payload), metadata.Sha256, "Prepared metadata must include the content hash.");

            var channel = new CollectingChannel();
            FileSender.SendPreparedAsync(path, metadata, channel, null, CancellationToken.None).GetAwaiter().GetResult();
            TestAssert.SequenceEqual(payload, channel.Bytes.ToArray(), "The prepared transfer should then send the matching file bytes.");
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    public static void SenderRejectsFileChangedAfterMetadataPreparation()
    {
        var root = Path.Combine(Path.GetTempPath(), $"private-remote-tests-{Guid.NewGuid():N}");
        Directory.CreateDirectory(root);
        var path = Path.Combine(root, "changed.bin");
        File.WriteAllBytes(path, "before"u8.ToArray());
        try
        {
            var metadata = FileSender.PrepareAsync(path, CancellationToken.None).GetAwaiter().GetResult();
            File.WriteAllBytes(path, "change"u8.ToArray());
            TestAssert.Throws<IOException>(
                () => FileSender.SendPreparedAsync(path, metadata, new CollectingChannel(), null, CancellationToken.None).GetAwaiter().GetResult(),
                "A file that changes after its signed metadata is prepared must not report successful completion.");
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    private sealed class CollectingChannel(Action? onSend = null) : IEncryptedBulkDataChannel
    {
        public MemoryStream Bytes { get; } = new();

        public ValueTask SendAsync(ReadOnlyMemory<byte> chunk, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Bytes.Write(chunk.Span);
            onSend?.Invoke();
            return ValueTask.CompletedTask;
        }
    }

    private sealed class InlineProgress<T>(Action<T> callback) : IProgress<T>
    {
        public void Report(T value) => callback(value);
    }
}
