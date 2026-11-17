using System.Buffers.Binary;
using System.Text.Json;
using PrivateRemote.Protocol;
using PrivateRemote.Transfer;
using PrivateRemote.Transport;

namespace PrivateRemote.Client;

public sealed record SessionFileOffer(Guid Id, string FileName, long Length, byte[] Sha256);
public sealed record SessionFileProgress(string Direction, string FileName, long Completed, long Total, string Message);

/// <summary>One transfer in each direction. Content and end markers share the ordered bulk channel.</summary>
public sealed class SessionFiles(NativeWebRtcPeer peer) : IDisposable
{
    private readonly object _gate = new();
    private readonly SemaphoreSlim _sendGate = new(1, 1);
    private readonly CancellationTokenSource _lifetime = new();
    private readonly Queue<Guid> _retired = new();
    private Incoming? _incoming;
    private Outgoing? _outgoing;
    private bool _disposed;
    public Func<SessionFileOffer, CancellationToken, Task<string?>>? ChooseDestinationAsync { get; set; }
    public event EventHandler<SessionFileProgress>? ProgressChanged;
    public static bool IsPacket(byte[] bytes) => bytes.Length >= 4 && bytes.AsSpan(0, 4).SequenceEqual("PRF1"u8);

    public async Task SendFileAsync(string path, CancellationToken cancellationToken)
    {
        await _sendGate.WaitAsync(cancellationToken);
        Outgoing? current = null;
        CancellationTokenSource? linked = null;
        try
        {
            RequireActive();
            linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _lifetime.Token);
            var metadata = await FileSender.PrepareAsync(path, linked.Token);
            current = new(new(Guid.NewGuid(), metadata.FileName, metadata.Length, metadata.Sha256), linked);
            lock (_gate) { RequireActive(); _outgoing = current; }
            Report("发送", current.Offer, 0, "等待对方选择保存位置");
            await SendControlAsync(new("offer", current.Offer.Id, current.Offer), linked.Token);
            var accepted = await current.Decision.Task.WaitAsync(TimeSpan.FromMinutes(2), linked.Token);
            if (!accepted) throw new OperationCanceledException("对方拒绝接收。");
            await FileSender.SendPreparedAsync(path, metadata, new BulkSender(this, current),
                new InlineProgress(value => Report("发送", current.Offer, value.BytesSent, "正在发送")), linked.Token);
            await peer.SendAsync(PeerDataChannel.Bulk, Bulk(current.Offer.Id, 2, current.Offset, ReadOnlySpan<byte>.Empty), linked.Token);
            await current.Completed.Task.WaitAsync(TimeSpan.FromSeconds(30), linked.Token);
            Report("发送", current.Offer, metadata.Length, "对方已校验并保存");
        }
        catch
        {
            if (current is not null) await BestEffortCancelAsync(current.Offer.Id);
            throw;
        }
        finally
        {
            lock (_gate) { if (ReferenceEquals(_outgoing, current)) _outgoing = null; }
            linked?.Dispose();
            _sendGate.Release();
        }
    }

    public async Task HandleAsync(PeerDataMessage message, CancellationToken cancellationToken)
    {
        RequireActive();
        if (!IsPacket(message.Bytes)) throw new InvalidDataException("Unknown file message.");
        if (message.Channel == PeerDataChannel.Control)
        {
            if (message.Bytes.Length > 4096) throw new InvalidDataException("File metadata exceeds bounds.");
            var control = JsonSerializer.Deserialize<Control>(message.Bytes.AsSpan(4)) ?? throw new InvalidDataException("Empty file metadata.");
            if (control.Id == Guid.Empty) throw new InvalidDataException("Missing transfer identity.");
            if (control.Kind == "offer")
            {
                var offer = control.Offer ?? throw new InvalidDataException("Missing file offer.");
                ValidateOffer(offer);
                if (offer.Id != control.Id) throw new InvalidDataException("File offer identity mismatch.");
                Incoming? incoming = null;
                lock (_gate)
                {
                    if (_incoming is null && !_retired.Contains(offer.Id)) _incoming = incoming = new(offer);
                }
                if (incoming is null) await SendControlAsync(new("reject", offer.Id, null), cancellationToken);
                else _ = ApproveIncomingAsync(incoming);
                return;
            }
            lock (_gate)
            {
                switch (control.Kind)
                {
                    case "accept": if (_outgoing?.Offer.Id == control.Id) _outgoing.Decision.TrySetResult(true); break;
                    case "reject": if (_outgoing?.Offer.Id == control.Id) _outgoing.Decision.TrySetResult(false); break;
                    case "complete": if (_outgoing?.Offer.Id == control.Id) _outgoing.Completed.TrySetResult(); break;
                    case "cancel":
                        if (_outgoing?.Offer.Id == control.Id) _outgoing.Lifetime.Cancel();
                        if (_incoming?.Offer.Id == control.Id) CloseIncoming(_incoming, "对方已取消");
                        break;
                    default: throw new InvalidDataException("Unknown file control message.");
                }
            }
            return;
        }
        var bytes = message.Bytes;
        if (bytes.Length is < 29 or > 29 + 60 * 1024) throw new InvalidDataException("Invalid bulk chunk bounds.");
        var id = new Guid(bytes.AsSpan(4, 16)); var kind = bytes[20];
        var offset = BinaryPrimitives.ReadInt64LittleEndian(bytes.AsSpan(21));
        var completed = false;
        lock (_gate)
        {
            if (_retired.Contains(id)) return; // Discard authenticated chunks already in flight after cancellation.
            var incoming = _incoming;
            if (incoming?.Offer.Id != id || incoming.Receiver is null || incoming.Received != offset) throw new InvalidDataException("Unapproved or out-of-order file chunk.");
            if (kind == 1 && bytes.Length > 29)
            {
                incoming.Receiver.Write(bytes.AsSpan(29)); incoming.Received += bytes.Length - 29;
                Report("接收", incoming.Offer, incoming.Received, "正在接收");
            }
            else if (kind == 2 && bytes.Length == 29)
            {
                incoming.Receiver.Complete(); Report("接收", incoming.Offer, incoming.Received, "已校验并安全保存");
                CloseIncoming(incoming, null); completed = true;
            }
            else throw new InvalidDataException("Invalid bulk message type.");
        }
        if (completed) await SendControlAsync(new("complete", id, null), cancellationToken);
    }

    private async Task ApproveIncomingAsync(Incoming incoming)
    {
        try
        {
            var handler = ChooseDestinationAsync;
            var path = handler is null ? null : await handler(incoming.Offer, _lifetime.Token);
            lock (_gate)
            {
                if (!ReferenceEquals(_incoming, incoming) || _disposed) return;
                if (path is null) CloseIncoming(incoming, "已拒绝接收");
                else incoming.Receiver = new FileReceiver(Path.GetDirectoryName(Path.GetFullPath(path))!, Path.GetFileName(path), incoming.Offer.Length, incoming.Offer.Sha256);
            }
            await SendControlAsync(new(path is null ? "reject" : "accept", incoming.Offer.Id, null), _lifetime.Token);
        }
        catch (Exception exception)
        {
            lock (_gate) { if (ReferenceEquals(_incoming, incoming)) CloseIncoming(incoming, $"接收失败：{exception.Message}"); }
            await BestEffortCancelAsync(incoming.Offer.Id);
        }
    }

    public async Task CancelAsync()
    {
        Guid? send, receive;
        lock (_gate)
        {
            send = _outgoing?.Offer.Id; receive = _incoming?.Offer.Id;
            _outgoing?.Lifetime.Cancel();
            if (_incoming is not null) CloseIncoming(_incoming, "本机已取消，临时文件已清理");
        }
        if (send is Guid sender) await BestEffortCancelAsync(sender);
        if (receive is Guid receiver) await BestEffortCancelAsync(receiver);
    }
    private async Task BestEffortCancelAsync(Guid id)
    {
        try { using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(2)); await SendControlAsync(new("cancel", id, null), timeout.Token); }
        catch { await peer.DisposeAsync(); }
    }
    private Task SendControlAsync(Control control, CancellationToken token)
    {
        RequireActive(); var json = JsonSerializer.SerializeToUtf8Bytes(control);
        var packet = new byte[json.Length + 4]; "PRF1"u8.CopyTo(packet); json.CopyTo(packet, 4);
        return peer.SendAsync(PeerDataChannel.Control, packet, token);
    }
    private static byte[] Bulk(Guid id, byte kind, long offset, ReadOnlySpan<byte> data)
    {
        var packet = new byte[29 + data.Length]; "PRF1"u8.CopyTo(packet); id.TryWriteBytes(packet.AsSpan(4)); packet[20] = kind;
        BinaryPrimitives.WriteInt64LittleEndian(packet.AsSpan(21), offset); data.CopyTo(packet.AsSpan(29)); return packet;
    }
    private void RequireActive()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        CapabilityAuthorization.Require(peer.Capabilities, SessionCapability.FileTransfer);
        if (!peer.PeerIdentityVerified) throw new UnauthorizedAccessException("File transfer requires an active paired encrypted session.");
    }
    private static void ValidateOffer(SessionFileOffer offer)
    {
        if (offer.Id == Guid.Empty || offer.Length is < 0 or > 8L * 1024 * 1024 * 1024 || offer.Sha256?.Length != 32 || string.IsNullOrWhiteSpace(offer.FileName) || offer.FileName.Length > 255)
            throw new InvalidDataException("Invalid file metadata.");
        FileReceiver.ValidateFileName(offer.FileName);
    }
    private void Report(string direction, SessionFileOffer offer, long count, string message) => ProgressChanged?.Invoke(this, new(direction, offer.FileName, count, offer.Length, message));
    private void CloseIncoming(Incoming incoming, string? message)
    {
        incoming.Receiver?.Dispose(); _retired.Enqueue(incoming.Offer.Id); while (_retired.Count > 128) _retired.Dequeue();
        _incoming = null;
        if (message is not null) Report("接收", incoming.Offer, incoming.Received, message);
    }
    public void Dispose()
    {
        lock (_gate)
        {
            if (_disposed) return; _disposed = true; _lifetime.Cancel();
            _outgoing?.Lifetime.Cancel(); if (_incoming is not null) CloseIncoming(_incoming, "会话已结束，未完成文件已清理");
        }
    }
    private sealed record Control(string Kind, Guid Id, SessionFileOffer? Offer);
    private sealed class Incoming(SessionFileOffer offer) { public SessionFileOffer Offer = offer; public FileReceiver? Receiver; public long Received; }
    private sealed class Outgoing(SessionFileOffer offer, CancellationTokenSource lifetime)
    {
        public SessionFileOffer Offer = offer; public CancellationTokenSource Lifetime = lifetime; public long Offset;
        public TaskCompletionSource<bool> Decision = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource Completed = new(TaskCreationOptions.RunContinuationsAsynchronously);
    }
    private sealed class BulkSender(SessionFiles owner, Outgoing outgoing) : IEncryptedBulkDataChannel
    {
        public async ValueTask SendAsync(ReadOnlyMemory<byte> chunk, CancellationToken cancellationToken)
        {
            for (var position = 0; position < chunk.Length; position += 60 * 1024)
            {
                var count = Math.Min(60 * 1024, chunk.Length - position);
                await peerSend(chunk.Slice(position, count), cancellationToken); outgoing.Offset += count;
            }
        }
        private Task peerSend(ReadOnlyMemory<byte> bytes, CancellationToken token) => owner.peerSendAsync(outgoing.Offer.Id, outgoing.Offset, bytes, token);
    }
    private Task peerSendAsync(Guid id, long offset, ReadOnlyMemory<byte> data, CancellationToken token)
    { RequireActive(); return peer.SendAsync(PeerDataChannel.Bulk, Bulk(id, 1, offset, data.Span), token); }
    private sealed class InlineProgress(Action<FileTransferProgress> report) : IProgress<FileTransferProgress> { public void Report(FileTransferProgress value) => report(value); }
}
