using System.Collections.Concurrent;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Channels;
using PrivateRemote.Protocol;

namespace PrivateRemote.Transport;

public enum PeerDataChannel { Control, Bulk }
public sealed record PeerDataMessage(PeerDataChannel Channel, byte[] Bytes);

/// <summary>Signed negotiation and bounded ordered data channels over an actual native peer.</summary>
public sealed class NativeWebRtcPeer : IPeerConnection
{
    private readonly WebRtcNegotiation _negotiation;
    private readonly LibDataChannelNative.Lease _lease;
    private readonly Delegate[] _callbacks;
    private readonly Channel<SignalingEnvelope> _signals = Channel.CreateBounded<SignalingEnvelope>(128);
    private readonly Channel<PeerDataMessage> _messages = Channel.CreateBounded<PeerDataMessage>(128);
    private readonly ConcurrentDictionary<PeerDataChannel, int> _channels = new();
    private readonly ConcurrentDictionary<int, PeerDataChannel> _channelKinds = new();
    private readonly Dictionary<PeerDataChannel, TaskCompletionSource> _ready = [];
    private readonly TaskCompletionSource _connected = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly TaskCompletionSource _completion = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly CancellationTokenSource _lifetime = new();
    private readonly SemaphoreSlim _sendGate = new(1, 1);
    private readonly object _nativeGate = new();
    private readonly LibDataChannelNative.Description _descriptionCallback;
    private readonly LibDataChannelNative.Candidate _candidateCallback;
    private readonly LibDataChannelNative.State _stateCallback;
    private readonly LibDataChannelNative.DataChannel _channelCallback;
    private readonly LibDataChannelNative.ChannelEvent _openCallback, _closedCallback;
    private readonly LibDataChannelNative.Message _messageCallback;
    private Task _monitor = Task.CompletedTask;
    private Task? _disposal;
    private int _peer = -1, _closing, _started, _nativeState, _verifiedDescription;
    private PeerRouteKind _route;
    private readonly object _signalGate = new();
    private readonly Queue<SignalingEnvelope> _pendingLocalCandidates = new();
    private readonly Queue<WebRtcSignalPayload> _pendingRemoteCandidates = new();
    private bool _localDescriptionQueued;
    private int _localDescriptions, _remoteDescriptions, _localCandidates, _remoteCandidates;
    private string _localLanCandidate = "无", _remoteLanCandidate = "无";
    public string ConnectionDiagnostics => $"状态={Volatile.Read(ref _nativeState)}，SDP发/收={Volatile.Read(ref _localDescriptions)}/{Volatile.Read(ref _remoteDescriptions)}，ICE发/收={Volatile.Read(ref _localCandidates)}/{Volatile.Read(ref _remoteCandidates)}，数据通道={_ready.Values.Count(value => value.Task.IsCompletedSuccessfully)}/{_ready.Count}，本地地址={Volatile.Read(ref _localLanCandidate)}，对端地址={Volatile.Read(ref _remoteLanCandidate)}";

    public NativeWebRtcPeer(WebRtcNegotiation negotiation, string libraryPath, string? bindAddress = null,
        IReadOnlyList<string>? iceServers = null, bool relayOnly = false)
    {
        _negotiation = negotiation ?? throw new ArgumentNullException(nameof(negotiation));
        negotiation.RequireCurrentAuthorization();
        iceServers ??= Array.Empty<string>();
        if (iceServers.Count > 8 || iceServers.Any(server => string.IsNullOrWhiteSpace(server) || server.Length > 2048 || server.Any(char.IsControl)))
            throw new ArgumentException("Invalid ICE server configuration.", nameof(iceServers));
        if (relayOnly && !iceServers.Any(server => server.StartsWith("turn:", StringComparison.OrdinalIgnoreCase) || server.StartsWith("turns:", StringComparison.OrdinalIgnoreCase)))
            throw new ArgumentException("A relay-only peer requires TURN configuration.", nameof(iceServers));
        foreach (var channel in RequiredChannels()) _ready[channel] = new(TaskCreationOptions.RunContinuationsAsynchronously);
        _descriptionCallback = (_, sdp, type, _) => Guard(() => QueueSignal(negotiation.CreateDescription(Marshal.PtrToStringUTF8(type)!, Marshal.PtrToStringUTF8(sdp)!, DateTimeOffset.UtcNow)));
        _candidateCallback = (_, candidate, mid, _) => Guard(() => QueueSignal(negotiation.CreateCandidate(Marshal.PtrToStringUTF8(candidate)!, Marshal.PtrToStringUTF8(mid)!, DateTimeOffset.UtcNow)));
        _stateCallback = (_, state, _) => Guard(() =>
        {
            Volatile.Write(ref _nativeState, state);
            if (state == 2) _connected.TrySetResult();
            else if (state >= 3) Fail(new PeerRouteUnavailableException("The native peer disconnected or failed."));
        });
        _channelCallback = (_, channel, _) => Guard(() => AttachChannel(channel));
        _openCallback = (channel, _) => Guard(() => { if (_channelKinds.TryGetValue(channel, out var kind)) _ready[kind].TrySetResult(); });
        _closedCallback = (_, _) => Guard(() => Fail(new PeerRouteUnavailableException("A native data channel closed.")));
        _messageCallback = (channel, data, size, _) => Guard(() =>
        {
            RequireCurrent();
            if (size < 0 || size > 64 * 1024 || !_channelKinds.TryGetValue(channel, out var kind))
                throw new InvalidDataException("Unexpected native message type, channel or size.");
            RequireChannel(kind);
            var bytes = new byte[size];
            Marshal.Copy(data, bytes, 0, size);
            if (!_messages.Writer.TryWrite(new(kind, bytes)))
            {
                CryptographicOperations.ZeroMemory(bytes);
                throw new IOException("The bounded incoming data queue is full.");
            }
        });
        _callbacks = [_descriptionCallback, _candidateCallback, _stateCallback, _channelCallback, _openCallback, _closedCallback, _messageCallback];
        _lease = LibDataChannelNative.Acquire(libraryPath);
        var strings = new List<IntPtr>();
        IntPtr serverArray = IntPtr.Zero;
        try
        {
            var configuration = new LibDataChannelNative.Configuration { TransportPolicy = relayOnly ? 1 : 0, MaxMessageSize = 64 * 1024 };
            if (bindAddress is not null)
            {
                if (!System.Net.IPAddress.TryParse(bindAddress, out _)) throw new ArgumentException("Invalid bind address.", nameof(bindAddress));
                configuration.BindAddress = Marshal.StringToCoTaskMemUTF8(bindAddress);
                strings.Add(configuration.BindAddress);
            }
            if (iceServers.Count > 0)
            {
                serverArray = Marshal.AllocHGlobal(IntPtr.Size * iceServers.Count);
                for (var i = 0; i < iceServers.Count; i++)
                {
                    var text = Marshal.StringToCoTaskMemUTF8(iceServers[i]);
                    strings.Add(text);
                    Marshal.WriteIntPtr(serverArray, i * IntPtr.Size, text);
                }
                configuration.IceServers = serverArray;
                configuration.IceServersCount = iceServers.Count;
            }
            _peer = LibDataChannelNative.CreatePeer(ref configuration); Check(_peer);
            Check(LibDataChannelNative.SetDescription(_peer, _descriptionCallback));
            Check(LibDataChannelNative.SetCandidate(_peer, _candidateCallback));
            Check(LibDataChannelNative.SetState(_peer, _stateCallback));
            Check(LibDataChannelNative.SetDataChannel(_peer, _channelCallback));
            _monitor = MonitorAuthorizationAsync();
        }
        catch
        {
            Interlocked.Exchange(ref _closing, 1);
            if (_peer >= 0) LibDataChannelNative.DeletePeer(_peer);
            _lease.Release(_callbacks);
            _lifetime.Dispose();
            throw;
        }
        finally
        {
            foreach (var text in strings) Marshal.FreeCoTaskMem(text);
            if (serverArray != IntPtr.Zero) Marshal.FreeHGlobal(serverArray);
        }
    }

    public string PeerDeviceId => _negotiation.PeerDeviceId;
    public Guid SessionId => _negotiation.SessionId;
    public bool IsInitiator => _negotiation.IsInitiator;
    public SessionCapability Capabilities => _negotiation.Capabilities;
    public SignalingEnvelope CreateCloseSignal() => _negotiation.CreateClose(DateTimeOffset.UtcNow);
    public PeerRouteKind Route => _route;
    public bool IsEndToEndEncrypted => Volatile.Read(ref _closing) == 0 && Volatile.Read(ref _nativeState) == 2 && Volatile.Read(ref _verifiedDescription) != 0;
    public bool PeerIdentityVerified
    {
        get
        {
            if (!IsEndToEndEncrypted) return false;
            try { _negotiation.RequireCurrentAuthorization(); return true; }
            catch (Exception exception) when (exception is PeerAuthenticationException or UnauthorizedAccessException) { return false; }
        }
    }
    public Task Completion => _completion.Task;

    public void StartOutgoing()
    {
        lock (_nativeGate)
        {
            RequireCurrent();
            if (!_negotiation.IsInitiator || Interlocked.Exchange(ref _started, 1) != 0) throw new InvalidOperationException("Only an unstarted initiator may create outgoing channels.");
            try
            {
                foreach (var kind in RequiredChannels())
                {
                    var channel = LibDataChannelNative.CreateDataChannel(_peer, Label(kind));
                    Check(channel);
                    AttachChannel(channel);
                }
            }
            catch (Exception exception) { Fail(exception); throw; }
        }
    }

    public void ApplySignal(SignalingEnvelope envelope)
    {
        try { ApplyVerifiedSignal(_negotiation.Accept(envelope, DateTimeOffset.UtcNow)); }
        catch (Exception exception) { Fail(exception); throw; }
    }

    public void ApplyVerifiedSignal(VerifiedWebRtcSignal verified)
    {
        ArgumentNullException.ThrowIfNull(verified);
        lock (_nativeGate)
        {
            try
            {
                RequireCurrent();
                var payload = verified.Claim(_negotiation);
                if (verified.Type == "session-close") { Fail(new PeerRouteUnavailableException("The paired peer ended the session.")); return; }
                if (verified.Type == "ice")
                {
                    Interlocked.Increment(ref _remoteCandidates);
                    RecordLanCandidate(payload.Data, ref _remoteLanCandidate);
                    if (Volatile.Read(ref _verifiedDescription) == 0)
                    {
                        if (_pendingRemoteCandidates.Count >= 64) throw new InvalidDataException("Too many candidates before the remote description.");
                        _pendingRemoteCandidates.Enqueue(payload);
                    }
                    else Check(LibDataChannelNative.AddCandidate(_peer, payload.Data, payload.Auxiliary));
                }
                else
                {
                    var result = LibDataChannelNative.SetRemoteDescription(_peer, payload.Data, verified.Type);
                    if (result < 0) throw new PeerAuthenticationException("The native peer rejected the authenticated description.");
                    Volatile.Write(ref _verifiedDescription, 1);
                    Interlocked.Increment(ref _remoteDescriptions);
                    while (_pendingRemoteCandidates.TryDequeue(out var candidate)) Check(LibDataChannelNative.AddCandidate(_peer, candidate.Data, candidate.Auxiliary));
                }
            }
            catch (Exception exception) { Fail(exception); throw; }
        }
    }

    public async Task WaitForReadyAsync(CancellationToken cancellationToken)
    {
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _lifetime.Token);
        await Task.WhenAll(_ready.Values.Select(source => source.Task).Append(_connected.Task)).WaitAsync(linked.Token).ConfigureAwait(false);
        lock (_nativeGate)
        {
            RequireCurrent();
            if (!PeerIdentityVerified) throw new PeerAuthenticationException("The native session has not verified the signed DTLS description.");
            var local = new byte[2048]; var remote = new byte[2048];
            Check(LibDataChannelNative.GetSelectedCandidates(_peer, local, local.Length, remote, remote.Length));
            _route = Decode(local).Contains(" typ relay", StringComparison.Ordinal) || Decode(remote).Contains(" typ relay", StringComparison.Ordinal)
                ? PeerRouteKind.Relay : PeerRouteKind.Direct;
        }
    }

    public async Task SendAsync(PeerDataChannel kind, ReadOnlyMemory<byte> data, CancellationToken cancellationToken)
    {
        RequireCurrent(); RequireChannel(kind);
        if (data.Length == 0 || data.Length > 64 * 1024) throw new ArgumentOutOfRangeException(nameof(data));
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _lifetime.Token);
        await WaitForReadyAsync(linked.Token).ConfigureAwait(false);
        await _sendGate.WaitAsync(linked.Token).ConfigureAwait(false);
        byte[]? bytes = null;
        try
        {
            while (true)
            {
                lock (_nativeGate)
                {
                    RequireCurrent();
                    var channel = _channels[kind];
                    var buffered = LibDataChannelNative.BufferedAmount(channel); Check(buffered);
                    if (buffered < 1024 * 1024)
                    {
                        bytes = data.ToArray();
                        Check(LibDataChannelNative.Send(channel, bytes, bytes.Length));
                        return;
                    }
                }
                await Task.Delay(20, linked.Token).ConfigureAwait(false);
            }
        }
        finally
        {
            if (bytes is not null) CryptographicOperations.ZeroMemory(bytes);
            _sendGate.Release();
        }
    }

    public async Task<SignalingEnvelope> ReadOutgoingSignalAsync(CancellationToken cancellationToken)
    {
        RequireCurrent();
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _lifetime.Token);
        var signal = await _signals.Reader.ReadAsync(linked.Token).ConfigureAwait(false);
        RequireCurrent();
        return signal;
    }

    public async Task<PeerDataMessage> ReadMessageAsync(CancellationToken cancellationToken)
    {
        RequireCurrent();
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _lifetime.Token);
        var message = await _messages.Reader.ReadAsync(linked.Token).ConfigureAwait(false);
        try { RequireCurrent(); return message; }
        catch { CryptographicOperations.ZeroMemory(message.Bytes); throw; }
    }

    public ValueTask DisposeAsync()
    {
        lock (_nativeGate) return new ValueTask(_disposal ??= DisposeCoreAsync());
    }

    private async Task DisposeCoreAsync()
    {
        Interlocked.Exchange(ref _closing, 1);
        _lifetime.Cancel();
        _signals.Writer.TryComplete(); _messages.Writer.TryComplete();
        _connected.TrySetCanceled();
        foreach (var ready in _ready.Values) ready.TrySetCanceled();
        await _monitor.ConfigureAwait(false);
        await Task.Run(() =>
        {
            lock (_nativeGate)
            {
                foreach (var channel in _channelKinds.Keys) LibDataChannelNative.DeleteDataChannel(channel);
                _channelKinds.Clear(); _channels.Clear();
                if (_peer >= 0) { LibDataChannelNative.ClosePeer(_peer); LibDataChannelNative.DeletePeer(_peer); _peer = -1; }
            }
            _lease.Release(_callbacks);
        }).ConfigureAwait(false);
        while (_messages.Reader.TryRead(out var pending)) CryptographicOperations.ZeroMemory(pending.Bytes);
        _lifetime.Dispose();
        _completion.TrySetResult();
    }

    private async Task MonitorAuthorizationAsync()
    {
        try
        {
            while (true)
            {
                await Task.Delay(250, _lifetime.Token).ConfigureAwait(false);
                _negotiation.RequireCurrentAuthorization();
            }
        }
        catch (OperationCanceledException) when (_lifetime.IsCancellationRequested) { }
        catch (Exception exception) { Fail(exception); }
    }

    private void AttachChannel(int channel)
    {
        RequireCurrent();
        var labelBytes = new byte[128];
        Check(LibDataChannelNative.GetLabel(channel, labelBytes, labelBytes.Length));
        var label = Decode(labelBytes);
        var kind = label switch { "pr-control-v1" => PeerDataChannel.Control, "pr-bulk-v1" => PeerDataChannel.Bulk, _ => throw new PeerAuthenticationException("An unauthorized native channel was offered.") };
        RequireChannel(kind);
        Check(LibDataChannelNative.GetReliability(channel, out var reliability));
        if (reliability.Unordered != 0 || reliability.Unreliable != 0) throw new PeerAuthenticationException("Control and bulk channels must be reliable and ordered.");
        if (!_channels.TryAdd(kind, channel)) throw new PeerAuthenticationException("A duplicate native channel was offered.");
        _channelKinds[channel] = kind;
        Check(LibDataChannelNative.SetMessage(channel, _messageCallback));
        Check(LibDataChannelNative.SetClosed(channel, _closedCallback));
        Check(LibDataChannelNative.SetOpen(channel, _openCallback));
        if (LibDataChannelNative.IsOpen(channel)) _ready[kind].TrySetResult();
    }

    private IEnumerable<PeerDataChannel> RequiredChannels()
    {
        if ((_negotiation.Capabilities & SessionCapability.ScreenControl) != 0) yield return PeerDataChannel.Control;
        if ((_negotiation.Capabilities & SessionCapability.FileTransfer) != 0) yield return PeerDataChannel.Bulk;
    }
    private void RequireChannel(PeerDataChannel kind)
    {
        var capability = kind switch { PeerDataChannel.Control => SessionCapability.ScreenControl, PeerDataChannel.Bulk => SessionCapability.FileTransfer, _ => throw new ArgumentOutOfRangeException(nameof(kind)) };
        CapabilityAuthorization.Require(_negotiation.Capabilities, capability);
    }
    private static string Label(PeerDataChannel kind) => kind == PeerDataChannel.Control ? "pr-control-v1" : "pr-bulk-v1";
    private static string Decode(byte[] text)
    {
        var end = Array.IndexOf(text, (byte)0);
        return Encoding.UTF8.GetString(text, 0, end >= 0 ? end : text.Length);
    }
    private static void Check(int result) { if (result < 0) throw new IOException($"Native peer API returned error {result}."); }
    private void RequireCurrent()
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _closing) != 0, this);
        _negotiation.RequireCurrentAuthorization();
    }
    private void QueueSignal(SignalingEnvelope signal)
    {
        lock (_signalGate)
        {
            if (signal.MessageType == "ice")
            {
                Interlocked.Increment(ref _localCandidates);
                var payload = System.Text.Json.JsonSerializer.Deserialize<WebRtcSignalPayload>(signal.Payload);
                if (payload is not null) RecordLanCandidate(payload.Data, ref _localLanCandidate);
                if (!_localDescriptionQueued)
                {
                    if (_pendingLocalCandidates.Count >= 64) throw new IOException("Too many candidates before the local description.");
                    _pendingLocalCandidates.Enqueue(signal); return;
                }
            }
            if (!_signals.Writer.TryWrite(signal)) throw new IOException("The bounded outgoing signaling queue is full.");
            if (signal.MessageType is "offer" or "answer")
            {
                Interlocked.Increment(ref _localDescriptions); _localDescriptionQueued = true;
                while (_pendingLocalCandidates.TryDequeue(out var candidate))
                    if (!_signals.Writer.TryWrite(candidate)) throw new IOException("The bounded outgoing signaling queue is full.");
            }
        }
    }
    private static void RecordLanCandidate(string candidate, ref string destination)
    {
        var fields = candidate.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (fields.Length >= 6 && System.Net.IPAddress.TryParse(fields[4], out var address) &&
            address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork && !System.Net.IPAddress.IsLoopback(address) && !address.ToString().StartsWith("169.254.", StringComparison.Ordinal))
            Volatile.Write(ref destination, address + ":" + fields[5] + "/" + fields[2]);
    }
    private void Guard(Action callback)
    {
        if (Volatile.Read(ref _closing) != 0) return;
        try { callback(); } catch (Exception exception) { Fail(exception); }
    }
    private void Fail(Exception exception)
    {
        if (Interlocked.Exchange(ref _closing, 1) != 0) return;
        _connected.TrySetException(exception);
        foreach (var ready in _ready.Values) ready.TrySetException(exception);
        _completion.TrySetException(exception);
        _signals.Writer.TryComplete(exception); _messages.Writer.TryComplete(exception);
        _lifetime.Cancel();
        _ = DisposeAsync();
    }
}
