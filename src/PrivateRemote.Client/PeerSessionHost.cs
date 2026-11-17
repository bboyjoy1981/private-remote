using System.Text.Json;
using System.Threading.Channels;
using PrivateRemote.Protocol;
using PrivateRemote.Transport;

namespace PrivateRemote.Client;

public enum PeerHostPhase { Offline, Available, Negotiating, Connected, Failed }
public sealed record PeerHostStatus(PeerHostPhase Phase, string? PeerDeviceId, SessionCapability Capabilities, PeerRouteKind? Route, string Message);

/// <summary>One signaling connection and one active paired-device session; no public enrollment.</summary>
public sealed class PeerSessionHost : IAsyncDisposable
{
    private readonly DeviceSessionFactory _factory;
    private readonly string _libraryPath;
    private readonly string? _bindAddress;
    private readonly string[] _iceServers;
    private readonly SignalingClient _signaling = new();
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly CancellationTokenSource _lifetime = new();
    private readonly HashSet<PeerContext> _contexts = [];
    private PeerContext? _session;
    private Task _receiver = Task.CompletedTask;
    private Task? _disposal;
    private readonly object _disposeGate = new();
    private int _connectStarted, _disposeStarted;
    private volatile bool _signalingReady;
    private Exception? _failure;
    private PeerHostStatus _status = new(PeerHostPhase.Offline, null, SessionCapability.None, null, "未连接信令服务");

    public PeerSessionHost(DeviceSessionFactory factory, string libraryPath, string? bindAddress = null, IReadOnlyList<string>? iceServers = null)
    {
        _factory = factory ?? throw new ArgumentNullException(nameof(factory));
        _libraryPath = Path.GetFullPath(libraryPath);
        _bindAddress = bindAddress;
        _iceServers = iceServers?.ToArray() ?? [];
    }

    public PeerHostStatus Status => Volatile.Read(ref _status);
    public Exception? Failure => _failure;
    private readonly System.Collections.Concurrent.ConcurrentQueue<string> _signalTrace = new();
    public string SignalDiagnostics => string.Join("\n", _signalTrace.ToArray());
    private void Trace(string message)
    {
        _signalTrace.Enqueue($"{DateTimeOffset.UtcNow:HH:mm:ss.fff} {message}");
        while (_signalTrace.Count > 24) _signalTrace.TryDequeue(out _);
    }
    public string LastSessionDiagnostics { get; private set; } = "尚未开始设备握手";
    public NativeWebRtcPeer? ActivePeer => Volatile.Read(ref _session)?.Peer;
    public event EventHandler<PeerHostStatus>? StatusChanged;

    public async Task ConnectSignalingAsync(Uri endpoint, string bearerToken, CancellationToken cancellationToken, string? certificateSha256 = null)
    {
        EnsureAlive();
        if (Interlocked.Exchange(ref _connectStarted, 1) != 0) throw new InvalidOperationException("Create a new host to reconnect signaling.");
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _lifetime.Token);
        try
        {
            await _signaling.ConnectAsync(endpoint, _factory.LocalDeviceId, bearerToken, linked.Token, certificateSha256).ConfigureAwait(false);
            EnsureAlive();
            _signalingReady = true;
            SetStatus(new(PeerHostPhase.Available, null, SessionCapability.None, null, "信令已连接，等待已配对设备"));
            _receiver = ReceiveLoopAsync();
        }
        catch (Exception exception)
        {
            _failure = exception;
            SetStatus(new(PeerHostPhase.Failed, null, SessionCapability.None, null, "信令连接失败"));
            throw;
        }
    }

    public async Task<NativeWebRtcPeer> ConnectDeviceAsync(string peerDeviceId, SessionCapability capabilities, CancellationToken cancellationToken)
    {
        EnsureAlive();
        Trace("开始查询对方在线状态");
        bool? online;
        try { online = await _signaling.IsPeerOnlineAsync(peerDeviceId, cancellationToken).ConfigureAwait(false); }
        catch (Exception exception) { Trace("在线查询失败：" + exception.GetType().Name + ": " + exception.Message); throw; }
        Trace("在线查询结果=" + online);
        if (online == false)
            throw new InvalidOperationException("另一台软件尚未连到信令服务。请在另一台启动新版并确认信令在线，无需重新配对。");
        PeerContext context;
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            EnsureAlive();
            if (!_signalingReady) throw new InvalidOperationException("Connect signaling first.");
            if (_session is not null) throw new InvalidOperationException("Disconnect the current device first.");
            var peer = await _factory.BeginOutgoingNativeAsync(peerDeviceId, capabilities, _libraryPath, cancellationToken, _bindAddress, _iceServers).ConfigureAwait(false);
            context = Attach(peer);
        }
        finally { _gate.Release(); }
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _lifetime.Token);
        deadline.CancelAfter(TimeSpan.FromSeconds(30));
        try
        {
            await context.Peer.WaitForReadyAsync(deadline.Token).ConfigureAwait(false);
            return context.Peer;
        }
        catch when (Volatile.Read(ref context.Replacement) is not null)
        {
            await StopContextAsync(context).ConfigureAwait(false);
            await context.Stopped.Task.ConfigureAwait(false);
            var replacement = Volatile.Read(ref context.Replacement)!;
            await replacement.WaitForReadyAsync(deadline.Token).ConfigureAwait(false);
            return replacement;
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested && !_lifetime.IsCancellationRequested)
        {
            await StopContextAsync(context).ConfigureAwait(false);
            await context.Stopped.Task.ConfigureAwait(false);
            throw new TimeoutException($"加密连接超时：{LastSessionDiagnostics}。可点击“复制连接诊断”查看当前阶段。");
        }
        catch
        {
            await StopContextAsync(context).ConfigureAwait(false);
            await context.Stopped.Task.ConfigureAwait(false);
            throw;
        }
    }

    public async Task DisconnectDeviceAsync(CancellationToken cancellationToken = default)
    {
        var context = Volatile.Read(ref _session);
        if (context is null) return;
        try
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _lifetime.Token);
            timeout.CancelAfter(TimeSpan.FromSeconds(2));
            await _signaling.SendAsync(context.Peer.CreateCloseSignal(), timeout.Token).ConfigureAwait(false);
        }
        catch (Exception exception) when (exception is OperationCanceledException or ObjectDisposedException or PeerAuthenticationException or System.Net.WebSockets.WebSocketException or InvalidOperationException) { }
        finally
        {
            await StopContextAsync(context).ConfigureAwait(false);
            await context.Stopped.Task.ConfigureAwait(false);
        }
    }

    private PeerContext Attach(NativeWebRtcPeer peer)
    {
        var context = new PeerContext(peer, CancellationTokenSource.CreateLinkedTokenSource(_lifetime.Token));
        _session = context;
        _contexts.Add(context);
        SetStatus(new(PeerHostPhase.Negotiating, peer.PeerDeviceId, peer.Capabilities, null, "正在验证设备并建立加密会话…"));
        context.Sending = SendLoopAsync(context);
        context.Watching = WatchPeerAsync(context);
        return context;
    }

    private async Task ReceiveLoopAsync()
    {
        try
        {
            while (true)
            {
                var envelope = await _signaling.ReceiveAsync(_lifetime.Token).ConfigureAwait(false);
                Trace("收到 " + envelope.MessageType);
                await _gate.WaitAsync(_lifetime.Token).ConfigureAwait(false);
                try
                {
                    EnsureAlive();
                    var current = _session;
                    var payload = JsonSerializer.Deserialize<WebRtcSignalPayload>(envelope.Payload);
                    if (current is not null && envelope.SourceDeviceId == current.Peer.PeerDeviceId && payload?.SessionId == current.Peer.SessionId)
                    {
                        current.Peer.ApplySignal(envelope);
                    }
                    else if (current is not null && envelope.MessageType == "offer" && envelope.SourceDeviceId == current.Peer.PeerDeviceId &&
                        current.Peer.IsInitiator && !current.Peer.IsEndToEndEncrypted && payload?.Capabilities == current.Peer.Capabilities &&
                        StringComparer.Ordinal.Compare(envelope.SourceDeviceId, _factory.LocalDeviceId) < 0)
                    {
                        // Simultaneous outgoing calls: the lower identity owns the offer.
                        // Authenticate the winning offer before replacing any pending local peer.
                        var peer = await _factory.AcceptIncomingNativeAsync(envelope, _libraryPath, _lifetime.Token, _bindAddress, _iceServers).ConfigureAwait(false);
                        Volatile.Write(ref current.Replacement, peer);
                        Attach(peer);
                        _ = StopContextAsync(current); // Gate is released by this receive iteration.
                    }
                    else if (current is null && envelope.MessageType == "offer")
                    {
                        var peer = await _factory.AcceptIncomingNativeAsync(envelope, _libraryPath, _lifetime.Token, _bindAddress, _iceServers).ConfigureAwait(false);
                        Attach(peer);
                    }
                    else
                    {
                        // Authenticate and consume discarded stale/busy messages without disturbing an active peer.
                        _factory.VerifyUnroutedSignal(envelope);
                    }
                }
                catch (Exception exception) when (exception is PeerAuthenticationException or UnauthorizedAccessException or InvalidDataException or JsonException or ArgumentException or ObjectDisposedException or PeerRouteUnavailableException)
                {
                    LastSessionDiagnostics = $"拒绝信令：{exception.GetType().Name}: {exception.Message}";
                    Trace(LastSessionDiagnostics);
                    // A rejected message must not authenticate a new peer or tear down an unrelated active session.
                }
                finally { _gate.Release(); }
            }
        }
        catch (OperationCanceledException) when (_lifetime.IsCancellationRequested) { }
        catch (Exception exception)
        {
            _failure = exception;
            Trace("信令接收失败：" + exception.GetType().Name + ": " + exception.Message);
            _signalingReady = false;
            SetStatus(new(PeerHostPhase.Failed, null, SessionCapability.None, null, "信令连接已中断，会话正在关闭"));
            _ = DisposeAsync();
        }
    }

    private async Task SendLoopAsync(PeerContext context)
    {
        try
        {
            while (true)
            {
                var envelope = await context.Peer.ReadOutgoingSignalAsync(context.Lifetime.Token).ConfigureAwait(false);
                Trace("开始发送 " + envelope.MessageType);
                using var timeout = CancellationTokenSource.CreateLinkedTokenSource(context.Lifetime.Token);
                timeout.CancelAfter(TimeSpan.FromSeconds(10));
                await _signaling.SendAsync(envelope, timeout.Token).ConfigureAwait(false);
                Trace("发送完成 " + envelope.MessageType);
            }
        }
        catch (OperationCanceledException) when (context.Lifetime.IsCancellationRequested) { }
        catch (Exception exception)
        {
            context.Failure = exception;
            Trace("发送失败：" + exception.GetType().Name + ": " + exception.Message);
            await context.Peer.DisposeAsync().ConfigureAwait(false);
        }
    }

    private async Task WatchPeerAsync(PeerContext context)
    {
        try
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(context.Lifetime.Token);
            timeout.CancelAfter(TimeSpan.FromSeconds(30));
            await context.Peer.WaitForReadyAsync(timeout.Token).ConfigureAwait(false);
            await _gate.WaitAsync(context.Lifetime.Token).ConfigureAwait(false);
            try
            {
                if (ReferenceEquals(_session, context) && Volatile.Read(ref _disposeStarted) == 0 && Volatile.Read(ref context.StopStarted) == 0)
                    SetStatus(new(PeerHostPhase.Connected, context.Peer.PeerDeviceId, context.Peer.Capabilities, context.Peer.Route, "已建立加密数据会话"));
            }
            finally { _gate.Release(); }
            await context.Peer.Completion.ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (context.Lifetime.IsCancellationRequested) { }
        catch (Exception exception) { context.Failure = exception; }
        finally { await StopContextAsync(context).ConfigureAwait(false); }
    }

    private async Task StopContextAsync(PeerContext context)
    {
        if (Interlocked.Exchange(ref context.StopStarted, 1) != 0) return;
        await _gate.WaitAsync().ConfigureAwait(false);
        try
        {
            if (ReferenceEquals(_session, context))
            {
                LastSessionDiagnostics = context.Peer.ConnectionDiagnostics + (context.Failure is null ? "" : $"；原因={context.Failure.GetType().Name}: {context.Failure.Message}");
                _session = null;
                if (_signalingReady && Volatile.Read(ref _disposeStarted) == 0)
                    SetStatus(new(PeerHostPhase.Available, null, SessionCapability.None, null, context.Failure is null ? "设备已断开，信令仍在线" : "设备会话已结束，可重新连接"));
            }
            context.Lifetime.Cancel();
        }
        finally { _gate.Release(); }
        try
        {
            await context.Peer.DisposeAsync().ConfigureAwait(false);
            await context.Sending.ConfigureAwait(false);
        }
        finally
        {
            await _gate.WaitAsync().ConfigureAwait(false);
            try { _contexts.Remove(context); }
            finally { _gate.Release(); }
            context.Lifetime.Dispose();
            context.Stopped.TrySetResult();
        }
    }

    public ValueTask DisposeAsync()
    {
        lock (_disposeGate) return new ValueTask(_disposal ??= DisposeCoreAsync());
    }

    private async Task DisposeCoreAsync()
    {
        Interlocked.Exchange(ref _disposeStarted, 1);
        _signalingReady = false;
        _lifetime.Cancel();
        await _receiver.ConfigureAwait(false);
        PeerContext[] contexts;
        await _gate.WaitAsync().ConfigureAwait(false);
        try { contexts = _contexts.ToArray(); }
        finally { _gate.Release(); }
        foreach (var context in contexts)
        {
            await StopContextAsync(context).ConfigureAwait(false);
            await context.Stopped.Task.ConfigureAwait(false);
            await context.Watching.ConfigureAwait(false);
        }
        await _signaling.DisposeAsync().ConfigureAwait(false);
        _lifetime.Dispose();
        SetStatus(new(_failure is null ? PeerHostPhase.Offline : PeerHostPhase.Failed, null, SessionCapability.None, null,
            _failure is null ? "信令与设备会话已关闭" : "信令已断开，请检查服务后重新连接"));
    }

    private void EnsureAlive() => ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposeStarted) != 0, this);
    private void SetStatus(PeerHostStatus status) { Volatile.Write(ref _status, status); StatusChanged?.Invoke(this, status); }

    private sealed class PeerContext(NativeWebRtcPeer peer, CancellationTokenSource lifetime)
    {
        public NativeWebRtcPeer Peer { get; } = peer;
        public CancellationTokenSource Lifetime { get; } = lifetime;
        public Task Sending { get; set; } = Task.CompletedTask;
        public Task Watching { get; set; } = Task.CompletedTask;
        public TaskCompletionSource Stopped { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public Exception? Failure;
        public int StopStarted;
        public NativeWebRtcPeer? Replacement;
    }
}
