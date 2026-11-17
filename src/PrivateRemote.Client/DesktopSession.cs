using PrivateRemote.Protocol;
using PrivateRemote.Transport;

namespace PrivateRemote.Client;

public interface IDesktopFrameSource
{
    Task<byte[]> CaptureAsync(CancellationToken cancellationToken);
}
public interface IConfigurableDesktopFrameSource : IDesktopFrameSource { void SetProfile(byte profile); }

/// <summary>One consumer for desktop control messages; capture never queues frames ahead of sending.</summary>
public sealed class DesktopSession : IAsyncDisposable
{
    private readonly NativeWebRtcPeer _peer;
    private readonly IDesktopFrameSource _capture;
    private readonly Action<RemoteInputEvent> _input;
    private readonly Action _releaseInput;
    private readonly CancellationTokenSource _lifetime = new();
    private readonly DesktopFrameAssembler _assembler = new();
    private readonly Task _receiving, _capturing;
    private readonly object _disposeGate = new();
    private Task? _disposal;
    private volatile bool _sharing, _viewing;
    private ulong _frameId;
    public event EventHandler<byte[]>? FrameReceived;
    public event EventHandler<string>? StatusChanged;
    public event EventHandler<RemoteInputResult>? InputResultReceived;
    public NativeWebRtcPeer Peer => _peer;
    public bool IsSharing => _sharing;
    public bool IsViewing => _viewing;
    public byte ViewQuality { get; private set; } = 1;
    public SessionFiles? Files { get; }

    public DesktopSession(NativeWebRtcPeer peer, IDesktopFrameSource capture, Action<RemoteInputEvent> input, Action releaseInput)
    {
        _peer = peer; _capture = capture; _input = input; _releaseInput = releaseInput;
        if ((peer.Capabilities & SessionCapability.FileTransfer) != 0) Files = new(peer);
        _receiving = Task.Run(ReceiveAsync);
        _capturing = Task.Run(CaptureAsync);
    }

    public async Task StartViewingAsync(CancellationToken cancellationToken)
    {
        CapabilityAuthorization.Require(_peer.Capabilities, SessionCapability.ScreenControl);
        RequireActive(); _viewing = true;
        try { await _peer.SendAsync(PeerDataChannel.Control, DesktopWire.Command(3), cancellationToken); }
        catch { _viewing = false; throw; }
    }
    public async Task SetQualityAsync(byte profile, CancellationToken token)
    {
        RequireActive(); CapabilityAuthorization.Require(_peer.Capabilities, SessionCapability.ScreenControl);
        await _peer.SendAsync(PeerDataChannel.Control, DesktopWire.QualityCommand(profile), token);
        ViewQuality = profile;
    }

    public async Task StopViewingAsync(CancellationToken cancellationToken)
    {
        _viewing = false;
        if (_peer.PeerIdentityVerified)
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(TimeSpan.FromSeconds(2));
            try { await _peer.SendAsync(PeerDataChannel.Control, DesktopWire.Command(4), timeout.Token); }
            catch { await _peer.DisposeAsync(); throw; }
        }
    }

    public Task SendInputAsync(RemoteInputEvent input, CancellationToken cancellationToken)
    {
        RequireActive();
        if (!_viewing) throw new InvalidOperationException("Open the remote view before sending input.");
        return _peer.SendAsync(PeerDataChannel.Control, DesktopWire.EncodeInput(input), cancellationToken);
    }

    public async Task ReleaseInputAsync(CancellationToken cancellationToken)
    {
        RequireActive();
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(2));
        try { await _peer.SendAsync(PeerDataChannel.Control, DesktopWire.Command(5), timeout.Token); }
        catch { await _peer.DisposeAsync(); throw; }
    }

    private async Task ReceiveAsync()
    {
        try
        {
            while (true)
            {
                var message = await _peer.ReadMessageAsync(_lifetime.Token);
                RequireActive();
                if (SessionFiles.IsPacket(message.Bytes))
                {
                    if (Files is null) throw new UnauthorizedAccessException("File transfer is not granted.");
                    await Files.HandleAsync(message, _lifetime.Token); continue;
                }
                CapabilityAuthorization.Require(_peer.Capabilities, SessionCapability.ScreenControl);
                if (message.Channel != PeerDataChannel.Control) throw new InvalidDataException("Desktop messages require the control channel.");
                switch (DesktopWire.Type(message.Bytes))
                {
                    case 7:
                        if (_viewing) InputResultReceived?.Invoke(this, DesktopWire.DecodeInputResult(message.Bytes));
                        break;
                    case 6:
                        if (message.Bytes.Length != 6 || message.Bytes[5] > 2) throw new InvalidDataException("Invalid desktop quality profile.");
                        if (_capture is IConfigurableDesktopFrameSource configurable) configurable.SetProfile(message.Bytes[5]);
                        break;
                    case 1:
                        var frame = _assembler.Accept(message.Bytes);
                        if (frame is not null && _viewing) FrameReceived?.Invoke(this, frame);
                        break;
                    case 2:
                        if (!_sharing) throw new UnauthorizedAccessException("Remote input requires an active screen share.");
                        var input = DesktopWire.DecodeInput(message.Bytes);
                        RemoteInputResult? result = null;
                        try { _input(input); if (input is TextInputEvent) result = new(true, "文字输入已完成"); }
                        catch (Exception exception) when (exception is UnauthorizedAccessException or System.ComponentModel.Win32Exception or InvalidOperationException)
                        {
                            StatusChanged?.Invoke(this, $"输入暂停：{exception.Message}");
                            if (input is TextInputEvent) result = new(false, exception.Message.Length > 512 ? exception.Message[..512] : exception.Message);
                        }
                        if (result is not null) await _peer.SendAsync(PeerDataChannel.Control, DesktopWire.InputResult(result), _lifetime.Token);
                        break;
                    case 3: RequireCommand(message.Bytes); _sharing = true; StatusChanged?.Invoke(this, "已配对设备正在查看并可控制本机桌面"); break;
                    case 4: RequireCommand(message.Bytes); _sharing = false; _releaseInput(); StatusChanged?.Invoke(this, "对方已停止查看本机桌面"); break;
                    case 5: RequireCommand(message.Bytes); _releaseInput(); break;
                }
            }
        }
        catch (OperationCanceledException) when (_lifetime.IsCancellationRequested) { }
        catch (Exception exception) { await FailAsync(exception); }
        finally { _sharing = false; _viewing = false; Files?.Dispose(); _releaseInput(); }
    }

    private async Task CaptureAsync()
    {
        try
        {
            while (true)
            {
                await Task.Delay(83, _lifetime.Token);
                if (!_sharing) continue;
                RequireActive();
                byte[] frame;
                try { frame = await _capture.CaptureAsync(_lifetime.Token); }
                catch (UnauthorizedAccessException) { continue; } // Lock/UAC desktops are never captured.
                if (!_sharing) continue;
                foreach (var chunk in DesktopWire.EncodeFrame(++_frameId, frame))
                    await _peer.SendAsync(PeerDataChannel.Control, chunk, _lifetime.Token);
            }
        }
        catch (OperationCanceledException) when (_lifetime.IsCancellationRequested) { }
        catch (Exception exception) { await FailAsync(exception); }
    }

    private async Task FailAsync(Exception exception)
    {
        _lifetime.Cancel();
        StatusChanged?.Invoke(this, $"桌面会话已结束：{exception.Message}");
        await _peer.DisposeAsync();
    }

    private void RequireActive()
    {
        _lifetime.Token.ThrowIfCancellationRequested();
        if (!_peer.PeerIdentityVerified || !_peer.IsEndToEndEncrypted) throw new UnauthorizedAccessException("The paired encrypted session is no longer active.");
    }
    private static void RequireCommand(byte[] bytes) { if (bytes.Length != 5) throw new InvalidDataException("Invalid desktop command."); }
    public ValueTask DisposeAsync() { lock (_disposeGate) return new(_disposal ??= DisposeCoreAsync()); }
    private async Task DisposeCoreAsync()
    {
        _lifetime.Cancel(); _sharing = false; _viewing = false;
        Files?.Dispose();
        try { await Task.WhenAll(_receiving, _capturing); }
        finally { _releaseInput(); _assembler.Reset(); _lifetime.Dispose(); }
    }
}
