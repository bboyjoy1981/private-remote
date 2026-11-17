using System.Collections.ObjectModel;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Threading;
using PrivateRemote.Protocol;
using System.ComponentModel;
using System.Security.Cryptography;
using System.Text.Json;

namespace PrivateRemote.Client;

public partial class MainWindow : Window
{
    private readonly DeviceStore _store = new();
    private readonly PairingView _pairingView;
    private readonly DispatcherTimer _invitationTimer = new() { Interval = TimeSpan.FromSeconds(1) };
    private PairingInvitation? _pendingInvitation;
    private DeviceIdentity? _identity;
    internal DeviceSessionFactory? SessionFactory { get; private set; }
    private PeerSessionHost? _host;
    private bool _closing, _closedReady, _connecting;
    private readonly SemaphoreSlim _desktopGate = new(1, 1);
    private DesktopSession? _desktop;
    private RemoteDesktopWindow? _desktopWindow;
    private SessionFilesWindow? _filesWindow;
    private readonly WindowsInputControl _inputControl;
    private PairingExchange? _pairingExchange;
    private byte[]? _outboundPairing;
    private string _pairingExportName = "pairing.json";
    private LanSignalingService? _lanService;
    private Task<LanSignalingService>? _lanStart;
    private readonly string _connectionPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "PrivateRemote", "connection.dpapi");
    private readonly DispatcherTimer _reconnectTimer = new() { Interval = TimeSpan.FromSeconds(5) };
    private string? _autoEndpoint, _autoPin;
    private TrayIcon? _tray;
    private bool _exitRequested;

    public MainWindow()
    {
        InitializeComponent();
        _inputControl = new WindowsInputControl(() => _desktop?.Peer is { PeerIdentityVerified: true } peer ? peer.Capabilities : SessionCapability.None,
            text => Dispatcher.Invoke(() =>
            {
                if (_closing) throw new InvalidOperationException("软件正在退出。");
                Clipboard.SetText(text, TextDataFormat.UnicodeText);
            }));
        _pairingView = new PairingView(_store);
        _invitationTimer.Tick += InvitationTimer_Tick;
        try
        {
            _identity = _store.LoadOrCreateIdentity();
            SessionFactory = new DeviceSessionFactory(_store, _identity);
            _pairingExchange = new PairingExchange(_store, _identity);
            IdentityBadge.Text = $"本机 {_identity.DeviceId[..12]}";
            FooterStatus.Text = "设备身份已加载，私钥由 Windows 当前用户保护。";
        }
        catch (Exception exception)
        {
            IdentityBadge.Text = "身份不可用";
            FooterStatus.Text = $"身份初始化失败：{exception.Message}";
            CreateInviteButton.IsEnabled = false;
            ExportInviteButton.IsEnabled = false;
            ImportPairingButton.IsEnabled = false;
        }

        RefreshDevices();
        UpdateConnectionButtons();
        Loaded += RestoreConnectionAsync;
        Loaded += (_, _) =>
        {
            Application.Current.MainWindow = this;
            try { _tray = new TrayIcon(ShowMainWindow, () => { _exitRequested = true; Close(); }); }
            catch (Exception exception) { FooterStatus.Text = exception.Message; }
        };
        StateChanged += (_, _) => { if (WindowState == WindowState.Minimized && _tray is not null && !_closing) Hide(); };
        _reconnectTimer.Tick += (_, _) =>
        {
            if (!_closing && !_connecting && _autoEndpoint == SignalEndpoint.Text.Trim() && string.Equals(_autoPin, SignalCertificate.Text.Trim(), StringComparison.OrdinalIgnoreCase) &&
                _host?.Status.Phase is PeerHostPhase.Failed or PeerHostPhase.Offline)
                ConnectServiceButton_Click(this, new RoutedEventArgs());
        };
    }

    private void CreateInviteButton_Click(object sender, RoutedEventArgs e)
    {
        _pendingInvitation?.Invalidate();
        _pendingInvitation = _pairingView.CreateInvitation(DateTimeOffset.UtcNow);
        CopyInviteButton.IsEnabled = true;
        _invitationTimer.Start();
        RefreshInvitationText();
        FooterStatus.Text = "邀请已生成。请通过安全渠道交给另一台自有设备；配对仍需在本机批准。";
    }

    private void CopyInviteButton_Click(object sender, RoutedEventArgs e)
    {
        if (_pendingInvitation is null || DateTimeOffset.UtcNow >= _pendingInvitation.ExpiresAt)
        {
            ExpireInvitation();
            return;
        }

        Clipboard.SetText(_pendingInvitation.Token);
        FooterStatus.Text = "一次性配对码已复制到剪贴板。请只发送给你自己的另一台电脑。";
    }

    private void ExportInviteButton_Click(object sender, RoutedEventArgs e)
    {
        if (_pairingExchange is null) return;
        try
        {
            if (_pendingInvitation is null || _pendingInvitation.Token.Length == 0 || DateTimeOffset.UtcNow >= _pendingInvitation.ExpiresAt)
                CreateInviteButton_Click(sender, e);
            var invitation = _pairingExchange.ExportInvitation(_pendingInvitation!, DateTimeOffset.UtcNow);
            if (SavePairingFile(PairingExchange.Serialize(invitation), "private-remote-invitation.json"))
                FooterStatus.Text = "邀请文件已导出，请交给另一台自有电脑并在 5 分钟内完成配对。";
        }
        catch (Exception exception) { FooterStatus.Text = $"导出邀请失败：{exception.Message}"; }
    }

    private void ImportPairingButton_Click(object sender, RoutedEventArgs e)
    {
        if (_pairingExchange is null) return;
        var dialog = new Microsoft.Win32.OpenFileDialog { Title = "导入另一台电脑的邀请、申请或回执", Filter = "配对文件 (*.json)|*.json", CheckFileExists = true };
        if (dialog.ShowDialog(this) != true) return;
        try
        {
            using var file = new FileStream(dialog.FileName, FileMode.Open, FileAccess.Read, FileShare.Read);
            if (file.Length > PairingExchange.MaximumDocumentBytes) throw new InvalidDataException("配对文件过大。");
            var bytes = new byte[(int)file.Length]; file.ReadExactly(bytes);
            if (file.ReadByte() != -1) throw new InvalidDataException("配对文件已变化。");
            var document = PairingExchange.Parse(bytes, DateTimeOffset.UtcNow);
            if (document.SourceDeviceId == _identity!.DeviceId) throw new InvalidDataException("不能与本机配对。");
            switch (document.Kind)
            {
                case "invitation":
                    var capabilities = ChoosePairingCapabilities(document);
                    if (capabilities is null) return;
                    SetOutboundPairing(_pairingExchange.CreateRequest(document, capabilities.Value, DateTimeOffset.UtcNow, true), "private-remote-request.json");
                    FooterStatus.Text = "申请已生成。把申请文件交回邀请方；本机须保持打开，再导入对方批准后的回执。";
                    break;
                case "request":
                    var peer = _pairingExchange.InspectRequest(document, DateTimeOffset.UtcNow);
                    if (!_pairingView.ConfirmLocally(this, peer.DisplayName, peer.DeviceId, peer.Capabilities)) return;
                    SetOutboundPairing(_pairingExchange.ApproveRequest(document, DateTimeOffset.UtcNow, true), "private-remote-receipt.json");
                    ExpireInvitation(); RefreshDevices();
                    FooterStatus.Text = "本机已批准配对。请把回执交回申请方；未保存成功时可重新导出回执。";
                    break;
                case "receipt":
                    var paired = _pairingExchange.CompleteReceipt(document, DateTimeOffset.UtcNow);
                    RefreshDevices(); FooterStatus.Text = $"已完成与 {paired.DisplayName} 的双向配对。";
                    break;
            }
        }
        catch (Exception exception) { FooterStatus.Text = $"配对文件处理失败：{exception.Message}"; }
    }

    private SessionCapability? ChoosePairingCapabilities(PairingDocument document)
    {
        var screen = new CheckBox { Content = "允许屏幕查看和鼠标键盘控制", IsChecked = true, Margin = new Thickness(0, 12, 0, 6) };
        var files = new CheckBox { Content = "允许文件传输（接收时仍需确认）", IsChecked = true, Margin = new Thickness(0, 0, 0, 12) };
        var approve = new Button { Content = "批准并生成申请", Padding = new Thickness(14, 8, 14, 8), IsDefault = true };
        var panel = new StackPanel { Margin = new Thickness(20), MaxWidth = 520 };
        panel.Children.Add(new TextBlock { Text = $"对方：{document.DisplayName}\n设备 ID：{document.SourceDeviceId}\n请核对这是你另一台电脑的设备 ID。以下权限在双方设备上生效。", TextWrapping = TextWrapping.Wrap });
        panel.Children.Add(screen); panel.Children.Add(files); panel.Children.Add(approve);
        var window = new Window { Owner = this, Title = "本机批准配对权限", Content = panel, SizeToContent = SizeToContent.WidthAndHeight, WindowStartupLocation = WindowStartupLocation.CenterOwner, ResizeMode = ResizeMode.NoResize };
        approve.Click += (_, _) => { if (screen.IsChecked == true || files.IsChecked == true) window.DialogResult = true; };
        if (window.ShowDialog() != true) return null;
        return (screen.IsChecked == true ? SessionCapability.ScreenControl : SessionCapability.None) | (files.IsChecked == true ? SessionCapability.FileTransfer : SessionCapability.None);
    }

    private void SetOutboundPairing(PairingDocument document, string name)
    {
        _outboundPairing = PairingExchange.Serialize(document); _pairingExportName = name;
        ExportPairingReplyButton.IsEnabled = true;
        SavePairingFile(_outboundPairing, name);
    }
    private bool SavePairingFile(byte[] bytes, string name)
    {
        var dialog = new Microsoft.Win32.SaveFileDialog { Title = "保存后交给另一台电脑", FileName = name, Filter = "配对文件 (*.json)|*.json", AddExtension = true, DefaultExt = ".json" };
        if (dialog.ShowDialog(this) != true) return false;
        File.WriteAllBytes(dialog.FileName, bytes); return true;
    }
    private void ExportPairingReplyButton_Click(object sender, RoutedEventArgs e)
    {
        try { if (_outboundPairing is not null && SavePairingFile(_outboundPairing, _pairingExportName)) FooterStatus.Text = "文件已重新导出。"; }
        catch (Exception exception) { FooterStatus.Text = $"导出失败：{exception.Message}"; }
    }

    private void InvitationTimer_Tick(object? sender, EventArgs e)
    {
        if (_pendingInvitation is null || DateTimeOffset.UtcNow >= _pendingInvitation.ExpiresAt)
        {
            ExpireInvitation();
            return;
        }

        RefreshInvitationText();
    }

    private void RefreshInvitationText()
    {
        if (_pendingInvitation is null)
        {
            return;
        }

        var remaining = _pendingInvitation.ExpiresAt - DateTimeOffset.UtcNow;
        InvitationText.Text = $"{_pendingInvitation.Token}\n剩余 {Math.Max(0, (int)Math.Ceiling(remaining.TotalSeconds))} 秒 · 一次性配对码";
    }

    private void ExpireInvitation()
    {
        _invitationTimer.Stop();
        _pendingInvitation?.Invalidate();
        _pendingInvitation = null;
        CopyInviteButton.IsEnabled = false;
        InvitationText.Text = "配对码已过期，请重新生成。";
        FooterStatus.Text = "一次性配对码已失效。";
    }

    private void RefreshDevices()
    {
        try
        {
            DevicesList.ItemsSource = new ObservableCollection<DeviceListItem>(
                _pairingView.ListDevices().Select(device => new DeviceListItem(
                    device.DeviceId,
                    device.DisplayName,
                    device.IsRevoked ? "已撤销" : $"已配对 · {device.Capabilities}")));
        }
        catch (Exception exception)
        {
            FooterStatus.Text = $"读取已配对设备失败：{exception.Message}";
        }
    }

    private void RevokeDeviceButton_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not Button { Tag: string deviceId })
        {
            return;
        }

        if (MessageBox.Show(this, "撤销后，这台设备无法再次连接，直到重新配对。继续吗？", "撤销设备", MessageBoxButton.YesNo, MessageBoxImage.Warning, MessageBoxResult.No) != MessageBoxResult.Yes)
        {
            return;
        }

        FooterStatus.Text = _pairingView.Revoke(deviceId) ? "设备授权已撤销。" : "设备不存在或已经撤销。";
        try { _lanService?.Revoke(deviceId); }
        catch (Exception exception) { FooterStatus.Text = $"本地配对已撤销；保存服务撤销状态失败：{exception.Message}"; }
        RefreshDevices();
    }

    private void RenameDeviceButton_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not Button { Tag: string deviceId })
        {
            return;
        }

        var currentName = _pairingView.ListDevices().FirstOrDefault(device => device.DeviceId == deviceId)?.DisplayName;
        if (currentName is null)
        {
            FooterStatus.Text = "设备不存在。";
            RefreshDevices();
            return;
        }

        var nameInput = new TextBox { Text = currentName, Margin = new Thickness(0, 0, 0, 14), MinWidth = 300, MaxLength = 64 };
        var buttons = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right };
        var saveButton = new Button { Content = "保存", IsDefault = true, MinWidth = 72, Padding = new Thickness(12, 6, 12, 6), Margin = new Thickness(0, 0, 8, 0) };
        var cancelButton = new Button { Content = "取消", IsCancel = true, MinWidth = 72, Padding = new Thickness(12, 6, 12, 6) };
        buttons.Children.Add(saveButton);
        buttons.Children.Add(cancelButton);

        var content = new StackPanel { Margin = new Thickness(18) };
        content.Children.Add(new TextBlock { Text = "输入设备名称（最多 64 个字符）", Margin = new Thickness(0, 0, 0, 8) });
        content.Children.Add(nameInput);
        content.Children.Add(buttons);

        var dialog = new Window
        {
            Title = "重命名设备",
            Owner = this,
            Content = content,
            SizeToContent = SizeToContent.WidthAndHeight,
            WindowStartupLocation = WindowStartupLocation.CenterOwner,
            ResizeMode = ResizeMode.NoResize,
            ShowInTaskbar = false
        };
        saveButton.Click += (_, _) => dialog.DialogResult = true;

        if (dialog.ShowDialog() != true)
        {
            return;
        }

        try
        {
            FooterStatus.Text = _pairingView.Rename(deviceId, nameInput.Text) ? "设备名称已更新。" : "设备不存在。";
            RefreshDevices();
        }
        catch (ArgumentException exception)
        {
            FooterStatus.Text = exception.Message;
        }
    }

    private void DevicesList_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        UpdateConnectionButtons();
    }

    private string _previousSignalDiagnostics = "无";
    private async void ConnectServiceButton_Click(object sender, RoutedEventArgs e)
    {
        if (SessionFactory is null || _connecting || _closing) return;
        _connecting = true;
        UpdateConnectionButtons();
        try
        {
            if (SignalToken.Password.Length == 0 && File.Exists(_connectionPath))
            {
                var saved = LoadConnection();
                if (saved.Endpoint == SignalEndpoint.Text.Trim() && string.Equals(saved.CertificateSha256, SignalCertificate.Text.Trim(), StringComparison.OrdinalIgnoreCase)) ApplyConnection(saved);
            }
            if (_host is not null)
            {
                _previousSignalDiagnostics = _host.SignalDiagnostics + "\n接收故障：" + _host.Failure?.Message;
                await _host.DisposeAsync();
            }
            if (_closing) return;
            var host = new PeerSessionHost(SessionFactory, System.IO.Path.Combine(AppContext.BaseDirectory, "native", "datachannel.dll"));
            _host = host;
            host.StatusChanged += (_, status) => Dispatcher.InvokeAsync(async () =>
            {
                if (!ReferenceEquals(_host, host) || _closing) return;
                ConnectionStatus.Text = status.Message;
                ConnectionDetails.Text = status.Phase == PeerHostPhase.Connected
                    ? $"设备 {status.PeerDeviceId?[..12]} · {status.Route} · 端到端加密\n可打开远程桌面（JPEG 基础模式）。"
                    : "选择已配对设备来建立数据会话。";
                UpdateConnectionButtons();
                await UpdateDesktopSessionAsync();
            });
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
            await host.ConnectSignalingAsync(new Uri(SignalEndpoint.Text.Trim()), SignalToken.Password, timeout.Token, SignalCertificate.Text.Trim());
            SignalToken.Clear();
            _reconnectTimer.Interval = TimeSpan.FromSeconds(5);
        }
        catch (Exception exception) { FooterStatus.Text = $"信令连接失败：{exception.Message}"; _reconnectTimer.Interval = TimeSpan.FromSeconds(Math.Min(60, _reconnectTimer.Interval.TotalSeconds * 2)); }
        finally { _connecting = false; UpdateConnectionButtons(); }
    }

    private LanConnectionSettings SignConnection(LanConnectionSettings settings)
        => settings with { Signature = Convert.ToBase64String(_identity!.Sign(JsonSerializer.SerializeToUtf8Bytes(settings with { Signature = "" }))) };

    private void ApplyConnection(LanConnectionSettings settings)
    {
        if (_identity is null || settings.Version != 1 || settings.DeviceId != _identity.DeviceId || settings.BearerToken?.Length != 64 || settings.CertificateSha256?.Length != 64 || !settings.CertificateSha256.All(Uri.IsHexDigit))
            throw new InvalidDataException("连接配置与本机身份不匹配。");
        var publicKey = settings.ServiceDeviceId == _identity.DeviceId ? _identity.PublicKey : _store.FindActivePairing(settings.ServiceDeviceId)?.PublicKey;
        if (publicKey is null || !DeviceIdentity.Verify(publicKey, JsonSerializer.SerializeToUtf8Bytes(settings with { Signature = "" }), Convert.FromBase64String(settings.Signature)))
            throw new UnauthorizedAccessException("连接配置未由本机或已配对的服务电脑签名。");
        var endpoint = new Uri(settings.Endpoint);
        if (endpoint.Scheme != "wss" || endpoint.AbsolutePath != "/signal" || endpoint.UserInfo != "" || endpoint.Query != "") throw new InvalidDataException("连接配置必须使用 WSS 信令地址。");
        SignalEndpoint.Text = settings.Endpoint; SignalCertificate.Text = settings.CertificateSha256; SignalToken.Password = settings.BearerToken;
        _autoEndpoint = settings.Endpoint; _autoPin = settings.CertificateSha256; _reconnectTimer.Start();
    }
    private LanConnectionSettings LoadConnection()
    {
        var clear = DeviceSecretProtection.Unprotect(File.ReadAllBytes(_connectionPath));
        try { return JsonSerializer.Deserialize<LanConnectionSettings>(clear) ?? throw new InvalidDataException("连接配置为空。"); }
        finally { CryptographicOperations.ZeroMemory(clear); }
    }
    private void SaveConnection(LanConnectionSettings settings)
    {
        var clear = JsonSerializer.SerializeToUtf8Bytes(settings);
        try { var encrypted = DeviceSecretProtection.Protect(clear); File.WriteAllBytes(_connectionPath + ".tmp", encrypted); File.Move(_connectionPath + ".tmp", _connectionPath, true); }
        finally { CryptographicOperations.ZeroMemory(clear); }
    }
    private async void StartLanButton_Click(object sender, RoutedEventArgs e)
    {
        if (_identity is null || _closing) return;
        StartLanButton.IsEnabled = false;
        try
        {
            var selected = DevicesList.SelectedItem as DeviceListItem ?? throw new InvalidOperationException("先选择已配对的另一台电脑。");
            var paired = _store.FindActivePairing(selected.DeviceId) ?? throw new UnauthorizedAccessException("设备授权已撤销。");
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            _lanStart ??= LanSignalingService.StartAsync(_identity, paired, timeout.Token);
            _lanService ??= await _lanStart;
            if (_closing) { await _lanService.DisposeAsync(); _lanService = null; return; }
            if (string.IsNullOrWhiteSpace(LanAddress.Text)) LanAddress.Text = _lanService.SuggestedAddress;
            var peerSettings = SignConnection(_lanService.CreatePeerSettings(paired.DeviceId, LanAddress.Text.Trim()));
            var local = SignConnection(new(1, _identity.DeviceId, _identity.DeviceId, paired.DeviceId, "wss://127.0.0.1:5443/signal", _lanService.CertificateSha256, _lanService.LocalToken, ""));
            SaveConnection(local); ApplyConnection(local);
            SavePairingFile(JsonSerializer.SerializeToUtf8Bytes(peerSettings), "private-remote-connection.json");
            FooterStatus.Text = "本机信令已启动。把连接配置交给另一台电脑导入；Windows 防火墙如提示，请只允许专用网络。";
            ConnectServiceButton_Click(sender, e);
        }
        catch (Exception exception) { if (_lanStart?.IsFaulted == true || _lanStart?.IsCanceled == true) _lanStart = null; FooterStatus.Text = $"本机信令启动失败：{exception.Message}"; }
        finally { if (!_closing) StartLanButton.IsEnabled = true; }
    }
    private void ImportConnectionButton_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new Microsoft.Win32.OpenFileDialog { Title = "导入信令电脑生成的本机连接配置", Filter = "连接配置 (*.json)|*.json" };
        if (dialog.ShowDialog(this) != true) return;
        try
        {
            using var file = File.OpenRead(dialog.FileName);
            if (file.Length > 16384) throw new InvalidDataException("连接配置过大。");
            var bytes = new byte[(int)file.Length]; file.ReadExactly(bytes); if (file.ReadByte() != -1) throw new InvalidDataException("连接配置已变化。");
            var settings = JsonSerializer.Deserialize<LanConnectionSettings>(bytes) ?? throw new InvalidDataException("连接配置为空。");
            ApplyConnection(settings); SaveConnection(settings); ConnectServiceButton_Click(sender, e);
        }
        catch (Exception exception) { FooterStatus.Text = $"配置导入失败：{exception.Message}"; }
    }
    private async void RestoreConnectionAsync(object sender, RoutedEventArgs e)
    {
        if (_identity is null || !File.Exists(_connectionPath)) return;
        try
        {
            var settings = LoadConnection();
            ApplyConnection(settings);
            if (settings.ServiceDeviceId == _identity.DeviceId)
            {
                var peer = _store.FindActivePairing(settings.PeerDeviceId) ?? throw new UnauthorizedAccessException("服务设备配对已撤销。");
                _lanStart ??= LanSignalingService.StartAsync(_identity, peer, CancellationToken.None);
                _lanService = await _lanStart;
                if (_closing) return;
                LanAddress.Text = _lanService.SuggestedAddress;
            }
            if (!_closing) ConnectServiceButton_Click(sender, e);
        }
        catch (Exception exception) { FooterStatus.Text = $"自动连接失败：{exception.Message}"; }
    }

    private async void ConnectDeviceButton_Click(object sender, RoutedEventArgs e)
    {
        if (_host is null || DevicesList.SelectedItem is not DeviceListItem device || _connecting || _closing) return;
        _connecting = true;
        UpdateConnectionButtons();
        try
        {
            var pairing = _store.FindActivePairing(device.DeviceId) ?? throw new UnauthorizedAccessException("该设备授权已撤销。");
            await _host.ConnectDeviceAsync(device.DeviceId, pairing.Capabilities, CancellationToken.None);
            await UpdateDesktopSessionAsync();
            FooterStatus.Text = "加密会话已建立，可以打开远程桌面。";
        }
        catch (Exception exception) { FooterStatus.Text = $"设备连接失败：{exception.Message}"; }
        finally { _connecting = false; UpdateConnectionButtons(); }
    }

    private async void DisconnectButton_Click(object sender, RoutedEventArgs e)
    {
        try { if (_host is not null) await _host.DisconnectDeviceAsync(); }
        catch (Exception exception) { FooterStatus.Text = $"断开失败：{exception.Message}"; }
        UpdateConnectionButtons();
    }

    private void UpdateConnectionButtons()
    {
        if (ConnectServiceButton is null) return;
        var phase = _host?.Status.Phase ?? PeerHostPhase.Offline;
        ConnectServiceButton.IsEnabled = !_closing && !_connecting && SessionFactory is not null && phase is PeerHostPhase.Offline or PeerHostPhase.Failed;
        ConnectDeviceButton.IsEnabled = !_closing && !_connecting && phase == PeerHostPhase.Available && DevicesList.SelectedItem is DeviceListItem;
        DisconnectButton.IsEnabled = !_closing && phase is PeerHostPhase.Negotiating or PeerHostPhase.Connected;
        OpenDesktopButton.IsEnabled = !_closing && phase == PeerHostPhase.Connected && (_desktop?.Peer.Capabilities & SessionCapability.ScreenControl) != 0 && _desktop is not null;
        OpenFilesButton.IsEnabled = !_closing && phase == PeerHostPhase.Connected && _desktop?.Files is not null;
    }

    private async Task UpdateDesktopSessionAsync()
    {
        await _desktopGate.WaitAsync();
        try
        {
            var peer = _closing ? null : _host?.ActivePeer;
            if (_desktop is not null && ReferenceEquals(_desktop.Peer, peer) && peer!.PeerIdentityVerified) return;
            _desktopWindow?.Close(); _desktopWindow = null;
            _filesWindow?.Close(); _filesWindow = null;
            if (_desktop is not null) { await _desktop.DisposeAsync(); _desktop = null; }
            if (_closing || !ReferenceEquals(peer, _host?.ActivePeer)) peer = null;
            if (peer is not null && peer.PeerIdentityVerified)
            {
                var desktop = new DesktopSession(peer, new GdiJpegFrameSource(), _inputControl.Send, _inputControl.ReleaseAll);
                _desktop = desktop;
                if (desktop.Files is not null) desktop.Files.ChooseDestinationAsync = async (offer, token) =>
                {
                    return await (await Dispatcher.InvokeAsync(() =>
                    {
                        if (_closing || !ReferenceEquals(_desktop, desktop)) return Task.FromResult<string?>(null);
                        var window = EnsureFilesWindow();
                        return window.ChooseDestinationAsync(offer, token);
                    }));
                };
                desktop.StatusChanged += (_, message) => Dispatcher.InvokeAsync(() =>
                {
                    if (!_closing && ReferenceEquals(_desktop, desktop)) FooterStatus.Text = message;
                });
            }
        }
        catch (Exception exception) { FooterStatus.Text = $"桌面会话不可用：{exception.Message}"; }
        finally { _desktopGate.Release(); UpdateConnectionButtons(); }
    }

    private void OpenDesktopButton_Click(object sender, RoutedEventArgs e)
    {
        if (_desktop is null || _closing) return;
        if (_desktopWindow is not null) { _desktopWindow.Activate(); return; }
        var window = new RemoteDesktopWindow(_desktop);
        _desktopWindow = window;
        window.Closed += (_, _) => { if (ReferenceEquals(_desktopWindow, window)) _desktopWindow = null; };
        window.Show();
    }

    private SessionFilesWindow EnsureFilesWindow()
    {
        if (_filesWindow is not null) { _filesWindow.Activate(); return _filesWindow; }
        var window = new SessionFilesWindow(_desktop?.Files ?? throw new InvalidOperationException("文件传输权限不可用。"));
        _filesWindow = window;
        window.Closed += (_, _) => { if (ReferenceEquals(_filesWindow, window)) _filesWindow = null; };
        window.Show(); return window;
    }
    private void OpenFilesButton_Click(object sender, RoutedEventArgs e)
    {
        try { if (!_closing) EnsureFilesWindow(); }
        catch (Exception exception) { FooterStatus.Text = exception.Message; }
    }

    protected override async void OnClosing(CancelEventArgs e)
    {
        if (!_exitRequested && !_closing)
        {
            e.Cancel = true;
            if (_tray is not null) Hide();
            else WindowState = WindowState.Minimized;
            return;
        }
        if (!_closedReady)
        {
            e.Cancel = true;
            if (_closing) return;
            _closing = true;
            _reconnectTimer.Stop();
            UpdateConnectionButtons();
            try
            {
                await UpdateDesktopSessionAsync();
                if (_host is not null) await _host.DisposeAsync();
                if (_lanStart is not null) { try { _lanService ??= await _lanStart; } catch { } }
                if (_lanService is not null) await _lanService.DisposeAsync();
            }
            catch (Exception exception) { FooterStatus.Text = $"会话关闭：{exception.Message}"; }
            finally
            {
                _closedReady = true;
                if (!Dispatcher.HasShutdownStarted) _ = Dispatcher.BeginInvoke(new Action(Close));
            }
            return;
        }
        base.OnClosing(e);
    }

    protected override void OnClosed(EventArgs e)
    {
        _invitationTimer.Stop();
        _pendingInvitation?.Invalidate();
        _identity?.Dispose();
        _tray?.Dispose();
        base.OnClosed(e);
        Application.Current.Shutdown();
    }

    private void ShowMainWindow()
    {
        Show(); WindowState = WindowState.Normal; Activate();
    }
    private void ExitApplicationButton_Click(object sender, RoutedEventArgs e) => RequestExit();
    private void CopyConnectionDiagnosticsButton_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            var diagnostic = $"版本：信令追踪版\nUTC时间：{DateTimeOffset.UtcNow:o}\n本机：{_identity?.DeviceId[..12]}\n信令：{_host?.Status.Phase}\n当前握手：{_host?.ActivePeer?.ConnectionDiagnostics ?? "无"}\n最近握手：{_host?.LastSessionDiagnostics}\n界面提示：{FooterStatus.Text}\n信令轨迹：\n{_host?.SignalDiagnostics}\n上次信令轨迹：\n{_previousSignalDiagnostics}\n本机服务器轨迹：\n{_lanService?.Diagnostics ?? "此端不运行信令服务器"}\n状态含义：0新建/1连接中/2已连接/3断线/4失败/5关闭";
            Clipboard.SetText(diagnostic); FooterStatus.Text = "连接诊断已复制，请同时收集另一台的诊断。";
        }
        catch (Exception exception) { FooterStatus.Text = $"复制诊断失败：{exception.Message}"; }
    }
    internal void RequestExit() { _exitRequested = true; Close(); }

    private sealed record DeviceListItem(string DeviceId, string DisplayName, string StatusText);
}
