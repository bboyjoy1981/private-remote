using System.ComponentModel;
using System.Threading.Channels;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;

namespace PrivateRemote.Client;

public sealed class RemoteDesktopWindow : Window
{
    private readonly DesktopSession _session;
    private readonly Image _image = new() { Stretch = Stretch.Uniform, Focusable = true };
    private readonly TextBlock _status = new() { Text = "正在请求远程画面…", Margin = new Thickness(10) };
    private readonly CheckBox _control = new() { Content = "启用键盘鼠标（F12 释放）", IsChecked = true, Margin = new Thickness(10) };
    private readonly Channel<RemoteInputEvent> _inputs = Channel.CreateBounded<RemoteInputEvent>(128);
    private readonly CancellationTokenSource _lifetime = new();
    private readonly Task _sending;
    private byte[]? _latestFrame;
    private int _renderPending;
    private long _lastMove;
    private readonly HashSet<int> _pressedButtons = [];
    private bool _closing, _readyToClose;
    private bool _windowClosed;
    private readonly TextBlock _inputStatus = new() { Text = "", Margin = new Thickness(6), TextWrapping = TextWrapping.Wrap, MaxWidth = 440 };
    private readonly ScrollViewer _viewport = new() { Background = Brushes.Black, HorizontalScrollBarVisibility = ScrollBarVisibility.Disabled, VerticalScrollBarVisibility = ScrollBarVisibility.Disabled };
    private bool _originalSize, _fullScreen;
    private WindowState _previousState;
    private bool _textComposing;
    private long _receivedFrameBytes;
    private long _statsStarted = System.Diagnostics.Stopwatch.GetTimestamp();
    private int _displayedFrames;
    private string _streamStats = "";

    public RemoteDesktopWindow(DesktopSession session)
    {
        _session = session;
        // The viewing surface forwards physical keys to the host's IME. A local
        // IME must not consume them before PreviewKeyDown/Up can forward them.
        InputMethod.SetIsInputMethodEnabled(_image, false);
        Title = $"远程桌面 · {session.Peer.PeerDeviceId[..12]} · JPEG 基础模式";
        Width = 1100; Height = 720; MinWidth = 640; MinHeight = 420;
        var root = new DockPanel();
        var toolbar = new WrapPanel { Background = Brushes.WhiteSmoke };
        toolbar.Children.Add(_control); toolbar.Children.Add(_status);
        var fit = new Button { Content = "适应窗口", Margin = new Thickness(4), Padding = new Thickness(8, 4, 8, 4) };
        var original = new Button { Content = "原始大小 1:1", Margin = new Thickness(4), Padding = new Thickness(8, 4, 8, 4) };
        var full = new Button { Content = "全屏 / F11", Margin = new Thickness(4), Padding = new Thickness(8, 4, 8, 4) };
        var quality = new ComboBox { Margin = new Thickness(4), MinWidth = 140, VerticalContentAlignment = VerticalAlignment.Center };
        quality.Items.Add("省流（720p）"); quality.Items.Add("均衡（900p）"); quality.Items.Add("清晰（原画≤4K）"); quality.SelectedIndex = session.ViewQuality;
        quality.ToolTip = "外网先用均衡；阅读小字可选清晰并使用原始大小 1:1。清晰档传输量较大。";
        quality.SelectionChanged += async (_, _) =>
        {
            if (!IsLoaded || _closing) return;
            try { await _session.SetQualityAsync((byte)quality.SelectedIndex, _lifetime.Token); _image.Focus(); }
            catch (Exception exception) { _status.Text = $"画质切换失败：{exception.Message}"; }
        };
        fit.Click += (_, _) => { _originalSize = false; ApplyDisplaySize(); _image.Focus(); };
        original.Click += (_, _) => { _originalSize = true; ApplyDisplaySize(); _image.Focus(); };
        full.Click += (_, _) => ToggleFullScreen();
        toolbar.Children.Add(fit); toolbar.Children.Add(original); toolbar.Children.Add(full); toolbar.Children.Add(quality);
        var stop = new Button { Content = "停止投屏（保持在线）", Margin = new Thickness(4), Padding = new Thickness(8, 4, 8, 4) };
        stop.Click += (_, _) => Close(); toolbar.Children.Add(stop);
        var text = new TextBox { Width = 230, MaxLength = 128, Margin = new Thickness(4), Padding = new Thickness(6, 4, 6, 4), ToolTip = "先点远端输入框，再在这里用本机输入法选词，点发送文字。每次最多 128 个 UTF-16 字符。" };
        var sendText = new Button { Content = "发送文字", Margin = new Thickness(4), Padding = new Thickness(8, 4, 8, 4) };
        var paste = new CheckBox { Content = "兼容粘贴（写入远端剪贴板）", IsChecked = true, Margin = new Thickness(6), VerticalAlignment = VerticalAlignment.Center };
        toolbar.Children.Add(new TextBlock { Text = "中文/文字：", Margin = new Thickness(6), VerticalAlignment = VerticalAlignment.Center });
        toolbar.Children.Add(text); toolbar.Children.Add(paste); toolbar.Children.Add(sendText);
        toolbar.Children.Add(_inputStatus);
        _session.InputResultReceived += InputResultReceived;
        Closed += (_, _) => { _windowClosed = true; _session.InputResultReceived -= InputResultReceived; };
        TextCompositionManager.AddPreviewTextInputStartHandler(text, (_, _) => _textComposing = true);
        TextCompositionManager.AddPreviewTextInputHandler(text, (_, _) => _textComposing = false);
        text.LostKeyboardFocus += (_, _) => _textComposing = false;
        text.GotKeyboardFocus += (_, _) =>
        {
            if (_closing) return;
            while (_inputs.Reader.TryRead(out _)) { }
            if (!_inputs.Writer.TryWrite(new ReleaseMarker())) Close();
        };
        sendText.Click += (_, _) =>
        {
            if (_control.IsChecked != true) { _status.Text = "请先勾选“启用键盘鼠标”"; return; }
            if (_textComposing)
            { _status.Text = "请先完成输入法选词，再发送文字"; return; }
            if (string.IsNullOrEmpty(text.Text)) return;
            try
            {
                var submitted = new TextInputEvent(text.Text, paste.IsChecked == true);
                WindowsInputControl.ValidateRemoteInput(submitted, _session.Peer.Capabilities);
                Queue(submitted); _inputStatus.Text = "文字已提交，等待远端确认…"; _image.Focus();
            }
            catch (Exception exception) { _status.Text = $"文字输入失败：{exception.Message}"; }
        };
        DockPanel.SetDock(toolbar, Dock.Top); root.Children.Add(toolbar);
        _viewport.Content = _image; root.Children.Add(_viewport); Content = root;
        _session.FrameReceived += FrameReceived;
        _sending = Task.Run(SendInputsAsync);
        Loaded += async (_, _) =>
        {
            try
            {
                await _session.SetQualityAsync((byte)quality.SelectedIndex, _lifetime.Token);
                await _session.StartViewingAsync(_lifetime.Token); _image.Focus();
            }
            catch (Exception exception) { _status.Text = exception.Message; Close(); }
        };
        _image.MouseMove += (_, e) =>
        {
            var now = Environment.TickCount64;
            if (now - _lastMove < 33) return;
            if (Position(e.GetPosition(_image), out var input)) { _lastMove = now; Queue(input); }
        };
        _image.MouseDown += (_, e) =>
        {
            if (!_closing && _control.IsChecked == true && Position(e.GetPosition(_image), out var move) && Button(e.ChangedButton) is int button)
            { _image.Focus(); _image.CaptureMouse(); _pressedButtons.Add(button); Queue(move); Queue(new MouseButtonEvent(button, true)); e.Handled = true; }
        };
        _image.MouseUp += (_, e) =>
        {
            if (Button(e.ChangedButton) is int button && _pressedButtons.Remove(button))
            { Queue(new MouseButtonEvent(button, false)); if (_pressedButtons.Count == 0) _image.ReleaseMouseCapture(); e.Handled = true; }
        };
        _image.LostMouseCapture += async (_, _) => { if (_pressedButtons.Count > 0) await ReleaseRemoteInputAsync(); };
        _image.MouseWheel += (_, e) => { Queue(new MouseWheelEvent(e.Delta)); e.Handled = _control.IsChecked == true; };
        PreviewKeyDown += (_, e) => HandleKey(e, true);
        PreviewKeyUp += (_, e) => HandleKey(e, false);
        Deactivated += async (_, _) => await ReleaseRemoteInputAsync();
        _control.Unchecked += async (_, _) => await ReleaseRemoteInputAsync();
    }

    private void HandleKey(KeyEventArgs e, bool down)
    {
        var key = e.Key == Key.System ? e.SystemKey
            : e.Key == Key.ImeProcessed ? e.ImeProcessedKey : e.Key;
        if (key == Key.F11) { if (down && !e.IsRepeat) ToggleFullScreen(); e.Handled = true; return; }
        if (key == Key.F12) { _control.IsChecked = false; e.Handled = true; return; }
        if (_control.IsChecked != true || !_image.IsKeyboardFocusWithin) return;
        var code = KeyInterop.VirtualKeyFromKey(key);
        if (code is > 0 and < 255) { Queue(new KeyEvent((ushort)code, down)); e.Handled = true; }
    }

    private bool Position(Point point, out MouseMoveEvent input)
    {
        input = new(0, 0);
        if (_image.Source is not BitmapSource bitmap || _control.IsChecked != true) return false;
        var scale = Math.Min(_image.ActualWidth / bitmap.PixelWidth, _image.ActualHeight / bitmap.PixelHeight);
        if (scale <= 0) return false;
        var width = bitmap.PixelWidth * scale; var height = bitmap.PixelHeight * scale;
        var x = (point.X - (_image.ActualWidth - width) / 2) / width;
        var y = (point.Y - (_image.ActualHeight - height) / 2) / height;
        if (!_image.IsMouseCaptured && (x < 0 || x > 1 || y < 0 || y > 1)) return false;
        input = new(Math.Clamp(x, 0, 1), Math.Clamp(y, 0, 1)); return true;
    }
    private static int? Button(MouseButton button) => button switch { MouseButton.Left => 0, MouseButton.Right => 1, MouseButton.Middle => 2, _ => null };
    private void Queue(RemoteInputEvent input)
    {
        if (_closing || _control.IsChecked != true) return;
        if (!_inputs.Writer.TryWrite(input)) { _status.Text = "输入队列已满，正在停止控制"; Close(); }
    }
    private async Task SendInputsAsync()
    {
        try
        {
            await foreach (var input in _inputs.Reader.ReadAllAsync(_lifetime.Token))
                if (input is ReleaseMarker) await _session.ReleaseInputAsync(_lifetime.Token);
                else await _session.SendInputAsync(input, _lifetime.Token);
        }
        catch (OperationCanceledException) when (_lifetime.IsCancellationRequested) { }
        catch (Exception exception) { await Dispatcher.InvokeAsync(() => { _status.Text = exception.Message; Close(); }); }
    }
    private Task ReleaseRemoteInputAsync()
    {
        if (_closing) return Task.CompletedTask;
        _pressedButtons.Clear();
        _image.ReleaseMouseCapture();
        if (_control.IsChecked == true) _control.IsChecked = false;
        while (_inputs.Reader.TryRead(out _)) { }
        if (!_inputs.Writer.TryWrite(new ReleaseMarker())) Close();
        return Task.CompletedTask;
    }
    private void FrameReceived(object? sender, byte[] bytes)
    {
        Interlocked.Add(ref _receivedFrameBytes, bytes.Length);
        Volatile.Write(ref _latestFrame, bytes);
        if (Interlocked.Exchange(ref _renderPending, 1) != 0) return;
        Dispatcher.InvokeAsync(() =>
        {
            try
            {
                var frame = Interlocked.Exchange(ref _latestFrame, null);
                if (_closing || frame is null) return;
                JpegFrameBounds.Validate(frame);
                using var stream = new MemoryStream(frame, writable: false);
                var image = new BitmapImage(); image.BeginInit(); image.CacheOption = BitmapCacheOption.OnLoad; image.StreamSource = stream; image.EndInit(); image.Freeze();
                _image.Source = image;
                ApplyDisplaySize();
                _displayedFrames++;
                var elapsed = System.Diagnostics.Stopwatch.GetElapsedTime(_statsStarted).TotalSeconds;
                if (elapsed >= 1)
                {
                    var receivedBytes = Interlocked.Exchange(ref _receivedFrameBytes, 0);
                    _streamStats = $" · {_displayedFrames / elapsed:0.0} 帧/秒 · {receivedBytes * 8 / elapsed / 1_000_000:0.00} Mbps";
                    _displayedFrames = 0; _statsStarted = System.Diagnostics.Stopwatch.GetTimestamp();
                }
                _status.Text = $"{image.PixelWidth}×{image.PixelHeight}{_streamStats} · 加密";
            }
            catch (Exception exception) { _status.Text = $"画面不可用：{exception.Message}"; Close(); }
            finally { Interlocked.Exchange(ref _renderPending, 0); }
        });
    }
    private void ApplyDisplaySize()
    {
        _viewport.HorizontalScrollBarVisibility = _viewport.VerticalScrollBarVisibility = _originalSize ? ScrollBarVisibility.Auto : ScrollBarVisibility.Disabled;
        if (_originalSize && _image.Source is BitmapSource bitmap)
        {
            var dpi = VisualTreeHelper.GetDpi(_image);
            _image.Width = bitmap.PixelWidth / dpi.DpiScaleX; _image.Height = bitmap.PixelHeight / dpi.DpiScaleY;
        }
        else { _image.Width = double.NaN; _image.Height = double.NaN; }
    }
    private void ToggleFullScreen()
    {
        if (!_fullScreen)
        {
            _previousState = WindowState; WindowState = WindowState.Normal; WindowStyle = WindowStyle.None;
            ResizeMode = ResizeMode.NoResize; WindowState = WindowState.Maximized; _fullScreen = true;
        }
        else { WindowState = WindowState.Normal; WindowStyle = WindowStyle.SingleBorderWindow; ResizeMode = ResizeMode.CanResize; WindowState = _previousState; _fullScreen = false; }
        _image.Focus();
    }
    protected override async void OnClosing(CancelEventArgs e)
    {
        if (!_readyToClose)
        {
            e.Cancel = true;
            if (_closing) return;
            _closing = true; _session.FrameReceived -= FrameReceived;
            _lifetime.Cancel(); _inputs.Writer.TryComplete();
            try
            {
                await _sending;
                using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(2));
                await _session.StopViewingAsync(timeout.Token);
            }
            catch (Exception exception) { _status.Text = exception.Message; }
            finally
            {
                _image.Source = null; _latestFrame = null; _lifetime.Dispose(); _readyToClose = true;
                // Cleanup may complete synchronously. Leave WPF's current Closing callback before closing again.
                if (!Dispatcher.HasShutdownStarted) _ = Dispatcher.BeginInvoke(new Action(() => { if (!_windowClosed) Close(); }));
            }
            return;
        }
        base.OnClosing(e);
    }
    private void InputResultReceived(object? sender, RemoteInputResult result) => Dispatcher.InvokeAsync(() =>
    {
        if (!_closing) _inputStatus.Text = result.Success ? "远端 Windows 已接收输入，请查看目标输入框" : $"远端输入失败：{result.Message}";
    });
    private sealed record ReleaseMarker : RemoteInputEvent;
}
