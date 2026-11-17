using System.Windows;
using System.Windows.Controls;
using Microsoft.Win32;

namespace PrivateRemote.Client;

public sealed class SessionFilesWindow : Window
{
    private readonly SessionFiles _files;
    private readonly Button _send = new() { Content = "选择文件并发送", Padding = new Thickness(16, 9, 16, 9) };
    private readonly TextBlock _details = new() { Text = "接收文件前会询问保存位置。", Margin = new Thickness(0, 18, 0, 8), TextWrapping = TextWrapping.Wrap };
    private readonly ProgressBar _progress = new() { Minimum = 0, Maximum = 100, Height = 12 };
    private readonly CancellationTokenSource _lifetime = new();
    public SessionFilesWindow(SessionFiles files)
    {
        _files = files; Title = "加密文件传输"; Width = 520; Height = 240;
        var panel = new StackPanel { Margin = new Thickness(22) };
        var buttons = new StackPanel { Orientation = Orientation.Horizontal };
        var cancel = new Button { Content = "取消传输", Padding = new Thickness(16, 9, 16, 9), Margin = new Thickness(10, 0, 0, 0) };
        buttons.Children.Add(_send); buttons.Children.Add(cancel); panel.Children.Add(buttons); panel.Children.Add(_details); panel.Children.Add(_progress); Content = panel;
        _files.ProgressChanged += ProgressChanged;
        _send.Click += async (_, _) =>
        {
            var dialog = new OpenFileDialog { Title = "选择发送到另一台电脑的文件", CheckFileExists = true };
            if (dialog.ShowDialog(this) != true) return;
            _send.IsEnabled = false;
            try { await _files.SendFileAsync(dialog.FileName, _lifetime.Token); }
            catch (OperationCanceledException) { _details.Text = "传输已取消或对方拒绝。"; }
            catch (Exception exception) { _details.Text = $"传输失败：{exception.Message}"; }
            finally { _send.IsEnabled = true; }
        };
        cancel.Click += async (_, _) => await _files.CancelAsync();
    }
    public Task<string?> ChooseDestinationAsync(SessionFileOffer offer, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (_lifetime.IsCancellationRequested) return Task.FromResult<string?>(null);
        Activate();
        if (MessageBox.Show(this, $"对方要发送：{offer.FileName}\n大小：{offer.Length:N0} 字节\n是否选择保存位置并接收？", "接收文件", MessageBoxButton.YesNo, MessageBoxImage.Question, MessageBoxResult.No) != MessageBoxResult.Yes)
            return Task.FromResult<string?>(null);
        var dialog = new SaveFileDialog { Title = "选择保存位置（不能覆盖已有文件）", FileName = offer.FileName, OverwritePrompt = false, CheckPathExists = true };
        if (dialog.ShowDialog(this) != true) return Task.FromResult<string?>(null);
        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromResult<string?>(dialog.FileName);
    }
    private void ProgressChanged(object? sender, SessionFileProgress progress) => Dispatcher.InvokeAsync(() =>
    {
        if (_lifetime.IsCancellationRequested) return;
        _details.Text = $"{progress.Direction} · {progress.FileName}\n{progress.Message} · {progress.Completed:N0} / {progress.Total:N0} 字节";
        _progress.Value = progress.Total == 0 ? 100 : 100d * progress.Completed / progress.Total;
    });
    protected override async void OnClosed(EventArgs e)
    {
        _lifetime.Cancel(); _files.ProgressChanged -= ProgressChanged;
        try { await _files.CancelAsync(); }
        finally { _lifetime.Dispose(); }
        base.OnClosed(e);
    }
}
