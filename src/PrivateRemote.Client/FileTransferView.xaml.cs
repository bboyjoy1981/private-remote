using System.Diagnostics;
using Microsoft.Win32;
using PrivateRemote.Transfer;
using System.Windows;

namespace PrivateRemote.Client;

/// <summary>
/// Transfer UI for an already authenticated peer session. The peer supplies an encrypted
/// bulk channel for sends and a decrypted, ordered byte stream for each accepted offer.
/// </summary>
public partial class FileTransferView : Window
{
    private readonly IEncryptedBulkDataChannel _sendChannel;
    private readonly Func<OutgoingFileMetadata, CancellationToken, Task<bool>> _announceOfferAsync;
    private readonly CancellationTokenSource _windowLifetime = new();
    private CancellationTokenSource? _activeTransfer;

    public FileTransferView(
        IEncryptedBulkDataChannel sendChannel,
        Func<OutgoingFileMetadata, CancellationToken, Task<bool>> announceOfferAsync,
        string peerDisplayName)
    {
        ArgumentNullException.ThrowIfNull(sendChannel);
        ArgumentNullException.ThrowIfNull(announceOfferAsync);
        ArgumentException.ThrowIfNullOrWhiteSpace(peerDisplayName);
        InitializeComponent();
        _sendChannel = sendChannel;
        _announceOfferAsync = announceOfferAsync;
        SessionLabel.Text = $"已连接到 {peerDisplayName} · 文件内容通过加密通道传输";
        Closed += (_, _) => _windowLifetime.Cancel();
    }

    /// <summary>Shows a file offer and, after the user chooses a destination, receives its bytes.</summary>
    public async Task<bool> AcceptIncomingAsync(
        OutgoingFileMetadata offer,
        Stream encryptedContent,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(offer);
        ArgumentNullException.ThrowIfNull(encryptedContent);
        if (offer.Length < 0 || offer.Length > 8L * 1024 * 1024 * 1024 || offer.Sha256 is null || offer.Sha256.Length != 32)
        {
            throw new InvalidDataException("对方提供的文件信息无效或超出大小限制。");
        }

        var size = FormatSize(offer.Length);
        var answer = MessageBox.Show(
            this,
            $"对方要发送文件：\n\n{offer.FileName}\n大小：{size}\n\n是否选择保存位置并接收？",
            "接收文件",
            MessageBoxButton.YesNo,
            MessageBoxImage.Question,
            MessageBoxResult.No);
        if (answer != MessageBoxResult.Yes)
        {
            FooterStatus.Text = "已拒绝接收文件。";
            return false;
        }

        var saveDialog = new SaveFileDialog
        {
            Title = "选择接收文件的保存位置",
            FileName = Path.GetFileName(offer.FileName),
            AddExtension = true,
            OverwritePrompt = false,
            CheckPathExists = true
        };
        if (saveDialog.ShowDialog(this) != true)
        {
            FooterStatus.Text = "已取消接收。";
            return false;
        }

        if (File.Exists(saveDialog.FileName) || Directory.Exists(saveDialog.FileName))
        {
            FooterStatus.Text = "目标位置已存在同名文件，请选择其他名称。";
            return false;
        }

        using var transfer = BeginTransfer("正在接收", Path.GetFileName(saveDialog.FileName), offer.Length);
        try
        {
            var targetName = Path.GetFileName(saveDialog.FileName);
            using var receiver = new FileReceiver(Path.GetDirectoryName(saveDialog.FileName)!, targetName, offer.Length, offer.Sha256);
            var buffer = new byte[64 * 1024];
            var timer = Stopwatch.StartNew();
            long received = 0;
            try
            {
                while (received < offer.Length)
                {
                    var wanted = (int)Math.Min(buffer.Length, offer.Length - received);
                    var count = await encryptedContent.ReadAsync(buffer.AsMemory(0, wanted), transfer.Token);
                    if (count == 0)
                    {
                        throw new EndOfStreamException("连接在文件接收完成前中断。");
                    }

                    receiver.Write(buffer.AsSpan(0, count));
                    received += count;
                    UpdateProgress(received, offer.Length, timer.Elapsed);
                }

                var savedPath = receiver.Complete();
                UpdateProgress(received, offer.Length, timer.Elapsed);
                FooterStatus.Text = "文件已安全保存。";
                TransferStatus.Text = "接收完成";
                TransferDetails.Text = Path.GetFileName(savedPath);
                return true;
            }
            finally
            {
                System.Security.Cryptography.CryptographicOperations.ZeroMemory(buffer);
            }
        }
        catch (OperationCanceledException)
        {
            FooterStatus.Text = "接收已取消，未完成的临时文件已清理。";
            TransferStatus.Text = "接收已取消";
            return false;
        }
        catch (Exception exception)
        {
            FooterStatus.Text = $"接收失败：{exception.Message}";
            TransferStatus.Text = "接收失败";
            return false;
        }
    }

    private async void SendButton_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog
        {
            Title = "选择要发送的文件",
            CheckFileExists = true,
            Multiselect = false
        };
        if (dialog.ShowDialog(this) != true)
        {
            return;
        }

        using var transfer = BeginTransfer("正在发送", Path.GetFileName(dialog.FileName), new FileInfo(dialog.FileName).Length);
        try
        {
            var timer = Stopwatch.StartNew();
            var progress = new Progress<FileTransferProgress>(value => UpdateProgress(value.BytesSent, value.TotalBytes, timer.Elapsed));
            var metadata = await FileSender.PrepareAsync(dialog.FileName, transfer.Token);
            try
            {
                var accepted = await _announceOfferAsync(metadata, transfer.Token);
                if (!accepted)
                {
                    FooterStatus.Text = "对方拒绝或未确认接收。";
                    TransferStatus.Text = "发送未开始";
                    return;
                }

                await FileSender.SendPreparedAsync(dialog.FileName, metadata, _sendChannel, progress, transfer.Token);
            }
            finally
            {
                System.Security.Cryptography.CryptographicOperations.ZeroMemory(metadata.Sha256);
            }

            FooterStatus.Text = "文件已发送。";
            UpdateProgress(metadata.Length, metadata.Length, timer.Elapsed);
            TransferStatus.Text = "发送完成";
        }
        catch (OperationCanceledException)
        {
            FooterStatus.Text = "发送已取消。";
            TransferStatus.Text = "发送已取消";
        }
        catch (Exception exception)
        {
            FooterStatus.Text = $"发送失败：{exception.Message}";
            TransferStatus.Text = "发送失败";
        }
    }

    private TransferLifetime BeginTransfer(string direction, string fileName, long length)
    {
        if (_activeTransfer is not null)
        {
            throw new InvalidOperationException("已有文件传输正在进行。");
        }

        var transfer = CancellationTokenSource.CreateLinkedTokenSource(_windowLifetime.Token);
        _activeTransfer = transfer;
        SendButton.IsEnabled = false;
        CancelButton.IsEnabled = true;
        TransferProgress.Value = 0;
        ProgressLabel.Text = $"0% · {FormatSize(length)}";
        TransferStatus.Text = direction;
        TransferDetails.Text = $"{fileName} · {FormatSize(length)}";
        FooterStatus.Text = direction;
        return new TransferLifetime(transfer, () =>
        {
            _activeTransfer = null;
            SendButton.IsEnabled = true;
            CancelButton.IsEnabled = false;
        });
    }

    private void UpdateProgress(long transferred, long total, TimeSpan elapsed)
    {
        var percent = total == 0 ? 100 : Math.Clamp(transferred * 100d / total, 0, 100);
        TransferProgress.Value = percent;
        ProgressLabel.Text = $"{percent:0}% · {FormatSize(transferred)} / {FormatSize(total)} · {FormatSize(elapsed.TotalSeconds > 0 ? (long)(transferred / elapsed.TotalSeconds) : 0)}/秒";
    }

    private void CancelButton_Click(object sender, RoutedEventArgs e)
    {
        _activeTransfer?.Cancel();
        FooterStatus.Text = "正在取消传输…";
    }

    private static string FormatSize(long bytes)
    {
        string[] units = ["B", "KB", "MB", "GB"];
        double size = bytes;
        var unit = 0;
        while (size >= 1024 && unit < units.Length - 1)
        {
            size /= 1024;
            unit++;
        }

        return $"{size:0.##} {units[unit]}";
    }

    private sealed class TransferLifetime : IDisposable
    {
        private readonly Action _onDispose;

        public TransferLifetime(CancellationTokenSource tokenSource, Action onDispose)
        {
            TokenSource = tokenSource;
            _onDispose = onDispose;
        }

        public CancellationTokenSource TokenSource { get; }
        public CancellationToken Token => TokenSource.Token;

        public void Dispose()
        {
            TokenSource.Dispose();
            _onDispose();
        }
    }
}
