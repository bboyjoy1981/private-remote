using System.Configuration;
using System.Data;
using System.Windows;

namespace PrivateRemote.Client;

/// <summary>
/// Interaction logic for App.xaml
/// </summary>
public partial class App : Application
{
    private Mutex? _instance;
    private bool _ownsInstance;
    protected override void OnStartup(StartupEventArgs e)
    {
        var user = System.Security.Principal.WindowsIdentity.GetCurrent().User?.Value ?? Environment.UserName;
        _instance = new Mutex(true, "Local\\PrivateRemote-" + user, out _ownsInstance);
        if (!_ownsInstance)
        {
            MessageBox.Show("软件已在运行，请从右下角托盘恢复窗口。更新版本前请先退出旧程序。", "Private Remote");
            Shutdown(); return;
        }
        base.OnStartup(e);
    }
    protected override void OnExit(ExitEventArgs e)
    {
        if (_ownsInstance) _instance?.ReleaseMutex();
        _instance?.Dispose(); base.OnExit(e);
    }
    protected override void OnSessionEnding(SessionEndingCancelEventArgs e)
    {
        if (MainWindow is MainWindow window) window.RequestExit();
        base.OnSessionEnding(e);
    }
}

