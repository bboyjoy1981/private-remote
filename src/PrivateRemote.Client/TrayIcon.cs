using System.Runtime.InteropServices;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Interop;

namespace PrivateRemote.Client;

internal sealed class TrayIcon : IDisposable
{
    private readonly HwndSource _source;
    private readonly ContextMenu _menu = new();
    private readonly uint _taskbarCreated;
    private Data _data;
    public TrayIcon(Action show, Action exit)
    {
        _source = new HwndSource(new HwndSourceParameters("PrivateRemoteTray") { Width = 0, Height = 0, WindowStyle = 0 });
        _taskbarCreated = RegisterWindowMessage("TaskbarCreated");
        _data = new Data { Size = (uint)Marshal.SizeOf<Data>(), Window = _source.Handle, Id = 1, Flags = 7, Callback = 0x8001,
            Icon = LoadIcon(IntPtr.Zero, new IntPtr(32512)), Tip = "Private Remote · 后台在线", Info = "", InfoTitle = "" };
        var open = new MenuItem { Header = "显示主窗口" }; open.Click += (_, _) => show();
        var quit = new MenuItem { Header = "退出软件（断开连接）" }; quit.Click += (_, _) => exit();
        _menu.Items.Add(open); _menu.Items.Add(new Separator()); _menu.Items.Add(quit);
        _source.AddHook((IntPtr window, int message, IntPtr wParam, IntPtr lParam, ref bool handled) =>
        {
            if ((uint)message == _taskbarCreated) ShellNotifyIcon(0, ref _data);
            if (message == 0x8001)
            {
                if (lParam.ToInt32() == 0x203) show();
                if (lParam.ToInt32() == 0x205)
                {
                    GetCursorPos(out var point); SetForegroundWindow(_source.Handle);
                    _menu.Placement = PlacementMode.AbsolutePoint;
                    var transform = _source.CompositionTarget?.TransformFromDevice ?? System.Windows.Media.Matrix.Identity;
                    var position = transform.Transform(new System.Windows.Point(point.X, point.Y));
                    _menu.HorizontalOffset = position.X; _menu.VerticalOffset = position.Y; _menu.IsOpen = true;
                }
                handled = true;
            }
            return IntPtr.Zero;
        });
        if (!ShellNotifyIcon(0, ref _data)) { _source.Dispose(); throw new InvalidOperationException("无法创建托盘图标，主窗口不会隐藏。"); }
    }
    public void Dispose() { _menu.IsOpen = false; ShellNotifyIcon(2, ref _data); _source.Dispose(); }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)] private struct Data
    {
        public uint Size; public IntPtr Window; public uint Id, Flags, Callback; public IntPtr Icon;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)] public string Tip;
        public uint State, StateMask;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)] public string Info;
        public uint Timeout;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)] public string InfoTitle;
        public uint InfoFlags; public Guid Guid; public IntPtr BalloonIcon;
    }
    [StructLayout(LayoutKind.Sequential)] private struct Point { public int X, Y; }
    [DllImport("shell32.dll", EntryPoint = "Shell_NotifyIconW", CharSet = CharSet.Unicode)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool ShellNotifyIcon(uint action, ref Data data);
    [DllImport("user32.dll", EntryPoint = "LoadIconW")] private static extern IntPtr LoadIcon(IntPtr instance, IntPtr name);
    [DllImport("user32.dll", EntryPoint = "RegisterWindowMessageW", CharSet = CharSet.Unicode)] private static extern uint RegisterWindowMessage(string message);
    [DllImport("user32.dll")] private static extern bool GetCursorPos(out Point point);
    [DllImport("user32.dll")] private static extern bool SetForegroundWindow(IntPtr window);
}
