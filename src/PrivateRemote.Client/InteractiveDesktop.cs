using System.Runtime.InteropServices;
using System.Text;

namespace PrivateRemote.Client;

internal static class InteractiveDesktop
{
    public static void RequireDefault()
    {
        var desktop = OpenInputDesktop(0, false, 1);
        if (desktop == IntPtr.Zero) throw new UnauthorizedAccessException("锁屏或安全桌面不可远程操作。");
        try
        {
            var name = new StringBuilder(256);
            if (!GetUserObjectInformation(desktop, 2, name, name.Capacity * 2, out _) || name.ToString() != "Default")
                throw new UnauthorizedAccessException("锁屏或 UAC 安全桌面不可远程操作。");
        }
        finally { CloseDesktop(desktop); }
    }
    [DllImport("user32.dll", SetLastError = true)] private static extern IntPtr OpenInputDesktop(uint flags, bool inherit, uint access);
    [DllImport("user32.dll", CharSet = CharSet.Unicode, EntryPoint = "GetUserObjectInformationW", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)] private static extern bool GetUserObjectInformation(IntPtr handle, int index, StringBuilder info, int length, out int needed);
    [DllImport("user32.dll")] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool CloseDesktop(IntPtr desktop);
}
