using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Windows.Media;
using System.Windows.Media.Imaging;

namespace PrivateRemote.Client;

/// <summary>Baseline desktop transport; WGC/H.264 remains the planned performance implementation.</summary>
public sealed class GdiJpegFrameSource : IConfigurableDesktopFrameSource
{
    private int _profile = 1;
    public void SetProfile(byte profile) { if (profile > 2) throw new ArgumentOutOfRangeException(nameof(profile)); Volatile.Write(ref _profile, profile); }
    public Task<byte[]> CaptureAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        InteractiveDesktop.RequireDefault();
        var left = GetSystemMetrics(76); var top = GetSystemMetrics(77);
        var sourceWidth = GetSystemMetrics(78); var sourceHeight = GetSystemMetrics(79);
        if (sourceWidth <= 0 || sourceHeight <= 0) throw new InvalidOperationException("No interactive desktop is available.");
        var profile = Volatile.Read(ref _profile);
        var (maxWidth, maxHeight, quality) = profile switch { 0 => (1280, 720, 45), 2 => (3840, 2160, 95), _ => (1600, 900, 70) };
        var scale = Math.Min(1, Math.Min((double)maxWidth / sourceWidth, (double)maxHeight / sourceHeight));
        var width = Math.Max(1, (int)(sourceWidth * scale)); var height = Math.Max(1, (int)(sourceHeight * scale));
        var screen = GetDC(IntPtr.Zero);
        if (screen == IntPtr.Zero) throw new Win32Exception();
        var memory = IntPtr.Zero; var bitmap = IntPtr.Zero; var old = IntPtr.Zero;
        try
        {
            memory = CreateCompatibleDC(screen);
            if (memory == IntPtr.Zero) throw new Win32Exception();
            var info = new BitmapInfo { Size = 40, Width = width, Height = -height, Planes = 1, BitCount = 32, ImageSize = (uint)(width * height * 4) };
            bitmap = CreateDIBSection(screen, ref info, 0, out var pixels, IntPtr.Zero, 0);
            if (bitmap == IntPtr.Zero || pixels == IntPtr.Zero) throw new Win32Exception();
            old = SelectObject(memory, bitmap);
            if (old == IntPtr.Zero || old == new IntPtr(-1)) throw new Win32Exception();
            // HALFTONE preserves thin text strokes better when shrinking the desktop.
            if (SetStretchBltMode(memory, 4) == 0) throw new Win32Exception();
            if (!SetBrushOrgEx(memory, 0, 0, IntPtr.Zero)) throw new Win32Exception();
            if (!StretchBlt(memory, 0, 0, width, height, screen, left, top, sourceWidth, sourceHeight, 0x00CC0020)) throw new Win32Exception();
            GdiFlush();
            cancellationToken.ThrowIfCancellationRequested();
            InteractiveDesktop.RequireDefault();
            var source = BitmapSource.Create(width, height, 96, 96, PixelFormats.Bgr32, null, pixels, width * height * 4, width * 4);
            source.Freeze();
            var encoder = new JpegBitmapEncoder { QualityLevel = quality };
            encoder.Frames.Add(BitmapFrame.Create(source));
            using var output = new MemoryStream(); encoder.Save(output);
            if (output.Length > DesktopWire.MaximumFrameBytes) throw new InvalidDataException("Encoded desktop exceeds frame size bound.");
            return Task.FromResult(output.ToArray());
        }
        finally
        {
            if (old != IntPtr.Zero && old != new IntPtr(-1)) SelectObject(memory, old);
            if (bitmap != IntPtr.Zero) DeleteObject(bitmap);
            if (memory != IntPtr.Zero) DeleteDC(memory);
            ReleaseDC(IntPtr.Zero, screen);
        }
    }
    [StructLayout(LayoutKind.Sequential)] private struct BitmapInfo
    {
        public uint Size; public int Width, Height; public ushort Planes, BitCount; public uint Compression, ImageSize;
        public int XPelsPerMeter, YPelsPerMeter; public uint ClrUsed, ClrImportant;
    }
    [DllImport("user32.dll")] private static extern int GetSystemMetrics(int index);
    [DllImport("user32.dll")] private static extern IntPtr GetDC(IntPtr window);
    [DllImport("user32.dll")] private static extern int ReleaseDC(IntPtr window, IntPtr dc);
    [DllImport("gdi32.dll", SetLastError = true)] private static extern IntPtr CreateCompatibleDC(IntPtr dc);
    [DllImport("gdi32.dll", SetLastError = true)] private static extern IntPtr CreateDIBSection(IntPtr dc, ref BitmapInfo info, uint usage, out IntPtr bits, IntPtr section, uint offset);
    [DllImport("gdi32.dll", SetLastError = true)] private static extern IntPtr SelectObject(IntPtr dc, IntPtr item);
    [DllImport("gdi32.dll")] private static extern bool DeleteObject(IntPtr item);
    [DllImport("gdi32.dll")] private static extern bool DeleteDC(IntPtr dc);
    [DllImport("gdi32.dll")] private static extern int SetStretchBltMode(IntPtr dc, int mode);
    [DllImport("gdi32.dll", SetLastError = true)] private static extern bool SetBrushOrgEx(IntPtr dc, int x, int y, IntPtr previous);
    [DllImport("gdi32.dll")] private static extern bool GdiFlush();
    [DllImport("gdi32.dll", SetLastError = true)] private static extern bool StretchBlt(IntPtr dest, int x, int y, int width, int height, IntPtr source, int sx, int sy, int sw, int sh, uint operation);
}
