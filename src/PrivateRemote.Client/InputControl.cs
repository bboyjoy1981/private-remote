using System.Runtime.InteropServices;
using PrivateRemote.Protocol;

namespace PrivateRemote.Client;

public sealed class WindowsInputControl
{
    private readonly Func<SessionCapability> _activeCapabilities;
    private readonly object _gate = new();
    private readonly HashSet<ushort> _keys = [];
    private readonly HashSet<int> _buttons = [];
    private readonly HashSet<ushort> _pendingKeys = [];
    private readonly HashSet<int> _pendingButtons = [];
    private readonly Action _requireDesktop;
    private readonly Func<RemoteInputEvent[], uint> _inject;
    private Task _releaseWorker = Task.CompletedTask;
    private bool _releaseWorkerRunning;
    private readonly Action<string>? _setClipboard;

    public WindowsInputControl(Func<SessionCapability> activeCapabilities, Action<string>? setClipboard = null) : this(activeCapabilities, InteractiveDesktop.RequireDefault, InjectNative) { _setClipboard = setClipboard; }

    internal WindowsInputControl(Func<SessionCapability> activeCapabilities, Action requireDesktop, Func<RemoteInputEvent[], uint> inject)
    {
        _activeCapabilities = activeCapabilities ?? throw new ArgumentNullException(nameof(activeCapabilities));
        _requireDesktop = requireDesktop;
        _inject = inject;
    }
    internal Task PendingReleases { get { lock (_gate) return _releaseWorker; } }

    public void Send(RemoteInputEvent input)
    {
        lock (_gate) SendCore(input);
    }

    private void SendCore(RemoteInputEvent input)
    {
        ArgumentNullException.ThrowIfNull(input);
        ValidateRemoteInput(input, _activeCapabilities());

        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException("Remote input is available only on Windows.");
        }
        _requireDesktop();
        if (input is TextInputEvent) ReleaseAll();
        AttemptPendingReleases();
        if (_pendingKeys.Count + _pendingButtons.Count != 0) throw new InvalidOperationException("Pending input releases must complete before accepting new input.");
        if (input is TextInputEvent { Paste: true } pasted)
        {
            if (_setClipboard is null) throw new InvalidOperationException("远端没有启用兼容粘贴支持。");
            try { _setClipboard(pasted.Text); }
            catch (Exception exception) { throw new InvalidOperationException("无法写入远端剪贴板，请稍后重试。", exception); }
            try
            {
                SendCore(new KeyEvent(0x11, true)); SendCore(new KeyEvent(0x56, true));
                SendCore(new KeyEvent(0x56, false)); SendCore(new KeyEvent(0x11, false));
            }
            finally { ReleaseAll(); }
            return;
        }
        if (_inject([input]) != 1)
        {
            var error = Marshal.GetLastWin32Error();
            throw new InvalidOperationException($"Windows 未接收完整输入（错误 {error}）。请检查目标窗口是否以管理员权限运行、是否处于锁屏/UAC，或应用是否支持 Unicode 输入。");
        }
        if (input is KeyEvent keyEvent) { if (keyEvent.IsDown) _keys.Add(keyEvent.VirtualKey); else _keys.Remove(keyEvent.VirtualKey); }
        if (input is MouseButtonEvent buttonEvent) { if (buttonEvent.IsDown) _buttons.Add(buttonEvent.Button); else _buttons.Remove(buttonEvent.Button); }
    }

    public void ReleaseAll()
    {
        lock (_gate)
        {
            _pendingKeys.UnionWith(_keys); _pendingButtons.UnionWith(_buttons); _keys.Clear(); _buttons.Clear();
            AttemptPendingReleases();
            if (_pendingKeys.Count + _pendingButtons.Count != 0 && !_releaseWorkerRunning)
            { _releaseWorkerRunning = true; _releaseWorker = Task.Run(RetryReleasesAsync); }
        }
    }

    private void AttemptPendingReleases()
    {
        if (_pendingKeys.Count + _pendingButtons.Count == 0) return;
        try
        {
            _requireDesktop();
            var releases = _pendingKeys.Select(key => (RemoteInputEvent)new KeyEvent(key, false))
                .Concat(_pendingButtons.Select(button => new MouseButtonEvent(button, false))).ToArray();
            var count = Math.Min(_inject(releases), (uint)releases.Length);
            for (var index = 0; index < count; index++)
            {
                if (releases[index] is KeyEvent key) _pendingKeys.Remove(key.VirtualKey);
                if (releases[index] is MouseButtonEvent button) _pendingButtons.Remove(button.Button);
            }
        }
        catch (Exception exception) when (exception is UnauthorizedAccessException or System.ComponentModel.Win32Exception) { }
    }

    private async Task RetryReleasesAsync()
    {
        while (true)
        {
            await Task.Delay(250);
            lock (_gate)
            {
                AttemptPendingReleases();
                if (_pendingKeys.Count + _pendingButtons.Count == 0) { _releaseWorkerRunning = false; return; }
            }
        }
    }

    private static uint InjectNative(RemoteInputEvent[] events)
    {
        if (events.Length == 1 && events[0] is TextInputEvent text)
        {
            var accepted = new List<Input>(text.Text.Length * 2);
            foreach (var value in text.Text) { accepted.Add(Input.Unicode(value, true)); accepted.Add(Input.Unicode(value, false)); }
            var values = accepted.ToArray();
            var sent = SendInput((uint)values.Length, values, Marshal.SizeOf<Input>());
            // A partially inserted UTF-16 pair must not leave VK_PACKET held.
            if (sent < values.Length && sent % 2 == 1) SendInput(1, [Input.Unicode(text.Text[(int)sent / 2], false)], Marshal.SizeOf<Input>());
            return sent == values.Length ? 1u : 0u;
        }
        var native = events.Select(input => input switch
        {
            MouseMoveEvent move => Input.Mouse(move.NormalizedX, move.NormalizedY, MouseEventFlags.Move | MouseEventFlags.Absolute | MouseEventFlags.VirtualDesk),
            MouseButtonEvent button => Input.MouseButton(button.Button, button.IsDown),
            MouseWheelEvent wheel => Input.MouseWheel(wheel.Delta),
            KeyEvent key => Input.Keyboard(key.VirtualKey, key.IsDown),
            _ => throw new ArgumentOutOfRangeException(nameof(events))
        }).ToArray();
        return SendInput((uint)native.Length, native, Marshal.SizeOf<Input>());
    }

    public static void ValidateRemoteInput(RemoteInputEvent input, SessionCapability activeCapabilities)
    {
        ArgumentNullException.ThrowIfNull(input);
        CapabilityAuthorization.Require(activeCapabilities, SessionCapability.ScreenControl);

        switch (input)
        {
            case MouseMoveEvent move when double.IsFinite(move.NormalizedX) && double.IsFinite(move.NormalizedY) &&
                                          move.NormalizedX is >= 0 and <= 1 && move.NormalizedY is >= 0 and <= 1:
            case MouseWheelEvent:
                return;
            case MouseButtonEvent { Button: >= 0 and <= 2 }:
                return;
            case KeyEvent { VirtualKey: > 0 and < 0xFF }:
                return;
            case TextInputEvent text when IsValidText(text.Text):
                return;
            default:
                throw new ArgumentOutOfRangeException(nameof(input), "The remote input event contains unsupported or out-of-range values.");
        }
    }
    private static bool IsValidText(string? text)
    {
        if (string.IsNullOrEmpty(text) || text.Length > 128) return false;
        for (var index = 0; index < text.Length; index++)
        {
            var value = text[index];
            if (char.IsControl(value)) return false;
            if (char.IsHighSurrogate(value))
            {
                if (++index >= text.Length || !char.IsLowSurrogate(text[index])) return false;
            }
            else if (char.IsLowSurrogate(value)) return false;
        }
        return true;
    }

    [DllImport("user32.dll", SetLastError = true)]
    private static extern uint SendInput(uint count, [In] Input[] inputs, int size);

    [StructLayout(LayoutKind.Sequential)]
    private struct Input
    {
        public uint Type;
        public InputUnion Data;

        public static Input Mouse(double x, double y, MouseEventFlags flags)
        {
            var virtualDesktopLeft = NativeGetSystemMetrics(76);
            var virtualDesktopTop = NativeGetSystemMetrics(77);
            var virtualDesktopWidth = Math.Max(1, NativeGetSystemMetrics(78));
            var virtualDesktopHeight = Math.Max(1, NativeGetSystemMetrics(79));
            var screenX = virtualDesktopLeft + (int)Math.Round(Math.Clamp(x, 0, 1) * (virtualDesktopWidth - 1));
            var screenY = virtualDesktopTop + (int)Math.Round(Math.Clamp(y, 0, 1) * (virtualDesktopHeight - 1));
            var absoluteX = (int)Math.Round((screenX - virtualDesktopLeft) * 65535d / Math.Max(1, virtualDesktopWidth - 1));
            var absoluteY = (int)Math.Round((screenY - virtualDesktopTop) * 65535d / Math.Max(1, virtualDesktopHeight - 1));
            return new Input
            {
                Type = 0,
                Data = new InputUnion
                {
                    Mouse = new MouseInput
                    {
                        X = absoluteX,
                        Y = absoluteY,
                        Flags = flags,
                    }
                }
            };
        }

        public static Input MouseButton(int button, bool down)
        {
            var (downFlag, upFlag) = button switch
            {
                0 => (MouseEventFlags.LeftDown, MouseEventFlags.LeftUp),
                1 => (MouseEventFlags.RightDown, MouseEventFlags.RightUp),
                2 => (MouseEventFlags.MiddleDown, MouseEventFlags.MiddleUp),
                _ => throw new ArgumentOutOfRangeException(nameof(button))
            };
            return new Input { Type = 0, Data = new InputUnion { Mouse = new MouseInput { Flags = down ? downFlag : upFlag } } };
        }

        public static Input MouseWheel(int delta) => new() { Type = 0, Data = new InputUnion { Mouse = new MouseInput { MouseData = unchecked((uint)delta), Flags = MouseEventFlags.Wheel } } };

        public static Input Keyboard(ushort virtualKey, bool down)
        {
            var extended = virtualKey is 0x21 or 0x22 or 0x23 or 0x24 or 0x25 or 0x26 or 0x27 or 0x28 or 0x2c or 0x2d or 0x2e or 0x5b or 0x5c or 0x5d or 0x6f or 0x90 or 0xa3 or 0xa5;
            return new() { Type = 1, Data = new InputUnion { Keyboard = new KeyboardInput { VirtualKey = virtualKey, Flags = (down ? 0u : 2u) | (extended ? 1u : 0u) } } };
        }
        public static Input Unicode(char value, bool down) => new()
        {
            Type = 1, Data = new InputUnion { Keyboard = new KeyboardInput { VirtualKey = 0, ScanCode = value, Flags = 4u | (down ? 0u : 2u) } }
        };
    }

    [StructLayout(LayoutKind.Explicit)]
    private struct InputUnion
    {
        [FieldOffset(0)] public MouseInput Mouse;
        [FieldOffset(0)] public KeyboardInput Keyboard;
    }

    [DllImport("user32.dll", EntryPoint = "GetSystemMetrics")]
    private static extern int NativeGetSystemMetrics(int index);

    [StructLayout(LayoutKind.Sequential)]
    private struct MouseInput
    {
        public int X;
        public int Y;
        public uint MouseData;
        public MouseEventFlags Flags;
        public uint Time;
        public UIntPtr ExtraInfo;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct KeyboardInput
    {
        public ushort VirtualKey;
        public ushort ScanCode;
        public uint Flags;
        public uint Time;
        public UIntPtr ExtraInfo;
    }

    [Flags]
    private enum MouseEventFlags : uint
    {
        Move = 0x0001,
        LeftDown = 0x0002,
        LeftUp = 0x0004,
        RightDown = 0x0008,
        RightUp = 0x0010,
        MiddleDown = 0x0020,
        MiddleUp = 0x0040,
        Wheel = 0x0800,
        Absolute = 0x8000,
        VirtualDesk = 0x4000
    }

}
