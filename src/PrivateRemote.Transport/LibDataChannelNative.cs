using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace PrivateRemote.Transport;

internal static class LibDataChannelNative
{
    private static readonly object RuntimeGate = new();
    private static readonly List<Delegate[]> RetiredCallbacks = [];
    private static IntPtr _library;
    private static string? _libraryPath;
    private static int _leases;

    static LibDataChannelNative() => NativeLibrary.SetDllImportResolver(typeof(LibDataChannelNative).Assembly,
        (name, assembly, searchPath) => name == "datachannel" ? _library : IntPtr.Zero);

    internal static Lease Acquire(string libraryPath)
    {
        if (!OperatingSystem.IsWindows() || RuntimeInformation.ProcessArchitecture != Architecture.X64 || Marshal.SizeOf<Configuration>() != 56)
            throw new PlatformNotSupportedException("The native peer requires Windows x64 and the pinned C API layout.");
        libraryPath = Path.GetFullPath(libraryPath);
        lock (RuntimeGate)
        {
            if (_library == IntPtr.Zero)
            {
                using var stream = File.OpenRead(libraryPath);
                var actual = Convert.ToHexString(SHA256.HashData(stream));
                var expected = File.ReadAllText(libraryPath + ".sha256").Trim();
                if (!StringComparer.OrdinalIgnoreCase.Equals(actual, expected)) throw new InvalidDataException("Native DLL hash mismatch.");
                _library = NativeLibrary.Load(libraryPath);
                _libraryPath = libraryPath;
            }
            else if (!StringComparer.OrdinalIgnoreCase.Equals(_libraryPath, libraryPath))
                throw new InvalidOperationException("A process cannot switch native peer libraries.");
            if (_leases == 0) Preload();
            _leases++;
            return new Lease();
        }
    }

    internal sealed class Lease
    {
        private int _released;
        internal void Release(Delegate[] callbacks)
        {
            if (Interlocked.Exchange(ref _released, 1) != 0) return;
            lock (RuntimeGate)
            {
                // Deletion can race with native callback tasks. Retain delegates until global cleanup finishes.
                RetiredCallbacks.Add(callbacks);
                if (--_leases == 0)
                {
                    Cleanup();
                    RetiredCallbacks.Clear();
                }
            }
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct Configuration
    {
        public IntPtr IceServers;
        public int IceServersCount;
        public IntPtr ProxyServer, BindAddress;
        public int CertificateType, TransportPolicy;
        public byte EnableIceTcp, EnableIceUdpMux, DisableAutoNegotiation, ForceMediaTransport;
        public ushort PortRangeBegin, PortRangeEnd;
        public int Mtu, MaxMessageSize;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct Reliability
    {
        public byte Unordered, Unreliable;
        public uint MaximumLifetime, MaximumRetransmits;
    }

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] internal delegate void Description(int peer, IntPtr sdp, IntPtr type, IntPtr user);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] internal delegate void Candidate(int peer, IntPtr candidate, IntPtr mid, IntPtr user);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] internal delegate void State(int peer, int state, IntPtr user);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] internal delegate void DataChannel(int peer, int channel, IntPtr user);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] internal delegate void ChannelEvent(int channel, IntPtr user);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] internal delegate void Message(int channel, IntPtr data, int size, IntPtr user);

    [DllImport("datachannel", EntryPoint="rtcPreload", CallingConvention=CallingConvention.Cdecl)] private static extern void Preload();
    [DllImport("datachannel", EntryPoint="rtcCleanup", CallingConvention=CallingConvention.Cdecl)] private static extern void Cleanup();
    [DllImport("datachannel", EntryPoint="rtcCreatePeerConnection", CallingConvention=CallingConvention.Cdecl)] internal static extern int CreatePeer(ref Configuration configuration);
    [DllImport("datachannel", EntryPoint="rtcClosePeerConnection", CallingConvention=CallingConvention.Cdecl)] internal static extern int ClosePeer(int peer);
    [DllImport("datachannel", EntryPoint="rtcDeletePeerConnection", CallingConvention=CallingConvention.Cdecl)] internal static extern int DeletePeer(int peer);
    [DllImport("datachannel", EntryPoint="rtcSetLocalDescriptionCallback", CallingConvention=CallingConvention.Cdecl)] internal static extern int SetDescription(int peer, Description callback);
    [DllImport("datachannel", EntryPoint="rtcSetLocalCandidateCallback", CallingConvention=CallingConvention.Cdecl)] internal static extern int SetCandidate(int peer, Candidate callback);
    [DllImport("datachannel", EntryPoint="rtcSetStateChangeCallback", CallingConvention=CallingConvention.Cdecl)] internal static extern int SetState(int peer, State callback);
    [DllImport("datachannel", EntryPoint="rtcSetDataChannelCallback", CallingConvention=CallingConvention.Cdecl)] internal static extern int SetDataChannel(int peer, DataChannel callback);
    [DllImport("datachannel", EntryPoint="rtcSetOpenCallback", CallingConvention=CallingConvention.Cdecl)] internal static extern int SetOpen(int channel, ChannelEvent callback);
    [DllImport("datachannel", EntryPoint="rtcSetClosedCallback", CallingConvention=CallingConvention.Cdecl)] internal static extern int SetClosed(int channel, ChannelEvent callback);
    [DllImport("datachannel", EntryPoint="rtcSetMessageCallback", CallingConvention=CallingConvention.Cdecl)] internal static extern int SetMessage(int channel, Message callback);
    [DllImport("datachannel", EntryPoint="rtcSetRemoteDescription", CallingConvention=CallingConvention.Cdecl)] internal static extern int SetRemoteDescription(int peer, [MarshalAs(UnmanagedType.LPUTF8Str)] string sdp, [MarshalAs(UnmanagedType.LPUTF8Str)] string type);
    [DllImport("datachannel", EntryPoint="rtcAddRemoteCandidate", CallingConvention=CallingConvention.Cdecl)] internal static extern int AddCandidate(int peer, [MarshalAs(UnmanagedType.LPUTF8Str)] string candidate, [MarshalAs(UnmanagedType.LPUTF8Str)] string mid);
    [DllImport("datachannel", EntryPoint="rtcCreateDataChannel", CallingConvention=CallingConvention.Cdecl)] internal static extern int CreateDataChannel(int peer, [MarshalAs(UnmanagedType.LPUTF8Str)] string label);
    [DllImport("datachannel", EntryPoint="rtcDeleteDataChannel", CallingConvention=CallingConvention.Cdecl)] internal static extern int DeleteDataChannel(int channel);
    [DllImport("datachannel", EntryPoint="rtcGetDataChannelLabel", CallingConvention=CallingConvention.Cdecl)] internal static extern int GetLabel(int channel, byte[] buffer, int size);
    [DllImport("datachannel", EntryPoint="rtcGetDataChannelReliability", CallingConvention=CallingConvention.Cdecl)] internal static extern int GetReliability(int channel, out Reliability reliability);
    [DllImport("datachannel", EntryPoint="rtcIsOpen", CallingConvention=CallingConvention.Cdecl)] [return:MarshalAs(UnmanagedType.I1)] internal static extern bool IsOpen(int channel);
    [DllImport("datachannel", EntryPoint="rtcSendMessage", CallingConvention=CallingConvention.Cdecl)] internal static extern int Send(int channel, byte[] data, int size);
    [DllImport("datachannel", EntryPoint="rtcGetBufferedAmount", CallingConvention=CallingConvention.Cdecl)] internal static extern int BufferedAmount(int channel);
    [DllImport("datachannel", EntryPoint="rtcGetSelectedCandidatePair", CallingConvention=CallingConvention.Cdecl)] internal static extern int GetSelectedCandidates(int peer, byte[] local, int localSize, byte[] remote, int remoteSize);
}
