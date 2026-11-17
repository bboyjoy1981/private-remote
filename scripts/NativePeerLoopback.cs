#nullable enable
using System;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

// Native transport diagnostic only: product device authentication is intentionally
// outside this loopback check, and no remote endpoint or STUN/TURN server is used.
public static class PrivateRemoteNativePeerLoopback
{
    private static readonly object RuntimeGate = new();
    private static IntPtr _library;
    private static string? _libraryPath;

    public sealed class SignalData
    {
        public SignalData(string data, string auxiliary) { Data = data; Auxiliary = auxiliary; }
        public string Data { get; }
        public string Auxiliary { get; }
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct Configuration
    {
        public IntPtr IceServers;
        public int IceServersCount;
        public IntPtr ProxyServer, BindAddress;
        public int CertificateType, TransportPolicy;
        public byte EnableIceTcp, EnableIceUdpMux, DisableAutoNegotiation, ForceMediaTransport;
        public ushort PortRangeBegin, PortRangeEnd;
        public int Mtu, MaxMessageSize;
    }

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate void Description(int peer, IntPtr sdp, IntPtr type, IntPtr user);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate void Candidate(int peer, IntPtr candidate, IntPtr mid, IntPtr user);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate void DataChannel(int peer, int channel, IntPtr user);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate void Message(int channel, IntPtr data, int size, IntPtr user);

    [DllImport("datachannel", CallingConvention = CallingConvention.Cdecl)] private static extern void rtcPreload();
    [DllImport("datachannel", CallingConvention = CallingConvention.Cdecl)] private static extern void rtcCleanup();
    [DllImport("datachannel", CallingConvention = CallingConvention.Cdecl)] private static extern int rtcCreatePeerConnection(ref Configuration configuration);
    [DllImport("datachannel", CallingConvention = CallingConvention.Cdecl)] private static extern int rtcDeletePeerConnection(int peer);
    [DllImport("datachannel", CallingConvention = CallingConvention.Cdecl)] private static extern int rtcDeleteDataChannel(int channel);
    [DllImport("datachannel", CallingConvention = CallingConvention.Cdecl)] private static extern int rtcSetLocalDescriptionCallback(int peer, Description callback);
    [DllImport("datachannel", CallingConvention = CallingConvention.Cdecl)] private static extern int rtcSetLocalCandidateCallback(int peer, Candidate callback);
    [DllImport("datachannel", CallingConvention = CallingConvention.Cdecl)] private static extern int rtcSetDataChannelCallback(int peer, DataChannel callback);
    [DllImport("datachannel", CallingConvention = CallingConvention.Cdecl)] private static extern int rtcSetMessageCallback(int channel, Message callback);
    [DllImport("datachannel", CallingConvention = CallingConvention.Cdecl)] private static extern int rtcSetRemoteDescription(int peer, [MarshalAs(UnmanagedType.LPUTF8Str)] string sdp, [MarshalAs(UnmanagedType.LPUTF8Str)] string type);
    [DllImport("datachannel", CallingConvention = CallingConvention.Cdecl)] private static extern int rtcAddRemoteCandidate(int peer, [MarshalAs(UnmanagedType.LPUTF8Str)] string candidate, [MarshalAs(UnmanagedType.LPUTF8Str)] string mid);
    [DllImport("datachannel", CallingConvention = CallingConvention.Cdecl)] private static extern int rtcCreateDataChannel(int peer, [MarshalAs(UnmanagedType.LPUTF8Str)] string label);
    [DllImport("datachannel", CallingConvention = CallingConvention.Cdecl)] [return: MarshalAs(UnmanagedType.I1)] private static extern bool rtcIsOpen(int channel);
    [DllImport("datachannel", CallingConvention = CallingConvention.Cdecl)] private static extern int rtcSendMessage(int channel, byte[] data, int size);

    private static void Check(int result) { if (result < 0) throw new InvalidOperationException("Native API error: " + result); }

    public static string Run(string libraryPath)
        => Run(libraryPath, (source, kind, data, auxiliary) => new SignalData(data, auxiliary));

    public static string Run(string libraryPath, Func<int, string, string, string, SignalData> exchange)
    {
        lock (RuntimeGate)
        {
            libraryPath = Path.GetFullPath(libraryPath);
            if (_library == IntPtr.Zero)
            {
                _library = NativeLibrary.Load(libraryPath);
                _libraryPath = libraryPath;
                NativeLibrary.SetDllImportResolver(typeof(PrivateRemoteNativePeerLoopback).Assembly, (name, assembly, path) => name == "datachannel" ? _library : IntPtr.Zero);
            }
            else if (!string.Equals(_libraryPath, libraryPath, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException("The diagnostic runtime cannot switch native libraries in one process.");
            }

            return RunCore(exchange);
        }
    }

    private static string RunCore(Func<int, string, string, string, SignalData> exchange)
    {
        if (IntPtr.Size != 8 || Marshal.SizeOf<Configuration>() != 56) throw new InvalidOperationException("Unexpected native configuration ABI.");
        IntPtr bindAddress = Marshal.StringToCoTaskMemUTF8("127.0.0.1");
        int first = -1, second = -1, outgoing = -1, incoming = -1;
        int stopping = 0;
        var received = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
        var callbackRoots = new System.Collections.Generic.List<Delegate>();
        Action<Action> guarded = action => { if (Volatile.Read(ref stopping) == 0) { try { action(); } catch (Exception exception) { received.TrySetException(exception); } } };
        try
        {
            rtcPreload();
            var configuration = new Configuration { BindAddress = bindAddress };
            first = rtcCreatePeerConnection(ref configuration); Check(first);
            second = rtcCreatePeerConnection(ref configuration); Check(second);
            Description fromFirst = (id, sdp, type, user) => guarded(() => {
                var kind = Marshal.PtrToStringUTF8(type)!;
                var verified = exchange(0, kind, Marshal.PtrToStringUTF8(sdp)!, string.Empty);
                Check(rtcSetRemoteDescription(second, verified.Data, kind));
            });
            Description fromSecond = (id, sdp, type, user) => guarded(() => {
                var kind = Marshal.PtrToStringUTF8(type)!;
                var verified = exchange(1, kind, Marshal.PtrToStringUTF8(sdp)!, string.Empty);
                Check(rtcSetRemoteDescription(first, verified.Data, kind));
            });
            Candidate firstCandidate = (id, candidate, mid, user) => guarded(() => {
                var verified = exchange(0, "ice", Marshal.PtrToStringUTF8(candidate)!, Marshal.PtrToStringUTF8(mid)!);
                Check(rtcAddRemoteCandidate(second, verified.Data, verified.Auxiliary));
            });
            Candidate secondCandidate = (id, candidate, mid, user) => guarded(() => {
                var verified = exchange(1, "ice", Marshal.PtrToStringUTF8(candidate)!, Marshal.PtrToStringUTF8(mid)!);
                Check(rtcAddRemoteCandidate(first, verified.Data, verified.Auxiliary));
            });
            Message onMessage = (id, data, size, user) => guarded(() => {
                if (size < 0 || size > 65536) throw new InvalidOperationException("Unexpected diagnostic payload size.");
                var bytes = new byte[size];
                Marshal.Copy(data, bytes, 0, size);
                received.TrySetResult(bytes);
            });
            DataChannel onChannel = (id, channel, user) => guarded(() => {
                Check(rtcSetMessageCallback(channel, onMessage));
                Volatile.Write(ref incoming, channel);
            });
            callbackRoots.AddRange(new Delegate[] { fromFirst, fromSecond, firstCandidate, secondCandidate, onMessage, onChannel });
            Check(rtcSetLocalDescriptionCallback(first, fromFirst));
            Check(rtcSetLocalDescriptionCallback(second, fromSecond));
            Check(rtcSetLocalCandidateCallback(first, firstCandidate));
            Check(rtcSetLocalCandidateCallback(second, secondCandidate));
            Check(rtcSetDataChannelCallback(second, onChannel));
            outgoing = rtcCreateDataChannel(first, "control"); Check(outgoing);
            var deadline = DateTime.UtcNow.AddSeconds(15);
            while (!rtcIsOpen(outgoing) || Volatile.Read(ref incoming) < 0)
            {
                if (received.Task.IsFaulted) received.Task.GetAwaiter().GetResult();
                if (DateTime.UtcNow > deadline) throw new TimeoutException("Native loopback negotiation did not finish.");
                Thread.Sleep(10);
            }
            byte[] payload = Encoding.UTF8.GetBytes("private-remote-native-loopback");
            Check(rtcSendMessage(outgoing, payload, payload.Length));
            if (!received.Task.Wait(TimeSpan.FromSeconds(5))) throw new TimeoutException("Native loopback message was not received.");
            if (!payload.SequenceEqual(received.Task.GetAwaiter().GetResult())) throw new InvalidOperationException("Native payload mismatch.");
            return "PASS: two native loopback peers completed WebRTC negotiation and delivered the exact binary payload over their data channel.";
        }
        finally
        {
            Volatile.Write(ref stopping, 1);
            if (outgoing >= 0) rtcDeleteDataChannel(outgoing);
            if (incoming >= 0) rtcDeleteDataChannel(incoming);
            if (first >= 0) rtcDeletePeerConnection(first);
            if (second >= 0) rtcDeletePeerConnection(second);
            rtcCleanup();
            GC.KeepAlive(callbackRoots);
            Marshal.FreeCoTaskMem(bindAddress);
            // Keep the module loaded for subsequent runs: P/Invoke caches export addresses.
        }
    }
}
