using System.Runtime.InteropServices;
using System.Security.Cryptography;
using PrivateRemote.Protocol;
using PrivateRemote.Transport;

namespace PrivateRemote.Tests.Transport;

internal sealed class NativeDependencyUnavailableException(string message) : Exception(message);

internal static class NativeNegotiationTests
{
    public static void SignedNegotiationEstablishesNativeDataChannel() => Run(false, false);

    public static void TamperedNegotiationNeverReachesNativePeer() => TestAssert.Throws<PeerAuthenticationException>(
        () => Run(true, false), "A modified signed offer must be rejected before being passed to the native peer.");

    public static void CapabilityMismatchNeverReachesNativePeer() => TestAssert.Throws<PeerAuthenticationException>(
        () => Run(false, true), "A signed offer for other capabilities must not establish this session.");

    public static void SessionAndFingerprintRemainBound()
    {
        using var left = DeviceIdentity.Create();
        using var right = DeviceIdentity.Create();
        var leftRecord = new PairedDevice(left.DeviceId, left.PublicKey, "left", SessionCapability.ScreenControl);
        var rightRecord = new PairedDevice(right.DeviceId, right.PublicKey, "right", SessionCapability.ScreenControl);
        var leftInbox = new AuthenticatedSignalingInbox(left.DeviceId, id => id == right.DeviceId ? rightRecord : null);
        var rightInbox = new AuthenticatedSignalingInbox(right.DeviceId, id => id == left.DeviceId ? leftRecord : null);
        var session = Guid.NewGuid();
        var sender = new WebRtcNegotiation(left, rightRecord, leftInbox, session, SessionCapability.ScreenControl, true, () => rightRecord);
        var receiver = new WebRtcNegotiation(right, leftRecord, rightInbox, session, SessionCapability.ScreenControl, false, () => leftRecord);
        var otherSession = new WebRtcNegotiation(left, rightRecord, leftInbox, Guid.NewGuid(), SessionCapability.ScreenControl, true, () => rightRecord);
        var now = DateTimeOffset.UtcNow;
        var firstSdp = "v=0\r\na=fingerprint:sha-256 " + string.Join(":", Enumerable.Repeat("AA", 32)) + "\r\n";
        var changedSdp = firstSdp.Replace("AA", "BB", StringComparison.Ordinal);
        TestAssert.Throws<PeerAuthenticationException>(() => receiver.Accept(otherSession.CreateDescription("offer", firstSdp, now), now), "An otherwise valid signature for another session must fail.");
        receiver.Accept(sender.CreateDescription("offer", firstSdp, now), now);
        TestAssert.Throws<PeerAuthenticationException>(() => receiver.Accept(sender.CreateDescription("offer", changedSdp, now), now), "An authenticated session must retain the same DTLS certificate fingerprint.");
        TestAssert.Throws<InvalidDataException>(() => sender.CreateCandidate("candidate:host\r\ninjected", "0", now), "ICE candidates must not accept line injection.");
        TestAssert.Throws<PeerAuthenticationException>(() => sender.CreateDescription("offer", "v=0\r\n", now), "Descriptions without a DTLS fingerprint must fail.");
    }

    private static void Run(bool tamper, bool mismatchedCapabilities)
    {
        var library = FindLibrary();
        using var left = DeviceIdentity.Create();
        using var right = DeviceIdentity.Create();
        const SessionCapability all = SessionCapability.ScreenControl | SessionCapability.FileTransfer;
        var leftRecord = new PairedDevice(left.DeviceId, left.PublicKey, "left", all);
        var rightRecord = new PairedDevice(right.DeviceId, right.PublicKey, "right", all);
        var leftInbox = new AuthenticatedSignalingInbox(left.DeviceId, id => id == right.DeviceId ? rightRecord : null);
        var rightInbox = new AuthenticatedSignalingInbox(right.DeviceId, id => id == left.DeviceId ? leftRecord : null);
        var sessionId = Guid.NewGuid();
        var peers = new[]
        {
            new WebRtcNegotiation(left, rightRecord, leftInbox, sessionId, all, true, () => rightRecord),
            new WebRtcNegotiation(right, leftRecord, rightInbox, sessionId, mismatchedCapabilities ? SessionCapability.FileTransfer : all, false, () => leftRecord)
        };
        var descriptions = 0;
        PrivateRemoteNativePeerLoopback.Run(library, (source, kind, data, auxiliary) =>
        {
            var now = DateTimeOffset.UtcNow;
            var envelope = kind == "ice"
                ? peers[source].CreateCandidate(data, auxiliary, now)
                : peers[source].CreateDescription(kind, data, now);
            if (tamper && kind == "offer")
            {
                envelope = envelope with { Payload = envelope.Payload + " " };
            }

            var accepted = peers[1 - source].Accept(envelope, now);
            if (kind != "ice") Interlocked.Increment(ref descriptions);
            return new PrivateRemoteNativePeerLoopback.SignalData(accepted.Data, accepted.Auxiliary);
        });
        TestAssert.True(descriptions >= 2, "Both signed descriptions must be accepted before native binary delivery succeeds.");
    }

    internal static string FindLibrary()
    {
        if (!OperatingSystem.IsWindows() || RuntimeInformation.ProcessArchitecture != Architecture.X64)
        {
            throw new NativeDependencyUnavailableException("Native diagnostic requires Windows x64.");
        }

        string? library = Environment.GetEnvironmentVariable("PRIVATE_REMOTE_NATIVE_DLL");
        if (string.IsNullOrWhiteSpace(library))
        {
            for (var directory = new DirectoryInfo(AppContext.BaseDirectory); directory is not null; directory = directory.Parent)
            {
                var candidate = Path.Combine(directory.FullName, "artifacts", "native", "datachannel.dll");
                if (File.Exists(candidate)) { library = candidate; break; }
            }
        }

        if (string.IsNullOrWhiteSpace(library) || !File.Exists(library))
        {
            throw new NativeDependencyUnavailableException("Build the native DLL or set PRIVATE_REMOTE_NATIVE_DLL.");
        }

        using var stream = File.OpenRead(library);
        var actual = Convert.ToHexString(SHA256.HashData(stream));
        var expected = File.ReadAllText(library + ".sha256").Trim();
        if (!string.Equals(actual, expected, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException("Native DLL hash does not match its build manifest.");
        }

        return Path.GetFullPath(library);
    }
}
