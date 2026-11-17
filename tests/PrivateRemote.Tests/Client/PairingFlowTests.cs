using PrivateRemote.Client;
using PrivateRemote.Protocol;
using PrivateRemote.Transport;

namespace PrivateRemote.Tests.Client;

internal static class PairingFlowTests
{
    public static void StoredPairingsAuthorizeSessionsAndRevocationStopsExistingNegotiation()
    {
        using var leftDirectory = new TemporaryDirectory();
        using var rightDirectory = new TemporaryDirectory();
        using var left = DeviceIdentity.Create();
        using var right = DeviceIdentity.Create();
        var leftStore = new DeviceStore(leftDirectory.Path);
        var rightStore = new DeviceStore(rightDirectory.Path);
        leftStore.SaveApprovedDevice(new PairedDevice(right.DeviceId, right.PublicKey, "right", SessionCapability.ScreenControl));
        rightStore.SaveApprovedDevice(new PairedDevice(left.DeviceId, left.PublicKey, "left", SessionCapability.ScreenControl));
        var leftFactory = new DeviceSessionFactory(leftStore, left);
        var rightFactory = new DeviceSessionFactory(rightStore, right);
        TestAssert.Throws<UnauthorizedAccessException>(() => leftFactory.CreateOutgoing(right.DeviceId, SessionCapability.FileTransfer), "A stored screen grant must not authorize file transfer.");
        var outgoing = leftFactory.CreateOutgoing(right.DeviceId, SessionCapability.ScreenControl);
        var another = leftFactory.CreateOutgoing(right.DeviceId, SessionCapability.ScreenControl);
        TestAssert.True(outgoing.SessionId != another.SessionId, "Every new session must get a fresh session identity.");
        var sdp = "v=0\r\na=fingerprint:sha-256 " + string.Join(":", Enumerable.Repeat("AA", 32)) + "\r\n";
        var now = DateTimeOffset.UtcNow;
        var offer = outgoing.CreateDescription("offer", sdp, now);
        var incoming = rightFactory.AcceptIncoming(offer, now);
        TestAssert.Equal(outgoing.SessionId, incoming.Negotiation.SessionId, "An accepted incoming session must bind the signed offer's identity.");
        TestAssert.Throws<PeerAuthenticationException>(() => rightFactory.AcceptIncoming(offer, now), "The application factory must retain replay history between sessions.");
        outgoing.Accept(incoming.Negotiation.CreateDescription("answer", sdp, now), now);
        new DeviceStore(leftDirectory.Path).RevokeDevice(right.DeviceId);
        TestAssert.Throws<PeerAuthenticationException>(() => outgoing.CreateCandidate("candidate:1 1 UDP 1 127.0.0.1 5000 typ host", "0", now), "Existing outbound negotiation must stop after persistent revocation.");
        TestAssert.Throws<PeerAuthenticationException>(() => leftFactory.CreateOutgoing(right.DeviceId, SessionCapability.ScreenControl), "A revoked stored device must not create another session.");
        rightStore.RevokeDevice(left.DeviceId);
        TestAssert.Throws<PeerAuthenticationException>(() => incoming.Negotiation.CreateDescription("answer", sdp, now), "A receiving session must also stop using a revoked pairing.");
    }

    public static void PairingRequiresLocalApprovalAndPersistsAfterApproval()
    {
        using var directory = new TemporaryDirectory();
        using var peer = DeviceIdentity.Create();
        var store = new DeviceStore(directory.Path);
        var approval = new PairingApproval(store);
        var now = DateTimeOffset.UtcNow;
        var declinedInvitation = PairingInvitation.Create(now);

        TestAssert.Throws<UnauthorizedAccessException>(
            () => approval.Approve(declinedInvitation, declinedInvitation.Token, now, peer.DeviceId, peer.PublicKey, "Office PC", SessionCapability.ScreenControl, false),
            "Pairing must not be stored before local approval.");
        TestAssert.Equal(0, store.LoadPairedDevices().Count, "A declined request must not appear in the device list.");

        var invitation = PairingInvitation.Create(now);
        approval.Approve(invitation, invitation.Token, now, peer.DeviceId, peer.PublicKey, "Office PC", SessionCapability.ScreenControl, true);
        TestAssert.Equal(1, new DeviceStore(directory.Path).LoadPairedDevices().Count, "An explicitly approved device should remain after reloading the store.");
    }

    public static void ExpiredInvitationCannotBePersisted()
    {
        using var directory = new TemporaryDirectory();
        using var peer = DeviceIdentity.Create();
        var store = new DeviceStore(directory.Path);
        var approval = new PairingApproval(store);
        var invitation = PairingInvitation.Create(DateTimeOffset.UtcNow.AddMinutes(-6));

        TestAssert.Throws<UnauthorizedAccessException>(
            () => approval.Approve(invitation, invitation.Token, DateTimeOffset.UtcNow, peer.DeviceId, peer.PublicKey, "Office PC", SessionCapability.ScreenControl, true),
            "An expired invitation must fail approval.");
        TestAssert.Equal(0, store.LoadPairedDevices().Count, "An expired invitation must not create a pairing.");
    }

    public static void InvalidPeerIdentityDoesNotConsumeInvitation()
    {
        using var directory = new TemporaryDirectory();
        using var peer = DeviceIdentity.Create();
        var store = new DeviceStore(directory.Path);
        var approval = new PairingApproval(store);
        var invitation = PairingInvitation.Create(DateTimeOffset.UtcNow);

        TestAssert.Throws<ArgumentException>(
            () => approval.Approve(invitation, invitation.Token, DateTimeOffset.UtcNow, new string('0', 64), peer.PublicKey, "Office PC", SessionCapability.ScreenControl, true),
            "The public key fingerprint must match the submitted peer identity.");
        approval.Approve(invitation, invitation.Token, DateTimeOffset.UtcNow, peer.DeviceId, peer.PublicKey, "Office PC", SessionCapability.ScreenControl, true);
        TestAssert.Equal(1, store.LoadPairedDevices().Count, "A malformed peer identity must not burn the valid invitation.");
    }

    public static void DeviceCanBeRenamedAndRevoked()
    {
        using var directory = new TemporaryDirectory();
        using var peer = DeviceIdentity.Create();
        var store = new DeviceStore(directory.Path);
        store.SaveApprovedDevice(new PairedDevice(peer.DeviceId, peer.PublicKey, "Office PC", SessionCapability.FileTransfer));

        TestAssert.True(store.RenameDevice(peer.DeviceId, "Workstation"), "An existing pairing should be renameable.");
        var renamed = store.LoadPairedDevices().Single();
        TestAssert.Equal("Workstation", renamed.DisplayName, "The new name should persist.");
        TestAssert.True(store.RenameDevice(peer.DeviceId, "  Office  "), "Names should be trimmed before saving.");
        TestAssert.Equal("Office", store.LoadPairedDevices().Single().DisplayName, "Whitespace around a device name should not persist.");
        TestAssert.True(!store.RenameDevice(new string('0', 64), "Unknown"), "An unknown device should not be created by rename.");
        TestAssert.Throws<ArgumentException>(() => store.RenameDevice(peer.DeviceId, "  "), "An empty device name must be rejected.");
        TestAssert.True(store.RevokeDevice(peer.DeviceId), "An active pairing should be revocable.");
        TestAssert.True(store.LoadPairedDevices().Single().IsRevoked, "Revocation should persist.");
    }

    private sealed class TemporaryDirectory : IDisposable
    {
        public TemporaryDirectory()
        {
            Path = System.IO.Path.Combine(System.IO.Path.GetTempPath(), $"PrivateRemoteTests-{Guid.NewGuid():N}");
            Directory.CreateDirectory(Path);
        }

        public string Path { get; }

        public void Dispose()
        {
            Directory.Delete(Path, recursive: true);
        }
    }
}
