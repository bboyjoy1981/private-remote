using PrivateRemote.Protocol;

namespace PrivateRemote.Tests.Protocol;

internal static class PairingTests
{
    public static void InvitationsAreSingleUse()
    {
        var createdAt = new DateTimeOffset(2026, 10, 13, 8, 0, 0, TimeSpan.Zero);
        var invitation = PairingInvitation.Create(createdAt);

        TestAssert.True(!invitation.TryConsume(invitation.Token + "x", createdAt.AddSeconds(10)), "An incorrect invitation token must be rejected.");
        TestAssert.True(invitation.TryConsume(invitation.Token, createdAt.AddSeconds(10)), "A valid invitation must be accepted once.");
        TestAssert.True(!invitation.TryConsume(invitation.Token, createdAt.AddSeconds(11)), "A consumed invitation must not be reusable.");
    }

    public static void ExpiredInvitationsAreRejected()
    {
        var createdAt = new DateTimeOffset(2026, 10, 13, 8, 0, 0, TimeSpan.Zero);
        var invitation = PairingInvitation.Create(createdAt);

        TestAssert.True(!invitation.TryConsume(invitation.Token, createdAt.AddMinutes(6)), "An invitation older than its five-minute lifetime must be rejected.");
    }

    public static void RevocationRemovesAuthorization()
    {
        using var identity = DeviceIdentity.Create();
        var registry = new PairingRegistry();
        var device = new PairedDevice(identity.DeviceId, identity.PublicKey, "Office PC", SessionCapability.ScreenControl | SessionCapability.FileTransfer);
        registry.AddApproved(device);

        TestAssert.True(registry.IsAuthorized(identity.DeviceId, SessionCapability.ScreenControl), "An approved device must receive its granted capability.");
        TestAssert.True(registry.Revoke(identity.DeviceId), "Revocation should report that a paired device was found.");
        TestAssert.True(!registry.IsAuthorized(identity.DeviceId, SessionCapability.ScreenControl), "A revoked device must no longer be authorized.");
    }

    public static void UnknownDevicesAndUnapprovedCapabilitiesAreRejected()
    {
        using var identity = DeviceIdentity.Create();
        var registry = new PairingRegistry();
        registry.AddApproved(new PairedDevice(identity.DeviceId, identity.PublicKey, "Screen only PC", SessionCapability.ScreenControl));

        TestAssert.True(!registry.IsAuthorized(identity.DeviceId, SessionCapability.FileTransfer), "A device must not gain an unapproved capability.");
        TestAssert.True(!registry.IsAuthorized(identity.DeviceId, SessionCapability.ScreenControl | SessionCapability.FileTransfer), "Combined grants must reject any unapproved capability.");
        TestAssert.True(!registry.IsAuthorized(new string('0', 64), SessionCapability.ScreenControl), "Unknown devices must not be authorized.");
    }
}
