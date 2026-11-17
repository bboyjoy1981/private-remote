using PrivateRemote.Client;
using PrivateRemote.Protocol;

namespace PrivateRemote.Tests.Client;

internal static class PairingExchangeTests
{
    public static void OfflinePairingRequiresApprovalAndRejectsTamperReplay()
    {
        var root = Path.Combine(Path.GetTempPath(), "pr-pair-files-" + Guid.NewGuid().ToString("N"));
        try
        {
            using var a = DeviceIdentity.Create(); using var b = DeviceIdentity.Create(); using var attacker = DeviceIdentity.Create();
            var aStore = new DeviceStore(Path.Combine(root, "a")); var bStore = new DeviceStore(Path.Combine(root, "b"));
            var aFlow = new PairingExchange(aStore, a); var bFlow = new PairingExchange(bStore, b);
            var now = DateTimeOffset.UtcNow;
            var invite = aFlow.ExportInvitation(PairingInvitation.Create(now), now);
            var parsed = PairingExchange.Parse(PairingExchange.Serialize(invite), now);
            TestAssert.Throws<UnauthorizedAccessException>(() => bFlow.CreateRequest(parsed, SessionCapability.ScreenControl, now, false), "Request generation requires local approval.");
            var request = bFlow.CreateRequest(parsed, SessionCapability.ScreenControl | SessionCapability.FileTransfer, now, true);
            TestAssert.True(request.Token == "", "Request files must not disclose the invitation secret.");
            TestAssert.Throws<UnauthorizedAccessException>(() => aFlow.ApproveRequest(request, now, false), "Inviter must locally approve before saving pairing.");
            TestAssert.Equal(0, aStore.LoadPairedDevices().Count, "Rejected approval must not persist anything.");
            TestAssert.Throws<UnauthorizedAccessException>(() => aFlow.InspectRequest(request with { TargetDeviceId = attacker.DeviceId }, now), "Modified identities must fail signature validation.");
            var receipt = aFlow.ApproveRequest(request, now, true);
            TestAssert.Throws<UnauthorizedAccessException>(() => aFlow.ApproveRequest(request, now, true), "Consumed invitation must reject repeated requests.");
            TestAssert.Throws<UnauthorizedAccessException>(() => new PairingExchange(bStore, b).CompleteReceipt(receipt, now), "Receipt requires the matching in-memory approved request.");
            var paired = bFlow.CompleteReceipt(PairingExchange.Parse(PairingExchange.Serialize(receipt), now), now);
            TestAssert.Equal(a.DeviceId, paired.DeviceId, "Receipt must complete the expected peer identity.");
            TestAssert.True(aStore.FindActivePairing(b.DeviceId) is not null && bStore.FindActivePairing(a.DeviceId) is not null, "Both sides must persist only after their local approvals.");
            TestAssert.Throws<UnauthorizedAccessException>(() => bFlow.CompleteReceipt(receipt, now), "Receipt cannot replay.");
            TestAssert.Throws<InvalidDataException>(() => PairingExchange.Parse(PairingExchange.Serialize(invite), now.AddMinutes(6)), "Expired documents must fail.");
            aStore.RevokeDevice(b.DeviceId); bStore.RevokeDevice(a.DeviceId);
            var nextInvite = aFlow.ExportInvitation(PairingInvitation.Create(now), now);
            var nextRequest = bFlow.CreateRequest(nextInvite, SessionCapability.ScreenControl, now, true);
            bFlow.CompleteReceipt(aFlow.ApproveRequest(nextRequest, now, true), now);
            TestAssert.Equal(SessionCapability.ScreenControl, aStore.FindActivePairing(b.DeviceId)!.Capabilities, "Fresh local approval must restore revoked pairing with the new grant.");
        }
        finally { if (Directory.Exists(root)) Directory.Delete(root, true); }
    }
}
