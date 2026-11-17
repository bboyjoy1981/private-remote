using PrivateRemote.Protocol;
using PrivateRemote.Relay;

namespace PrivateRemote.Tests.Relay;

internal static class RelaySecurityTests
{
    public static void AccessRequiresActivePairedDevicesAndFreshNonce()
    {
        using var source = DeviceIdentity.Create();
        using var target = DeviceIdentity.Create();
        var policy = new AccessPolicy();
        var sourceCredential = new DeviceCredential(source.DeviceId, "source-secret", source.PublicKey);
        var targetCredential = new DeviceCredential(target.DeviceId, "target-secret", target.PublicKey);
        TestAssert.True(policy.TryRegister(sourceCredential), "A valid paired identity should register.");
        TestAssert.True(policy.TryRegister(targetCredential), "The second paired identity should register.");
        TestAssert.True(policy.TryAuthenticate(source.DeviceId, "source-secret", out _), "A paired device with the correct token should authenticate.");
        TestAssert.True(!policy.TryAuthenticate(source.DeviceId, "wrong-secret", out _), "An incorrect token must fail.");

        var now = DateTimeOffset.UtcNow;
        TestAssert.True(!policy.TryAuthorizeMessage(source.DeviceId, target.DeviceId, "future", now.AddSeconds(5), now), "Future-dated messages must fail.");
        TestAssert.True(policy.TryAuthorizeMessage(source.DeviceId, target.DeviceId, "nonce-one", now, now), "A fresh message between paired devices should be authorized.");
        TestAssert.True(!policy.TryAuthorizeMessage(source.DeviceId, target.DeviceId, "nonce-one", now, now), "A replayed nonce must fail.");
        TestAssert.True(policy.Revoke(target.DeviceId), "A paired device should be revocable.");
        TestAssert.True(!policy.TryAuthorizeMessage(source.DeviceId, target.DeviceId, "nonce-two", now, now), "A revoked target must not receive signaling.");
    }
}
