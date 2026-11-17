using PrivateRemote.Protocol;

namespace PrivateRemote.Tests.Protocol;

internal static class IdentityTests
{
    public static void SignaturesAreBoundToTheDeviceKey()
    {
        using var signer = DeviceIdentity.Create();
        using var otherDevice = DeviceIdentity.Create();
        var message = "pairing transcript v1"u8.ToArray();
        var signature = signer.Sign(message);

        TestAssert.True(DeviceIdentity.Verify(signer.PublicKey, message, signature), "The matching public key must verify the signature.");
        TestAssert.True(!DeviceIdentity.Verify(otherDevice.PublicKey, message, signature), "A different device key must not verify the signature.");
    }

    public static void ProtectedKeyRoundTrips()
    {
        using var original = DeviceIdentity.Create();
        var protectedKey = original.ExportProtectedPrivateKey();

        using var restored = DeviceIdentity.FromProtectedPrivateKey(protectedKey);

        TestAssert.Equal(original.DeviceId, restored.DeviceId, "A protected key reload must preserve the device identity.");
        var message = "restore check"u8.ToArray();
        TestAssert.True(DeviceIdentity.Verify(original.PublicKey, message, restored.Sign(message)), "The reloaded private key must still authenticate as the device.");
    }
}
