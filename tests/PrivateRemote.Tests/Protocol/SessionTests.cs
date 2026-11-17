using PrivateRemote.Protocol;
using System.Security.Cryptography;

namespace PrivateRemote.Tests.Protocol;

internal static class SessionTests
{
    public static void SignaturesBindTheTranscript()
    {
        using var identity = DeviceIdentity.Create();
        using var peer = DeviceIdentity.Create();
        using var first = EphemeralKeyAgreement.Create();
        using var second = EphemeralKeyAgreement.Create();
        var transcript = CreateTranscript(identity, peer, first.PublicKey, second.PublicKey, SessionCapability.ScreenControl);
        var signature = transcript.Sign(identity);
        var changed = CreateTranscript(identity, peer, first.PublicKey, second.PublicKey, SessionCapability.FileTransfer);

        TestAssert.True(transcript.Verify(identity.PublicKey, signature), "The original signed transcript must verify.");
        TestAssert.True(!transcript.Verify(peer.PublicKey, signature), "A peer signature must not verify as the other participant.");
        TestAssert.True(!changed.Verify(identity.PublicKey, signature), "Changing the granted capabilities must invalidate the signature.");
    }

    public static void EphemeralKeysAreFreshAndAgree()
    {
        using var left = EphemeralKeyAgreement.Create();
        using var right = EphemeralKeyAgreement.Create();
        using var reconnectLeft = EphemeralKeyAgreement.Create();
        using var reconnectRight = EphemeralKeyAgreement.Create();
        var context = new byte[32];
        context[0] = 9;

        var leftKey = left.DeriveSessionKey(right.PublicKey, context);
        var rightKey = right.DeriveSessionKey(left.PublicKey, context);
        var reconnectKey = reconnectLeft.DeriveSessionKey(reconnectRight.PublicKey, context);

        TestAssert.Equal(32, leftKey.Length, "A session key must be 256 bits.");
        TestAssert.SequenceEqual(leftKey, rightKey, "Both peers must derive the same key for one session.");
        TestAssert.True(!leftKey.AsSpan().SequenceEqual(reconnectKey), "A reconnect must use fresh ephemeral key material.");
        CryptographicOperations.ZeroMemory(leftKey);
        CryptographicOperations.ZeroMemory(rightKey);
        CryptographicOperations.ZeroMemory(reconnectKey);
    }

    public static void FramesRequireInOrderDelivery()
    {
        var clientKey = Enumerable.Repeat((byte)0x31, 32).ToArray();
        var hostKey = Enumerable.Repeat((byte)0x72, 32).ToArray();
        var clientPrefix = new byte[] { 1, 2, 3, 4 };
        var hostPrefix = new byte[] { 5, 6, 7, 8 };
        var transcriptHash = Enumerable.Repeat((byte)0x19, 32).ToArray();
        using var clientMaterial = SessionKeySchedule.Derive(clientKey, transcriptHash, isInitiator: true);
        using var hostMaterial = SessionKeySchedule.Derive(clientKey, transcriptHash, isInitiator: false);
        TestAssert.SequenceEqual(clientMaterial.SendKey, hostMaterial.ReceiveKey, "The initiator send key must match the responder receive key.");
        TestAssert.SequenceEqual(clientMaterial.ReceiveKey, hostMaterial.SendKey, "The responder send key must be distinct and match the initiator receive key.");
        using var sender = new SessionFrameCipher(clientMaterial.SendKey, clientMaterial.ReceiveKey, clientMaterial.SendNoncePrefix, clientMaterial.ReceiveNoncePrefix);
        using var receiver = new SessionFrameCipher(hostMaterial.SendKey, hostMaterial.ReceiveKey, hostMaterial.SendNoncePrefix, hostMaterial.ReceiveNoncePrefix);
        var first = sender.Encrypt("first"u8.ToArray());
        var second = sender.Encrypt("second"u8.ToArray());
        var tampered = second.ToArray();
        tampered[^1] ^= 0x80;

        TestAssert.Throws<InvalidDataException>(() => receiver.Decrypt(second), "Out-of-order frames must be rejected.");
        TestAssert.SequenceEqual("first"u8.ToArray(), receiver.Decrypt(first), "The expected frame must decrypt.");
        TestAssert.Throws<InvalidDataException>(() => receiver.Decrypt(tampered), "A frame with an altered authentication tag must be rejected.");
        TestAssert.SequenceEqual("second"u8.ToArray(), receiver.Decrypt(second), "A rejected out-of-order frame may be retried after its predecessor.");
        TestAssert.Throws<InvalidDataException>(() => receiver.Decrypt(first), "A replayed frame must be rejected.");
    }

    private static SessionTranscript CreateTranscript(
        DeviceIdentity initiator,
        DeviceIdentity responder,
        byte[] initiatorEphemeral,
        byte[] responderEphemeral,
        SessionCapability capabilities)
    {
        var nonce = Enumerable.Range(0, 32).Select(value => (byte)value).ToArray();
        return new SessionTranscript(
            1,
            initiator.DeviceId,
            responder.DeviceId,
            initiatorEphemeral,
            responderEphemeral,
            "sha-256/0123456789abcdef",
            capabilities,
            nonce);
    }
}
