using PrivateRemote.Protocol;
using PrivateRemote.Transport;

namespace PrivateRemote.Tests.Transport;

internal static class SignalingTests
{
    public static void SignatureMustMatchClaimedDeviceIdentity()
    {
        using var source = DeviceIdentity.Create();
        using var claimed = DeviceIdentity.Create();
        using var target = DeviceIdentity.Create();
        var now = DateTimeOffset.UtcNow;
        var envelope = SignalingProtocol.CreateSigned(source, target.DeviceId, "offer", "offer", now) with { SourceDeviceId = claimed.DeviceId };
        envelope = envelope with { Signature = Convert.ToBase64String(source.Sign(SignalingProtocol.EncodeSignedContent(envelope))) };
        TestAssert.True(!SignalingProtocol.Verify(envelope, source.PublicKey, now), "A valid signature from another device must not verify a claimed source identity.");
    }

    public static void InboxRequiresActivePairingAndRejectsReplay()
    {
        using var source = DeviceIdentity.Create();
        using var target = DeviceIdentity.Create();
        using var stranger = DeviceIdentity.Create();
        var now = DateTimeOffset.UtcNow;
        var peer = new PairedDevice(source.DeviceId, source.PublicKey, "source", SessionCapability.ScreenControl);
        var revoked = false;
        var inbox = new AuthenticatedSignalingInbox(target.DeviceId, id => !revoked && id == source.DeviceId ? peer : null);
        var envelope = SignalingProtocol.CreateSigned(source, target.DeviceId, "offer", "offer", now);
        TestAssert.Throws<PeerAuthenticationException>(() => inbox.Accept(envelope with { Payload = "tampered" }, now), "Invalid signatures must be rejected without consuming a nonce.");
        TestAssert.Equal(source.DeviceId, inbox.Accept(envelope, now).Peer.DeviceId, "A current paired identity should authenticate after a rejected tamper.");
        TestAssert.Throws<PeerAuthenticationException>(() => inbox.Accept(envelope, now), "Replay must fail even if the source signature is valid.");
        var unknown = SignalingProtocol.CreateSigned(stranger, target.DeviceId, "offer", "offer", now);
        TestAssert.Throws<PeerAuthenticationException>(() => inbox.Accept(unknown, now), "An unpaired device must not reach native negotiation.");
        var wrongTarget = SignalingProtocol.CreateSigned(source, stranger.DeviceId, "offer", "offer", now);
        TestAssert.Throws<PeerAuthenticationException>(() => inbox.Accept(wrongTarget, now), "Messages addressed elsewhere must fail.");
        revoked = true;
        var afterRevoke = SignalingProtocol.CreateSigned(source, target.DeviceId, "ice", "candidate", now);
        TestAssert.Throws<PeerAuthenticationException>(() => inbox.Accept(afterRevoke, now), "Revocation must be checked again for every message.");
    }

    public static void MessagesBindPayloadAndExpiry()
    {
        using var source = DeviceIdentity.Create();
        using var target = DeviceIdentity.Create();
        var now = DateTimeOffset.UtcNow;
        var signed = SignalingProtocol.CreateSigned(source, target.DeviceId, "offer", "sdp-offer", now);
        TestAssert.True(SignalingProtocol.Verify(signed, source.PublicKey, now), "A valid, current signaling message must verify.");
        TestAssert.True(!SignalingProtocol.Verify(signed with { Payload = "altered-sdp" }, source.PublicKey, now), "The signature must bind the payload.");
        TestAssert.Throws<InvalidDataException>(() => SignalingProtocol.Validate(signed, now.AddMinutes(2)), "Expired messages must be rejected.");
    }

    public static void RemoteSignalingRequiresTls()
    {
        TestAssert.Throws<ArgumentException>(
            () => SignalingClient.ValidateEndpoint(new Uri("ws://signaling.example.invalid/signal")),
            "A bearer token must not be sent to a remote plaintext WebSocket.");
        SignalingClient.ValidateEndpoint(new Uri("ws://localhost:5030/signal"));
        SignalingClient.ValidateEndpoint(new Uri("wss://signaling.example.invalid/signal"));
    }
}
