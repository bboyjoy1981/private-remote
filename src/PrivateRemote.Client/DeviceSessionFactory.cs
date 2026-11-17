using System.Text.Json;
using PrivateRemote.Protocol;
using PrivateRemote.Transport;

namespace PrivateRemote.Client;

/// <summary>One factory per application lifetime retains signaling replay history across reconnects.</summary>
public sealed class DeviceSessionFactory
{
    private readonly DeviceStore _store;
    private readonly DeviceIdentity _identity;
    private readonly AuthenticatedSignalingInbox _inbox;

    public DeviceSessionFactory(DeviceStore store, DeviceIdentity identity)
    {
        _store = store ?? throw new ArgumentNullException(nameof(store));
        _identity = identity ?? throw new ArgumentNullException(nameof(identity));
        _inbox = new AuthenticatedSignalingInbox(identity.DeviceId, store.FindActivePairing);
    }

    public WebRtcNegotiation CreateOutgoing(string peerDeviceId, SessionCapability capabilities)
        => Create(peerDeviceId, Guid.NewGuid(), capabilities, true);

    public string LocalDeviceId => _identity.DeviceId;
    public VerifiedSignalingMessage VerifyUnroutedSignal(SignalingEnvelope envelope) => _inbox.Accept(envelope, DateTimeOffset.UtcNow);

    public async Task<NativeWebRtcPeer> BeginOutgoingNativeAsync(string peerDeviceId, SessionCapability capabilities, string libraryPath,
        CancellationToken cancellationToken, string? bindAddress = null, IReadOnlyList<string>? iceServers = null, bool relayOnly = false)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var peer = new NativeWebRtcPeer(CreateOutgoing(peerDeviceId, capabilities), libraryPath, bindAddress, iceServers, relayOnly);
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            peer.StartOutgoing();
            return peer;
        }
        catch { await peer.DisposeAsync().ConfigureAwait(false); throw; }
    }

    public async Task<NativeWebRtcPeer> AcceptIncomingNativeAsync(SignalingEnvelope offer, string libraryPath, CancellationToken cancellationToken,
        string? bindAddress = null, IReadOnlyList<string>? iceServers = null, bool relayOnly = false)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var incoming = AcceptIncoming(offer, DateTimeOffset.UtcNow);
        var peer = new NativeWebRtcPeer(incoming.Negotiation, libraryPath, bindAddress, iceServers, relayOnly);
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            peer.ApplyVerifiedSignal(incoming.Description);
            return peer;
        }
        catch { await peer.DisposeAsync().ConfigureAwait(false); throw; }
    }

    public IncomingDeviceNegotiation AcceptIncoming(SignalingEnvelope offer, DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(offer);
        if (offer.MessageType != "offer") throw new InvalidDataException("An incoming session must begin with an offer.");
        SignalingProtocol.Validate(offer, now);
        WebRtcSignalPayload payload;
        try
        {
            payload = JsonSerializer.Deserialize<WebRtcSignalPayload>(offer.Payload) ?? throw new InvalidDataException("Empty session offer.");
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException("Malformed session offer.", exception);
        }

        var negotiation = Create(offer.SourceDeviceId, payload.SessionId, payload.Capabilities, false);
        // The untrusted metadata above only selects context; verify before any native peer is created.
        var accepted = negotiation.Accept(offer, now);
        return new IncomingDeviceNegotiation(negotiation, accepted);
    }

    private WebRtcNegotiation Create(string peerDeviceId, Guid sessionId, SessionCapability capabilities, bool initiator)
    {
        var peer = _store.FindActivePairing(peerDeviceId) ?? throw new PeerAuthenticationException("This device is unknown or its pairing was revoked.");
        return new WebRtcNegotiation(_identity, peer, _inbox, sessionId, capabilities, initiator, () => _store.FindActivePairing(peerDeviceId));
    }
}

public sealed record IncomingDeviceNegotiation(WebRtcNegotiation Negotiation, VerifiedWebRtcSignal Description);
