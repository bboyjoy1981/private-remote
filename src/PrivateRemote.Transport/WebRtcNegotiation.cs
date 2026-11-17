using System.Text.Json;
using System.Text.RegularExpressions;
using PrivateRemote.Protocol;

namespace PrivateRemote.Transport;

public sealed record WebRtcSignalPayload(int Version, Guid SessionId, SessionCapability Capabilities, string Data, string Auxiliary);

/// <summary>Authenticates negotiation metadata before passing SDP/ICE to the native peer.</summary>
public sealed class WebRtcNegotiation
{
    private static readonly Regex FingerprintLine = new("^a=fingerprint:sha-256 ([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){31})$", RegexOptions.CultureInvariant);
    private readonly DeviceIdentity _identity;
    private readonly PairedDevice _peer;
    private readonly AuthenticatedSignalingInbox _inbox;
    private readonly bool _initiator;
    private readonly Func<PairedDevice?> _currentPeer;
    private readonly object _gate = new();
    private string? _remoteFingerprint;

    public WebRtcNegotiation(DeviceIdentity identity, PairedDevice peer, AuthenticatedSignalingInbox inbox, Guid sessionId, SessionCapability capabilities, bool initiator, Func<PairedDevice?> currentPeer)
    {
        _identity = identity ?? throw new ArgumentNullException(nameof(identity));
        _peer = peer ?? throw new ArgumentNullException(nameof(peer));
        _inbox = inbox ?? throw new ArgumentNullException(nameof(inbox));
        _currentPeer = currentPeer ?? throw new ArgumentNullException(nameof(currentPeer));
        CapabilityAuthorization.Require(peer.Capabilities, capabilities);
        if (identity.DeviceId == peer.DeviceId || sessionId == Guid.Empty)
        {
            throw new ArgumentException("Negotiation requires a distinct peer and a fresh nonempty session ID.");
        }

        SessionId = sessionId;
        Capabilities = capabilities;
        _initiator = initiator;
        RequireCurrentAuthorization();
    }

    public Guid SessionId { get; }
    public SessionCapability Capabilities { get; }
    public bool IsInitiator => _initiator;
    public string PeerDeviceId => _peer.DeviceId;

    public SignalingEnvelope CreateDescription(string type, string sdp, DateTimeOffset now)
    {
        if (type != (_initiator ? "offer" : "answer"))
        {
            throw new InvalidDataException("Unexpected local description type for this session role.");
        }

        ExtractFingerprint(sdp);
        return Create(type, sdp, string.Empty, now);
    }

    public SignalingEnvelope CreateCandidate(string candidate, string mid, DateTimeOffset now)
    {
        ValidateCandidate(candidate, mid);
        return Create("ice", candidate, mid, now);
    }

    public SignalingEnvelope CreateClose(DateTimeOffset now) => Create("session-close", "disconnected", string.Empty, now);

    private SignalingEnvelope Create(string type, string data, string auxiliary, DateTimeOffset now)
    {
        RequireCurrentAuthorization();
        ValidateFields(data, auxiliary);
        var payload = new WebRtcSignalPayload(1, SessionId, Capabilities, data, auxiliary);
        return SignalingProtocol.CreateSigned(_identity, _peer.DeviceId, type, JsonSerializer.Serialize(payload), now);
    }

    public VerifiedWebRtcSignal Accept(SignalingEnvelope envelope, DateTimeOffset now)
    {
        lock (_gate)
        {
            RequireCurrentAuthorization();
            var verified = _inbox.Accept(envelope, now);
            if (verified.Peer.DeviceId != _peer.DeviceId)
            {
                throw new PeerAuthenticationException("The negotiation message belongs to another paired peer.");
            }

            CapabilityAuthorization.Require(verified.Peer.Capabilities, Capabilities);
            WebRtcSignalPayload payload;
            try
            {
                payload = JsonSerializer.Deserialize<WebRtcSignalPayload>(envelope.Payload) ?? throw new InvalidDataException("Empty negotiation payload.");
            }
            catch (JsonException exception)
            {
                throw new InvalidDataException("Malformed negotiation payload.", exception);
            }

            if (payload.Version != 1 || payload.SessionId != SessionId || payload.Capabilities != Capabilities)
            {
                throw new PeerAuthenticationException("Negotiation session ID or capability grant does not match.");
            }

            ValidateFields(payload.Data, payload.Auxiliary);
            if (envelope.MessageType == "session-close")
            {
                if (payload.Auxiliary.Length != 0 || payload.Data.Length > 256 || payload.Data.Any(char.IsControl))
                    throw new InvalidDataException("Invalid close message.");
                return new VerifiedWebRtcSignal(this, envelope.MessageType, payload);
            }
            if (envelope.MessageType == "ice")
            {
                ValidateCandidate(payload.Data, payload.Auxiliary);
                return new VerifiedWebRtcSignal(this, envelope.MessageType, payload);
            }

            if (envelope.MessageType != (_initiator ? "answer" : "offer") || payload.Auxiliary.Length != 0)
            {
                throw new PeerAuthenticationException("Unexpected remote negotiation description.");
            }

            var fingerprint = ExtractFingerprint(payload.Data);
            if (_remoteFingerprint is not null && _remoteFingerprint != fingerprint)
            {
                throw new PeerAuthenticationException("The DTLS fingerprint changed within the session.");
            }

            _remoteFingerprint = fingerprint;
            return new VerifiedWebRtcSignal(this, envelope.MessageType, payload);
        }
    }

    public void RequireCurrentAuthorization()
    {
        var current = _currentPeer();
        if (current is null || !StringComparer.Ordinal.Equals(current.DeviceId, _peer.DeviceId))
        {
            throw new PeerAuthenticationException("The paired device is unknown or revoked.");
        }

        CapabilityAuthorization.Require(current.Capabilities, Capabilities);
    }

    private static void ValidateFields(string data, string auxiliary)
    {
        if (string.IsNullOrWhiteSpace(data) || data.Length > 32 * 1024 || auxiliary is null || auxiliary.Length > 256 || auxiliary.Any(char.IsControl))
        {
            throw new InvalidDataException("Invalid negotiation field size or content.");
        }
    }

    private static void ValidateCandidate(string candidate, string mid)
    {
        if (string.IsNullOrWhiteSpace(candidate) || candidate.Length > 4096 || !candidate.StartsWith("candidate:", StringComparison.Ordinal) ||
            candidate.Any(char.IsControl) || string.IsNullOrWhiteSpace(mid) || mid.Length > 256 || mid.Any(char.IsControl))
        {
            throw new InvalidDataException("Invalid ICE candidate or media identifier.");
        }
    }

    private static string ExtractFingerprint(string sdp)
    {
        if (string.IsNullOrWhiteSpace(sdp) || sdp.Length > 32 * 1024)
        {
            throw new InvalidDataException("Invalid SDP size.");
        }

        var fingerprints = sdp.Split('\n').Select(line => line.TrimEnd('\r')).Where(line => line.StartsWith("a=fingerprint:", StringComparison.Ordinal)).ToArray();
        if (fingerprints.Length == 0)
        {
            throw new PeerAuthenticationException("The description has no DTLS certificate fingerprint.");
        }

        var values = fingerprints.Select(line => FingerprintLine.Match(line)).ToArray();
        if (values.Any(match => !match.Success) || values.Select(match => match.Groups[1].Value.ToUpperInvariant()).Distinct().Count() != 1)
        {
            throw new PeerAuthenticationException("The description has an unsupported or inconsistent DTLS fingerprint.");
        }

        return values[0].Groups[1].Value.ToUpperInvariant();
    }
}

public sealed class VerifiedWebRtcSignal
{
    private readonly WebRtcNegotiation _owner;
    private readonly WebRtcSignalPayload _payload;
    private int _claimed;

    internal VerifiedWebRtcSignal(WebRtcNegotiation owner, string type, WebRtcSignalPayload payload)
    {
        _owner = owner;
        Type = type;
        _payload = payload;
    }

    public string Type { get; }
    public string Data => _payload.Data;
    public string Auxiliary => _payload.Auxiliary;

    internal WebRtcSignalPayload Claim(WebRtcNegotiation owner)
    {
        if (!ReferenceEquals(owner, _owner) || Interlocked.Exchange(ref _claimed, 1) != 0)
        {
            throw new PeerAuthenticationException("The verified negotiation message belongs to another session or was already applied.");
        }

        return _payload;
    }
}
