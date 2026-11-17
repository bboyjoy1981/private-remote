using PrivateRemote.Protocol;

namespace PrivateRemote.Transport;

/// <summary>Keep this inbox alive across reconnects so recent message nonces remain remembered.</summary>
public sealed class AuthenticatedSignalingInbox
{
    private const int MaximumNonces = 16_384;
    private readonly string _localDeviceId;
    private readonly Func<string, PairedDevice?> _findActivePeer;
    private readonly Dictionary<string, DateTimeOffset> _nonces = new(StringComparer.Ordinal);
    private readonly object _gate = new();

    public AuthenticatedSignalingInbox(string localDeviceId, Func<string, PairedDevice?> findActivePeer)
    {
        if (localDeviceId is null || localDeviceId.Length != 64 || localDeviceId.Any(c => !Uri.IsHexDigit(c)))
        {
            throw new ArgumentException("Invalid local device fingerprint.", nameof(localDeviceId));
        }

        _localDeviceId = localDeviceId;
        _findActivePeer = findActivePeer ?? throw new ArgumentNullException(nameof(findActivePeer));
    }

    public VerifiedSignalingMessage Accept(SignalingEnvelope envelope, DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(envelope);
        SignalingProtocol.Validate(envelope, now);
        lock (_gate)
        {
            if (!StringComparer.Ordinal.Equals(envelope.TargetDeviceId, _localDeviceId))
            {
                throw new PeerAuthenticationException("Signaling is addressed to another device.");
            }

            var peer = _findActivePeer(envelope.SourceDeviceId);
            if (peer is null || !StringComparer.Ordinal.Equals(peer.DeviceId, envelope.SourceDeviceId) ||
                !SignalingProtocol.Verify(envelope, peer.PublicKey, now))
            {
                throw new PeerAuthenticationException("The signaling device is unknown, revoked, or has an invalid signature.");
            }

            // Re-read authorization after verification, which may overlap a local revoke.
            var currentPeer = _findActivePeer(envelope.SourceDeviceId);
            if (currentPeer is null || !StringComparer.Ordinal.Equals(currentPeer.DeviceId, peer.DeviceId))
            {
                throw new PeerAuthenticationException("The signaling device was revoked.");
            }

            foreach (var key in _nonces.Where(entry => now - entry.Value > TimeSpan.FromMinutes(2)).Select(entry => entry.Key).ToArray())
            {
                _nonces.Remove(key);
            }

            var nonceKey = envelope.SourceDeviceId + ":" + envelope.Nonce;
            if (_nonces.ContainsKey(nonceKey) || _nonces.Count >= MaximumNonces)
            {
                throw new PeerAuthenticationException("Replayed signaling message or replay-cache capacity reached.");
            }

            _nonces.Add(nonceKey, now);
            return new VerifiedSignalingMessage(envelope, currentPeer);
        }
    }
}

public sealed class VerifiedSignalingMessage
{
    internal VerifiedSignalingMessage(SignalingEnvelope envelope, PairedDevice peer)
    {
        Envelope = envelope;
        Peer = peer;
    }

    public SignalingEnvelope Envelope { get; }
    public PairedDevice Peer { get; }
}
