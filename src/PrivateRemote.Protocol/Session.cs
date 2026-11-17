using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace PrivateRemote.Protocol;

public sealed class SessionTranscript
{
    private const int NonceLength = 32;
    private const SessionCapability AllCapabilities = SessionCapability.ScreenControl | SessionCapability.FileTransfer;
    private readonly byte[] _initiatorEphemeralPublicKey;
    private readonly byte[] _responderEphemeralPublicKey;
    private readonly byte[] _nonce;
    private readonly byte[] _encoded;

    public SessionTranscript(
        int protocolVersion,
        string initiatorDeviceId,
        string responderDeviceId,
        byte[] initiatorEphemeralPublicKey,
        byte[] responderEphemeralPublicKey,
        string dtlsFingerprint,
        SessionCapability capabilities,
        byte[] nonce)
    {
        if (protocolVersion != 1)
        {
            throw new ArgumentOutOfRangeException(nameof(protocolVersion), "Only protocol version 1 is supported.");
        }

        ValidateDeviceId(initiatorDeviceId, nameof(initiatorDeviceId));
        ValidateDeviceId(responderDeviceId, nameof(responderDeviceId));
        if (StringComparer.Ordinal.Equals(initiatorDeviceId, responderDeviceId))
        {
            throw new ArgumentException("A session requires two distinct device identities.");
        }

        ArgumentNullException.ThrowIfNull(initiatorEphemeralPublicKey);
        ArgumentNullException.ThrowIfNull(responderEphemeralPublicKey);
        if (initiatorEphemeralPublicKey.Length is 0 or > 512 || responderEphemeralPublicKey.Length is 0 or > 512)
        {
            throw new ArgumentException("Ephemeral public keys must contain between 1 and 512 bytes.");
        }

        ArgumentException.ThrowIfNullOrWhiteSpace(dtlsFingerprint);
        if (dtlsFingerprint.Length > 128 || dtlsFingerprint.Any(char.IsControl))
        {
            throw new ArgumentException("The DTLS fingerprint is invalid.", nameof(dtlsFingerprint));
        }

        if (capabilities == SessionCapability.None || (capabilities & ~AllCapabilities) != 0)
        {
            throw new ArgumentOutOfRangeException(nameof(capabilities));
        }

        ArgumentNullException.ThrowIfNull(nonce);
        if (nonce.Length != NonceLength)
        {
            throw new ArgumentException("The session nonce must contain 32 bytes.", nameof(nonce));
        }

        ProtocolVersion = protocolVersion;
        InitiatorDeviceId = initiatorDeviceId;
        ResponderDeviceId = responderDeviceId;
        _initiatorEphemeralPublicKey = initiatorEphemeralPublicKey.ToArray();
        _responderEphemeralPublicKey = responderEphemeralPublicKey.ToArray();
        DtlsFingerprint = dtlsFingerprint;
        Capabilities = capabilities;
        _nonce = nonce.ToArray();
        _encoded = EncodeCanonical();
    }

    public int ProtocolVersion { get; }

    public string InitiatorDeviceId { get; }

    public string ResponderDeviceId { get; }

    public string DtlsFingerprint { get; }

    public SessionCapability Capabilities { get; }

    public byte[] InitiatorEphemeralPublicKey => _initiatorEphemeralPublicKey.ToArray();

    public byte[] ResponderEphemeralPublicKey => _responderEphemeralPublicKey.ToArray();

    public byte[] Nonce => _nonce.ToArray();

    public byte[] Encode() => _encoded.ToArray();

    public byte[] Sign(DeviceIdentity identity)
    {
        ArgumentNullException.ThrowIfNull(identity);
        if (!StringComparer.Ordinal.Equals(identity.DeviceId, InitiatorDeviceId) &&
            !StringComparer.Ordinal.Equals(identity.DeviceId, ResponderDeviceId))
        {
            throw new CryptographicException("Only a session participant may sign the transcript.");
        }

        return identity.Sign(_encoded);
    }

    public bool Verify(byte[] publicKey, byte[] signature)
    {
        ArgumentNullException.ThrowIfNull(publicKey);
        ArgumentNullException.ThrowIfNull(signature);
        try
        {
            var deviceId = DeviceIdentity.GetDeviceId(publicKey);
            return (StringComparer.Ordinal.Equals(deviceId, InitiatorDeviceId) ||
                    StringComparer.Ordinal.Equals(deviceId, ResponderDeviceId)) &&
                   DeviceIdentity.Verify(publicKey, _encoded, signature);
        }
        catch (CryptographicException)
        {
            return false;
        }
    }

    private byte[] EncodeCanonical()
    {
        using var stream = new MemoryStream();
        using var writer = new BinaryWriter(stream, Encoding.UTF8, leaveOpen: true);
        writer.Write("PrivateRemote/session/v1");
        writer.Write(ProtocolVersion);
        writer.Write(InitiatorDeviceId);
        writer.Write(ResponderDeviceId);
        writer.Write(_initiatorEphemeralPublicKey.Length);
        writer.Write(_initiatorEphemeralPublicKey);
        writer.Write(_responderEphemeralPublicKey.Length);
        writer.Write(_responderEphemeralPublicKey);
        writer.Write(DtlsFingerprint);
        writer.Write((int)Capabilities);
        writer.Write(_nonce.Length);
        writer.Write(_nonce);
        writer.Flush();
        return stream.ToArray();
    }

    private static void ValidateDeviceId(string deviceId, string parameterName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(deviceId);
        if (deviceId.Length != 64 || deviceId.Any(character => !Uri.IsHexDigit(character)) || deviceId.Any(char.IsUpper))
        {
            throw new ArgumentException("Device IDs must be lowercase SHA-256 fingerprints.", parameterName);
        }
    }
}

public sealed class EphemeralKeyAgreement : IDisposable
{
    private readonly ECDiffieHellman _agreement;
    private bool _disposed;

    private EphemeralKeyAgreement(ECDiffieHellman agreement)
    {
        _agreement = agreement;
        PublicKey = agreement.ExportSubjectPublicKeyInfo();
    }

    public byte[] PublicKey { get; }

    public static EphemeralKeyAgreement Create()
    {
        return new EphemeralKeyAgreement(ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256));
    }

    public byte[] DeriveSessionKey(byte[] peerPublicKey, byte[] transcriptHash)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(peerPublicKey);
        ArgumentNullException.ThrowIfNull(transcriptHash);
        if (transcriptHash.Length != 32)
        {
            throw new ArgumentException("The transcript hash must contain 32 bytes.", nameof(transcriptHash));
        }

        using var peer = ECDiffieHellman.Create();
        peer.ImportSubjectPublicKeyInfo(peerPublicKey, out var bytesRead);
        if (bytesRead != peerPublicKey.Length)
        {
            throw new CryptographicException("The peer key contains trailing data.");
        }

        var sharedSecret = _agreement.DeriveKeyFromHash(peer.PublicKey, HashAlgorithmName.SHA256);
        try
        {
            return HKDF.DeriveKey(
                HashAlgorithmName.SHA256,
                sharedSecret,
                outputLength: 32,
                salt: transcriptHash,
                info: "PrivateRemote session master v1"u8.ToArray());
        }
        finally
        {
            CryptographicOperations.ZeroMemory(sharedSecret);
        }
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _agreement.Dispose();
        _disposed = true;
    }
}

public sealed class SessionKeyMaterial : IDisposable
{
    private readonly byte[] _sendKey;
    private readonly byte[] _receiveKey;
    private readonly byte[] _sendNoncePrefix;
    private readonly byte[] _receiveNoncePrefix;
    private bool _disposed;

    internal SessionKeyMaterial(byte[] sendKey, byte[] receiveKey, byte[] sendNoncePrefix, byte[] receiveNoncePrefix)
    {
        _sendKey = sendKey;
        _receiveKey = receiveKey;
        _sendNoncePrefix = sendNoncePrefix;
        _receiveNoncePrefix = receiveNoncePrefix;
    }

    public byte[] SendKey => GetCopy(_sendKey);

    public byte[] ReceiveKey => GetCopy(_receiveKey);

    public byte[] SendNoncePrefix => GetCopy(_sendNoncePrefix);

    public byte[] ReceiveNoncePrefix => GetCopy(_receiveNoncePrefix);

    private byte[] GetCopy(byte[] value)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return value.ToArray();
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        CryptographicOperations.ZeroMemory(_sendKey);
        CryptographicOperations.ZeroMemory(_receiveKey);
        CryptographicOperations.ZeroMemory(_sendNoncePrefix);
        CryptographicOperations.ZeroMemory(_receiveNoncePrefix);
        _disposed = true;
    }
}

public static class SessionKeySchedule
{
    private static readonly byte[] ClientToHostKeyInfo = "PrivateRemote/v1/client-to-host/key"u8.ToArray();
    private static readonly byte[] HostToClientKeyInfo = "PrivateRemote/v1/host-to-client/key"u8.ToArray();
    private static readonly byte[] ClientToHostNonceInfo = "PrivateRemote/v1/client-to-host/nonce"u8.ToArray();
    private static readonly byte[] HostToClientNonceInfo = "PrivateRemote/v1/host-to-client/nonce"u8.ToArray();

    public static SessionKeyMaterial Derive(byte[] masterKey, byte[] transcriptHash, bool isInitiator)
    {
        ArgumentNullException.ThrowIfNull(masterKey);
        ArgumentNullException.ThrowIfNull(transcriptHash);
        if (masterKey.Length != 32 || transcriptHash.Length != 32)
        {
            throw new ArgumentException("The master key and transcript hash must each contain 32 bytes.");
        }

        var clientToHostKey = Derive(masterKey, transcriptHash, ClientToHostKeyInfo, 32);
        var hostToClientKey = Derive(masterKey, transcriptHash, HostToClientKeyInfo, 32);
        var clientToHostNonce = Derive(masterKey, transcriptHash, ClientToHostNonceInfo, 4);
        var hostToClientNonce = Derive(masterKey, transcriptHash, HostToClientNonceInfo, 4);

        return isInitiator
            ? new SessionKeyMaterial(clientToHostKey, hostToClientKey, clientToHostNonce, hostToClientNonce)
            : new SessionKeyMaterial(hostToClientKey, clientToHostKey, hostToClientNonce, clientToHostNonce);
    }

    private static byte[] Derive(byte[] key, byte[] salt, byte[] info, int length)
    {
        return HKDF.DeriveKey(HashAlgorithmName.SHA256, key, length, salt, info);
    }
}

public sealed class SessionFrameCipher : IDisposable
{
    private const int SequenceLength = sizeof(ulong);
    private const int NoncePrefixLength = 4;
    private const int TagLength = 16;
    private const int MaximumFrameLength = 64 * 1024 * 1024;
    private readonly byte[] _sendKey;
    private readonly byte[] _receiveKey;
    private readonly byte[] _sendNoncePrefix;
    private readonly byte[] _receiveNoncePrefix;
    private readonly object _sendGate = new();
    private readonly object _receiveGate = new();
    private ulong _nextSendSequence;
    private ulong _nextReceiveSequence;
    private bool _disposed;

    public SessionFrameCipher(byte[] sendKey, byte[] receiveKey, byte[] sendNoncePrefix, byte[] receiveNoncePrefix)
    {
        ValidateKey(sendKey, nameof(sendKey));
        ValidateKey(receiveKey, nameof(receiveKey));
        ValidateNoncePrefix(sendNoncePrefix, nameof(sendNoncePrefix));
        ValidateNoncePrefix(receiveNoncePrefix, nameof(receiveNoncePrefix));
        if (sendKey.AsSpan().SequenceEqual(receiveKey) && sendNoncePrefix.AsSpan().SequenceEqual(receiveNoncePrefix))
        {
            throw new ArgumentException("Opposite directions cannot reuse the same AES-GCM key and nonce prefix.");
        }

        _sendKey = sendKey.ToArray();
        _receiveKey = receiveKey.ToArray();
        _sendNoncePrefix = sendNoncePrefix.ToArray();
        _receiveNoncePrefix = receiveNoncePrefix.ToArray();
    }

    public byte[] Encrypt(byte[] plaintext)
    {
        ArgumentNullException.ThrowIfNull(plaintext);
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (plaintext.Length > MaximumFrameLength)
        {
            throw new ArgumentOutOfRangeException(nameof(plaintext), "A session frame exceeds the maximum size.");
        }

        lock (_sendGate)
        {
            if (_nextSendSequence == ulong.MaxValue)
            {
                throw new InvalidOperationException("The session send sequence is exhausted.");
            }

            var frame = new byte[SequenceLength + plaintext.Length + TagLength];
            var header = frame.AsSpan(0, SequenceLength);
            BinaryPrimitives.WriteUInt64BigEndian(header, _nextSendSequence);
            Span<byte> nonce = stackalloc byte[12];
            _sendNoncePrefix.CopyTo(nonce);
            header.CopyTo(nonce[NoncePrefixLength..]);
            using var aes = new AesGcm(_sendKey, TagLength);
            aes.Encrypt(nonce, plaintext, frame.AsSpan(SequenceLength, plaintext.Length), frame.AsSpan(SequenceLength + plaintext.Length, TagLength), header);
            _nextSendSequence++;
            return frame;
        }
    }

    public byte[] Decrypt(byte[] frame)
    {
        ArgumentNullException.ThrowIfNull(frame);
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (frame.Length < SequenceLength + TagLength || frame.Length > SequenceLength + MaximumFrameLength + TagLength)
        {
            throw new InvalidDataException("The session frame has an invalid size.");
        }

        lock (_receiveGate)
        {
            var header = frame.AsSpan(0, SequenceLength);
            var sequence = BinaryPrimitives.ReadUInt64BigEndian(header);
            if (sequence != _nextReceiveSequence || _nextReceiveSequence == ulong.MaxValue)
            {
                throw new InvalidDataException("The session frame is replayed or out of order.");
            }

            var plaintextLength = frame.Length - SequenceLength - TagLength;
            var plaintext = new byte[plaintextLength];
            Span<byte> nonce = stackalloc byte[12];
            _receiveNoncePrefix.CopyTo(nonce);
            header.CopyTo(nonce[NoncePrefixLength..]);
            using var aes = new AesGcm(_receiveKey, TagLength);
            try
            {
                aes.Decrypt(
                    nonce,
                    frame.AsSpan(SequenceLength, plaintextLength),
                    frame.AsSpan(SequenceLength + plaintextLength, TagLength),
                    plaintext,
                    header);
                _nextReceiveSequence++;
                return plaintext;
            }
            catch (CryptographicException exception)
            {
                CryptographicOperations.ZeroMemory(plaintext);
                throw new InvalidDataException("The session frame failed authentication.", exception);
            }
        }
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        CryptographicOperations.ZeroMemory(_sendKey);
        CryptographicOperations.ZeroMemory(_receiveKey);
        CryptographicOperations.ZeroMemory(_sendNoncePrefix);
        CryptographicOperations.ZeroMemory(_receiveNoncePrefix);
        _disposed = true;
    }

    private static void ValidateKey(byte[] key, string parameterName)
    {
        ArgumentNullException.ThrowIfNull(key);
        if (key.Length != 32)
        {
            throw new ArgumentException("AES-GCM session keys must contain 32 bytes.", parameterName);
        }
    }

    private static void ValidateNoncePrefix(byte[] prefix, string parameterName)
    {
        ArgumentNullException.ThrowIfNull(prefix);
        if (prefix.Length != NoncePrefixLength)
        {
            throw new ArgumentException("AES-GCM nonce prefixes must contain 4 bytes.", parameterName);
        }
    }
}
