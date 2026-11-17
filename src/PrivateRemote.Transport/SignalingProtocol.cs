using System.Security.Cryptography;
using System.Text.Json;
using PrivateRemote.Protocol;

namespace PrivateRemote.Transport;

public sealed record SignalingEnvelope(
    string SourceDeviceId,
    string TargetDeviceId,
    string MessageType,
    string Payload,
    long TimestampUnixSeconds,
    string Nonce,
    string Signature);

public static class SignalingProtocol
{
    public const int MaximumPayloadCharacters = 48 * 1024;
    private static readonly HashSet<string> AllowedMessageTypes = new(StringComparer.Ordinal)
    {
        "offer", "answer", "ice", "session-auth", "session-close"
    };

    public static SignalingEnvelope CreateSigned(DeviceIdentity identity, string targetDeviceId, string messageType, string payload, DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(identity);
        var unsigned = new SignalingEnvelope(
            identity.DeviceId,
            targetDeviceId,
            messageType,
            payload,
            now.ToUnixTimeSeconds(),
            Convert.ToBase64String(RandomNumberGenerator.GetBytes(24)),
            "pending");
        var signed = unsigned with { Signature = Convert.ToBase64String(identity.Sign(EncodeSignedContent(unsigned))) };
        Validate(signed, now);
        return signed;
    }

    public static byte[] EncodeSignedContent(SignalingEnvelope envelope)
    {
        ArgumentNullException.ThrowIfNull(envelope);
        ValidateDeviceId(envelope.SourceDeviceId, nameof(envelope.SourceDeviceId));
        ValidateDeviceId(envelope.TargetDeviceId, nameof(envelope.TargetDeviceId));
        if (StringComparer.Ordinal.Equals(envelope.SourceDeviceId, envelope.TargetDeviceId) ||
            envelope.MessageType is null || !AllowedMessageTypes.Contains(envelope.MessageType) ||
            string.IsNullOrWhiteSpace(envelope.Payload) || envelope.Payload.Length > MaximumPayloadCharacters ||
            envelope.Payload.Any(char.IsControl) || envelope.Nonce is null || envelope.Nonce.Length is < 22 or > 64)
        {
            throw new InvalidDataException("The unsigned signaling content is invalid.");
        }

        var content = new
        {
            envelope.SourceDeviceId,
            envelope.TargetDeviceId,
            envelope.MessageType,
            envelope.Payload,
            envelope.TimestampUnixSeconds,
            envelope.Nonce
        };
        return JsonSerializer.SerializeToUtf8Bytes(content);
    }

    public static bool Verify(SignalingEnvelope envelope, byte[] publicKey, DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(envelope);
        ArgumentNullException.ThrowIfNull(publicKey);
        Validate(envelope, now);
        try
        {
            if (!StringComparer.Ordinal.Equals(DeviceIdentity.GetDeviceId(publicKey), envelope.SourceDeviceId))
            {
                return false;
            }
        }
        catch (CryptographicException)
        {
            return false;
        }

        byte[] signature;
        try
        {
            signature = Convert.FromBase64String(envelope.Signature);
        }
        catch (FormatException)
        {
            return false;
        }

        var signedContent = EncodeSignedContent(envelope);
        try
        {
            return DeviceIdentity.Verify(publicKey, signedContent, signature);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(signedContent);
            CryptographicOperations.ZeroMemory(signature);
        }
    }

    public static void Validate(SignalingEnvelope envelope, DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(envelope);
        ValidateDeviceId(envelope.SourceDeviceId, nameof(envelope.SourceDeviceId));
        ValidateDeviceId(envelope.TargetDeviceId, nameof(envelope.TargetDeviceId));
        if (StringComparer.Ordinal.Equals(envelope.SourceDeviceId, envelope.TargetDeviceId))
        {
            throw new InvalidDataException("A signaling message must target a different device.");
        }

        if (envelope.MessageType is null || !AllowedMessageTypes.Contains(envelope.MessageType))
        {
            throw new InvalidDataException("The signaling message type is not supported.");
        }

        if (string.IsNullOrWhiteSpace(envelope.Payload) || envelope.Payload.Length > MaximumPayloadCharacters || envelope.Payload.Any(char.IsControl))
        {
            throw new InvalidDataException("The signaling payload is empty, oversized, or contains control characters.");
        }

        if (envelope.Nonce is null || envelope.Signature is null || envelope.Nonce.Length is < 22 or > 64 || envelope.Signature.Length is < 1 or > 128)
        {
            throw new InvalidDataException("The signaling nonce or signature has an invalid size.");
        }

        try
        {
            var nonce = Convert.FromBase64String(envelope.Nonce);
            var signature = Convert.FromBase64String(envelope.Signature);
            if (nonce.Length != 24 || signature.Length is < 64 or > 72)
            {
                throw new InvalidDataException("The signaling nonce or signature is malformed.");
            }
        }
        catch (FormatException exception)
        {
            throw new InvalidDataException("The signaling nonce or signature is not valid Base64.", exception);
        }

        DateTimeOffset timestamp;
        try
        {
            timestamp = DateTimeOffset.FromUnixTimeSeconds(envelope.TimestampUnixSeconds);
        }
        catch (ArgumentOutOfRangeException exception)
        {
            throw new InvalidDataException("The signaling timestamp is invalid.", exception);
        }

        if ((now - timestamp).Duration() > TimeSpan.FromMinutes(1))
        {
            throw new InvalidDataException("The signaling message has expired.");
        }
    }

    private static void ValidateDeviceId(string deviceId, string parameterName)
    {
        if (deviceId is null || deviceId.Length != 64 || deviceId.Any(character => !Uri.IsHexDigit(character)))
        {
            throw new InvalidDataException($"The {parameterName} is malformed.");
        }
    }
}
