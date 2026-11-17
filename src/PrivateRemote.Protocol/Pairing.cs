using System.Security.Cryptography;
using System.Text;

namespace PrivateRemote.Protocol;

[Flags]
public enum SessionCapability
{
    None = 0,
    ScreenControl = 1,
    FileTransfer = 2
}

public static class CapabilityAuthorization
{
    public static void Require(SessionCapability granted, SessionCapability requested)
    {
        if (requested == SessionCapability.None || (granted & requested) != requested)
        {
            throw new UnauthorizedAccessException("The active session does not grant the requested capability.");
        }
    }
}

public sealed class PairingInvitation
{
    private const int TokenBytes = 32;
    private const int LifetimeMinutes = 5;
    private readonly object _gate = new();
    private readonly byte[] _tokenHash;
    private string _displayToken;
    private bool _consumed;

    private PairingInvitation(string token, DateTimeOffset createdAt)
    {
        _displayToken = token;
        _tokenHash = SHA256.HashData(Encoding.ASCII.GetBytes(token));
        CreatedAt = createdAt;
        ExpiresAt = createdAt.AddMinutes(LifetimeMinutes);
    }

    public string Token
    {
        get
        {
            lock (_gate)
            {
                return _displayToken;
            }
        }
    }

    public DateTimeOffset CreatedAt { get; }

    public DateTimeOffset ExpiresAt { get; }

    public static PairingInvitation Create(DateTimeOffset now)
    {
        var random = RandomNumberGenerator.GetBytes(TokenBytes);
        var token = Convert.ToBase64String(random).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        CryptographicOperations.ZeroMemory(random);
        return new PairingInvitation(token, now);
    }

    public bool TryConsume(string token, DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(token);
        lock (_gate)
        {
            if (_consumed)
            {
                return false;
            }

            if (now >= ExpiresAt)
            {
                InvalidateCore();
                return false;
            }

            var candidateHash = SHA256.HashData(Encoding.ASCII.GetBytes(token));
            var matches = CryptographicOperations.FixedTimeEquals(_tokenHash, candidateHash);
            CryptographicOperations.ZeroMemory(candidateHash);
            if (!matches)
            {
                return false;
            }

            _consumed = true;
            InvalidateCore();
            return true;
        }
    }

    public void Invalidate()
    {
        lock (_gate)
        {
            InvalidateCore();
        }
    }

    private void InvalidateCore()
    {
        _consumed = true;
        _displayToken = string.Empty;
        CryptographicOperations.ZeroMemory(_tokenHash);
    }

    public override string ToString() => $"Pairing invitation expires at {ExpiresAt:O}";
}

public sealed class PairedDevice
{
    private readonly byte[] _publicKey;

    public PairedDevice(string deviceId, byte[] publicKey, string displayName, SessionCapability capabilities)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(deviceId);
        ArgumentNullException.ThrowIfNull(publicKey);
        ArgumentException.ThrowIfNullOrWhiteSpace(displayName);
        PairingRegistry.ValidateCapabilities(capabilities);

        var derivedId = DeviceIdentity.GetDeviceId(publicKey);
        if (!StringComparer.Ordinal.Equals(deviceId, derivedId))
        {
            throw new ArgumentException("The device ID must match the public key fingerprint.", nameof(deviceId));
        }

        DeviceId = deviceId;
        _publicKey = publicKey.ToArray();
        DisplayName = displayName.Trim();
        Capabilities = capabilities;
    }

    public string DeviceId { get; }

    public byte[] PublicKey => _publicKey.ToArray();

    public string DisplayName { get; }

    public SessionCapability Capabilities { get; }
}

public sealed class PairingRegistry
{
    private const SessionCapability AllCapabilities = SessionCapability.ScreenControl | SessionCapability.FileTransfer;
    private readonly Dictionary<string, RegistryEntry> _devices = new(StringComparer.Ordinal);
    private readonly object _gate = new();

    public void AddApproved(PairedDevice device)
    {
        ArgumentNullException.ThrowIfNull(device);
        lock (_gate)
        {
            if (!_devices.TryAdd(device.DeviceId, new RegistryEntry(device)))
            {
                throw new InvalidOperationException("This device is already paired.");
            }
        }
    }

    public bool Revoke(string deviceId)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(deviceId);
        lock (_gate)
        {
            if (!_devices.TryGetValue(deviceId, out var entry))
            {
                return false;
            }

            entry.IsRevoked = true;
            return true;
        }
    }

    public bool IsAuthorized(string deviceId, SessionCapability requestedCapabilities)
    {
        if (string.IsNullOrWhiteSpace(deviceId) || requestedCapabilities == SessionCapability.None ||
            (requestedCapabilities & ~AllCapabilities) != 0)
        {
            return false;
        }

        lock (_gate)
        {
            return _devices.TryGetValue(deviceId, out var entry) &&
                   !entry.IsRevoked &&
                   (entry.Device.Capabilities & requestedCapabilities) == requestedCapabilities;
        }
    }

    internal static void ValidateCapabilities(SessionCapability capabilities)
    {
        if (capabilities == SessionCapability.None || (capabilities & ~AllCapabilities) != 0)
        {
            throw new ArgumentOutOfRangeException(nameof(capabilities), "At least one supported capability must be granted.");
        }
    }

    private sealed class RegistryEntry(PairedDevice device)
    {
        public PairedDevice Device { get; } = device;

        public bool IsRevoked { get; set; }
    }
}
