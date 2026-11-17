namespace PrivateRemote.Relay;

public sealed class AccessPolicy
{
    private const int MaximumNonceEntries = 100_000;
    private readonly Dictionary<string, DeviceCredential> _devices = new(StringComparer.Ordinal);
    private readonly Dictionary<string, DateTimeOffset> _seenNonces = new(StringComparer.Ordinal);
    private readonly object _gate = new();

    public bool TryRegister(DeviceCredential credential)
    {
        ArgumentNullException.ThrowIfNull(credential);
        lock (_gate)
        {
            if (credential.DeviceId is null || credential.DeviceId.Length != 64 || credential.PublicKey is null ||
                !StringComparer.Ordinal.Equals(PrivateRemote.Protocol.DeviceIdentity.GetDeviceId(credential.PublicKey), credential.DeviceId) ||
                string.IsNullOrWhiteSpace(credential.BearerToken))
            {
                return false;
            }

            return _devices.TryAdd(credential.DeviceId, credential);
        }
    }

    public bool TryAuthenticate(string deviceId, string bearerToken, out DeviceCredential? credential)
    {
        credential = null;
        DeviceCredential? stored;
        lock (_gate)
        {
            if (string.IsNullOrWhiteSpace(deviceId) || string.IsNullOrWhiteSpace(bearerToken) || !_devices.TryGetValue(deviceId, out stored) || stored.IsRevoked)
            {
                return false;
            }
        }

        if (!CryptographicTokenEquals(stored.BearerToken, bearerToken))
        {
            return false;
        }

        credential = stored;
        return true;
    }

    public bool TryAuthorizeMessage(string authenticatedSourceId, string targetDeviceId, string nonce, DateTimeOffset timestamp, DateTimeOffset now)
    {
        lock (_gate)
        {
            // SignalingProtocol allows one minute of clock skew in either direction.
            // Keep the same window below; a slightly faster paired PC is not a replay.
            foreach (var expired in _seenNonces.Where(pair => now - pair.Value > TimeSpan.FromMinutes(2)).Select(pair => pair.Key).ToArray())
            {
                _seenNonces.Remove(expired);
            }

            if (!_devices.TryGetValue(authenticatedSourceId, out var source) || source.IsRevoked ||
                !_devices.TryGetValue(targetDeviceId, out var target) || target.IsRevoked ||
                (now - timestamp).Duration() > TimeSpan.FromMinutes(1) || string.IsNullOrWhiteSpace(nonce) || _seenNonces.Count >= MaximumNonceEntries)
            {
                return false;
            }

            var key = $"{authenticatedSourceId}:{nonce}";
            if (_seenNonces.ContainsKey(key))
            {
                return false;
            }

            _seenNonces.Add(key, now);
            return true;
        }
    }

    public bool Revoke(string deviceId)
    {
        if (string.IsNullOrWhiteSpace(deviceId))
        {
            return false;
        }

        lock (_gate)
        {
            if (!_devices.TryGetValue(deviceId, out var credential))
            {
                return false;
            }

            credential.IsRevoked = true;
            return true;
        }
    }

    private static bool CryptographicTokenEquals(string left, string right)
    {
        var leftInput = System.Text.Encoding.UTF8.GetBytes(left);
        var rightInput = System.Text.Encoding.UTF8.GetBytes(right);
        var leftBytes = System.Security.Cryptography.SHA256.HashData(leftInput);
        var rightBytes = System.Security.Cryptography.SHA256.HashData(rightInput);
        try
        {
            return System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(leftBytes, rightBytes);
        }
        finally
        {
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(leftBytes);
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(rightBytes);
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(leftInput);
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(rightInput);
        }
    }
}

public sealed class DeviceCredential(string deviceId, string bearerToken, byte[] publicKey)
{
    public string DeviceId { get; } = deviceId;
    public string BearerToken { get; } = bearerToken;
    private readonly byte[] _publicKey = publicKey.ToArray();
    public byte[] PublicKey => _publicKey.ToArray();
    public bool IsRevoked { get; set; }
}
