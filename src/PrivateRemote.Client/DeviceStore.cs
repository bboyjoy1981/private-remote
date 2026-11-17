using System.Security.Cryptography;
using System.Text.Json;
using PrivateRemote.Protocol;

namespace PrivateRemote.Client;

public sealed class DeviceStore
{
    private readonly string _directory;
    private readonly string _identityPath;
    private readonly string _pairedDevicesPath;
    private readonly object _gate = new();

    public DeviceStore(string? directory = null)
    {
        _directory = directory ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "PrivateRemote");
        _identityPath = Path.Combine(_directory, "identity.dpapi");
        _pairedDevicesPath = Path.Combine(_directory, "paired-devices.json");
    }

    public DeviceIdentity LoadOrCreateIdentity()
    {
        lock (_gate)
        {
            Directory.CreateDirectory(_directory);
            if (File.Exists(_identityPath))
            {
                return DeviceIdentity.FromProtectedPrivateKey(File.ReadAllBytes(_identityPath));
            }

            var identity = DeviceIdentity.Create();
            try
            {
                SaveBytesAtomically(_identityPath, identity.ExportProtectedPrivateKey());
                return identity;
            }
            catch
            {
                identity.Dispose();
                throw;
            }
        }
    }

    public IReadOnlyList<StoredPairedDevice> LoadPairedDevices()
    {
        lock (_gate)
        {
            if (!File.Exists(_pairedDevicesPath))
            {
                return Array.Empty<StoredPairedDevice>();
            }

            var devices = JsonSerializer.Deserialize<List<StoredPairedDevice>>(File.ReadAllBytes(_pairedDevicesPath)) ?? [];
            foreach (var device in devices)
            {
                if (!StringComparer.Ordinal.Equals(DeviceIdentity.GetDeviceId(device.PublicKey), device.DeviceId))
                {
                    throw new InvalidDataException("The paired-device store contains an invalid identity fingerprint.");
                }
            }

            return devices.AsReadOnly();
        }
    }

    public void SaveApprovedDevice(PairedDevice device)
    {
        ArgumentNullException.ThrowIfNull(device);
        lock (_gate)
        {
            var devices = File.Exists(_pairedDevicesPath)
                ? JsonSerializer.Deserialize<List<StoredPairedDevice>>(File.ReadAllBytes(_pairedDevicesPath)) ?? []
                : [];
            var existingIndex = devices.FindIndex(existing => StringComparer.Ordinal.Equals(existing.DeviceId, device.DeviceId));
            if (existingIndex >= 0 && !devices[existingIndex].IsRevoked)
            {
                throw new InvalidOperationException("This device is already stored.");
            }

            var approved = new StoredPairedDevice(device.DeviceId, device.PublicKey, device.DisplayName, device.Capabilities, false);
            if (existingIndex >= 0) devices[existingIndex] = approved;
            else devices.Add(approved);
            SaveBytesAtomically(_pairedDevicesPath, JsonSerializer.SerializeToUtf8Bytes(devices));
        }
    }

    public PairedDevice? FindActivePairing(string deviceId)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(deviceId);
        var stored = LoadPairedDevices().SingleOrDefault(device => device.DeviceId == deviceId);
        return stored is null || stored.IsRevoked
            ? null
            : new PairedDevice(stored.DeviceId, stored.PublicKey, stored.DisplayName, stored.Capabilities);
    }

    public bool RenameDevice(string deviceId, string displayName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(deviceId);
        ArgumentException.ThrowIfNullOrWhiteSpace(displayName);
        var normalizedName = displayName.Trim();
        if (normalizedName.Length > 64)
        {
            throw new ArgumentOutOfRangeException(nameof(displayName), "Device names must be 64 characters or fewer.");
        }

        lock (_gate)
        {
            if (!File.Exists(_pairedDevicesPath))
            {
                return false;
            }

            var devices = JsonSerializer.Deserialize<List<StoredPairedDevice>>(File.ReadAllBytes(_pairedDevicesPath)) ?? [];
            var index = devices.FindIndex(device => StringComparer.Ordinal.Equals(device.DeviceId, deviceId));
            if (index < 0)
            {
                return false;
            }

            devices[index] = devices[index] with { DisplayName = normalizedName };
            SaveBytesAtomically(_pairedDevicesPath, JsonSerializer.SerializeToUtf8Bytes(devices));
            return true;
        }
    }

    public bool RevokeDevice(string deviceId)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(deviceId);
        lock (_gate)
        {
            if (!File.Exists(_pairedDevicesPath))
            {
                return false;
            }

            var devices = JsonSerializer.Deserialize<List<StoredPairedDevice>>(File.ReadAllBytes(_pairedDevicesPath)) ?? [];
            var index = devices.FindIndex(device => StringComparer.Ordinal.Equals(device.DeviceId, deviceId));
            if (index < 0 || devices[index].IsRevoked)
            {
                return false;
            }

            devices[index] = devices[index] with { IsRevoked = true };
            SaveBytesAtomically(_pairedDevicesPath, JsonSerializer.SerializeToUtf8Bytes(devices));
            return true;
        }
    }

    private static void SaveBytesAtomically(string path, byte[] content)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        var temporaryPath = Path.Combine(Path.GetDirectoryName(path)!, $".{Guid.NewGuid():N}.tmp");
        try
        {
            using (var stream = new FileStream(temporaryPath, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough))
            {
                stream.Write(content);
                stream.Flush(flushToDisk: true);
            }

            File.Move(temporaryPath, path, overwrite: true);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(content);
            if (File.Exists(temporaryPath))
            {
                File.Delete(temporaryPath);
            }
        }
    }
}

public sealed record StoredPairedDevice(
    string DeviceId,
    byte[] PublicKey,
    string DisplayName,
    SessionCapability Capabilities,
    bool IsRevoked);
