using System.Windows;
using PrivateRemote.Protocol;

namespace PrivateRemote.Client;

public sealed class PairingView(DeviceStore store)
{
    private readonly DeviceStore _store = store;

    public PairingInvitation CreateInvitation(DateTimeOffset now) => PairingInvitation.Create(now);

    public IReadOnlyList<StoredPairedDevice> ListDevices() => _store.LoadPairedDevices();

    public bool Rename(string deviceId, string displayName) => _store.RenameDevice(deviceId, displayName);

    public bool Revoke(string deviceId) => _store.RevokeDevice(deviceId);

    public bool ConfirmLocally(Window owner, string deviceName, string deviceId, SessionCapability capabilities)
    {
        var result = MessageBox.Show(
            owner,
            $"设备：{deviceName}\n设备 ID：{deviceId}\n申请权限：{capabilities}\n\n确认配对这台设备吗？",
            "批准远程设备配对",
            MessageBoxButton.YesNo,
            MessageBoxImage.Warning,
            MessageBoxResult.No);
        return result == MessageBoxResult.Yes;
    }
}
