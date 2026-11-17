using PrivateRemote.Protocol;

namespace PrivateRemote.Client;

public sealed class PairingApproval(DeviceStore deviceStore)
{
    private readonly DeviceStore _deviceStore = deviceStore ?? throw new ArgumentNullException(nameof(deviceStore));

    public PairedDevice Approve(
        PairingInvitation invitation,
        string submittedToken,
        DateTimeOffset now,
        string peerDeviceId,
        byte[] peerPublicKey,
        string displayName,
        SessionCapability approvedCapabilities,
        bool localUserConfirmed)
    {
        ArgumentNullException.ThrowIfNull(invitation);
        ArgumentNullException.ThrowIfNull(peerPublicKey);
        if (!localUserConfirmed)
        {
            throw new UnauthorizedAccessException("A person at this computer must approve the pairing.");
        }

        // Validate the peer identity and requested grant before consuming the one-time invitation.
        var device = new PairedDevice(peerDeviceId, peerPublicKey, displayName, approvedCapabilities);
        if (!invitation.TryConsume(submittedToken, now))
        {
            throw new UnauthorizedAccessException("The pairing invitation is invalid, expired, or already used.");
        }

        _deviceStore.SaveApprovedDevice(device);
        return device;
    }
}
