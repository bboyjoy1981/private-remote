using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using PrivateRemote.Protocol;

namespace PrivateRemote.Client;

public sealed record PairingDocument(int Version, string Kind, Guid InvitationId, Guid RequestId,
    string SourceDeviceId, string TargetDeviceId, string PublicKeyBase64, string DisplayName,
    SessionCapability Capabilities, long ExpiresUnixSeconds, string Token, string Proof, string Signature);

/// <summary>Offline signed invitation/request/receipt exchange. Private keys never leave this device.</summary>
public sealed class PairingExchange(DeviceStore store, DeviceIdentity identity)
{
    private PairingInvitation? _invitation;
    private PairingDocument? _invitationDocument;
    private readonly Dictionary<Guid, PendingRequest> _pending = [];
    public const int MaximumDocumentBytes = 16 * 1024;

    public PairingDocument ExportInvitation(PairingInvitation invitation, DateTimeOffset now)
    {
        if (invitation.Token.Length != 43 || now >= invitation.ExpiresAt) throw new UnauthorizedAccessException("邀请已失效，请重新生成。");
        if (ReferenceEquals(_invitation, invitation)) return _invitationDocument!;
        _invitation = invitation;
        _invitationDocument = Sign(new(1, "invitation", Guid.NewGuid(), Guid.Empty, identity.DeviceId, "", Convert.ToBase64String(identity.PublicKey),
            Environment.MachineName, SessionCapability.None, invitation.ExpiresAt.ToUnixTimeSeconds(), invitation.Token, "", ""));
        return _invitationDocument;
    }

    public PairingDocument CreateRequest(PairingDocument invitation, SessionCapability capabilities, DateTimeOffset now, bool localConfirmed)
    {
        Validate(invitation, now);
        if (!localConfirmed) throw new UnauthorizedAccessException("需要在本机批准配对。");
        if (invitation.Kind != "invitation" || invitation.Token.Length != 43 || invitation.TargetDeviceId != "" || invitation.RequestId != Guid.Empty || invitation.Proof != "" || invitation.Capabilities != SessionCapability.None)
            throw new InvalidDataException("不是有效的配对邀请。");
        _ = new PairedDevice(invitation.SourceDeviceId, Convert.FromBase64String(invitation.PublicKeyBase64), invitation.DisplayName, capabilities);
        Prune(now);
        if (_pending.Count >= 8) throw new InvalidOperationException("待完成配对过多，请等待邀请过期。");
        var request = new PairingDocument(1, "request", invitation.InvitationId, Guid.NewGuid(), identity.DeviceId, invitation.SourceDeviceId,
            Convert.ToBase64String(identity.PublicKey), Environment.MachineName, capabilities, invitation.ExpiresUnixSeconds, "", "", "");
        request = Sign(request with { Proof = Proof(request, invitation.Token) });
        _pending.Add(request.RequestId, new(invitation, capabilities));
        return request;
    }

    public PairedDevice InspectRequest(PairingDocument request, DateTimeOffset now)
    {
        Validate(request, now);
        var invitation = _invitationDocument;
        if (request.Kind != "request" || request.RequestId == Guid.Empty || request.Token != "" || request.TargetDeviceId != identity.DeviceId ||
            invitation is null || _invitation?.Token.Length != 43 || request.InvitationId != invitation.InvitationId || request.ExpiresUnixSeconds != invitation.ExpiresUnixSeconds ||
            !VerifyProof(request, _invitation.Token)) throw new UnauthorizedAccessException("申请与本机邀请不匹配或邀请已使用。");
        return new(request.SourceDeviceId, Convert.FromBase64String(request.PublicKeyBase64), request.DisplayName, request.Capabilities);
    }

    public PairingDocument ApproveRequest(PairingDocument request, DateTimeOffset now, bool localConfirmed)
    {
        var peer = InspectRequest(request, now);
        if (!localConfirmed) throw new UnauthorizedAccessException("需要在本机批准配对。");
        var token = _invitation!.Token;
        var receipt = new PairingDocument(1, "receipt", request.InvitationId, request.RequestId, identity.DeviceId, request.SourceDeviceId,
            Convert.ToBase64String(identity.PublicKey), Environment.MachineName, request.Capabilities, request.ExpiresUnixSeconds, "", "", "");
        receipt = Sign(receipt with { Proof = Proof(receipt, token) });
        new PairingApproval(store).Approve(_invitation, token, now, peer.DeviceId, peer.PublicKey, peer.DisplayName, peer.Capabilities, true);
        return receipt;
    }

    public PairedDevice CompleteReceipt(PairingDocument receipt, DateTimeOffset now)
    {
        Validate(receipt, now); Prune(now);
        if (receipt.Kind != "receipt" || receipt.Token != "" || receipt.TargetDeviceId != identity.DeviceId || !_pending.TryGetValue(receipt.RequestId, out var pending) ||
            receipt.InvitationId != pending.Invitation.InvitationId || receipt.SourceDeviceId != pending.Invitation.SourceDeviceId ||
            receipt.PublicKeyBase64 != pending.Invitation.PublicKeyBase64 || receipt.Capabilities != pending.Capabilities || receipt.ExpiresUnixSeconds != pending.Invitation.ExpiresUnixSeconds ||
            !VerifyProof(receipt, pending.Invitation.Token)) throw new UnauthorizedAccessException("回执不匹配、已使用或申请已过期。");
        var peer = new PairedDevice(receipt.SourceDeviceId, Convert.FromBase64String(receipt.PublicKeyBase64), receipt.DisplayName, receipt.Capabilities);
        store.SaveApprovedDevice(peer); _pending.Remove(receipt.RequestId); return peer;
    }

    public static byte[] Serialize(PairingDocument document) => JsonSerializer.SerializeToUtf8Bytes(document);
    public static PairingDocument Parse(byte[] bytes, DateTimeOffset now)
    {
        if (bytes.Length > MaximumDocumentBytes) throw new InvalidDataException("配对文件过大。");
        var document = JsonSerializer.Deserialize<PairingDocument>(bytes) ?? throw new InvalidDataException("配对文件为空。");
        Validate(document, now); return document;
    }
    private PairingDocument Sign(PairingDocument document) => document with { Signature = Convert.ToBase64String(identity.Sign(Serialize(document with { Signature = "" }))) };
    private static string Proof(PairingDocument document, string token)
        => Convert.ToBase64String(HMACSHA256.HashData(Encoding.ASCII.GetBytes(token), Serialize(document with { Proof = "", Signature = "" })));
    private static bool VerifyProof(PairingDocument document, string token)
    {
        try { return CryptographicOperations.FixedTimeEquals(Convert.FromBase64String(document.Proof), Convert.FromBase64String(Proof(document, token))); }
        catch (FormatException) { return false; }
    }
    private static void Validate(PairingDocument document, DateTimeOffset now)
    {
        if (document.Version != 1 || document.Kind is not ("invitation" or "request" or "receipt") || document.InvitationId == Guid.Empty ||
            document.SourceDeviceId == null || document.TargetDeviceId == null || document.PublicKeyBase64 == null || document.Token == null || document.Proof == null || document.Signature == null ||
            string.IsNullOrWhiteSpace(document.DisplayName) || document.DisplayName.Length > 64 || document.DisplayName.Any(char.IsControl) ||
            document.ExpiresUnixSeconds <= now.ToUnixTimeSeconds() || document.ExpiresUnixSeconds > now.AddMinutes(5).ToUnixTimeSeconds() || Serialize(document).Length > MaximumDocumentBytes)
            throw new InvalidDataException("配对文件格式或有效期无效。");
        var publicKey = Convert.FromBase64String(document.PublicKeyBase64);
        if (document.SourceDeviceId != DeviceIdentity.GetDeviceId(publicKey) || !DeviceIdentity.Verify(publicKey, Serialize(document with { Signature = "" }), Convert.FromBase64String(document.Signature)))
            throw new UnauthorizedAccessException("配对文件签名与设备身份不匹配。");
    }
    private void Prune(DateTimeOffset now)
    {
        foreach (var id in _pending.Where(entry => entry.Value.Invitation.ExpiresUnixSeconds <= now.ToUnixTimeSeconds()).Select(entry => entry.Key).ToArray()) _pending.Remove(id);
    }
    private sealed record PendingRequest(PairingDocument Invitation, SessionCapability Capabilities);
}
