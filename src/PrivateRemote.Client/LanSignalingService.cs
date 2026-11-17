using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using PrivateRemote.Protocol;
using PrivateRemote.Relay;

namespace PrivateRemote.Client;

public sealed record LanConnectionSettings(int Version, string DeviceId, string ServiceDeviceId, string PeerDeviceId, string Endpoint, string CertificateSha256, string BearerToken, string Signature);

public sealed class LanSignalingService : IAsyncDisposable
{
    private readonly WebApplication _app;
    private readonly X509Certificate2 _certificate;
    private readonly State _state;
    private readonly string _statePath;
    private readonly string _localId;
    private readonly object _disposeGate = new();
    private Task? _disposal;
    private LanSignalingService(WebApplication app, X509Certificate2 certificate, State state, string statePath, string localId)
    { _app = app; _certificate = certificate; _state = state; _statePath = statePath; _localId = localId; }
    public string CertificateSha256 => Convert.ToHexString(SHA256.HashData(_certificate.RawData));
    public string LocalToken => _state.Tokens[_localId];
    public string Diagnostics => _app.Services.GetRequiredService<ConnectedDevices>().Diagnostics;
    public string LocalEndpoint => $"wss://127.0.0.1:{new Uri(_app.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()!.Addresses.Single()).Port}/signal";
    public string SuggestedAddress => NetworkInterface.GetAllNetworkInterfaces()
        .Where(network => network.OperationalStatus == OperationalStatus.Up && network.NetworkInterfaceType != NetworkInterfaceType.Loopback)
        .SelectMany(network => network.GetIPProperties().UnicastAddresses)
        .Select(address => address.Address).FirstOrDefault(address => address.AddressFamily == AddressFamily.InterNetwork && !IPAddress.IsLoopback(address))?.ToString() ?? "127.0.0.1";

    public static async Task<LanSignalingService> StartAsync(DeviceIdentity identity, PairedDevice peer, CancellationToken token, string? settingsDirectory = null, IPAddress? listenAddress = null, int port = 5443)
    {
        var directory = settingsDirectory ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "PrivateRemote"); Directory.CreateDirectory(directory);
        var path = Path.Combine(directory, "lan-service.dpapi");
        State? state = null;
        if (File.Exists(path))
        {
            var clear = DeviceSecretProtection.Unprotect(File.ReadAllBytes(path));
            try { state = JsonSerializer.Deserialize<State>(clear); }
            finally { CryptographicOperations.ZeroMemory(clear); }
        }
        X509Certificate2 certificate;
        if (state is not null)
        {
            if (state.DeviceId != identity.DeviceId) throw new InvalidDataException("LAN service identity mismatch.");
            var pfx = Convert.FromBase64String(state.CertificatePfx);
            try { certificate = X509CertificateLoader.LoadPkcs12(pfx, null, X509KeyStorageFlags.UserKeySet); }
            finally { CryptographicOperations.ZeroMemory(pfx); }
            if (certificate.NotAfter.ToUniversalTime() <= DateTime.UtcNow) { certificate.Dispose(); throw new InvalidOperationException("本机信令证书已到期，需要更新连接配置。"); }
        }
        else
        {
            using var key = RSA.Create(2048);
            var request = new CertificateRequest("CN=Private Remote LAN", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
            request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new("1.3.6.1.5.5.7.3.1") }, true));
            using var created = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddYears(1));
            var pfx = created.Export(X509ContentType.Pfx);
            try { state = new(identity.DeviceId, Convert.ToBase64String(pfx), []); certificate = X509CertificateLoader.LoadPkcs12(pfx, null, X509KeyStorageFlags.UserKeySet); }
            finally { CryptographicOperations.ZeroMemory(pfx); }
        }
        foreach (var id in new[] { identity.DeviceId, peer.DeviceId }) if (!state.Tokens.ContainsKey(id)) state.Tokens.Add(id, Convert.ToHexString(RandomNumberGenerator.GetBytes(32)));
        Save(path, state);
        var app = RelayServer.Build(["--environment", "Development", "--Logging:LogLevel:Default", "Warning"], certificate, listenAddress ?? IPAddress.Any, port);
        var service = new LanSignalingService(app, certificate, state, path, identity.DeviceId);
        try
        {
            var policy = app.Services.GetRequiredService<AccessPolicy>();
            policy.TryRegister(new(identity.DeviceId, state.Tokens[identity.DeviceId], identity.PublicKey));
            policy.TryRegister(new(peer.DeviceId, state.Tokens[peer.DeviceId], peer.PublicKey));
            await app.StartAsync(token); return service;
        }
        catch { await service.DisposeAsync(); throw; }
    }
    public LanConnectionSettings CreatePeerSettings(string peerId, string address)
    {
        if (!IPAddress.TryParse(address, out var ip) || ip.AddressFamily != AddressFamily.InterNetwork || IPAddress.IsLoopback(ip)) throw new ArgumentException("请填写本机局域网 IPv4 地址。");
        return new(1, peerId, _localId, _localId, $"wss://{ip}:5443/signal", CertificateSha256, _state.Tokens[peerId], "");
    }
    public void Revoke(string peerId)
    {
        _app.Services.GetRequiredService<AccessPolicy>().Revoke(peerId);
        _app.Services.GetRequiredService<ConnectedDevices>().Revoke(peerId);
        _state.Tokens.Remove(peerId); Save(_statePath, _state);
    }
    private static void Save(string path, State state)
    {
        var clear = JsonSerializer.SerializeToUtf8Bytes(state);
        try
        {
            var encrypted = DeviceSecretProtection.Protect(clear); var temporary = path + ".tmp";
            try { File.WriteAllBytes(temporary, encrypted); File.Move(temporary, path, true); }
            finally { if (File.Exists(temporary)) File.Delete(temporary); }
        }
        finally { CryptographicOperations.ZeroMemory(clear); }
    }
    public ValueTask DisposeAsync() { lock (_disposeGate) return new(_disposal ??= DisposeCoreAsync()); }
    private async Task DisposeCoreAsync()
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        try { await _app.StopAsync(timeout.Token); }
        finally { await _app.DisposeAsync(); _certificate.Dispose(); }
    }
    private sealed record State(string DeviceId, string CertificatePfx, Dictionary<string, string> Tokens);
}
