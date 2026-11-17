using System.Windows.Media.Imaging;
using System.IO;
using PrivateRemote.Client;
using PrivateRemote.Protocol;
using PrivateRemote.Transport;

if (args.Contains("--lan-smoke"))
{
    var directory = Path.Combine(Path.GetTempPath(), "pr-lan-smoke-" + Guid.NewGuid().ToString("N"));
    try
    {
        using var local = DeviceIdentity.Create(); using var remote = DeviceIdentity.Create();
        var paired = new PairedDevice(remote.DeviceId, remote.PublicKey, "remote", SessionCapability.ScreenControl);
        string savedToken, savedPin;
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        await using (var service = await LanSignalingService.StartAsync(local, paired, timeout.Token, directory, System.Net.IPAddress.Loopback, 0))
        {
            savedToken = service.LocalToken; savedPin = service.CertificateSha256;
            var peerSettings = service.CreatePeerSettings(remote.DeviceId, "192.168.1.2");
            await using var client = new SignalingClient();
            await client.ConnectAsync(new Uri(service.LocalEndpoint), remote.DeviceId, peerSettings.BearerToken, timeout.Token, savedPin);
            service.Revoke(remote.DeviceId);
            try { await client.ReceiveAsync(timeout.Token); throw new InvalidOperationException("Revoked peer socket stayed open."); }
            catch (System.Net.WebSockets.WebSocketException) { }
        }
        await using (var restored = await LanSignalingService.StartAsync(local, paired, timeout.Token, directory, System.Net.IPAddress.Loopback, 0))
        {
            if (restored.LocalToken != savedToken || restored.CertificateSha256 != savedPin) throw new InvalidOperationException("Protected LAN state changed across restart.");
            await using var client = new SignalingClient();
            await client.ConnectAsync(new Uri(restored.LocalEndpoint), local.DeviceId, restored.LocalToken, timeout.Token, savedPin);
        }
        Console.WriteLine("PASS LAN service: WSS pin, protected state restart, credential revocation");
        return 0;
    }
    finally { if (Directory.Exists(directory)) Directory.Delete(directory, true); }
}

// Captures three transient frames; saves no desktop content and injects no input.
try
{
    var capture = new GdiJpegFrameSource();
    for (var index = 0; index < 3; index++)
    {
        var bytes = await Task.Run(() => capture.CaptureAsync(CancellationToken.None));
        JpegFrameBounds.Validate(bytes);
        using var stream = new MemoryStream(bytes, writable: false);
        var decoded = BitmapFrame.Create(stream, BitmapCreateOptions.None, BitmapCacheOption.OnLoad);
        if (decoded.PixelWidth is < 1 or > 1600 || decoded.PixelHeight is < 1 or > 900) throw new InvalidDataException("Capture dimensions exceeded bounds.");
        Console.WriteLine($"PASS capture/decode {index + 1}: {decoded.PixelWidth}x{decoded.PixelHeight}, {bytes.Length} bytes");
    }
    return 0;
}
catch (Exception exception) when (exception is UnauthorizedAccessException or System.ComponentModel.Win32Exception { NativeErrorCode: 5 })
{
    Console.WriteLine($"SKIP interactive desktop unavailable: {exception.Message}");
    return 2;
}
