using System.Collections.Concurrent;
using System.Net.WebSockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using PrivateRemote.Transport;
using System.Security.Cryptography.X509Certificates;
using System.Net;

namespace PrivateRemote.Relay;

public static class RelayServer
{
    private const int MaximumMessageBytes = 64 * 1024;

    public static WebApplication Build(string[] args, X509Certificate2? certificate = null, IPAddress? listenAddress = null, int port = 5443)
    {
        var builder = WebApplication.CreateBuilder(args);
        if (certificate is not null) builder.WebHost.ConfigureKestrel(options => options.Listen(listenAddress ?? IPAddress.Loopback, port, listen => listen.UseHttps(certificate)));
        builder.Services.AddSingleton<AccessPolicy>();
        builder.Services.AddSingleton<ConnectedDevices>();
        var app = builder.Build();
        if (!app.Environment.IsDevelopment())
        {
            throw new InvalidOperationException("Production device enrollment, persistence, and TURN credential issuance are not implemented; refusing to start an incomplete public signaling service.");
        }
        ConfigureDevelopmentCredentials(app.Services.GetRequiredService<AccessPolicy>(), app.Configuration);
        app.UseWebSockets(new WebSocketOptions { KeepAliveInterval = TimeSpan.FromSeconds(20) });
        app.MapGet("/health", () => Results.Ok(new { status = "healthy" }));
        app.MapGet("/peer-status/{peerId}", (string peerId, HttpContext context) =>
        {
            var authorization = context.Request.Headers.Authorization.ToString();
            var source = context.Request.Headers["X-Device-Id"].ToString();
            if (!authorization.StartsWith("Bearer ", StringComparison.Ordinal) || !context.RequestServices.GetRequiredService<AccessPolicy>().TryAuthenticate(source, authorization[7..], out _))
                return Results.Unauthorized();
            var online = context.RequestServices.GetRequiredService<ConnectedDevices>().TryGet(peerId, out var connection) && connection.Socket.State == WebSocketState.Open;
            return Results.Ok(online);
        });
        app.MapPost("/admin/devices/{deviceId}/revoke", (string deviceId, HttpContext context, IConfiguration configuration) =>
        {
            var configuredToken = configuration["RelayAdmin:BearerToken"];
            var supplied = context.Request.Headers.Authorization.ToString();
            if (string.IsNullOrWhiteSpace(configuredToken) || !FixedTimeEquals(supplied, $"Bearer {configuredToken}"))
            {
                return Results.Unauthorized();
            }

            var policy = context.RequestServices.GetRequiredService<AccessPolicy>();
            var revoked = policy.Revoke(deviceId);
            if (revoked)
            {
                context.RequestServices.GetRequiredService<ConnectedDevices>().Revoke(deviceId);
            }

            return revoked ? Results.NoContent() : Results.NotFound();
        });
        app.Map("/signal", HandleSignalAsync);
        return app;
    }

    private static bool FixedTimeEquals(string left, string right)
    {
        var leftBytes = Encoding.UTF8.GetBytes(left);
        var rightBytes = Encoding.UTF8.GetBytes(right);
        try
        {
            return CryptographicOperations.FixedTimeEquals(SHA256.HashData(leftBytes), SHA256.HashData(rightBytes));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(leftBytes);
            CryptographicOperations.ZeroMemory(rightBytes);
        }
    }

    private static void ConfigureDevelopmentCredentials(AccessPolicy policy, IConfiguration configuration)
    {
        var sections = configuration.GetSection("DevelopmentDevices").GetChildren().ToList();
        var legacy = configuration.GetSection("DevelopmentDevice");
        if (legacy.Exists())
        {
            sections.Add(legacy);
        }

        foreach (var section in sections)
        {
            var deviceId = section["DeviceId"];
            var bearerToken = section["BearerToken"];
            var publicKeyText = section["PublicKeyBase64"];
            if (string.IsNullOrWhiteSpace(deviceId) || string.IsNullOrWhiteSpace(bearerToken) || string.IsNullOrWhiteSpace(publicKeyText))
            {
                throw new InvalidOperationException($"{section.Path} requires DeviceId, BearerToken, and PublicKeyBase64.");
            }

            try
            {
                var publicKey = Convert.FromBase64String(publicKeyText);
                var actualDeviceId = PrivateRemote.Protocol.DeviceIdentity.GetDeviceId(publicKey);
                if (!StringComparer.Ordinal.Equals(actualDeviceId, deviceId))
                {
                    throw new InvalidOperationException("The development device ID must match its public-key fingerprint.");
                }

                if (!policy.TryRegister(new DeviceCredential(deviceId, bearerToken, publicKey)))
                {
                    throw new InvalidOperationException("The development device is duplicated.");
                }
            }
            catch (Exception exception) when (exception is FormatException or CryptographicException)
            {
                throw new InvalidOperationException($"{section.Path}:PublicKeyBase64 is invalid.", exception);
            }
        }
    }

    private static async Task HandleSignalAsync(HttpContext context)
    {
        if (!context.WebSockets.IsWebSocketRequest || !context.Request.Headers.TryGetValue("X-Device-Id", out var deviceIdValues))
        {
            context.Response.StatusCode = StatusCodes.Status400BadRequest;
            return;
        }

        var deviceId = deviceIdValues.ToString();
        var bearer = context.Request.Headers.Authorization.ToString();
        if (!bearer.StartsWith("Bearer ", StringComparison.Ordinal) ||
            !context.RequestServices.GetRequiredService<AccessPolicy>().TryAuthenticate(deviceId, bearer[7..], out _))
        {
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            return;
        }

        using var socket = await context.WebSockets.AcceptWebSocketAsync().ConfigureAwait(false);
        var connected = context.RequestServices.GetRequiredService<ConnectedDevices>();
        var connection = connected.Add(deviceId, socket);
        var policy = context.RequestServices.GetRequiredService<AccessPolicy>();
        // Revocation can race with the await above: the admin endpoint might revoke the
        // device before it appears in ConnectedDevices. Recheck after registration so
        // that a connection cannot remain idle and open after that revoke completed.
        if (!policy.TryAuthenticate(deviceId, bearer[7..], out _))
        {
            connected.Revoke(deviceId);
            return;
        }

        var buffer = new byte[MaximumMessageBytes];
        try
        {
            while (socket.State == WebSocketState.Open && !context.RequestAborted.IsCancellationRequested)
            {
                using var message = new MemoryStream();
                WebSocketReceiveResult result;
                do
                {
                    result = await socket.ReceiveAsync(buffer, context.RequestAborted).ConfigureAwait(false);
                    if (result.MessageType == WebSocketMessageType.Close)
                    {
                        await socket.CloseOutputAsync(WebSocketCloseStatus.NormalClosure, "closed", CancellationToken.None).ConfigureAwait(false);
                        return;
                    }

                    if (result.MessageType != WebSocketMessageType.Text || message.Length + result.Count > MaximumMessageBytes)
                    {
                        await socket.CloseAsync(WebSocketCloseStatus.MessageTooBig, "invalid-message", CancellationToken.None).ConfigureAwait(false);
                        return;
                    }

                    message.Write(buffer, 0, result.Count);
                } while (!result.EndOfMessage);
                connected.Trace(deviceId, "收到消息，字节=" + message.Length);

                SignalingEnvelope envelope;
                try
                {
                    envelope = JsonSerializer.Deserialize<SignalingEnvelope>(message.ToArray())
                        ?? throw new InvalidDataException("Empty message.");
                    SignalingProtocol.Validate(envelope, DateTimeOffset.UtcNow);
                }
                catch (Exception exception) when (exception is JsonException or InvalidDataException or ArgumentOutOfRangeException)
                {
                    connected.Trace(deviceId, "格式拒绝：" + exception.Message);
                    await socket.CloseAsync(WebSocketCloseStatus.InvalidPayloadData, "invalid-message", CancellationToken.None).ConfigureAwait(false);
                    return;
                }

                DeviceCredential? credential = null;
                var authenticatedAndSigned = StringComparer.Ordinal.Equals(envelope.SourceDeviceId, deviceId) &&
                                             policy.TryAuthenticate(deviceId, bearer[7..], out credential) &&
                                             credential is not null &&
                                             SignalingProtocol.Verify(envelope, credential.PublicKey, DateTimeOffset.UtcNow);
                if (!authenticatedAndSigned ||
                    !policy.TryAuthorizeMessage(deviceId, envelope.TargetDeviceId, envelope.Nonce, DateTimeOffset.FromUnixTimeSeconds(envelope.TimestampUnixSeconds), DateTimeOffset.UtcNow))
                {
                    connected.Trace(deviceId, "身份、时间或重放校验拒绝");
                    await socket.CloseAsync(WebSocketCloseStatus.PolicyViolation, "device-not-authorized", CancellationToken.None).ConfigureAwait(false);
                    return;
                }

                var json = JsonSerializer.SerializeToUtf8Bytes(envelope);
                try
                {
                    if (!connected.TryGet(envelope.TargetDeviceId, out var target) || target.Socket.State != WebSocketState.Open)
                    {
                        connected.Trace(deviceId, "目标不在线：" + envelope.MessageType);
                        continue;
                    }

                    await target.SendAsync(json, context.RequestAborted).ConfigureAwait(false);
                    connected.Trace(deviceId, "已转发 " + envelope.MessageType + " 到 " + envelope.TargetDeviceId[..12]);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(json);
                }
            }
        }
        catch (OperationCanceledException)
        {
        }
        catch (WebSocketException)
        {
        }
        finally
        {
            CryptographicOperations.ZeroMemory(buffer);
            connected.Remove(deviceId, connection);
        }
    }
}

public sealed class ConnectedDevices
{
    private readonly ConcurrentQueue<string> _trace = new();
    public void Trace(string deviceId, string message)
    {
        _trace.Enqueue($"{DateTimeOffset.UtcNow:HH:mm:ss.fff} {deviceId[..Math.Min(12, deviceId.Length)]} {message}");
        while (_trace.Count > 32) _trace.TryDequeue(out _);
    }
    public string Diagnostics => string.Join("\n", _trace.ToArray());
    private readonly ConcurrentDictionary<string, DeviceConnection> _sockets = new(StringComparer.Ordinal);

    public DeviceConnection Add(string deviceId, WebSocket socket)
    {
        Trace(deviceId, "信令接入");
        var connection = new DeviceConnection(socket);
        _sockets.AddOrUpdate(deviceId, connection, (_, existing) =>
        {
            existing.Close();
            return connection;
        });
        return connection;
    }

    public bool TryGet(string deviceId, out DeviceConnection connection) => _sockets.TryGetValue(deviceId, out connection!);

    public void Revoke(string deviceId)
    {
        if (_sockets.TryRemove(deviceId, out var connection))
        {
            connection.Close(WebSocketCloseStatus.PolicyViolation, "device-revoked");
        }
    }

    public void Remove(string deviceId, DeviceConnection connection)
    {
        if (_sockets.TryGetValue(deviceId, out var current) && ReferenceEquals(current, connection))
        {
            _sockets.TryRemove(new KeyValuePair<string, DeviceConnection>(deviceId, connection));
        }
    }
}

public sealed class DeviceConnection(WebSocket socket)
{
    private readonly SemaphoreSlim _sendLock = new(1, 1);
    public WebSocket Socket { get; } = socket;

    public async Task SendAsync(byte[] message, CancellationToken cancellationToken)
    {
        await _sendLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (Socket.State == WebSocketState.Open)
            {
                await Socket.SendAsync(message, WebSocketMessageType.Text, true, cancellationToken).ConfigureAwait(false);
            }
        }
        finally
        {
            _sendLock.Release();
        }
    }

    public void Close(WebSocketCloseStatus status = WebSocketCloseStatus.NormalClosure, string description = "replaced")
    {
        if (Socket.State == WebSocketState.Open)
        {
            _ = CloseAsync(status, description);
        }
    }

    private async Task CloseAsync(WebSocketCloseStatus status, string description)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(2));
        var acquired = false;
        try
        {
            await _sendLock.WaitAsync(timeout.Token).ConfigureAwait(false);
            acquired = true;
            if (Socket.State == WebSocketState.Open)
            {
                // Receive is owned by HandleSignalAsync; closing must not start a second receive.
                await Socket.CloseOutputAsync(status, description, timeout.Token).ConfigureAwait(false);
                Socket.Abort();
            }
        }
        catch (OperationCanceledException)
        {
            Socket.Abort();
        }
        catch (WebSocketException)
        {
            Socket.Abort();
        }
        catch (ObjectDisposedException)
        {
        }
        finally
        {
            if (acquired)
            {
                _sendLock.Release();
            }
        }
    }
}
