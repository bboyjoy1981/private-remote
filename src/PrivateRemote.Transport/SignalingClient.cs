using System.Net.WebSockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace PrivateRemote.Transport;

public sealed class SignalingClient : IAsyncDisposable
{
    private readonly ClientWebSocket _socket = new();
    private readonly SemaphoreSlim _sendGate = new(1, 1);
    private int _disposeStarted;
    private Uri? _endpoint;
    private string? _deviceId, _bearerToken, _certificatePin;

    public async Task ConnectAsync(Uri endpoint, string deviceId, string bearerToken, CancellationToken cancellationToken, string? certificateSha256 = null)
    {
        ValidateEndpoint(endpoint);
        ArgumentException.ThrowIfNullOrWhiteSpace(deviceId);
        ArgumentException.ThrowIfNullOrWhiteSpace(bearerToken);
        if (!string.IsNullOrWhiteSpace(certificateSha256))
        {
            if (endpoint.Scheme != "wss" || certificateSha256.Length != 64 || !certificateSha256.All(Uri.IsHexDigit))
                throw new ArgumentException("A TLS certificate pin must be 64 hexadecimal characters and use WSS.");
            var pin = Convert.FromHexString(certificateSha256);
            _socket.Options.RemoteCertificateValidationCallback = (_, certificate, _, _) =>
            {
                if (certificate is null) return false;
                using var parsed = new System.Security.Cryptography.X509Certificates.X509Certificate2(certificate);
                return DateTime.UtcNow >= parsed.NotBefore.ToUniversalTime() && DateTime.UtcNow <= parsed.NotAfter.ToUniversalTime() &&
                    CryptographicOperations.FixedTimeEquals(SHA256.HashData(parsed.RawData), pin);
            };
        }

        _socket.Options.SetRequestHeader("Authorization", $"Bearer {bearerToken}");
        _socket.Options.SetRequestHeader("X-Device-Id", deviceId);
        await _socket.ConnectAsync(endpoint, cancellationToken).ConfigureAwait(false);
        _endpoint = endpoint; _deviceId = deviceId; _bearerToken = bearerToken; _certificatePin = certificateSha256;
    }
    public async Task<bool?> IsPeerOnlineAsync(string peerId, CancellationToken token)
    {
        if (_endpoint is null) throw new InvalidOperationException("Signaling is not connected.");
        if (peerId.Length != 64 || !peerId.All(Uri.IsHexDigit)) throw new ArgumentException("Invalid peer identity.");
        using var handler = new System.Net.Http.HttpClientHandler();
        if (!string.IsNullOrWhiteSpace(_certificatePin))
        {
            var pin = Convert.FromHexString(_certificatePin);
            handler.ServerCertificateCustomValidationCallback = (_, cert, _, _) => cert is not null && DateTime.UtcNow >= cert.NotBefore.ToUniversalTime() && DateTime.UtcNow <= cert.NotAfter.ToUniversalTime() && CryptographicOperations.FixedTimeEquals(SHA256.HashData(cert.RawData), pin);
        }
        using var client = new System.Net.Http.HttpClient(handler);
        client.DefaultRequestHeaders.Authorization = new("Bearer", _bearerToken);
        client.DefaultRequestHeaders.Add("X-Device-Id", _deviceId);
        var uri = new UriBuilder(_endpoint) { Scheme = _endpoint.Scheme == "wss" ? "https" : "http", Path = "/peer-status/" + peerId, Query = "" }.Uri;
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(token); deadline.CancelAfter(TimeSpan.FromSeconds(5));
        using var response = await client.GetAsync(uri, deadline.Token).ConfigureAwait(false);
        if (response.StatusCode == System.Net.HttpStatusCode.NotFound) return null; // Older compatible relay.
        response.EnsureSuccessStatusCode();
        var content = await response.Content.ReadAsStringAsync(deadline.Token).ConfigureAwait(false);
        return JsonSerializer.Deserialize<bool>(content);
    }

    public static void ValidateEndpoint(Uri endpoint)
    {
        ArgumentNullException.ThrowIfNull(endpoint);
        if (!endpoint.IsAbsoluteUri || endpoint.Scheme != "wss" && !(endpoint.Scheme == "ws" && endpoint.IsLoopback))
        {
            throw new ArgumentException("Signaling must use WSS; plaintext WebSocket is allowed only on loopback for development.", nameof(endpoint));
        }
    }

    public async Task SendAsync(SignalingEnvelope envelope, CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposeStarted) != 0, this);
        if (_socket.State != WebSocketState.Open)
        {
            throw new InvalidOperationException("The signaling connection is not open.");
        }

        var bytes = JsonSerializer.SerializeToUtf8Bytes(envelope);
        if (bytes.Length > 64 * 1024)
        {
            CryptographicOperations.ZeroMemory(bytes);
            throw new InvalidDataException("The signaling message exceeds the allowed size.");
        }

        try
        {
            await _sendGate.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposeStarted) != 0, this);
                if (_socket.State != WebSocketState.Open)
                {
                    throw new InvalidOperationException("The signaling connection is not open.");
                }

                await _socket.SendAsync(bytes, WebSocketMessageType.Text, endOfMessage: true, cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                _sendGate.Release();
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }

    public async Task<VerifiedSignalingMessage> ReceiveAuthenticatedAsync(AuthenticatedSignalingInbox inbox, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(inbox);
        var envelope = await ReceiveAsync(cancellationToken).ConfigureAwait(false);
        return inbox.Accept(envelope, DateTimeOffset.UtcNow);
    }

    public async Task<SignalingEnvelope> ReceiveAsync(CancellationToken cancellationToken)
    {
        var buffer = new byte[64 * 1024];
        using var message = new MemoryStream();
        try
        {
            WebSocketReceiveResult result;
            do
            {
                result = await _socket.ReceiveAsync(buffer, cancellationToken).ConfigureAwait(false);
                if (result.MessageType == WebSocketMessageType.Close)
                {
                    throw new WebSocketException("The signaling server closed the connection.");
                }

                if (result.MessageType != WebSocketMessageType.Text || message.Length + result.Count > buffer.Length)
                {
                    throw new InvalidDataException("The signaling message is invalid or too large.");
                }

                message.Write(buffer, 0, result.Count);
            } while (!result.EndOfMessage);

            var envelope = JsonSerializer.Deserialize<SignalingEnvelope>(message.ToArray())
                ?? throw new InvalidDataException("The signaling message is empty.");
            SignalingProtocol.Validate(envelope, DateTimeOffset.UtcNow);
            return envelope;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(buffer);
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposeStarted, 1) != 0)
        {
            return;
        }

        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(2));
        var acquired = false;
        try
        {
            await _sendGate.WaitAsync(timeout.Token).ConfigureAwait(false);
            acquired = true;
            if (_socket.State == WebSocketState.Open)
            {
                await _socket.CloseOutputAsync(WebSocketCloseStatus.NormalClosure, "closed", timeout.Token).ConfigureAwait(false);
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
            _socket.Abort();
            _socket.Dispose();
            if (acquired)
            {
                _sendGate.Release();
            }
        }
    }
}
