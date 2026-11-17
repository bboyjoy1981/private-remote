using PrivateRemote.Protocol;

namespace PrivateRemote.Transport;

public sealed record PeerConnectRequest(
    string LocalDeviceId,
    string PeerDeviceId,
    SessionCapability Capabilities,
    Uri SignalingEndpoint,
    string SignalingBearerToken)
{
    public void Validate()
    {
        ValidateDeviceId(LocalDeviceId, nameof(LocalDeviceId));
        ValidateDeviceId(PeerDeviceId, nameof(PeerDeviceId));
        if (StringComparer.Ordinal.Equals(LocalDeviceId, PeerDeviceId))
        {
            throw new ArgumentException("A device cannot open a remote session to itself.");
        }

        const SessionCapability allCapabilities = SessionCapability.ScreenControl | SessionCapability.FileTransfer;
        if (Capabilities == SessionCapability.None || (Capabilities & ~allCapabilities) != 0)
        {
            throw new ArgumentOutOfRangeException(nameof(Capabilities));
        }
        SignalingClient.ValidateEndpoint(SignalingEndpoint);

        ArgumentException.ThrowIfNullOrWhiteSpace(SignalingBearerToken);
    }

    private static void ValidateDeviceId(string deviceId, string parameterName)
    {
        if (deviceId is null || deviceId.Length != 64 || deviceId.Any(character => !Uri.IsHexDigit(character)))
        {
            throw new ArgumentException("A device ID must be a 64-character hexadecimal fingerprint.", parameterName);
        }
    }
}

public interface IPeerConnector
{
    Task<IPeerConnection> ConnectAsync(PeerConnectRequest request, PeerRouteKind route, CancellationToken cancellationToken);
}

public interface IPeerConnection : IAsyncDisposable
{
    PeerRouteKind Route { get; }
    string PeerDeviceId { get; }
    bool IsEndToEndEncrypted { get; }
    bool PeerIdentityVerified { get; }
}

public sealed class DirectPeer : IAsyncDisposable
{
    private readonly IPeerConnector _connector;
    private readonly TimeSpan _attemptTimeout;
    private readonly SemaphoreSlim _connectGate = new(1, 1);
    private IPeerConnection? _connection;
    private PeerRouteStatus _status = PeerRouteStatus.Disconnected;

    public DirectPeer(IPeerConnector connector, TimeSpan attemptTimeout)
    {
        _connector = connector ?? throw new ArgumentNullException(nameof(connector));
        if (attemptTimeout <= TimeSpan.Zero || attemptTimeout > TimeSpan.FromMinutes(2))
        {
            throw new ArgumentOutOfRangeException(nameof(attemptTimeout));
        }

        _attemptTimeout = attemptTimeout;
    }

    public PeerRouteStatus Status => _status;

    public event EventHandler<PeerRouteStatus>? StatusChanged;

    public async Task<IPeerConnection> ConnectAsync(PeerConnectRequest request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        request.Validate();
        await _connectGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await DisposeConnectionAsync().ConfigureAwait(false);
            IPeerConnection connection;
            SetStatus(new PeerRouteStatus(PeerConnectionPhase.ConnectingDirect, null, "正在尝试直接连接…"));
            try
            {
                connection = await ConnectOnRouteAsync(request, PeerRouteKind.Direct, cancellationToken).ConfigureAwait(false);
            }
            catch (PeerRouteUnavailableException directFailure)
            {
                if (cancellationToken.IsCancellationRequested)
                {
                    SetStatus(PeerRouteStatus.Disconnected);
                    throw new OperationCanceledException(cancellationToken);
                }

                SetStatus(new PeerRouteStatus(PeerConnectionPhase.ConnectingRelay, null, "直连不可用，正在尝试加密中继…"));
                try
                {
                    connection = await ConnectOnRouteAsync(request, PeerRouteKind.Relay, cancellationToken).ConfigureAwait(false);
                }
                catch (PeerRouteUnavailableException relayFailure)
                {
                    var failure = new PeerConnectionException("直接连接和中继连接均不可用。请检查信令服务、网络及 TURN 配置。", new AggregateException(directFailure, relayFailure));
                    SetStatus(new PeerRouteStatus(PeerConnectionPhase.Failed, null, failure.Message));
                    throw failure;
                }
            }

            _connection = connection;
            SetStatus(new PeerRouteStatus(
                PeerConnectionPhase.Connected,
                connection.Route,
                connection.Route == PeerRouteKind.Direct ? "已通过直连建立加密连接" : "已通过自托管中继建立加密连接"));
            return connection;
        }
        catch (PeerAuthenticationException exception)
        {
            SetStatus(new PeerRouteStatus(PeerConnectionPhase.Failed, null, exception.Message));
            throw;
        }
        catch (OperationCanceledException)
        {
            SetStatus(PeerRouteStatus.Disconnected);
            throw;
        }
        finally
        {
            _connectGate.Release();
        }
    }

    public async Task DisconnectAsync()
    {
        await _connectGate.WaitAsync().ConfigureAwait(false);
        try
        {
            await DisposeConnectionAsync().ConfigureAwait(false);
            SetStatus(PeerRouteStatus.Disconnected);
        }
        finally
        {
            _connectGate.Release();
        }
    }

    public async ValueTask DisposeAsync()
    {
        await DisconnectAsync().ConfigureAwait(false);
        _connectGate.Dispose();
    }

    private async Task<IPeerConnection> ConnectOnRouteAsync(PeerConnectRequest request, PeerRouteKind route, CancellationToken callerToken)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(callerToken);
        timeout.CancelAfter(_attemptTimeout);
        IPeerConnection connection;
        try
        {
            connection = await _connector.ConnectAsync(request, route, timeout.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException exception) when (!callerToken.IsCancellationRequested)
        {
            throw new PeerRouteUnavailableException($"{route} route timed out.", exception);
        }
        catch (TimeoutException exception)
        {
            throw new PeerRouteUnavailableException($"{route} route timed out.", exception);
        }

        if (connection is null)
        {
            throw new PeerRouteUnavailableException($"{route} connector returned no peer connection.");
        }

        if (connection.Route != route || !StringComparer.Ordinal.Equals(connection.PeerDeviceId, request.PeerDeviceId) ||
            !connection.IsEndToEndEncrypted || !connection.PeerIdentityVerified)
        {
            await connection.DisposeAsync().ConfigureAwait(false);
            throw new PeerAuthenticationException("The peer identity or encrypted route could not be verified; the session was rejected.");
        }

        return connection;
    }

    private async Task DisposeConnectionAsync()
    {
        var connection = Interlocked.Exchange(ref _connection, null);
        if (connection is not null)
        {
            await connection.DisposeAsync().ConfigureAwait(false);
        }
    }

    private void SetStatus(PeerRouteStatus status)
    {
        _status = status;
        StatusChanged?.Invoke(this, status);
    }
}
