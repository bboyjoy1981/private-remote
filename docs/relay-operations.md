# Relay operations

The signaling service is an incomplete development skeleton. It exchanges signed, size-limited signaling messages and has health and authenticated revocation endpoints. It intentionally refuses to start in Production until multi-device enrollment, persistent credentials, and secure TURN REST credential issuance exist. The current development mode does not provide a production enrollment workflow.

For local two-device development, configure indexed entries using environment variables:

```text
ASPNETCORE_ENVIRONMENT=Development
ASPNETCORE_URLS=http://127.0.0.1:5080
DevelopmentDevices__0__DeviceId=<first public-key fingerprint>
DevelopmentDevices__0__PublicKeyBase64=<first public key>
DevelopmentDevices__0__BearerToken=<first device token>
DevelopmentDevices__1__DeviceId=<second public-key fingerprint>
DevelopmentDevices__1__PublicKeyBase64=<second public key>
DevelopmentDevices__1__BearerToken=<second device token>
RelayAdmin__BearerToken=<separate admin token>
```

The legacy single `DevelopmentDevice` entry remains supported. Every configured entry must have all three fields; invalid keys, mismatched fingerprints and duplicate identities stop startup. Keep tokens in local environment configuration rather than committed files. The integration test starts an ephemeral loopback server, connects two identities, verifies concurrent signed messages in both directions and checks that the authenticated revocation endpoint closes the target socket.

The coturn configuration is a deployment template. Replace all placeholder hostnames and secrets, configure a TLS certificate, set the server's external/private addresses and UDP relay range, and restrict its network exposure. Signaling must issue short-lived TURN REST credentials using the same server-only secret; that issuance code is not yet implemented.

Never commit secrets, disable TURN authentication, expose the development service publicly, or rely on the example container tag without reviewing the upstream image. Back up and protect the device enrollment database once it is implemented. Revoke devices at the signaling service and verify their active sockets close.
