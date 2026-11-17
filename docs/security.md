# Security status

## Implemented building blocks

- ECDSA P-256 device identity, signed session transcript, ECDH ephemeral agreement, HKDF directional keys, and AES-GCM frames with sequence/replay checks.
- Five-minute single-use pairing invitations, per-device capability grants, and revocation checks.
- Current-user DPAPI wrapper for private identity keys. This wrapper must be validated under a normal interactive Windows user profile because the Codex sandbox does not expose the user's DPAPI profile.
- Local device store, explicit approval dialog, and revoke UI.
- `SendInput` behind the ScreenControl capability check and current-user permissions.
- File sender and receiver with bounded size, progress/cancellation, filename validation, SHA-256 validation, temporary staging, and atomic completion.
- Signed, short-lived, size-limited signaling envelopes and a relay-side verification/access-policy skeleton.
- Direct-first route coordinator with relay fallback only on connectivity/timeout failures; identity or encryption failures stop the connection. This is verified against an in-process connector, not a real WebRTC peer.

## Incomplete security boundaries

- The Windows Graphics Capture and Media Foundation classes are stubs; screen pixels are not captured or streamed.
- The libdatachannel native library is not yet packaged, and direct WebRTC/data-channel negotiation is absent.
- Pairing is not exchanged between devices; there is no authenticated enrollment API.
- Signaling device credentials are only a development skeleton, and Production startup is blocked until persistence is implemented.
- TURN REST credentials are not issued; coturn configuration contains placeholders.
- Relay deployment uses HTTP behind a local reverse proxy; TLS, certificates, proxy headers, and host firewall must be configured by an operator.
- No signed installer, update channel, rate-limited invitation endpoint, persistent revocation database, or two-computer integration test exists.

Do not use this prototype for remote access over the Internet until those boundaries are implemented and reviewed.
