# Threat model

## Scope and security goals

Protect the user's screen, remote input, transferred files, and paired-device credentials during sessions between the user's Windows computers. Prevent an unpaired, revoked, or network-positioned attacker from taking control, impersonating a device, reading relayed content, or writing outside a destination explicitly selected by the receiver.

The app runs with the interactive user's permissions. It does not bypass Windows sign-in, UAC, secure desktop, lock screen, or endpoint protection. A compromised endpoint or Windows account is outside the protection the application can provide.

## Assets

- Device private signing keys and refresh secrets.
- Pairing invitation tokens and per-pair capability grants.
- Screen frames, keyboard/mouse events, and file contents.
- Paired device identities, names, and revocation state.
- TURN credentials and signaling authorization tokens.

## Trust boundaries and data flow

1. **Local pairing UI → device identity store:** invitation accepted only after the controlled computer's local user confirms the peer identity and capabilities. The peer's public key is stored only after approval; private key material is protected with current-user DPAPI.
2. **Client → signaling service:** authenticated WebSocket carries signed device/session metadata, SDP, and ICE candidates. The service validates active device grants but cannot authorize capabilities absent from the signed grant.
3. **Client ↔ client peer session:** endpoints verify signed transcript, mutual identity, nonce freshness, capabilities, and DTLS fingerprint binding before enabling screen control or file transfer. WebRTC encrypts media and data channels end to end.
4. **Client ↔ coturn:** coturn authenticates a short-lived allocation and forwards encrypted WebRTC packets. It can observe network metadata, volume, and timing, but has no content keys.
5. **File receiver → filesystem:** incoming file is written to a random temporary file beneath a receiver-selected directory, checked for declared length and content hash, then atomically renamed to a sanitized target. Incomplete data is discarded or retained only as an explicitly marked resumable transfer.

## Adversaries and abuse cases

- **Unpaired internet user:** attempts invitation guessing, replay, stolen TURN credentials, or arbitrary signaling. Mitigations: high-entropy single-use invitation, short expiry, rate limits, endpoint local approval, signed identities, and time-limited TURN credentials.
- **Revoked device:** tries reconnecting or continuing an existing session. Mitigations: check revocation at signaling/session establishment and terminate active sessions on revocation notification; revalidate before reconnect and before each new capability grant.
- **Malicious signaling or relay operator:** modifies signaling, substitutes a peer, or inspects relay traffic. Mitigations: signatures bind SDP fingerprints and capabilities; DTLS fingerprint pinning prevents undetected substitution; TURN carries ciphertext only. Signaling can deny service or observe metadata.
- **Malicious network peer:** injects malformed frames, huge transfer metadata, path traversal, or flood traffic. Mitigations: strict protocol version/size limits, authenticated messages, bounded queues, transfer quotas, path canonicalization, and atomic file finalization.
- **Local observer:** encounters an unattended active session. Mitigations: persistent connected indicator with peer identity/capabilities, one-action disconnect, local pairing revocation, and no hidden mode.
- **Endpoint malware or stolen logged-in account:** can act with the user's local privileges and may access decrypted screen/files. This application cannot defend a compromised endpoint; rely on Windows account/device security.

## Security invariants

- No session enables control or file transfer until mutual device authentication and signed capability checks complete.
- No relay or signaling process receives application plaintext or session private keys.
- No plaintext fallback is permitted after peer transport or certificate verification failure.
- Pairing is local-user approved, single-use, short-lived, and revocable.
- Screen control and file transfer are separately granted.
- Received paths are canonicalized and constrained beneath the user-selected root; file completion is atomic.
- Logs contain no screen/file data, secrets, or private keys.
- The app does not elevate itself and does not attempt to control secure desktop surfaces.

## Availability and privacy limits

The signaling endpoint must be reachable to coordinate sessions. Direct connectivity may fail behind some NAT/firewall combinations; the user then needs a reachable self-hosted TURN service with configured ports. A relay learns IP addresses, connection times, byte counts, and other transport metadata. It can block or delay traffic. End-to-end encryption protects content confidentiality and integrity, not availability or traffic analysis.
