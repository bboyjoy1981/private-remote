# Private Windows Remote Control Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a Windows-only remote-control application for the user's paired computers with remote screen/input, file transfer, unattended reconnection, and a self-hosted encrypted relay fallback.

**Architecture:** Use a Windows desktop client with separate UI, device authorization, screen/input, and transfer modules. Establish sessions through authenticated signaling, prefer a direct peer connection, and route encrypted data through a self-hosted relay only when direct connectivity fails. Keep cryptographic and transport choices behind narrow interfaces selected in the technology decision record.

**Tech Stack:** C#/.NET 10 LTS with WPF; Windows Graphics Capture; Media Foundation H.264; libdatachannel C API for WebRTC; ASP.NET Core signaling; self-hosted coturn for TURN; current-user DPAPI for local private keys; signed self-contained x64 client installer.

**Spec:** `docs/superpowers/specs/2026-10-13-private-windows-remote-control-design.md`

## Global Constraints

- The first release targets Windows computers only.
- The intended deployment is two computers owned by the same user.
- Initial pairing must be approved locally on the computer being controlled.
- After pairing, the controlling computer may connect unattended using its device identity and protected credentials.
- The user can inspect and revoke paired devices.
- Screen control and file transfer are both required.
- Connections attempt a direct peer-to-peer route first. If that fails, traffic may use a relay operated by the user.
- Relay traffic is end-to-end encrypted; the relay cannot decrypt screen, input, or file data.
- The controlled-device component runs with the signed-in user's permissions and does not install a privileged service in the first release.
- The controlled computer visibly indicates the connected device identity and active capabilities and provides immediate disconnect and pairing revocation.
- Received files are never automatically executed; the receiver chooses or confirms the destination.
- Logs exclude file contents, screen contents, passwords, and long-lived credentials.
- No security boundary such as Windows sign-in, UAC, or lock-screen may be bypassed.

## Review Focus

- Malformed, expired, or replayed pairing invitations must fail without creating a device pairing.
- Revocation during an active or reconnecting session must prevent subsequent authentication and close the session.
- Interrupted or malicious file transfers must not escape the receiver-selected destination or report partial files as complete.
- Direct-path failure and relay failure must preserve encryption and report a useful error without silent downgrade.
- Locked desktops, permission failures, high latency, and simultaneous file transfer must not hang the UI or starve input events.

---

## File Structure

The first task establishes the repository layout and selects concrete libraries before product code is written. The proposed layout keeps client, shared protocol, and service responsibilities separate:

- `src/PrivateRemote.Client/` — pairing UI, device list, session UI, user-visible status.
- `src/PrivateRemote.Agent/` — screen capture, encoding, authorized input, transfer mediation, Windows lifecycle.
- `src/PrivateRemote.Protocol/` — versioned messages, identity, authorization, encrypted session framing.
- `src/PrivateRemote.Transport/` — signaling, direct connection, route selection, relay client.
- `src/PrivateRemote.Relay/` — authenticated signaling service; coturn handles encrypted TURN forwarding as a separately deployed service.
- `tests/PrivateRemote.Tests/` — unit, integration, and security regression coverage aligned with each module.
- `docs/` — setup, relay operations, security model, and user instructions.

The plan uses C# source files and module-specific project directories. Do not add a privileged Windows service in the first release.

## Task 1: Dependency and protocol decision record

**Files:**
- Create: `docs/architecture/technology-decisions.md`
- Create: `docs/architecture/threat-model.md`

**Interfaces:**
- Produces: selected language/UI framework, capture/encoding path, signaling and peer transport, relay protocol, cryptographic library, Windows credential-storage API, installer/signing model, and supported Windows versions.
- Every selection must cite current primary documentation and explain how it satisfies the spec's end-to-end encryption, Windows support, and self-hosting constraints.

- [x] Review primary documentation for supported peer transport, relay mode, session identity, end-to-end encryption boundaries, and Windows packaging.
- [x] Record the selected dependency set and current prototype Windows version in `docs/architecture/technology-decisions.md`.
- [x] Document assets, trust boundaries, pairing flow, session authentication, relay visibility, revocation, file path handling, and abuse cases in `docs/architecture/threat-model.md`.
- [x] Check the decision record against every security requirement in the spec; preserve peer-to-peer DTLS/SRTP encryption through TURN.

## Task 2: Shared identity and encrypted session protocol

**Files:**
- Create: `src/PrivateRemote.Protocol/Identity.cs`
- Create: `src/PrivateRemote.Protocol/Pairing.cs`
- Create: `src/PrivateRemote.Protocol/Session.cs`
- Create: `tests/PrivateRemote.Tests/Protocol/IdentityTests.cs`
- Create: `tests/PrivateRemote.Tests/Protocol/PairingTests.cs`
- Create: `tests/PrivateRemote.Tests/Protocol/SessionTests.cs`

**Interfaces:**
- Consumes: technology and threat model decisions from Task 1.
- Produces: versioned device identity, expiring one-use pairing invitation, mutual session authentication, per-session encryption keys, capability grants, and revocation checks for client and relay.

- [x] Write tests for invitation expiry, single use, transcript signatures, unknown device, revoked device, and capability mismatch.
- [x] Run protocol tests and confirm they fail for missing protocol behavior.
- [x] Implement identity and pairing validation; private identity material is protected with DPAPI when the user's Windows profile is available.
- [x] Write tests that verify session key freshness across reconnects and rejection of altered or out-of-order authenticated frames.
- [x] Implement version-1 session transcripts, ECDH/HKDF keys, and authenticated encrypted framing.
- [x] Run protocol tests; all runnable tests pass, while DPAPI round-trip is skipped when Windows reports that the sandbox DPAPI profile is unavailable.

## Task 3: Pairing and device management UI

**Files:**
- Create: `src/PrivateRemote.Client/PairingView.cs`
- Create: `src/PrivateRemote.Client/DeviceStore.cs`
- Create: `src/PrivateRemote.Agent/PairingApproval.cs`
- Create: `tests/PrivateRemote.Tests/Client/PairingFlowTests.cs`

**Interfaces:**
- Consumes: identity and invitation interfaces from Task 2.
- Produces: create-invitation, approve-pairing, list-paired-devices, rename-device, and revoke-device flows.

- [x] Write flow tests proving a new pairing is not stored until locally approved on the controlled computer.
- [x] Write flow tests proving expired invitations and revoked devices cannot pair or reconnect.
- [ ] Implement the pairing screen with a single-use, expiring code and explicit local approval.
- [x] Implement device listing, rename, and revoke controls on the controlled computer.
- [ ] Run pairing-flow tests, including restarting the app and confirming credentials remain protected.

**Progress note (2026-10-14):** Added approval-flow tests for decline-before-store, successful approval, expired invites, store reload, rename normalization, unknown IDs, revocation, and malformed peer identity handling. The device list now exposes rename and revoke actions. A regression test caught that an invalid public-key fingerprint consumed the invite before rejecting the peer; peer ID/key and grant validation now happen before invite consumption. The harness reports 24/24 passing, with the DPAPI round-trip case explicitly skipped because this sandbox has no current-user profile. The WPF client builds with 0 warnings and 0 errors when its already-built project references are reused. Cross-computer invitation exchange and the local-approval dialog are not yet connected to a signaling/enrollment flow.

**Progress note (2026-10-14):** The visible invite now has a live expiry countdown, a copy button, and clears itself when expired; replacing or closing the window invalidates the pending invitation in memory. `PairingInvitation` now erases its displayed token and token hash when it expires or is explicitly invalidated. The local approval helper and device persistence exist, but the two-computer request exchange still needs the signaling/enrollment flow.

## Task 4: Signaling and direct connection

**Files:**
- Create: `src/PrivateRemote.Transport/SignalingClient.cs`
- Create: `src/PrivateRemote.Transport/DirectPeer.cs`
- Create: `src/PrivateRemote.Transport/RouteStatus.cs`
- Create: `tests/PrivateRemote.Tests/Transport/DirectConnectionTests.cs`

**Interfaces:**
- Consumes: authenticated session handshake and device authorization from Task 2; paired device records from Task 3.
- Produces: `connect(device_id, capabilities) -> Session`, active route status (`direct` or `relay`), encrypted ordered control channel, and disconnect/error events.

- [ ] Write tests for successful direct negotiation, auth rejection, timeout, peer disconnect, and prevention of plaintext fallback.
- [x] Implement signed signaling messages that exchange only bounded connection metadata and do not store session media or file payloads.
- [ ] Implement direct peer connection and route status reporting.
- [ ] Run transport tests with a local test peer and confirm failure states are surfaced to the client.

**Progress note (2026-10-13):** The route coordinator and route status reporting are implemented and tested with an in-process connector: direct first, relay fallback for route failures/timeouts only, caller cancellation, and strict peer identity/encryption checks. `ws://` is permitted only for loopback signaling; remote endpoints require `wss://`. The native libdatachannel adapter and real two-device negotiation remain pending because this machine has no CMake/MSVC/NMake toolchain. The build helper is `scripts/build-libdatachannel.ps1`; it stops before download when prerequisites are absent.

**Progress note (2026-10-14):** Corrected signaling message validation order: the relay now authenticates the bearer and verifies the device signature before recording the nonce in the replay cache. This prevents invalidly signed messages from consuming the bounded replay-cache capacity. Relay project builds with 0 warnings and 0 errors; tests were not run in this step.

**Progress note (2026-10-14):** Closed the connection-registration/revocation race in the signaling endpoint. It now checks authorization again after adding the accepted WebSocket to the live-device map and removes the socket if revocation happened during the accept/registration gap. Relay project builds with 0 warnings and 0 errors; tests were not run in this step.

**Progress note (2026-10-14):** Hardened `WindowsInputControl` validation before `SendInput`: coordinates must be finite and normalized, mouse buttons must be left/right/middle, and virtual-key values must be in the supported nonzero range. Client project builds with 0 warnings and 0 errors; tests were not run in this step.

## Task 5: Self-hosted relay and fallback routing

**Files:**
- Create: `src/PrivateRemote.Relay/RelayServer.cs`
- Create: `src/PrivateRemote.Relay/AccessPolicy.cs`
- Create: `src/PrivateRemote.Transport/RelayClient.cs`
- Create: `deploy/coturn/turnserver.conf`
- Create: `deploy/coturn/README.md`
- Create: `tests/PrivateRemote.Tests/Relay/RelaySecurityTests.cs`

**Interfaces:**
- Consumes: authenticated device identity and encrypted frames from Task 2; direct route failure from Task 4.
- Produces: self-hosted coturn deployment configuration, paired-device access policy, time-limited TURN credentials, relay health status, and client route fallback.

- [x] Write tests proving unknown and revoked device identities cannot create relay routes.
- [ ] Write tests proving the relay forwards ciphertext without access to endpoint session keys or application payloads.
- [ ] Integrate coturn TURN REST authentication with short-lived credentials issued only for paired devices; disable unauthenticated allocation and configure bandwidth/session limits.
- [ ] Implement fallback after direct negotiation failure and expose the route change in client status.
- [x] Add coturn deployment configuration and operator instructions for installation, updates, and shutdown.
- [ ] Run relay tests and a two-client integration check through the relay.

## Task 6: Screen capture, encoding, and input control

**Files:**
- Create: `src/PrivateRemote.Agent/ScreenCapture.cs`
- Create: `src/PrivateRemote.Agent/VideoEncoder.cs`
- Create: `src/PrivateRemote.Agent/InputControl.cs`
- Create: `src/PrivateRemote.Client/RemoteView.cs`
- Create: `tests/PrivateRemote.Tests/Agent/ScreenSessionTests.cs`

**Interfaces:**
- Consumes: encrypted low-latency session channel from Task 4, with Task 5 fallback.
- Produces: authorized screen frame stream, adaptive quality controls, mouse/keyboard input events, and visible connected-device/capability status.

- [ ] Write tests for capability checks, inaccessible or locked desktop behavior, disconnect handling, and route interruption.
- [ ] Implement desktop capture and encoding using the supported Windows path selected in Task 1.
- [ ] Implement input injection within the signed-in user's permissions; reject input when the capability is not granted or the session is revoked.
- [ ] Implement frame-rate, bitrate, and image-quality adaptation from measured network conditions.
- [ ] Implement a visible connected state showing the controller identity, active capabilities, route, and immediate disconnect action.
- [ ] Run local loopback session checks and verify file transfer load does not block the input channel.

## Task 7: Safe file transfer

**Files:**
- Create: `src/PrivateRemote.Agent/FileReceiver.cs`
- Create: `src/PrivateRemote.Client/FileTransferView.cs`
- Create: `tests/PrivateRemote.Tests/Agent/FileTransferTests.cs`

**Interfaces:**
- Consumes: separately authorized encrypted bulk-data channel from Task 4, with Task 5 fallback.
- Produces: bidirectional transfer with progress, cancellation, receiver-selected destination, atomic completion, and clear failure status.

- [ ] Write tests for traversal paths, absolute paths, reserved names, interrupted transfers, cancellation, duplicate names, and mismatched content length or hash.
- [ ] Implement transfers into a receiver-selected staging file, validate paths and integrity, then atomically finalize only complete transfers.
- [x] Implement transfer progress, direction, completion/failure state, and cancellation in the client UI.
- [ ] Confirm received content is never automatically executed and logs contain no file payloads or credentials.
- [ ] Run file-transfer tests over direct and relayed sessions.

**Progress note (2026-10-14):** Added a two-stage sender API: `PrepareAsync` returns the file name, length, and SHA-256 before bulk bytes are sent; `SendPreparedAsync` transmits only after the caller has had an opportunity to announce/approve that metadata. It validates the bytes actually sent against the prepared hash, preventing a changed file from being reported as a successful transfer. Both behaviors have regression coverage. The full harness now reports 26/26 passing (with the DPAPI test skipped for the unavailable user profile), and the WPF client builds with 0 warnings/errors. The UI and the remote metadata-acceptance/bulk-channel handshake are still not wired to a real peer session.

**Progress note (2026-10-14):** Added `FileTransferView`, a session-bound WPF transfer window with sender file selection, receiver offer confirmation and save location selection, progress/rate display, cancellation, and explicit completion/failure status. Incoming data is written through the safe staging receiver and finalized only after length/hash verification. The host must approve the outgoing metadata before bytes are sent. The view awaits a real authenticated peer session and is not yet reachable from the main window; no remote transfer is available until the WebRTC session layer exists.

## Task 8: Packaging, operations, and release readiness

**Files:**
- Create: `docs/user-guide.md`
- Create: `docs/relay-operations.md`
- Create: `docs/security.md`
- Create: installer and signing configuration selected in Task 1
- Create: `tests/PrivateRemote.Tests/Integration/TwoWindowsDevicesTests.cs`

**Interfaces:**
- Consumes: completed pairing, transport, screen/input, relay, and transfer components from Tasks 2–7.
- Produces: installable Windows client, self-hosted relay package, update verification, and user/operator instructions.

- [ ] Write an end-to-end test for two supported Windows devices: locally approved pairing, unattended reconnect, remote view/input, bidirectional file transfer, and revocation.
- [ ] Write failure-path tests for direct and relay outage, network interruption, permission denial, and interrupted file transfer.
- [ ] Package the client and relay with the selected verifiable signing/update approach.
- [ ] Document installation, pairing, unattended use, status indicators, disconnect, revocation, relay setup, update, and shutdown.
- [ ] Run the full required test suite and verify the packaged build on the minimum supported Windows version.

## Coverage self-review

- Pairing and device lifecycle: Tasks 2–3.
- Direct connection and route status: Task 4.
- Self-hosted relay and no-decryption property: Task 5.
- Screen view, authorized input, adaptive quality, and status: Task 6.
- Bidirectional safe transfer and progress: Task 7.
- Packaging, operations, update verification, and end-to-end acceptance: Task 8.
- The five Review Focus cases are explicitly tested in Tasks 2, 3, 5, 6, and 7.

## Implementation rulings

- **Handshake investigation (2026-10-16).** Screenshot/presence show signaling online but native connection times out. Read-only inspection found all local Windows firewall profiles disabled; no local firewall changes were made, and the remote firewall is not known. Code inspection found candidates could be queued before local SDP, then discarded by a recipient without a session; remote candidates could also be applied before remote SDP. Enforce SDP-first sending, bound deferred candidates at 64 per direction, and flush authenticated remote candidates after description. Resolve simultaneous outgoing offers by deterministic device-ID priority without replacing established connections; authenticate winning offer before replacement. Add clipboard diagnostic snapshot with counters/state/LAN endpoints and UTC clock. This is a code-risk correction plus instrumentation, not proof of the user's exact network cause. Physical two-PC outcome remains pending; compilation is the available verification.

- **Crash-log-driven close/input fix (2026-10-15).** Actual Application/.NET Runtime events at 15:50 and 16:50 identify `InvalidOperationException: VerifyNotClosing` from reentrant `RemoteDesktopWindow.OnClosing`. Cleanup may finish synchronously, so both viewer/main final Close now dispatch after the Closing callback unwinds; add explicit stop-view button and keep normal host lifetime. Add explicit clipboard-paste text transport option, receiver result feedback that acknowledges Windows injection rather than application persistence, and retain unsent text. Authenticated/pinned HTTP peer-presence preflight distinguishes offline peer from native timeout; add per-user single-instance mutex to avoid new-version duplicate identity connections. User-facing package requires both endpoints updated. No interactive reproduction/test execution is claimed for this batch; crash-log evidence and compilation are the available checks.

- **IME text entry (2026-10-15).** User confirmed raw mouse control works and supplied a second video for local-IME text failure. Existing protocol only carried virtual-key events and had no committed-text path. Added a dedicated local WPF text entry box/send action and bounded Unicode text packets, delivered as KEYEVENTF_UNICODE UTF-16 down/up pairs at the receiver without clipboard synchronization. Validate surrogate pairs/control characters and limit each message to 128 code units; preserve ordered release-before-text and existing sharing/grant checks. This is an explicit text-entry workflow, not transparent forwarding of every local IME. Requires both endpoints updated. Interactive IME/target-application compatibility remains to be confirmed; no new test execution claimed.

- **User-requested tray/display changes (2026-10-15).** Set explicit application shutdown/main-window ownership, keep normal main close/minimize in tray, expose explicit exit with existing async cleanup, and keep session windows independent of main-window minimize. Added native notification-area icon/restore/exit menu. Viewer adds fit/physical-pixel 1:1/full-screen and authenticated capture quality profiles (720p/900p/native within 4K); frames remain bounded at 8 MiB and JPEG dimensions at 3840×2160. Both peers must update for the added quality message. Client builds with zero warnings/errors. No interactive tray/physical-two-PC validation or new test execution is claimed for this UI update.

- **LAN trial batch (2026-10-15).** Added signed offline mutual pairing with local approvals and HMAC-bound one-time request/receipt; restored revoked pairs require fresh approval. Added native file demultiplexing, duplex offer/approval/chunk/end/ack, safe finalization and cancellation, plus its session UI. Embedded a selected-pair WSS LAN service, DPAPI certificate/credential state, signed recipient-bound connection files, strict certificate pins and saved-configuration reconnection. Fixed Schannel ephemeral-server-key incompatibility using user-key loading. Normal-profile suite: 42 passed, 0 skipped, 0 failed, including pinned WSS/native desktop/control/file scenarios. Client compiles. Packaging uses installed .NET 10.0.12 runtimes after official runtime-feed access/approval was unavailable; no SDK is included. New broad independent review failed due model capacity, and the LAN protected-state restart probe still needs normal-profile execution. This is a trial artifact: physical two-PC UI/input, LAN firewall conditions, H.264, TURN, code signing/update and certificate rotation remain open.

- **Interim desktop flow verified (2026-10-15).** Added bounded frame/input wire protocol, GDI/JPEG source, native desktop session consumer and WPF viewer with mouse/keyboard/F12 control. Network integration verifies 160-KiB synthetic frame reassembly and ordered input through actual native peers, normal stop and failed-stop native teardown. Injected input-backend checks verify secure-desktop/partial-release retries without operating the user's input. A separate normal-desktop probe captures/decodes three real 1600×900 frames without saving them or sending input. Independent review identified failed-stop and lost-release cleanup bugs; both are fixed with regression coverage. Evidence: 40 passed, 1 DPAPI-profile skip, 0 failures. No physical two-PC view/input or performance claim; pairing/enrollment, file UI, H.264 and production deployment remain pending.

- **Ruling: use GDI/JPEG as an interim desktop path (2026-10-15).** Add a bounded, explicitly labeled baseline to validate screen-to-input behavior through the existing authenticated connection while WGC/H.264 remains the final performance path. This costs bandwidth and frame rate; do not present it as the smooth final release. Capture is restricted to the Default interactive desktop, downscaled within 1600×900 at JPEG quality 65, with at most one frame being sent and an 83-ms minimum interval. Frames are chunked over the authorized encrypted control channel, bounded to 2 MiB, and decoded only after dimension checks. Input is accepted only during active sharing, and tracked keys/buttons are released on stop/disconnect. File-channel integration remains pending.

- **Network/native session and main-window controls verified (2026-10-14).** `PeerSessionHost` connects real WebSocket signaling to authenticated native peers, accepts authorized incoming offers, preserves signaling on signed disconnect, uses fresh IDs on reconnect and closes native state after service revocation/failure. WPF now exposes service address/token and paired-device connect/disconnect/status; closing awaits native cleanup before disposing identity. A real loopback ASP.NET/native integration transfers bidirectional control plus 64-KiB bulk data, reconnects twice and revokes the service credential. Evidence: 38 passed, 1 DPAPI-profile skip, 0 failures; WPF builds without warnings/errors and includes pinned native DLL/checksum/licenses. These are same-machine integration results; two physical PCs, screen/H.264, enrollment exchange, file UI integration and production TURN remain pending.

- **Managed native lifecycle verified (2026-10-14).** `NativeWebRtcPeer` now implements actual peer creation/deletion, signed SDP/ICE application, separate reliable ordered control/bulk channels, bounded queues, send backpressure and selected-route reporting. Verified signals are single-use and scoped to the negotiation instance. Native callback exceptions stay within managed guards, and delegate roots are retained through global cleanup. The live pairing monitor closes native sessions after persistent revocation. `DeviceSessionFactory` exposes outgoing/incoming native creation with cleanup on failure. Tests transfer control bytes and a 64-KiB bulk chunk between actual native peers, reject bulk on a screen-only grant and observe revocation-driven closure. Evidence: 37 passed, 1 DPAPI-profile skip, 0 failures; client builds without warnings/errors. Real WebSocket/native orchestration, enrollment exchange and screen/video integration remain pending.

- **Persistent pairing/session bridge verified (2026-10-14).** Main-window initialization now creates one `DeviceSessionFactory` using the protected local identity and live device store. The factory retains replay state across reconnects, checks granted capabilities and authenticates incoming offers before returning native metadata. Existing negotiations recheck persisted authorization on each send/receive. Tests verify fresh session IDs, capability rejection, replay rejection and revocation observed from another store instance. Evidence: 35 passed, 1 DPAPI-profile skip, 0 failures; client builds without warnings/errors. Native connection lifecycle and active channel cancellation remain pending.

- **Signed native negotiation verified (2026-10-14).** Added `WebRtcNegotiation` to bind SDP/ICE to the paired identity, fresh session ID, explicit capabilities, session role and stable SHA-256 DTLS fingerprint. The native loopback diagnostic now supports a verified signaling exchange hook. Managed tests use this hook to prove actual native binary delivery after signed negotiation and rejection before native use when signatures, grants, sessions or certificates do not match. Current evidence: 34 passed, 1 DPAPI-profile skip, 0 failures; client compiles with no warnings/errors. Product session and enrollment UI integration remain pending.

- **Paired-device signaling receive boundary verified (2026-10-14).** Added an authenticated inbox for recipient checks, live paired-device lookup, signature/fingerprint binding and bounded nonce replay protection. A regression test first reproduced acceptance of a correctly signed message claiming another source identity; fingerprint binding now rejects it. The two-client WebSocket integration now receives through the authenticated inbox. The managed suite reports 30 passed, 1 DPAPI-profile skip and 0 failures. Native peer negotiation and session capability authorization still require integration.

- **Native build prerequisite resolved (2026-10-14).** The user explicitly authorized the Microsoft C++ toolchain installation. The official installer signature was verified and installation exited successfully. The fixed libdatachannel version now builds from SHA-256-pinned official archives and fixed submodule commits with static Mbed TLS 3.6.7; Git transport was unavailable. The x64 DLL passes native loading, peer/channel creation and encrypted-offer checks. The actual authenticated connector remains pending.
- **Two-client signaling integration verified (2026-10-14).** Development configuration now accepts multiple indexed devices and respects the actual ASP.NET environment. A loopback integration check exchanges eight concurrent signed messages, verifies bidirectional delivery and authenticated revocation closure. Client sends and close output are serialized; server close operations include a bounded wait for active sends. Production enrollment and TURN issuance remain pending.
- **Actual native loopback verified (2026-10-14).** The C# diagnostic in `scripts/NativePeerLoopback.cs` creates two native peers bound to loopback, negotiates SDP/ICE through callbacks and verifies binary data-channel delivery. This removes the uncertainty about the native build, ABI and local negotiation path. Device identity authentication and production integration remain pending. The managed suite reports 28 passed, 1 DPAPI-profile skip and 0 failures; the WPF client builds without warnings/errors.

- **Pin libdatachannel v0.24.6 and defer the native adapter until a C++ toolchain is available.** The environment has no CMake, MSVC, or NMake; adding an unverified native binary or placeholder adapter would make the connection path misleading. The cost is that a real two-device session is not yet available. `scripts/build-libdatachannel.ps1` checks prerequisites before downloading source.
- **Require WSS for non-loopback signaling.** WebSocket signaling may carry signed peer metadata and credentials, so only loopback development endpoints may use plaintext `ws://`.
- **Validate pairing identity before consuming the invitation.** A malformed peer ID/public-key pair should not burn a valid one-use invitation; local approval still remains mandatory before the device is persisted.
- **Build WPF separately from its project references in this environment.** MSBuild intermittently reports that referenced DLLs are locked while rebuilding the full project graph. Building dependencies once, then compiling the client with `BuildProjectReferences=false`, produces a clean WPF build without changing application behavior.
