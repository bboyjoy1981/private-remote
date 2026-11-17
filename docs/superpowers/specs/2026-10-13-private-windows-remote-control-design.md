# Private Windows Remote Control Design

## Purpose

Build a remote control application for the user's own Windows computers. The first release must let a paired computer stream its screen, accept mouse and keyboard input, transfer files, and support unattended connections after initial local authorization.

## Confirmed product decisions

- The first release targets Windows computers only.
- The intended deployment is two computers owned by the same user.
- Initial pairing must be approved locally on the computer being controlled.
- After pairing, the controlling computer may connect unattended using its device identity and protected credentials.
- The user can inspect and revoke paired devices.
- Screen control and file transfer are both required.
- Connections attempt a direct peer-to-peer route first. If that fails, traffic may use a relay operated by the user.
- Relay traffic is end-to-end encrypted; the relay cannot decrypt screen, input, or file data.

## Out of scope for the first release

- macOS, Linux, mobile, or browser clients.
- Public device discovery, public account registration, multi-user teams, or help-desk workflows.
- A vendor-operated relay service.
- Audio, printing, clipboard synchronization, remote wake, multi-monitor selection, and concurrent controllers.
- Bypassing Windows sign-in, User Account Control, lock-screen, or other operating-system security boundaries.

## User experience

The user installs the application on both computers. The computer being controlled displays a pairing code or equivalent short-lived invitation. The controlling computer enters it, and the local user approves the first pairing on the controlled computer. Both devices then show the paired device name and identity. The user can rename or revoke a pairing from the controlled computer.

For a later connection, the controller selects a paired computer. The controlled computer displays a persistent, visible connected state and provides a direct disconnect control. If its screen is locked or the application lacks permission, the client explains the limitation rather than attempting to bypass it.

During a session, the controller can switch between screen control and file transfer. File transfers show direction, file name, progress, completion, and failure. The receiver chooses or confirms the destination before files are written. The initial release does not automatically execute received files.

## System design

### Windows clients

Each Windows installation has a controller and controlled-device mode. A single installation may perform both roles. The UI manages pairing, connection status, permissions, screen view, input, transfer progress, and device revocation.

The controlled-device component captures the desktop, encodes frames, applies authorized input, and mediates file reads and writes. It runs with the signed-in user's permissions and does not install a privileged service in the first release.

### Connection establishment

The clients use an authenticated signaling path to exchange connection metadata. They attempt a direct encrypted peer connection first. If NAT or firewall conditions prevent direct connectivity, they may establish an encrypted relay path through a self-hosted relay. Signaling and relay services do not store screen frames, input events, or file contents.

The product must expose whether the active route is direct or relayed. Failure to reach either route produces a useful error and does not silently weaken encryption.

### Security and authorization

- Pairing invitations are single-use and expire after a short, documented period.
- The controlled computer must approve each new device pairing locally.
- Device credentials are generated per pairing and stored using Windows-protected storage.
- Every session authenticates both device identities and establishes fresh session keys.
- Screen, input, and file data are encrypted end to end on direct and relay routes.
- The relay cannot impersonate either endpoint or decrypt session content.
- Screen control and file transfer are separately authorized capabilities.
- The controlled computer shows the connected device identity and active capabilities, and offers immediate disconnect and pairing revocation.
- File transfer validates names and paths, prevents path traversal, and writes only into a destination selected or confirmed by the receiver.
- Logs exclude file contents, screen contents, passwords, and long-lived credentials.

### Performance

The client adapts frame rate, image quality, and bitrate to network conditions. Input events use a low-latency channel separate from bulk file transfer so a large transfer does not unnecessarily block mouse and keyboard control. The UI reports when a relayed route or constrained network may affect responsiveness. The design targets responsive use on a stable broadband connection, but does not promise a specific latency independent of network conditions.

## Operational requirements

- The self-hosted signaling and relay services have documented installation, configuration, update, and shutdown steps.
- Relay configuration supports restricting access to the user's paired devices.
- The client must work on a local network without requiring a relay service when a direct route is available.
- The user can remove a pairing locally even when the relay service is unavailable.
- Updates are obtained from a verifiable release source and checked before installation.

## Acceptance criteria

1. Two supported Windows computers can pair after local approval and later reconnect unattended.
2. A controller can view the controlled desktop and send mouse and keyboard input within the controlled user's Windows permissions.
3. The user can transfer a file in either direction, see progress, and choose/confirm the destination.
4. A pairing can be revoked, after which that device cannot authenticate a new session.
5. A direct route is attempted first; a configured self-hosted relay can carry the session when direct connectivity fails.
6. A network inspection of the relay path cannot recover screen, input, or file contents.
7. The controlled computer visibly indicates the active session, authorized capabilities, and provides a working disconnect control.
8. A connection failure, revoked pairing, inaccessible screen, or interrupted transfer yields a clear status and does not claim success.

## Decisions reserved for implementation planning

The implementation plan must select the Windows UI framework, screen capture and encoding components, peer-connection and relay protocol, cryptographic library, signing/distribution method, and packaging approach. Those choices must be checked against the security requirements above and current Windows support before dependencies are introduced.
