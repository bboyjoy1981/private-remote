# Technology decisions

## Status

Initial decision record for the first release. Revisit any item if an implementation spike contradicts the assumptions below.

## Client and target platform

- **Language/runtime:** C# on .NET 10 LTS.
- **UI:** WPF desktop application. Keep transport and device logic outside the UI assembly so native interop can be tested independently.
- **Prototype OS:** Windows 11 version 23H2, x64 (the user's current development computer, build 22631). **Release baseline:** choose the current serviced Windows 11 release at packaging time; do not distribute the remote-control build for Internet use on this 23H2 Home/Pro system because its security updates ended on November 11, 2025. [Windows 11 23H2 lifecycle](https://learn.microsoft.com/en-us/lifecycle/announcements/windows-11-23h2-end-of-updates-home-pro) · [Windows client supported versions](https://learn.microsoft.com/en-us/windows/release-health/supported-versions-windows-client)
- **Runtime distribution:** self-contained signed x64 installer; no administrator service. Final installer technology and signing provider are release decisions after a working package prototype.
- **.NET lifecycle:** .NET 10 is an LTS release supported through November 2028. [.NET releases and support](https://learn.microsoft.com/en-us/dotnet/core/releases-and-support)

## Screen capture, encoding, and input

- **Capture:** Windows Graphics Capture via the Win32/WinRT interop path for desktop displays. Its API family predates the current host OS, but the unattended capture consent behavior must be validated on the release baseline; if capture cannot work after local pairing, stop and revisit the requirement rather than bypass Windows controls. [Screen capture documentation](https://learn.microsoft.com/en-us/windows/apps/develop/media-authoring-processing/screen-capture) · [GraphicsCaptureItem API](https://learn.microsoft.com/en-us/uwp/api/windows.graphics.capture.graphicscaptureitem)
- **Encoding:** Media Foundation H.264 transform, preferring hardware acceleration when available and falling back to a supported software encoder. [Media Foundation encoding overview](https://learn.microsoft.com/en-us/windows/win32/medfound/overview-of-encoding-in-media-foundation)
- **Input:** `SendInput` under the signed-in user's permissions. It does not grant elevation or access across secure desktop boundaries. [SendInput documentation](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-sendinput)

## Peer transport, signaling, and relay

- **Peer transport:** libdatachannel v0.24.6 through its documented C API, called from C# using a narrow P/Invoke wrapper. Preserve its MPL-2.0 and dependency notices. It implements WebRTC peer connections, data channels, ICE, DTLS, and SRTP; media codec integration remains in our Windows capture/encoder adapter. The x64 native DLL is now built from pinned upstream archives using MSVC and CMake/Ninja, with static Mbed TLS 3.6.7 and DTLS-SRTP enabled. Native loading and peer/channel/offer creation have passed the smoke check; the authenticated C# connector remains pending. [libdatachannel v0.24.6 release](https://github.com/paullouisageneau/libdatachannel/releases/tag/v0.24.6) · [C API documentation](https://github.com/paullouisageneau/libdatachannel/blob/v0.24.6/DOC.md) · [Windows build instructions](https://github.com/paullouisageneau/libdatachannel/blob/v0.24.6/BUILDING.md)
- **Signaling:** a small ASP.NET Core service over authenticated WebSockets. It exchanges SDP/ICE metadata and signed pairing/session messages only; it does not receive screen, input, or file payloads.
- **Relay fallback:** coturn, self-hosted on a Linux server, configured with time-limited credentials issued by the signaling service. The TURN service forwards WebRTC packets; WebRTC DTLS/SRTP remains end-to-end between clients. [coturn project](https://github.com/coturn/coturn) · [coturn relay architecture](https://github.com/coturn/coturn/blob/master/docs/netarch.md)
- **Route:** attempt direct ICE candidates first, use TURN relay candidates when required, and show the selected route. Never continue without successful WebRTC peer authentication.

## Device identity and local secrets

- **Identity:** ECDSA P-256 device signing keys and ECDH P-256 ephemeral session keys using .NET cryptographic APIs. Peer signaling transcript binds both identities, fresh nonces, WebRTC DTLS fingerprints, protocol version, and separately authorized capabilities.
- **Credential storage:** protect each device private key and refresh secret with Windows DPAPI in current-user scope (`CryptProtectData` without `CRYPTPROTECT_LOCAL_MACHINE`). [CryptProtectData documentation](https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptprotectdata)
- **Session protection:** use WebRTC DTLS-SRTP/data-channel encryption and independently authenticate the DTLS certificate fingerprints through the signed device-identity handshake. The relay receives no session keys.

## Service and packaging

- **Service deployment:** signaling service and coturn are separate self-hosted Linux services. The user guide must state that remote use requires an Internet-reachable signaling endpoint and TURN server/port configuration. Local-network direct sessions may work without coturn, subject to signaling availability.
- **Operations:** provide a reproducible container configuration for signaling and coturn, rotate ephemeral TURN credentials, disable public unauthenticated allocation, apply bandwidth/session limits, and document update/shutdown steps.
- **Packaging:** signed self-contained Windows x64 client. Do not ship the signing key. Select an installer tool after a prototype confirms native DLL packaging, upgrade, and signature verification behavior.

## Implementation risks to validate early

1. Windows Graphics Capture unattended session behavior and display resize/device-loss handling.
2. libdatachannel C API callback lifetime and native DLL deployment from a self-contained .NET app.
3. H.264 packetization between Media Foundation and libdatachannel media tracks.
4. TURN REST credential compatibility and expiry with both clients.
5. The client can verify the remote WebRTC DTLS fingerprint against the signed signaling transcript before exposing control or file-transfer capabilities.
