# Private Remote user guide (prototype)

This repository is a LAN trial, not a finished public remote-access release. It now includes signed offline two-way pairing, a desktop-hosted WSS signaling service with pinned certificates and protected saved credentials, native encrypted desktop/control sessions and an integrated duplex file-transfer window. JPEG remains an interim baseline. Physical two-PC display/input, Internet traversal and latency have not been verified. See [the Chinese LAN instructions](局域网试用说明.md) for the current UI flow and limits.

## Build the current prototype

Install the .NET 10 SDK, open PowerShell in the repository directory, then run:

```powershell
$env:DOTNET_CLI_HOME = Join-Path (Get-Location).Path '.dotnet-sdk\.cli-home'
$env:NUGET_PACKAGES = Join-Path (Get-Location).Path '.dotnet-sdk\.nuget'
$env:APPDATA = Join-Path (Get-Location).Path '.dotnet-sdk\appdata'
dotnet restore src/PrivateRemote.Client/PrivateRemote.Client.csproj --configfile NuGet.Config
dotnet run --project src/PrivateRemote.Client/PrivateRemote.Client.csproj --no-restore
```

The executable test harness is run with:

```powershell
dotnet run --project tests/PrivateRemote.Tests/PrivateRemote.Tests.csproj --no-restore
```

The user's current Windows 11 23H2 build can compile the prototype, but Home/Pro security updates ended on November 11, 2025. Upgrade to a currently serviced Windows release before Internet-connected remote access.

## Identity and device data

The client creates an ECDSA device identity under `%LOCALAPPDATA%\PrivateRemote`. The private key is stored only as current-user DPAPI ciphertext. In the current Codex execution sandbox, DPAPI reports Win32 error 2 because the user's DPAPI profile is not available; identity creation therefore displays an error in this environment. Run under the signed-in desktop user's normal Windows profile to validate this feature.

Pairing invitations expire after five minutes and are single use. The inviting computer exports a signed invitation file. The other computer verifies it, approves requested capabilities locally and exports a signed request with a token-bound HMAC, without copying the invitation secret into the request. The inviting computer inspects and locally approves the request, persists its peer and exports a signed/HMAC-bound receipt. The requester accepts a receipt only for its pending in-memory approved request and then persists its peer. Revoked peers may be restored only through fresh approval. Existing active duplicate records remain rejected. The UI shows full device IDs for local verification; invitation/configuration files should be exchanged only through a trusted channel.

## Remote connectivity

For development with identities already enrolled on the service and paired locally, enter the signaling endpoint and this device's bearer token, click “连接信令服务”, select a paired device, then click “连接选中的设备”. The other endpoint accepts only actively paired identities and granted capabilities. “断开连接” closes the device session while keeping signaling online. Tokens are cleared from the password field after successful service connection and are not saved by the UI.

For a screen-control grant, click “打开远程桌面” after connection. The receiver captures only its Default interactive desktop when requested by the paired peer. The interim mode scales the virtual desktop to fit 1600×900, uses JPEG quality 65 and waits at least 83 ms between frames; this is not a measured frame-rate or latency guarantee. Input maps to the displayed content rectangle, including letterboxing. F12, unchecking the input box or switching away releases remote input and disables the input toggle; re-enable it to resume. Closing the viewer stops sharing; failure to deliver the stop/release command closes the native session. UAC/lock-screen capture/input are rejected. If a secure desktop blocks key/button releases, only those pending release events retry after Default becomes available. Keyboard handling is limited to keys received by the viewer; it does not intercept Windows system shortcuts or generate a secure attention sequence.

The screen capture probe saves no frames and injects no input:

```powershell
dotnet run --project tests/PrivateRemote.DesktopProbe/PrivateRemote.DesktopProbe.csproj
```

Run it as the signed-in desktop user. A restricted execution sandbox can deny `StretchBlt`; the probe reports desktop access denial separately from a successful capture.

The client copies the pinned DLL and its checksum from `artifacts/native` into its `native` output directory when building. Build the native dependency with `scripts/build-native-from-archives.ps1` if those artifacts are absent.

Plaintext WebSockets are allowed only on loopback. The LAN service listens on TCP 5443 using a self-signed certificate; signed per-device connection configuration binds the certificate SHA-256, endpoint and bearer token to the receiving device. The client never accepts an arbitrary certificate when a pin is configured, checks certificate validity dates, and does not install a trusted root. Certificate PFX and device tokens persist as current-user DPAPI ciphertext. On Windows, Schannel requires user-key loading rather than ephemeral certificate keys; default user-key lifetime cleanup is used, without PersistKeySet. Saved configurations restore connections; reconnect attempts back off from 5 to 60 seconds while the endpoint/pin still match the saved configuration. The server must remain open on one computer. Keep the firewall rule limited to private/local-subnet traffic. The development relay still refuses Production startup; public enrollment, TURN, automatic certificate rotation and deployment remain unfinished.

## File transfer status

`SessionFiles` prepares metadata and obtains a user-selected destination before sending bulk content. Data and its end marker use the same ordered bulk channel; offsets, byte count and hash must agree before atomic finalization. The sender reports success only after the receiver's completion acknowledgement. One transfer per direction may coexist with desktop traffic. Reject/cancel/zero-byte and 180-KiB bidirectional transfers are exercised over actual native peers/WSS; canceled staging files are removed. In-flight chunks from a canceled transfer are discarded using a bounded retired-ID history. Closing the transfer window cancels its active transfers. Publicly exposed services and file performance remain unverified.
