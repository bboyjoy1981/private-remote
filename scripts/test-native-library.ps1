[CmdletBinding()]
param([string]$LibraryPath = (Join-Path $PSScriptRoot '..\artifacts\native\datachannel.dll'))

$ErrorActionPreference = 'Stop'
if ([IntPtr]::Size -ne 8) { throw 'Use a 64-bit PowerShell process.' }
$libraryPath = [IO.Path]::GetFullPath($LibraryPath)
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class PrivateRemoteNativeSmoke {
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] public delegate void VoidCall();
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] public delegate int CreatePeer(IntPtr configuration);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] public delegate int DeletePeer(int peer);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] public delegate int CreateChannel(int peer, IntPtr label);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] public delegate int Offer(int peer, IntPtr buffer, int size);
}
'@
$library = [Runtime.InteropServices.NativeLibrary]::Load($libraryPath)
$configuration = [Runtime.InteropServices.Marshal]::AllocHGlobal(56)
$bindAddress = [Runtime.InteropServices.Marshal]::StringToCoTaskMemUTF8('127.0.0.1')
$label = [Runtime.InteropServices.Marshal]::StringToCoTaskMemUTF8('control')
$buffer = [Runtime.InteropServices.Marshal]::AllocHGlobal(65536)
$peer = -1
$channel = -1
try {
    $marshal = [Runtime.InteropServices.Marshal]
    $native = [Runtime.InteropServices.NativeLibrary]
    $preload = $marshal::GetDelegateForFunctionPointer($native::GetExport($library, 'rtcPreload'), [PrivateRemoteNativeSmoke+VoidCall])
    $cleanup = $marshal::GetDelegateForFunctionPointer($native::GetExport($library, 'rtcCleanup'), [PrivateRemoteNativeSmoke+VoidCall])
    $createPeer = $marshal::GetDelegateForFunctionPointer($native::GetExport($library, 'rtcCreatePeerConnection'), [PrivateRemoteNativeSmoke+CreatePeer])
    $deletePeer = $marshal::GetDelegateForFunctionPointer($native::GetExport($library, 'rtcDeletePeerConnection'), [PrivateRemoteNativeSmoke+DeletePeer])
    $createChannel = $marshal::GetDelegateForFunctionPointer($native::GetExport($library, 'rtcCreateDataChannel'), [PrivateRemoteNativeSmoke+CreateChannel])
    $deleteChannel = $marshal::GetDelegateForFunctionPointer($native::GetExport($library, 'rtcDeleteDataChannel'), [PrivateRemoteNativeSmoke+DeletePeer])
    $createOffer = $marshal::GetDelegateForFunctionPointer($native::GetExport($library, 'rtcCreateOffer'), [PrivateRemoteNativeSmoke+Offer])
    $marshal::Copy([byte[]]::new(56), 0, $configuration, 56)
    $marshal::WriteIntPtr($configuration, 24, $bindAddress)
    $marshal::WriteByte($configuration, 42, 1) # disableAutoNegotiation
    $preload.Invoke()
    $peer = $createPeer.Invoke($configuration)
    if ($peer -lt 0) { throw "Native peer creation failed: $peer" }
    $channel = $createChannel.Invoke($peer, $label)
    if ($channel -lt 0) { throw "Native channel creation failed: $channel" }
    $size = $createOffer.Invoke($peer, $buffer, 65536)
    if ($size -le 0) { throw "Native offer creation failed: $size" }
    $offer = $marshal::PtrToStringUTF8($buffer)
    if ($offer -notmatch 'a=fingerprint:' -or $offer -notmatch 'UDP/DTLS/SCTP') {
        throw 'The native offer is missing DTLS fingerprint or encrypted data-channel transport.'
    }
    Write-Output 'PASS: x64 native DLL loaded; peer and control channel created; offer contains DTLS fingerprint and encrypted SCTP transport.'
}
finally {
    if ($channel -ge 0) { $null = $deleteChannel.Invoke($channel) }
    if ($peer -ge 0) { $null = $deletePeer.Invoke($peer) }
    if ($cleanup) { $cleanup.Invoke() }
    [Runtime.InteropServices.Marshal]::FreeHGlobal($configuration)
    [Runtime.InteropServices.Marshal]::FreeHGlobal($buffer)
    [Runtime.InteropServices.Marshal]::FreeCoTaskMem($bindAddress)
    [Runtime.InteropServices.Marshal]::FreeCoTaskMem($label)
    [Runtime.InteropServices.NativeLibrary]::Free($library)
}
