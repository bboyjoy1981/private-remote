[CmdletBinding()]
param([string]$LibraryPath = (Join-Path $PSScriptRoot '..\artifacts\native\datachannel.dll'))

$ErrorActionPreference = 'Stop'
Add-Type -Path (Join-Path $PSScriptRoot 'NativePeerLoopback.cs')
[PrivateRemoteNativePeerLoopback]::Run([IO.Path]::GetFullPath($LibraryPath))
