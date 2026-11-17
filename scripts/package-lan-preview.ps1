param(
    [string]$RuntimeVersion = '10.0.12',
    [string]$ClientOutput = '.dotnet-sdk/pair-ui-serial/bin/PrivateRemote.Client/debug'
)
$ErrorActionPreference = 'Stop'
function Get-CheckedHash([string]$Path) {
    for ($attempt = 0; $attempt -lt 30; $attempt++) {
        try { return (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash }
        catch [IO.IOException] { if ($attempt -eq 29) { throw }; Start-Sleep -Milliseconds 300 }
    }
}
$workspace = Split-Path $PSScriptRoot -Parent
$client = [IO.Path]::GetFullPath((Join-Path $workspace $ClientOutput))
$dotnetRoot = Join-Path $env:ProgramFiles 'dotnet'
$outputRoot = Join-Path $workspace 'artifacts'
$bundle = Join-Path $outputRoot ('PrivateRemote-LAN-preview-' + [guid]::NewGuid().ToString('N').Substring(0,8))
if (!(Test-Path (Join-Path $client 'PrivateRemote.Client.exe'))) { throw 'Build the client before packaging.' }
$frameworks = @('Microsoft.NETCore.App', 'Microsoft.WindowsDesktop.App', 'Microsoft.AspNetCore.App')
foreach ($framework in $frameworks) {
    if (!(Test-Path (Join-Path $dotnetRoot "shared/$framework/$RuntimeVersion"))) { throw "Missing local runtime: $framework $RuntimeVersion" }
}
$expectedHash = (Get-Content (Join-Path $client 'native/datachannel.dll.sha256') -Raw).Trim().Split(' ')[0]
if ((Get-FileHash (Join-Path $client 'native/datachannel.dll') -Algorithm SHA256).Hash -ne $expectedHash) { throw 'Native DLL checksum mismatch.' }
New-Item $bundle -ItemType Directory -Force | Out-Null
Get-ChildItem $client | Where-Object { $_.Extension -ne '.pdb' } | Copy-Item -Destination $bundle -Recurse
$runtime = Join-Path $bundle 'runtime'
New-Item $runtime -ItemType Directory -Force | Out-Null
foreach ($name in @('dotnet.exe','LICENSE.txt','ThirdPartyNotices.txt')) { Copy-Item (Join-Path $dotnetRoot $name) $runtime }
New-Item (Join-Path $runtime 'host/fxr') -ItemType Directory -Force | Out-Null
Copy-Item (Join-Path $dotnetRoot "host/fxr/$RuntimeVersion") (Join-Path $runtime 'host/fxr') -Recurse
foreach ($framework in $frameworks) {
    $destination = Join-Path $runtime "shared/$framework"
    New-Item $destination -ItemType Directory -Force | Out-Null
    Copy-Item (Join-Path $dotnetRoot "shared/$framework/$RuntimeVersion") $destination -Recurse
}
$redist = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio/2022/BuildTools/VC/Redist/MSVC/14.44.35112/x64/Microsoft.VC143.CRT'
if (!(Test-Path $redist)) { throw 'Missing Microsoft VC++ redistributable files.' }
Get-ChildItem $redist -Filter '*.dll' | Copy-Item -Destination (Join-Path $bundle 'native')
Get-ChildItem $redist -Filter '*.dll' | Copy-Item -Destination $bundle
Copy-Item (Join-Path $workspace 'docs/局域网试用说明.md') (Join-Path $bundle '使用说明.md')
@'
@echo off
setlocal
set "DOTNET_ROOT_X64=%~dp0runtime"
set "DOTNET_ROOT=%~dp0runtime"
start "" "%~dp0PrivateRemote.Client.exe"
endlocal
'@ | Set-Content (Join-Path $bundle '启动软件.cmd') -Encoding ascii
@'
Microsoft Visual C++ Runtime: copyright Microsoft Corporation.
Files copied from the installed Microsoft.VC143.CRT redistributable directory.
.NET runtime license and third-party notices: runtime/LICENSE.txt and runtime/ThirdPartyNotices.txt.
libdatachannel and dependency licenses: native/licenses/.
'@ | Set-Content (Join-Path $bundle 'THIRD-PARTY-NOTICES.txt') -Encoding utf8
Get-ChildItem $bundle -File -Recurse | ForEach-Object {
    [pscustomobject]@{ Path = [IO.Path]::GetRelativePath($bundle, $_.FullName); Sha256 = Get-CheckedHash $_.FullName }
} | ConvertTo-Json | Set-Content (Join-Path $bundle 'files.sha256.json') -Encoding utf8
$zip = Join-Path $outputRoot 'PrivateRemote-LAN-preview.zip'
$temporaryZip = $zip + '.' + [guid]::NewGuid().ToString('N') + '.zip'
for ($attempt = 0; $attempt -lt 30; $attempt++) {
    try {
        [IO.Compression.ZipFile]::CreateFromDirectory($bundle, $temporaryZip, [IO.Compression.CompressionLevel]::Optimal, $true)
        $archive = [IO.Compression.ZipFile]::OpenRead($temporaryZip)
        try {
            foreach ($required in @('/PrivateRemote.Client.dll', '/PrivateRemote.Client.exe', '/启动软件.cmd', '/使用说明.md', '/native/datachannel.dll')) {
                if (!($archive.Entries | Where-Object { $_.FullName.Replace('\','/').EndsWith($required) })) { throw "Archive missing $required" }
            }
        } finally { $archive.Dispose() }
        [IO.File]::Move($temporaryZip, $zip, $true)
        break
    } catch {
        if (Test-Path -LiteralPath $temporaryZip) { Remove-Item -LiteralPath $temporaryZip -Force }
        if ($attempt -eq 29) { throw }
        Start-Sleep -Seconds 1
    }
}
Write-Output "Bundle: $bundle"
Write-Output "ZIP: $zip"
