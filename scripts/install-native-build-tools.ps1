[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$repositoryRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$installerDirectory = Join-Path $repositoryRoot '.native\installers'
New-Item -ItemType Directory -Force -Path $installerDirectory | Out-Null
$installerPath = Join-Path $installerDirectory 'vs_buildtools.exe'
curl.exe --fail --location --retry 3 --connect-timeout 20 --output $installerPath 'https://aka.ms/vs/17/release/vs_buildtools.exe'
if ($LASTEXITCODE -ne 0) {
    throw 'Could not download the Microsoft Build Tools installer.'
}
$signature = Get-AuthenticodeSignature -LiteralPath $installerPath
if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch 'O=Microsoft Corporation') {
    throw 'The Build Tools installer must have a valid Microsoft Authenticode signature.'
}

Write-Output 'Verified Microsoft installer; installing MSVC, Windows SDK and CMake without restarting Windows.'
$process = Start-Process -FilePath $installerPath -WindowStyle Hidden -PassThru -Wait -ArgumentList @(
    '--quiet', '--wait', '--norestart',
    '--add', 'Microsoft.VisualStudio.Workload.VCTools',
    '--includeRecommended',
    '--add', 'Microsoft.VisualStudio.Component.VC.CMake.Project'
)
if ($process.ExitCode -notin @(0, 3010)) {
    throw "Build Tools installation failed with exit code $($process.ExitCode). Check the dd_* logs in the Windows temporary directory."
}
Write-Output "Build Tools installation completed (exit code $($process.ExitCode))."
