[CmdletBinding()]
param(
    [string]$SourceDirectory = (Join-Path $PSScriptRoot '..\.native\libdatachannel-v0.24.6'),
    [string]$BuildDirectory = (Join-Path $PSScriptRoot '..\.native\build-libdatachannel'),
    [string]$OutputDirectory = (Join-Path $PSScriptRoot '..\artifacts\native')
)

$ErrorActionPreference = 'Stop'
if (-not (Get-Command cl -ErrorAction SilentlyContinue)) {
    $vswherePath = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    if (Test-Path -LiteralPath $vswherePath) {
        $installationPath = & $vswherePath -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
        if ($installationPath) {
            $launchScript = Join-Path $installationPath 'Common7\Tools\Launch-VsDevShell.ps1'
            & $launchScript -Arch amd64 -HostArch amd64 -SkipAutomaticLocation
            $cmakeDirectory = Join-Path $installationPath 'Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin'
            if (Test-Path -LiteralPath $cmakeDirectory) {
                $env:PATH = $cmakeDirectory + [IO.Path]::PathSeparator + $env:PATH
            }
        }
    }
}
$cmake = Get-Command cmake -ErrorAction SilentlyContinue
$compiler = Get-Command cl -ErrorAction SilentlyContinue
$make = Get-Command nmake -ErrorAction SilentlyContinue
if (-not $cmake -or -not $compiler -or -not $make) {
    throw 'Build prerequisites are missing. Install CMake 3.21+ and Visual Studio Build Tools with the Desktop development with C++ workload, Windows SDK, MSVC, and NMake; then open a Developer PowerShell and rerun this script.'
}

$sourcePath = [System.IO.Path]::GetFullPath($SourceDirectory)
$buildPath = [System.IO.Path]::GetFullPath($BuildDirectory)
$outputPath = [System.IO.Path]::GetFullPath($OutputDirectory)
$repositoryRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
function Test-IsInsideRepository([string]$Path, [string]$Root) {
    $relative = [System.IO.Path]::GetRelativePath($Root, $Path)
    return -not [System.IO.Path]::IsPathRooted($relative) -and
        $relative -ne '..' -and
        -not $relative.StartsWith('..' + [System.IO.Path]::DirectorySeparatorChar, [System.StringComparison]::Ordinal) -and
        -not $relative.StartsWith('..' + [System.IO.Path]::AltDirectorySeparatorChar, [System.StringComparison]::Ordinal)
}
if (-not (Test-IsInsideRepository $sourcePath $repositoryRoot) -or
    -not (Test-IsInsideRepository $buildPath $repositoryRoot) -or
    -not (Test-IsInsideRepository $outputPath $repositoryRoot)) {
    throw 'Source, build, and output directories must stay inside the repository.'
}

if (-not (Test-Path -LiteralPath (Join-Path $sourcePath '.git'))) {
    if (Test-Path -LiteralPath $sourcePath) {
        throw "Source directory already exists but is not a Git checkout: $sourcePath"
    }
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $sourcePath) | Out-Null
    git clone --depth 1 --branch v0.24.6 --recurse-submodules https://github.com/paullouisageneau/libdatachannel.git $sourcePath
    if ($LASTEXITCODE -ne 0) { throw 'Could not clone the pinned libdatachannel source.' }
}

$tag = git -C $sourcePath describe --tags --exact-match 2>$null
if ($LASTEXITCODE -ne 0 -or $tag -ne 'v0.24.6') {
    throw "The native source must be exactly v0.24.6; found '$tag'."
}

cmake -S $sourcePath -B $buildPath -G 'NMake Makefiles' -DCMAKE_BUILD_TYPE=Release -DUSE_GNUTLS=0 -DUSE_NICE=0
if ($LASTEXITCODE -ne 0) { throw 'CMake configuration failed.' }
cmake --build $buildPath --config Release --parallel
if ($LASTEXITCODE -ne 0) { throw 'The libdatachannel build failed.' }

$library = Get-ChildItem -LiteralPath $buildPath -Filter datachannel.dll -File -Recurse | Select-Object -First 1
if (-not $library) { throw 'Build succeeded but datachannel.dll was not found in the CMake output.' }
New-Item -ItemType Directory -Force -Path $outputPath | Out-Null
Copy-Item -LiteralPath $library.FullName -Destination (Join-Path $outputPath 'datachannel.dll') -Force
$hash = (Get-FileHash -LiteralPath (Join-Path $outputPath 'datachannel.dll') -Algorithm SHA256).Hash.ToLowerInvariant()
Set-Content -LiteralPath (Join-Path $outputPath 'datachannel.dll.sha256') -Value $hash -Encoding ascii
Write-Output "Built pinned libdatachannel v0.24.6: $outputPath\datachannel.dll"
Write-Output "SHA-256: $hash"
