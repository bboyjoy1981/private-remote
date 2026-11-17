[CmdletBinding()]
param([string]$PythonExecutable = (Join-Path $env:USERPROFILE '.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe'))

$ErrorActionPreference = 'Stop'
$repositoryRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
Push-Location $repositoryRoot
try {
    $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    $installationPath = & $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
    if (-not $installationPath) { throw 'Install the Microsoft C++ Build Tools first.' }
    & (Join-Path $installationPath 'Common7\Tools\Launch-VsDevShell.ps1') -Arch amd64 -HostArch amd64 -SkipAutomaticLocation
    $env:VSLANG = '1033' # Ninja must consistently recognize MSVC include-dependency output.
    $cmakeRoot = Join-Path $installationPath 'Common7\IDE\CommonExtensions\Microsoft\CMake'
    $env:PATH = (Join-Path $cmakeRoot 'CMake\bin') + [IO.Path]::PathSeparator + (Join-Path $cmakeRoot 'Ninja') + [IO.Path]::PathSeparator + $env:PATH
    if (-not (Test-Path -LiteralPath $PythonExecutable)) { throw 'Supply -PythonExecutable with a Python 3 executable.' }
    New-Item -ItemType Directory -Force -Path '.native', 'artifacts/native' | Out-Null

    $sources = @(
        @{Name='libdatachannel-v0.24.6'; Repo='paullouisageneau/libdatachannel'; Ref='refs/tags/v0.24.6'; Hash='c78ca1b7ce45f08c7e6233eba4d714bde10c6e3a4e60aad0be891e2594807519'; Directory='source-archive'},
        @{Name='plog'; Repo='SergiusTheBest/plog'; Ref='94899e0b926ac1b0f4750bfbd495167b4a6ae9ef'; Hash='195415f664dccc6682c344ca0e1966674555f0be07e9552d4f760860acce719d'},
        @{Name='usrsctp'; Repo='paullouisageneau/usrsctp'; Ref='fec583d54493f879d2ae44a743423bf8a04371ab'; Hash='752b4337bece1138f4f4151cec4240956a7230b007e11bc1a6915cbda58d7086'},
        @{Name='libjuice'; Repo='paullouisageneau/libjuice'; Ref='b89c792e3612faf2f12cf35bcc56857313a06be3'; Hash='c937ec97110b559e4a27885a3098c7a65dad2459c813569441a1329f74662381'},
        @{Name='libsrtp'; Repo='cisco/libsrtp'; Ref='24b3bf8f19b6f5ab4cd2bcceb4f4064efca86fd5'; Hash='76f2decca689144058bcade866c1bd9f5649ac466806ba090dcc368db5525d5f'},
        @{Name='mbedtls'; Repo='Mbed-TLS/mbedtls'; Ref='mbedtls-3.6.7'; Hash='d359314abc9bced38ddf9f0f9423e8c1c5084113a00f26d6864e1ceea6bf1153'},
        @{Name='mbedtls-framework'; Repo='Mbed-TLS/mbedtls-framework'; Ref='dde0c4a0e448a0552f18817dcea633bb851fd288'; Hash='2808e7a9b6fd87f294d1423bb29984057d0654b4f0d70b0d9cf085e887472337'}
    )
    $roots = @{}
    foreach ($source in $sources) {
        $archive = Join-Path '.native' ($source.Name + '.zip')
        if (-not (Test-Path -LiteralPath $archive)) {
            curl.exe --silent --show-error --ssl-revoke-best-effort --fail --location --connect-timeout 15 --max-time 120 --output $archive "https://codeload.github.com/$($source.Repo)/zip/$($source.Ref)"
            if ($LASTEXITCODE -ne 0) { throw "Download failed: $($source.Name)" }
        }
        if ((Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant() -ne $source.Hash) {
            throw "Archive hash mismatch: $($source.Name). Refusing to build changed source."
        }
        $destination = if ($source.Directory) { Join-Path '.native' $source.Directory } else { Join-Path '.native/expanded' $source.Name }
        Expand-Archive -LiteralPath $archive -DestinationPath $destination -Force
        $rootDirectories = @(Get-ChildItem -LiteralPath $destination -Directory)
        if ($rootDirectories.Count -ne 1) { throw "Unexpected archive layout: $($source.Name)" }
        $roots[$source.Name] = $rootDirectories[0].FullName
    }
    $dataSource = $roots['libdatachannel-v0.24.6']
    $mbedSource = $roots['mbedtls']
    foreach ($dependency in @('plog', 'usrsctp', 'libjuice', 'libsrtp')) {
        Copy-Item -Path (Join-Path $roots[$dependency] '*') -Destination (Join-Path $dataSource "deps/$dependency") -Recurse -Force
    }
    Copy-Item -Path (Join-Path $roots['mbedtls-framework'] '*') -Destination (Join-Path $mbedSource 'framework') -Recurse -Force
    Push-Location $mbedSource
    try {
        & $PythonExecutable scripts/config.py set MBEDTLS_SSL_DTLS_SRTP
        if ($LASTEXITCODE -ne 0) { throw 'Could not enable the required DTLS-SRTP extension.' }
    } finally { Pop-Location }
    $mbedPrefix = Join-Path $repositoryRoot '.native/mbedtls-install'
    cmake -S $mbedSource -B .native/build-mbedtls -G Ninja -DCMAKE_BUILD_TYPE=Release -DENABLE_TESTING=OFF -DENABLE_PROGRAMS=OFF -DUSE_SHARED_MBEDTLS_LIBRARY=OFF -DUSE_STATIC_MBEDTLS_LIBRARY=ON "-DCMAKE_INSTALL_PREFIX=$mbedPrefix" "-DPython3_EXECUTABLE=$PythonExecutable" *> .native/mbedtls-configure.log
    if ($LASTEXITCODE -ne 0) { throw 'Mbed TLS configuration failed; see .native/mbedtls-configure.log.' }
    cmake --build .native/build-mbedtls --parallel 4 *> .native/mbedtls-build.log
    if ($LASTEXITCODE -ne 0) { throw 'Mbed TLS build failed; see .native/mbedtls-build.log.' }
    cmake --install .native/build-mbedtls *> .native/mbedtls-install.log
    if ($LASTEXITCODE -ne 0) { throw 'Mbed TLS installation into the workspace failed.' }
    cmake -S $dataSource -B .native/build-datachannel -G Ninja -DCMAKE_BUILD_TYPE=Release -DUSE_MBEDTLS=ON -DUSE_GNUTLS=OFF -DUSE_NICE=OFF -DNO_EXAMPLES=ON -DNO_TESTS=ON -DNO_WEBSOCKET=ON "-DCMAKE_PREFIX_PATH=$mbedPrefix" *> .native/datachannel-configure.log
    if ($LASTEXITCODE -ne 0) { throw 'libdatachannel configuration failed; see .native/datachannel-configure.log.' }
    cmake --build .native/build-datachannel --parallel 4 *> .native/datachannel-build.log
    if ($LASTEXITCODE -ne 0) { throw 'libdatachannel build failed; see .native/datachannel-build.log.' }
    Copy-Item -LiteralPath .native/build-datachannel/datachannel.dll -Destination artifacts/native/datachannel.dll -Force
    $dllHash = (Get-FileHash artifacts/native/datachannel.dll -Algorithm SHA256).Hash.ToLowerInvariant()
    Set-Content artifacts/native/datachannel.dll.sha256 -Value $dllHash -Encoding ascii
    foreach ($name in $roots.Keys) {
        $licenseDirectory = Join-Path 'artifacts/native/licenses' $name
        New-Item -ItemType Directory -Force -Path $licenseDirectory | Out-Null
        Get-ChildItem -LiteralPath $roots[$name] -File | Where-Object Name -match '^(LICENSE|COPYING|NOTICE)' | Copy-Item -Destination $licenseDirectory -Force
    }
    Get-ChildItem (Join-Path $mbedSource '3rdparty') -Recurse -File | Where-Object Name -match '^(LICENSE|COPYING|NOTICE)' | ForEach-Object {
        $relativeLicense = [IO.Path]::GetRelativePath($mbedSource, $_.FullName)
        $target = Join-Path 'artifacts/native/licenses/mbedtls' $relativeLicense
        New-Item -ItemType Directory -Force -Path (Split-Path -Parent $target) | Out-Null
        Copy-Item -LiteralPath $_.FullName -Destination $target -Force
    }
    @{Version='0.24.6'; Architecture='x64'; Media=$true; NativeWebSocket=$false; Tls='Mbed TLS 3.6.7 with DTLS-SRTP'; DllSha256=$dllHash; Sources=$sources} | ConvertTo-Json -Depth 5 | Set-Content artifacts/native/build-info.json -Encoding utf8
    & (Join-Path $PSScriptRoot 'test-native-library.ps1')
    & (Join-Path $PSScriptRoot 'test-native-loopback.ps1')
    Write-Output "Built verified libdatachannel v0.24.6 x64 with media support: artifacts/native/datachannel.dll (SHA-256 $dllHash)"
} finally { Pop-Location }
