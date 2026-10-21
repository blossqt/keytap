# Keytap build bootstrap - fetches everything needed to run and build Keytap.
#
#   powershell -ExecutionPolicy Bypass -File build\bootstrap.ps1 [-Part all|python|components]
#
# Everything heavy lives in %LOCALAPPDATA%\KeytapBuild so the project folder
# stays small. Delete that folder any time; this script recreates it.
#   venv\        Python venv with PySide6 and PyInstaller
#   components\  bw\ - Bitwarden's CLI, bundled into the app beside Keytap.exe
#                sdk\ - Microsoft's makeappx and signtool, which build Keytap's package
# The script is idempotent: finished steps are skipped on re-run.

param(
    [ValidateSet('all', 'python', 'components')]
    [string]$Part = 'all'
)

$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'

$Cache = Join-Path $env:LOCALAPPDATA 'KeytapBuild'
$Dl    = Join-Path $Cache 'downloads'
$Venv  = Join-Path $Cache 'venv'
$Comp  = Join-Path $Cache 'components'
New-Item -ItemType Directory -Force $Dl, $Comp | Out-Null
# Windows' own tar (bsdtar), which reads zips - not a Git tar that may come first on PATH.
$Tar = Join-Path $env:SystemRoot 'System32\tar.exe'

# Bitwarden's open-source build of its CLI (GPL-3.0, no Bitwarden-licensed
# code), pinned to one release and checked against the digest GitHub lists for
# it. To move to a newer one, take both from
#   gh api repos/bitwarden/clients/releases/tags/cli-v<version>
$BwVersion = '2026.10.0'
$BwSha256  = '2711c0e9527bbc88ecda4b884f4f1cff896e727cf6d7e82324dce2476fa1ef03'

# Microsoft's Windows SDK build tools (makeappx, signtool), from its NuGet
# package, for the small package that makes Keytap a passkey provider
# (build\make_package.py). Pinned with the digest of the .nupkg.
$SdkVersion = '10.0.28000.2705'
$SdkBin     = 'bin/10.0.28000.0/x64'
$SdkSha256  = '8bfdfb6ca2633f531cf80b5fa22512ba61a394d7988f0970db83baadc67929ed'

function Fail($msg) { Write-Host "ERROR: $msg" -ForegroundColor Red; exit 1 }

function Get-File($url, $dest, $sha256) {
    if (-not (Test-Path $dest)) {
        Write-Host "fetch   $url"
        & curl.exe -L --fail --retry 3 --silent --show-error -o "$dest.part" $url
        if ($LASTEXITCODE -ne 0) { Fail "download failed: $url" }
        Move-Item -Force "$dest.part" $dest
    } else { Write-Host "cached  $dest" }
    $got = (Get-FileHash -Algorithm SHA256 $dest).Hash.ToLower()
    if ($got -ne $sha256) {
        Remove-Item -Force $dest
        Fail "checksum mismatch for $(Split-Path -Leaf $dest): got $got, expected $sha256"
    }
}

# --------------------------------------------------------------------------- Python
if ($Part -in 'all', 'python') {
    $py = Join-Path $Venv 'Scripts\python.exe'
    if (-not (Test-Path $py)) {
        Write-Host "venv    $Venv"
        & py -3.12 -m venv $Venv
        if ($LASTEXITCODE -ne 0) { Fail 'venv creation failed (needs Python 3.12 via the py launcher)' }
    }
    & $py -m pip install --disable-pip-version-check --upgrade pip | Out-Null
    & $py -m pip install --disable-pip-version-check -r (Join-Path $PSScriptRoot 'requirements.txt')
    if ($LASTEXITCODE -ne 0) { Fail 'pip install failed' }
    Write-Host 'Python venv ready'
}

# --------------------------------------------------------------------------- Bitwarden CLI
if ($Part -in 'all', 'components') {
    $zip = Join-Path $Dl "bw-oss-windows-$BwVersion.zip"
    Get-File "https://github.com/bitwarden/clients/releases/download/cli-v$BwVersion/bw-oss-windows-$BwVersion.zip" $zip $BwSha256
    $bwDir = Join-Path $Comp 'bw'
    $stamp = Join-Path $bwDir 'VERSION.txt'
    $have = if (Test-Path $stamp) { (Get-Content -Raw $stamp).Trim() } else { '' }
    if ($have -ne $BwVersion -or -not (Test-Path (Join-Path $bwDir 'bw.exe'))) {
        Remove-Item -Recurse -Force $bwDir -ErrorAction SilentlyContinue
        New-Item -ItemType Directory -Force $bwDir | Out-Null
        & $Tar -xf $zip -C $bwDir
        if (-not (Test-Path (Join-Path $bwDir 'bw.exe'))) { Fail 'bw.exe not found in archive' }
        Set-Content -Path $stamp -Value $BwVersion -Encoding ascii
    }
    Write-Host "components ready (Bitwarden CLI $BwVersion)"

    $nupkg = Join-Path $Dl "microsoft.windows.sdk.buildtools.$SdkVersion.nupkg"
    Get-File "https://api.nuget.org/v3-flatcontainer/microsoft.windows.sdk.buildtools/$SdkVersion/microsoft.windows.sdk.buildtools.$SdkVersion.nupkg" $nupkg $SdkSha256
    $sdkDir = Join-Path $Comp 'sdk'
    $stamp = Join-Path $sdkDir 'VERSION.txt'
    $have = if (Test-Path $stamp) { (Get-Content -Raw $stamp).Trim() } else { '' }
    if ($have -ne $SdkVersion) {
        Remove-Item -Recurse -Force $sdkDir -ErrorAction SilentlyContinue
        New-Item -ItemType Directory -Force (Join-Path $sdkDir 'pkg') | Out-Null
        & $Tar -xf $nupkg -C (Join-Path $sdkDir 'pkg') $SdkBin
        if (-not (Test-Path (Join-Path $sdkDir "pkg/$SdkBin/makeappx.exe"))) { Fail 'makeappx.exe not found in the SDK package' }
        Set-Content -Path $stamp -Value $SdkVersion -Encoding ascii
    }
    Write-Host "components ready (SDK build tools $SdkVersion)"
}
