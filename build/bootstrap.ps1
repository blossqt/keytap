# Keytap build bootstrap - fetches everything needed to run and build Keytap.
#
#   powershell -ExecutionPolicy Bypass -File build\bootstrap.ps1 [-Part all|python|components]
#
# Everything heavy lives in %LOCALAPPDATA%\KeytapBuild so the project folder
# stays small. Delete that folder any time; this script recreates it.
#   venv\        Python venv with PySide6 and PyInstaller
#   components\  bw\ - Bitwarden's CLI, bundled into the app beside Keytap.exe
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

# Bitwarden's open-source build of its CLI (GPL-3.0, no Bitwarden-licensed
# code), pinned to one release and checked against the digest GitHub lists for
# it. To move to a newer one, take both from
#   gh api repos/bitwarden/clients/releases/tags/cli-v<version>
$BwVersion = '2026.10.0'
$BwSha256  = '2711c0e9527bbc88ecda4b884f4f1cff896e727cf6d7e82324dce2476fa1ef03'

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
        & tar.exe -xf $zip -C $bwDir
        if (-not (Test-Path (Join-Path $bwDir 'bw.exe'))) { Fail 'bw.exe not found in archive' }
        Set-Content -Path $stamp -Value $BwVersion -Encoding ascii
    }
    Write-Host "components ready (Bitwarden CLI $BwVersion)"
}
