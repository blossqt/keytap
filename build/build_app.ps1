# Packages Keytap into dist\Keytap\Keytap.exe together with Bitwarden's CLI.
#
#   powershell -ExecutionPolicy Bypass -File build\build_app.ps1
#
# Needs bootstrap.ps1 (venv + bw).

$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'

$Root  = Split-Path -Parent $PSScriptRoot
$Cache = Join-Path $env:LOCALAPPDATA 'KeytapBuild'
$Venv  = Join-Path $Cache 'venv'
$Comp  = Join-Path $Cache 'components'
$Py    = Join-Path $Venv 'Scripts\python.exe'
$Dist  = Join-Path $Root 'dist\Keytap'
$Tools = Join-Path $Dist 'tools'

function Fail($msg) { Write-Host "ERROR: $msg" -ForegroundColor Red; exit 1 }

if (-not (Test-Path $Py)) { Fail "venv missing - run build\bootstrap.ps1 first" }
# PyInstaller empties dist\Keytap first and stops at the first file in use,
# which leaves a running copy with half its files gone.
$Running = Get-Process -Name Keytap -ErrorAction SilentlyContinue |
    Where-Object { $_.Path -and $_.Path -like (Join-Path $Dist '*') }
if ($Running) { Fail "Keytap is running from $Dist - quit it from the tray first" }
if (-not (Test-Path (Join-Path $Comp 'bw\bw.exe'))) { Fail "Bitwarden CLI missing - run build\bootstrap.ps1 first" }

# Every module must at least import before it is packaged: a mistake caught
# here prints a traceback, where the windowed exe would put up an error box.
Write-Host '>> import check'
& $Py -c "import sys; sys.path.insert(0, r'$Root\app'); import keytap.app"
if ($LASTEXITCODE -ne 0) { Fail 'Keytap does not import - fix the error above' }

Write-Host '>> UI Automation wrappers'
& $Py -c "import comtypes.client; comtypes.client.GetModule('UIAutomationCore.dll'); from comtypes.gen import UIAutomationClient"
if ($LASTEXITCODE -ne 0) { Fail 'comtypes could not read UIAutomationCore.dll' }

Write-Host '>> icon'
& $Py (Join-Path $PSScriptRoot 'make_icon.py')
if ($LASTEXITCODE -ne 0) { Fail 'icon generation failed' }

Write-Host '>> PyInstaller'
Push-Location $Root
& $Py -m PyInstaller --noconfirm --clean --distpath (Join-Path $Root 'dist') `
    --workpath (Join-Path $Cache 'pyinstaller') (Join-Path $PSScriptRoot 'keytap.spec')
$code = $LASTEXITCODE
Pop-Location
if ($code -ne 0) { Fail "PyInstaller failed ($code)" }
if (-not (Test-Path (Join-Path $Dist 'Keytap.exe'))) { Fail 'Keytap.exe was not produced' }

Write-Host '>> bundling the Bitwarden CLI'
New-Item -ItemType Directory -Force (Join-Path $Tools 'bw') | Out-Null
Copy-Item (Join-Path $Comp 'bw\*') (Join-Path $Tools 'bw') -Force -Recurse

# Keytap's package (package\Keytap.msix, signed, with its certificate and logos):
# the identity Windows asks of passkey providers. See make_package.py.
Write-Host '>> package'
& $Py (Join-Path $PSScriptRoot 'make_package.py')
if ($LASTEXITCODE -ne 0) { Fail 'packaging failed' }

Copy-Item (Join-Path $Root 'README.md') $Dist -Force -ErrorAction SilentlyContinue
Copy-Item (Join-Path $Root 'THIRD-PARTY-NOTICES.md') $Dist -Force -ErrorAction SilentlyContinue
Copy-Item (Join-Path $Root 'LICENSE') $Dist -Force -ErrorAction SilentlyContinue

# Does it start? A build can come out of PyInstaller without complaint and
# still be unable to open a window. --self-test loads what a real start loads,
# runs the bundled bw, and answers with both versions.
$Answer = Join-Path $env:TEMP "keytap-build-self-test-$PID.txt"
Remove-Item $Answer -ErrorAction SilentlyContinue
$Probe = Start-Process -FilePath (Join-Path $Dist 'Keytap.exe') -ArgumentList '--self-test', "`"$Answer`"" -PassThru
if (-not $Probe.WaitForExit(120000)) { $Probe.Kill(); Fail 'the built Keytap.exe hung when started (--self-test)' }
$Said = if (Test-Path $Answer) { (Get-Content -Raw $Answer).Trim() } else { '' }
Remove-Item $Answer -ErrorAction SilentlyContinue
if (-not $Said) { Fail 'the built Keytap.exe does not start (--self-test gave no answer)' }
if ($Said.StartsWith('FAILED')) { Fail "the built Keytap.exe starts but its self-test failed: $Said" }
Write-Host ">> it starts: Keytap $Said"

$size = (Get-ChildItem $Dist -Recurse -File | Measure-Object Length -Sum).Sum
Write-Host ('>> done: {0}  ({1:N0} MB)' -f (Join-Path $Dist 'Keytap.exe'), ($size / 1MB))
