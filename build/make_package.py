r"""Keytap's package, which gives Keytap.exe the identity Windows asks of passkey providers.

    python build\make_package.py              pack and sign dist\Keytap\package\Keytap.msix
    python build\make_package.py --make-key   once: Keytap's package-signing certificate

The package holds only package\AppxManifest.xml: it points at the folder
Keytap.exe is in. Windows installs it only signed by a certificate the PC
trusts, so Keytap ships the certificate (package\Keytap.cer) and asks once,
with an administrator prompt, to trust it (Settings > Passkeys).

The certificate's key lives in ~\.keytap\release\, beside the update-signing
key, and must never be replaced: a PC that trusts the old certificate would
refuse packages signed with a new one.
"""

from __future__ import annotations

import os
import secrets
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DIST = ROOT / 'dist' / 'Keytap'
TEMPLATE = ROOT / 'build' / 'package'
KEYS = Path.home() / '.keytap' / 'release'
PFX, PASSWORD = KEYS / 'package-signing.pfx', KEYS / 'package-signing.password'
PUBLISHER = 'CN=blossqt'
TOOLS = Path(os.environ.get('LOCALAPPDATA', '')) / 'KeytapBuild' / 'components' / 'sdk'


def tool(name: str) -> Path:
    found = sorted(TOOLS.glob(f'**/x64/{name}'))
    if not found:
        raise SystemExit(f'{name} is missing - run build\\bootstrap.ps1')
    # Run from a copy in %TEMP%: from inside the Claude app, %LOCALAPPDATA% is redirected to a
    # path long enough that Windows can't load the tools' side-by-side DLLs ("configuration is incorrect").
    short = Path(tempfile.gettempdir()) / f'keytap-sdk-{found[-1].parent.parent.name}'
    if not (short / name).exists():
        shutil.copytree(found[-1].parent, short, dirs_exist_ok=True)
    return short / name


def make_key() -> None:
    if PFX.exists():
        raise SystemExit(f'{PFX} exists already - never replace it (PCs trust its certificate)')
    KEYS.mkdir(parents=True, exist_ok=True)
    password = secrets.token_urlsafe(24)
    script = f"""
$ErrorActionPreference = 'Stop'
$cert = New-SelfSignedCertificate -Type Custom -Subject '{PUBLISHER}' -FriendlyName 'Keytap package signing' `
    -KeyUsage DigitalSignature -KeyAlgorithm RSA -KeyLength 3072 -HashAlgorithm SHA256 -KeyExportPolicy Exportable `
    -CertStoreLocation 'Cert:\\CurrentUser\\My' -NotAfter (Get-Date).AddYears(25) `
    -TextExtension @('2.5.29.37={{text}}1.3.6.1.5.5.7.3.3', '2.5.29.19={{text}}')
$secret = ConvertTo-SecureString -String $env:KEYTAP_PFX_PASSWORD -AsPlainText -Force
Export-PfxCertificate -Cert $cert -FilePath '{PFX}' -Password $secret | Out-Null
Export-Certificate -Cert $cert -FilePath '{TEMPLATE / "Keytap.cer"}' | Out-Null
Remove-Item -Path $cert.PSPath -DeleteKey
Write-Output $cert.Thumbprint
"""
    done = subprocess.run(['powershell', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', script],
                          capture_output=True, text=True, env=dict(os.environ, KEYTAP_PFX_PASSWORD=password))
    if done.returncode != 0:
        raise SystemExit(done.stderr or done.stdout)
    PASSWORD.write_text(password, encoding='ascii')
    print(f'certificate {done.stdout.strip()} - key in {PFX}; public half in {TEMPLATE / "Keytap.cer"}')
    print('Back the key and its password up. Never replace them.')


def logos(folder: Path) -> None:
    os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')
    sys.path.insert(0, str(ROOT / 'app'))
    from PySide6.QtGui import QGuiApplication
    app = QGuiApplication.instance() or QGuiApplication([])  # noqa: F841 - Qt needs one to draw
    from keytap.ui import icons
    for size in (44, 50, 150):
        icons.render_app_icon(size).save(str(folder / f'logo-{size}.png'))


def build() -> None:
    if not (DIST / 'Keytap.exe').exists():
        raise SystemExit(f'{DIST} has no Keytap.exe - build it first')
    out = DIST / 'package'
    out.mkdir(exist_ok=True)
    shutil.copy2(TEMPLATE / 'Keytap.cer', out / 'Keytap.cer')
    logos(out)
    if not PFX.exists():
        print('WARNING: no package-signing key - this build cannot set up passkeys (build\\make_package.py --make-key)')
        return
    msix = out / 'Keytap.msix'
    with tempfile.TemporaryDirectory(prefix='keytap-package-') as staging:
        shutil.copy2(TEMPLATE / 'AppxManifest.xml', Path(staging) / 'AppxManifest.xml')
        # /nv: the logos and the exe are in Keytap's folder, not in the package.
        subprocess.run([str(tool('makeappx.exe')), 'pack', '/o', '/nv', '/d', staging, '/p', str(msix)],
                       check=True, capture_output=True)
    subprocess.run([str(tool('signtool.exe')), 'sign', '/q', '/fd', 'SHA256', '/f', str(PFX), '/p',
                    PASSWORD.read_text(encoding='ascii').strip(), str(msix)], check=True)
    print(f'package: {msix}')


if __name__ == '__main__':
    make_key() if '--make-key' in sys.argv else build()
