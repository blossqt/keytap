r"""Setting Keytap up as a passkey provider: its small package, which gives it the identity
Windows asks of passkey providers.

Three steps, the first once per PC (Settings > Passkeys walks through them):

1. Trust Keytap's certificate (package\Keytap.cer). Windows installs packages
   only from signers the whole PC trusts, so this is an administrator prompt.
2. Register Keytap's package (package\Keytap.msix), pointing at the folder
   Keytap.exe is in. It holds no files; no prompt.
3. Start Keytap again - it now runs as its package - and switch it on in
   Windows' passkey settings.

Each of these waits on Windows or on the person, so they run off the UI thread.
"""

from __future__ import annotations

import base64
import ctypes
import hashlib
import json
import os
import subprocess
import sys
import xml.etree.ElementTree as ET
from ctypes import byref, c_void_p, c_wchar_p
from ctypes import wintypes as w
from pathlib import Path

PACKAGE = 'Blossqt.Keytap'
CREATE_NO_WINDOW = 0x08000000


class SetupError(Exception):
    """Why a step did not work, in words fit to show."""


def folder() -> Path | None:
    """Where Keytap.exe is - None when running from source, which has no package."""
    return Path(sys.executable).parent if getattr(sys, 'frozen', False) else None


def _file(name: str) -> Path | None:
    base = folder()
    path = base / 'package' / name if base else None
    return path if path and path.exists() else None


def unavailable() -> str:
    """'' if this Keytap can set up passkeys, else why not."""
    from . import provider
    if not provider.supported():
        return "This Windows can't take passkey providers yet: it needs Windows 11 24H2 or later, updated."
    if folder() is None:
        return 'Passkeys work in the installed Keytap.exe, not in Keytap run from source.'
    if not _file('Keytap.msix') or not _file('Keytap.cer'):
        return 'This copy of Keytap was built without its package.'
    return ''


def bundled_version() -> str:
    """The version of the package beside Keytap.exe, from its manifest (inside the .msix)."""
    import zipfile
    msix = _file('Keytap.msix')
    if not msix:
        return ''
    with zipfile.ZipFile(msix) as archive:
        root = ET.fromstring(archive.read('AppxManifest.xml'))
    identity = root.find('{http://schemas.microsoft.com/appx/manifest/foundation/windows10}Identity')
    return identity.get('Version', '') if identity is not None else ''


# --------------------------------------------------------------------------- the certificate

class _HashBlob(ctypes.Structure):
    _fields_ = [('cbData', w.DWORD), ('pbData', ctypes.POINTER(ctypes.c_ubyte))]


def certificate_trusted() -> bool:
    """Whether the PC trusts Keytap's certificate (Local Machine > Trusted People)."""
    cer = _file('Keytap.cer')
    if not cer:
        return False
    thumbprint = hashlib.sha1(cer.read_bytes()).digest()
    crypt32 = ctypes.WinDLL('crypt32')
    crypt32.CertOpenStore.restype = c_void_p
    crypt32.CertOpenStore.argtypes = [c_void_p, w.DWORD, c_void_p, w.DWORD, c_void_p]
    crypt32.CertFindCertificateInStore.restype = c_void_p
    crypt32.CertFindCertificateInStore.argtypes = [c_void_p, w.DWORD, w.DWORD, w.DWORD, c_void_p, c_void_p]
    crypt32.CertFreeCertificateContext.argtypes = [c_void_p]
    crypt32.CertCloseStore.argtypes = [c_void_p, w.DWORD]
    store = crypt32.CertOpenStore(c_void_p(10), 0, None, 0x20000 | 0x8000 | 0x4000,     # system store, local machine,
                                  c_wchar_p('TrustedPeople'))                          # read-only, existing
    if not store:
        return False
    try:
        data = (ctypes.c_ubyte * len(thumbprint)).from_buffer_copy(thumbprint)
        blob = _HashBlob(len(thumbprint), data)
        found = crypt32.CertFindCertificateInStore(store, 0x10001, 0, 0x10000, byref(blob), None)   # by SHA-1
        if found:
            crypt32.CertFreeCertificateContext(found)
        return bool(found)
    finally:
        crypt32.CertCloseStore(store, 0)


class _ShellExecuteInfo(ctypes.Structure):
    _fields_ = [('cbSize', w.DWORD), ('fMask', w.ULONG), ('hwnd', w.HWND), ('lpVerb', c_wchar_p),
                ('lpFile', c_wchar_p), ('lpParameters', c_wchar_p), ('lpDirectory', c_wchar_p), ('nShow', ctypes.c_int),
                ('hInstApp', w.HINSTANCE), ('lpIDList', c_void_p), ('lpClass', c_wchar_p), ('hkeyClass', w.HKEY),
                ('dwHotKey', w.DWORD), ('hIcon', w.HANDLE), ('hProcess', w.HANDLE)]


def trust_certificate() -> bool:
    """Ask Windows - an administrator prompt the person answers - to trust Keytap's certificate.
    False if they said no."""
    cer = _file('Keytap.cer')
    if not cer:
        raise SetupError('Keytap\'s certificate is missing from its folder - reinstall Keytap.')
    command = (f"Import-Certificate -FilePath '{cer}' -CertStoreLocation Cert:\\LocalMachine\\TrustedPeople "
               '| Out-Null')
    info = _ShellExecuteInfo()
    info.cbSize = ctypes.sizeof(info)
    info.fMask = 0x40                                    # SEE_MASK_NOCLOSEPROCESS
    info.lpVerb, info.lpFile = 'runas', 'powershell.exe'
    info.lpParameters = f'-NoProfile -NonInteractive -WindowStyle Hidden -Command "{command}"'
    info.nShow = 0
    shell32, kernel32 = ctypes.WinDLL('shell32', use_last_error=True), ctypes.WinDLL('kernel32')
    if not shell32.ShellExecuteExW(byref(info)):
        if ctypes.get_last_error() == 1223:              # ERROR_CANCELLED: no at the prompt
            return False
        raise SetupError(f'Windows did not start the certificate step (error {ctypes.get_last_error()}).')
    kernel32.WaitForSingleObject(info.hProcess, 0xFFFFFFFF)
    code = w.DWORD()
    kernel32.GetExitCodeProcess(info.hProcess, byref(code))
    kernel32.CloseHandle(info.hProcess)
    if code.value != 0 or not certificate_trusted():
        raise SetupError('Windows did not take Keytap\'s certificate.')
    return True


# --------------------------------------------------------------------------- the package

def _powershell(script: str) -> str:
    done = subprocess.run(['powershell', '-NoProfile', '-NonInteractive', '-Command', script],
                          capture_output=True, text=True, creationflags=CREATE_NO_WINDOW, timeout=120)
    if done.returncode != 0:
        lines = [line for line in (done.stderr or done.stdout).splitlines() if line.strip()]
        raise SetupError(lines[0].strip() if lines else f'PowerShell failed ({done.returncode})')
    return done.stdout


def registered() -> dict | None:
    """Keytap's package as Windows has it: {'name', 'version', 'location'} - or None."""
    out = _powershell(f"Get-AppxPackage -Name '{PACKAGE}' | Select-Object PackageFullName, Version, InstallLocation "
                      '| ConvertTo-Json -Compress')
    if not out.strip():
        return None
    found = json.loads(out)
    found = found[0] if isinstance(found, list) else found
    return {'name': found.get('PackageFullName', ''), 'version': found.get('Version', ''),
            'location': found.get('InstallLocation', '') or ''}


def register() -> None:
    """Register Keytap's package for this folder, replacing one for another folder or an older one."""
    msix, here = _file('Keytap.msix'), folder()
    if not msix or not here:
        raise SetupError('Keytap\'s package is missing from its folder - reinstall Keytap.')
    current = registered()
    if current is not None:
        _powershell(f"Remove-AppxPackage -Package '{current['name']}'")
    _powershell(f"Add-AppxPackage -Path '{msix}' -ExternalLocation '{here}'")


def unregister() -> None:
    current = registered()
    if current is not None:
        _powershell(f"Remove-AppxPackage -Package '{current['name']}'")


def needs_registering() -> bool:
    """Whether this Keytap must register its package: it is missing, or for another folder.

    Windows doesn't say which folder a package with an external location points
    at (its InstallLocation is a WindowsApps folder of its own), but it gives the
    identity to Keytap.exe only in that folder - so a Keytap running without it
    has no package for its own folder."""
    from . import provider
    return not provider.identity()


def running_version() -> str:
    """The version of the package this Keytap runs as ('' for none), from its full name
    (Blossqt.Keytap_1.0.1.0_x64__...)."""
    from . import provider
    parts = provider.identity().split('_')
    return parts[1] if len(parts) > 2 else ''


def outdated() -> bool:
    """Whether this Keytap runs as an older package than the one beside Keytap.exe."""
    running = running_version()
    return bool(running) and _version(running) < _version(bundled_version())


def update_and_restart(args: list[str]) -> None:
    """Once this Keytap has quit, update the package to the one beside Keytap.exe and start
    Keytap again with args.

    Windows updates a package only once every program running as it has closed, and an
    update tried while one runs leaves the package unable to start anything. So a PowerShell
    does it - a program Keytap starts doesn't run as its package - after this Keytap has gone.
    In place, as an update, not removed and added again. Should Windows still leave the
    package broken, it is removed: Keytap then starts without it, and Settings > Passkeys
    sets it up again."""
    msix, here = _file('Keytap.msix'), folder()
    if not msix or not here:
        raise SetupError("Keytap's package is missing from its folder - reinstall Keytap.")

    def quoted(text) -> str:
        return "'" + str(text).replace("'", "''") + "'"
    script = '\n'.join([
        f'Wait-Process -Id {os.getpid()} -Timeout 30 -ErrorAction SilentlyContinue',
        f'try {{ Add-AppxPackage -Path {quoted(msix)} -ExternalLocation {quoted(here)} -ForceApplicationShutdown '
        '-ErrorAction Stop } catch { }',
        f"$package = Get-AppxPackage -Name {PACKAGE}",
        "if ($package -and $package.Status -ne 'Ok') { Remove-AppxPackage -Package $package.PackageFullName }",
        f"Start-Process -FilePath {quoted(sys.executable)} -ArgumentList @({', '.join(quoted(a) for a in args)})",
    ])
    encoded = base64.b64encode(script.encode('utf-16-le')).decode('ascii')
    subprocess.Popen(['powershell', '-NoProfile', '-NonInteractive', '-EncodedCommand', encoded],
                     creationflags=CREATE_NO_WINDOW, close_fds=True)


def _version(text: str) -> tuple:
    try:
        return tuple(int(part) for part in text.split('.'))
    except ValueError:
        return ()
