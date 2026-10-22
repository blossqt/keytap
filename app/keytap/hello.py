r"""Unlocking with Windows Hello - a fingerprint, the face camera or the PIN -
instead of typing the master password.

It works as Bitwarden's desktop app does:

- Turning it on makes a Windows Hello key for Keytap. Windows keeps it in the
  PC's security chip where there is one, and uses it only once Windows Hello
  has checked it is you.
- Keytap has the key sign a random challenge. The signature comes out the same
  every time, so it can serve as a key itself: hashed, it seals the master
  password through Windows' DPAPI, which ties it to your Windows account too.
  The sealed password and the challenge are kept in %APPDATA%\Keytap\hello.json,
  useless without Windows Hello.
- Unlocking asks Windows Hello to sign the challenge again, opens the seal with
  the signature, and unlocks Bitwarden's tool with the password.
- Bitwarden's tool takes seconds to unlock and list the logins, so Keytap also
  keeps a copy of the logins, sealed the same way (with a key of its own that
  the signature seals - kept_logins). Windows Hello opens it at once, and the
  tool unlocks and lists the logins meanwhile, for anything changed.

Turning it off forgets the sealed password and logins and deletes the key.
Every call here waits on Windows Hello or the person, so they run off the UI
thread.
"""

from __future__ import annotations

import asyncio
import base64
import ctypes
import hashlib
import json
import os
import threading
import time
from ctypes import wintypes
from pathlib import Path
from typing import NamedTuple

from . import win32
from .vault import Login, VaultError, logins_from_json, logins_to_json

KEY_NAME = 'Keytap'
# Windows Hello's prompt, which can open behind other windows: Keytap brings it forward.
_PROMPT_CLASS = 'Credential Dialog Xaml Host'


class HelloError(VaultError):
    """Why Windows Hello did not unlock, in words fit to show."""


class HelloCancelled(HelloError):
    pass


def store() -> Path:
    override = os.environ.get('KEYTAP_HELLO_FILE')        # tests
    return Path(override) if override else win32.app_data() / 'hello.json'


def logins_store() -> Path:
    return store().with_name('hello-logins.bin')


def is_on() -> bool:
    return store().exists()


class Opened(NamedTuple):
    password: str
    logins_key: bytes          # opens the sealed copy of the logins (kept_logins)


def _wait(operation):
    async def run():
        return await operation
    return asyncio.run(run())


def supported() -> bool:
    """Whether this PC has Windows Hello set up (a PIN at least)."""
    try:
        from winrt.windows.security.credentials import KeyCredentialManager
        return bool(_wait(KeyCredentialManager.is_supported_async()))
    except Exception:  # noqa: BLE001 - no WinRT, or no Windows Hello
        return False


# --------------------------------------------------------------------------- DPAPI

class _Blob(ctypes.Structure):
    _fields_ = [('cbData', wintypes.DWORD), ('pbData', ctypes.POINTER(ctypes.c_char))]


_crypt32 = ctypes.WinDLL('crypt32', use_last_error=True)
_kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
for _name in ('CryptProtectData', 'CryptUnprotectData'):
    getattr(_crypt32, _name).argtypes = [ctypes.POINTER(_Blob), ctypes.c_void_p, ctypes.POINTER(_Blob), ctypes.c_void_p,
                                         ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(_Blob)]
    getattr(_crypt32, _name).restype = wintypes.BOOL
_kernel32.LocalFree.argtypes = [ctypes.c_void_p]
CRYPTPROTECT_UI_FORBIDDEN = 0x1


def _dpapi(data: bytes, entropy: bytes, protect: bool) -> bytes:
    data_buffer = ctypes.create_string_buffer(data, len(data))
    entropy_buffer = ctypes.create_string_buffer(entropy, len(entropy))
    given = _Blob(len(data), ctypes.cast(data_buffer, ctypes.POINTER(ctypes.c_char)))
    mixed = _Blob(len(entropy), ctypes.cast(entropy_buffer, ctypes.POINTER(ctypes.c_char)))
    result = _Blob()
    call = _crypt32.CryptProtectData if protect else _crypt32.CryptUnprotectData
    if not call(ctypes.byref(given), None, ctypes.byref(mixed), None, None, CRYPTPROTECT_UI_FORBIDDEN,
                ctypes.byref(result)):
        raise OSError(ctypes.get_last_error(), 'Windows could not seal or open the password')
    try:
        return ctypes.string_at(result.pbData, result.cbData)
    finally:
        _kernel32.LocalFree(result.pbData)


# --------------------------------------------------------------------------- Windows Hello

def _bring_prompt_forward() -> None:
    def watch():
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            hwnd = win32.user32.FindWindowW(_PROMPT_CLASS, None)
            if hwnd:
                win32.set_foreground(hwnd)
                return
            time.sleep(0.1)
    threading.Thread(target=watch, daemon=True).start()


def _check_cancelled():
    raise HelloCancelled('Windows Hello was cancelled - type your master password instead.')


def _check(status) -> None:
    from winrt.windows.security.credentials import KeyCredentialStatus as Status
    if status == Status.SUCCESS:
        return
    if status in (Status.USER_CANCELED, Status.USER_PREFERS_PASSWORD):
        _check_cancelled()
    if status == Status.NOT_FOUND:
        raise HelloError("Keytap's Windows Hello key is gone. Type your master password, then turn Windows "
                         'Hello on again in Settings.')
    if status == Status.SECURITY_DEVICE_LOCKED:
        raise HelloError('Windows Hello is locked for now - type your master password instead.')
    raise HelloError('Windows Hello could not check it is you - type your master password instead.')


def _fake() -> str:
    return os.environ.get('KEYTAP_FAKE_HELLO', '') if os.environ.get('KEYTAP_DEV') == '1' else ''


def _sign(challenge: bytes, create: bool) -> bytes:
    fake = _fake()
    if fake:
        # Tests only: a stand-in that signs at once. It cannot open what real Windows Hello sealed.
        if fake == 'cancel':
            _check_cancelled()
        return hashlib.sha256(b'stand-in for Windows Hello' + challenge).digest()
    from winrt.windows.security.credentials import KeyCredentialCreationOption, KeyCredentialManager
    from winrt.windows.security.cryptography import CryptographicBuffer
    _bring_prompt_forward()
    if create:
        opened = _wait(KeyCredentialManager.request_create_async(KEY_NAME, KeyCredentialCreationOption.REPLACE_EXISTING))
    else:
        opened = _wait(KeyCredentialManager.open_async(KEY_NAME))
    _check(opened.status)
    _bring_prompt_forward()
    signed = _wait(opened.credential.request_sign_async(CryptographicBuffer.create_from_byte_array(challenge)))
    _check(signed.status)
    return bytes(signed.result)


def seal(password: str, signature: bytes) -> bytes:
    return _dpapi(password.encode('utf-8'), hashlib.sha256(signature).digest(), protect=True)


def unseal(sealed: bytes, signature: bytes) -> str:
    try:
        return _dpapi(sealed, hashlib.sha256(signature).digest(), protect=False).decode('utf-8')
    except (OSError, UnicodeDecodeError):
        raise HelloError('Windows Hello could not open the password it keeps. Type your master password, then '
                         'turn Windows Hello on again in Settings.') from None


def _write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix('.tmp')
    temporary.write_bytes(data)
    os.replace(temporary, path)


def _new_logins_key(kept: dict, signature: bytes) -> bytes:
    key = os.urandom(32)
    kept['logins_key'] = base64.b64encode(_dpapi(key, hashlib.sha256(signature).digest(), protect=True)).decode()
    return key


def turn_on(password: str) -> bytes:
    """Make Keytap's Windows Hello key (Windows Hello asks) and seal the password with it. The key
    to the sealed copy of the logins."""
    challenge = os.urandom(32)
    signature = _sign(challenge, create=True)
    kept = {'version': 1, 'challenge': base64.b64encode(challenge).decode(),
            'sealed': base64.b64encode(seal(password, signature)).decode()}
    logins_key = _new_logins_key(kept, signature)
    forget_logins()
    _write(store(), json.dumps(kept).encode('utf-8'))
    return logins_key


def open_seal() -> Opened:
    """The master password, and the key to the copy of the logins, once Windows Hello has
    checked it is you."""
    try:
        kept = json.loads(store().read_text(encoding='utf-8'))
        challenge, sealed = base64.b64decode(kept['challenge']), base64.b64decode(kept['sealed'])
    except (OSError, ValueError, KeyError) as error:
        raise HelloError('Windows Hello is not set up for Keytap - turn it on in Settings.') from error
    signature = _sign(challenge, create=False)
    password = unseal(sealed, signature)
    try:
        logins_key = _dpapi(base64.b64decode(kept['logins_key']), hashlib.sha256(signature).digest(), protect=False)
    except (KeyError, ValueError, OSError):
        # Turned on before Keytap kept a copy of the logins: a key for one from now on.
        logins_key = _new_logins_key(kept, signature)
        forget_logins()
        _write(store(), json.dumps(kept).encode('utf-8'))
    return Opened(password, logins_key)


def password() -> str:
    """The master password, once Windows Hello has checked it is you."""
    return open_seal().password


def keep_logins(logins: list[Login], account: str, logins_key: bytes) -> None:
    """Seal a copy of the logins, for Windows Hello to open at once next time."""
    data = json.dumps({'version': 1, 'account': account, 'logins': logins_to_json(logins)})
    _write(logins_store(), _dpapi(data.encode('utf-8'), logins_key, protect=True))


def kept_logins(account: str, logins_key: bytes) -> list[Login] | None:
    """The sealed copy of the logins - None if there is none, it is another account's, or it
    won't open."""
    try:
        data = json.loads(_dpapi(logins_store().read_bytes(), logins_key, protect=False).decode('utf-8'))
        if data.get('version') != 1 or not account or data.get('account') != account:
            return None
        return logins_from_json(data['logins'])
    except (OSError, ValueError, TypeError, KeyError, AttributeError):
        return None


def forget_logins() -> None:
    logins_store().unlink(missing_ok=True)


def turn_off() -> None:
    store().unlink(missing_ok=True)
    forget_logins()
    if _fake():
        return                      # tests leave the real key alone
    try:
        from winrt.windows.security.credentials import KeyCredentialManager
        _wait(KeyCredentialManager.delete_async(KEY_NAME))
    except Exception:  # noqa: BLE001 - no key to delete, or no WinRT
        pass
