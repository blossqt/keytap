"""Keytap as a passkey provider in Windows 11, through webauthn.dll's plugin interface.

When a website or app asks for a passkey, Windows' passkey window lists the
providers switched on in Settings > Accounts > Passkeys > Advanced options.
Picking Keytap, Windows calls Keytap's COM class (IPluginAuthenticator) with
the request as CTAP2 CBOR, and Keytap answers with a passkey from the vault
(passkeys.py does the signing).

Windows takes plugin providers only from a process with a package identity,
which Keytap gets from a small signed package that points at its own folder
(see package.py). Without one, nothing here runs.

What this module does:
- registers Keytap with Windows, and keeps its details current;
- serves the COM class on a thread of its own (COM's multithreaded apartment),
  handing each request to a handler on Keytap's side;
- checks that each request really comes from Windows: Windows signs them with
  a key it gave Keytap when Keytap registered;
- asks Windows Hello to check it is you, for a sign-in;
- tells Windows which passkeys Keytap has (names only, never keys), so its
  window can list them before Keytap is even asked.
"""

from __future__ import annotations

import base64
import ctypes
import hashlib
import threading
import traceback
import uuid
from ctypes import POINTER, Structure, byref, c_int, c_ubyte, c_void_p, c_wchar_p
from ctypes import wintypes as w

NAME = 'Keytap'
CLSID = uuid.UUID('8e4a1c7b-5d3f-4b2a-9c6e-1f0d2a3b4c5d')
# Windows asks a plugin for the RP ID of its own website, for passkeys it might make for itself.
RP_ID = 'blossqt.github.io'

S_OK = 0
NTE_NOT_FOUND = 0x80090011
NTE_NOT_SUPPORTED = 0x80090029
NTE_USER_CANCELLED = 0x80090036
NTE_BAD_SIGNATURE = 0x80090006
E_ACCESSDENIED = 0x80070005
E_FAIL = 0x80004005
ERROR_BUSY_HR = 0x800700AA
APPMODEL_ERROR_NO_PACKAGE = 15700


def signed(hr: int) -> int:
    """An HRESULT as the signed 32-bit number COM's return value is."""
    return hr - (1 << 32) if hr & 0x80000000 else hr


def hresult_text(hr: int) -> str:
    return f'0x{hr & 0xffffffff:08X}'


class Refusal(Exception):
    """A request Keytap won't answer, with the HRESULT Windows is told."""

    def __init__(self, hr: int, message: str = ''):
        super().__init__(message or hresult_text(hr))
        self.hr = hr


# --------------------------------------------------------------------------- identity

def identity() -> str:
    """The package this process runs as ('' for none): Windows takes passkey providers only from one."""
    kernel32 = ctypes.WinDLL('kernel32')
    length = w.UINT(0)
    if kernel32.GetCurrentPackageFullName(byref(length), None) == APPMODEL_ERROR_NO_PACKAGE:
        return ''
    buffer = ctypes.create_unicode_buffer(max(length.value, 1))
    return buffer.value if kernel32.GetCurrentPackageFullName(byref(length), buffer) == 0 else ''


# --------------------------------------------------------------------------- webauthn.dll's plugin API

class _GUID(Structure):
    _fields_ = [('Data1', w.DWORD), ('Data2', w.WORD), ('Data3', w.WORD), ('Data4', c_ubyte * 8)]

    @classmethod
    def of(cls, value: uuid.UUID) -> _GUID:
        return cls.from_buffer_copy(value.bytes_le)

    def uuid(self) -> uuid.UUID:
        return uuid.UUID(bytes_le=bytes(self))


class _AddOptions(Structure):
    _fields_ = [('pwszAuthenticatorName', c_wchar_p), ('rclsid', POINTER(_GUID)), ('pwszPluginRpId', c_wchar_p),
                ('pwszLightThemeLogoSvg', c_wchar_p), ('pwszDarkThemeLogoSvg', c_wchar_p),
                ('cbAuthenticatorInfo', w.DWORD), ('pbAuthenticatorInfo', POINTER(c_ubyte)),
                ('cSupportedRpIds', w.DWORD), ('ppwszSupportedRpIds', c_void_p)]


class _AddResponse(Structure):
    _fields_ = [('cbOpSignPubKey', w.DWORD), ('pbOpSignPubKey', POINTER(c_ubyte))]


class _UpdateDetails(Structure):
    _fields_ = [('pwszAuthenticatorName', c_wchar_p), ('rclsid', POINTER(_GUID)), ('rclsidNew', POINTER(_GUID)),
                ('pwszLightThemeLogoSvg', c_wchar_p), ('pwszDarkThemeLogoSvg', c_wchar_p),
                ('cbAuthenticatorInfo', w.DWORD), ('pbAuthenticatorInfo', POINTER(c_ubyte)),
                ('cSupportedRpIds', w.DWORD), ('ppwszSupportedRpIds', c_void_p)]


class _CredentialDetails(Structure):
    _fields_ = [('cbCredentialId', w.DWORD), ('pbCredentialId', POINTER(c_ubyte)), ('pwszRpId', c_wchar_p),
                ('pwszRpName', c_wchar_p), ('cbUserId', w.DWORD), ('pbUserId', POINTER(c_ubyte)),
                ('pwszUserName', c_wchar_p), ('pwszUserDisplayName', c_wchar_p)]


class _UserVerification(Structure):
    _fields_ = [('hwnd', w.HWND), ('rguidTransactionId', POINTER(_GUID)), ('pwszUsername', c_wchar_p),
                ('pwszDisplayHint', c_wchar_p)]


def _dll():
    dll = ctypes.WinDLL('webauthn.dll')
    for name in ('WebAuthNPluginAddAuthenticator', 'WebAuthNPluginUpdateAuthenticatorDetails',
                 'WebAuthNPluginRemoveAuthenticator', 'WebAuthNPluginGetAuthenticatorState',
                 'WebAuthNPluginAuthenticatorAddCredentials', 'WebAuthNPluginAuthenticatorRemoveAllCredentials',
                 'WebAuthNPluginPerformUserVerification', 'WebAuthNPluginGetOperationSigningPublicKey'):
        getattr(dll, name).restype = ctypes.c_long
    return dll


def _bytes(data: bytes):
    return (c_ubyte * max(len(data), 1)).from_buffer_copy(data or b'\x00')


def supported() -> bool:
    """Whether this Windows has the plugin interface at all (Windows 11 24H2 and later, updated)."""
    try:
        return hasattr(_dll(), 'WebAuthNPluginAddAuthenticator')
    except OSError:
        return False


def state() -> str:
    """'enabled' or 'disabled' in Windows' passkey settings, or 'unregistered'."""
    value = c_int(-1)
    hr = _dll().WebAuthNPluginGetAuthenticatorState(byref(_GUID.of(CLSID)), byref(value))
    if hr:
        return 'unregistered'
    return 'enabled' if value.value == 1 else 'disabled'


def register(logo_svg: str, info: bytes) -> None:
    """Tell Windows about Keytap, or bring the details it has up to date. Raises OSError."""
    dll = _dll()
    clsid = _GUID.of(CLSID)
    logo = base64.b64encode(logo_svg.encode('utf-8')).decode('ascii')
    blob = _bytes(info)
    if state() == 'unregistered':
        options = _AddOptions(NAME, ctypes.pointer(clsid), RP_ID, logo, logo, len(info), blob, 0, None)
        response = POINTER(_AddResponse)()
        hr = dll.WebAuthNPluginAddAuthenticator(byref(options), byref(response))
        if hr:
            raise OSError(hr & 0xffffffff, f'Windows would not add Keytap as a passkey provider ({hresult_text(hr)})')
        if response:
            dll.WebAuthNPluginFreeAddAuthenticatorResponse(response)
        return
    details = _UpdateDetails(NAME, ctypes.pointer(clsid), ctypes.pointer(clsid), logo, logo, len(info), blob, 0, None)
    hr = dll.WebAuthNPluginUpdateAuthenticatorDetails(byref(details))
    if hr:
        raise OSError(hr & 0xffffffff, f'Windows would not update Keytap as a passkey provider ({hresult_text(hr)})')


def unregister() -> None:
    _dll().WebAuthNPluginRemoveAuthenticator(byref(_GUID.of(CLSID)))


def sync_credentials(keys) -> None:
    """Tell Windows which passkeys Keytap can sign in with - their websites and accounts, never
    their keys - so its passkey window can list them. Raises OSError."""
    dll = _dll()
    clsid = _GUID.of(CLSID)
    dll.WebAuthNPluginAuthenticatorRemoveAllCredentials(byref(clsid))
    keys = [key for key in keys if key.rp_id and key.credential_id]
    if not keys:
        return
    keep = []
    array = (_CredentialDetails * len(keys))()
    for slot, key in zip(array, keys):
        cid, uid = _bytes(key.credential_id), _bytes(key.user_handle or b'\x00')
        keep += [cid, uid]
        slot.cbCredentialId, slot.pbCredentialId = len(key.credential_id), cid
        slot.pwszRpId, slot.pwszRpName = key.rp_id, key.rp_name or key.rp_id
        slot.cbUserId, slot.pbUserId = max(len(key.user_handle), 1), uid
        slot.pwszUserName = key.user_name or key.user_display_name or key.rp_id
        slot.pwszUserDisplayName = key.user_display_name or key.user_name or key.rp_id
    hr = dll.WebAuthNPluginAuthenticatorAddCredentials(byref(clsid), len(keys), array)
    if hr:
        raise OSError(hr & 0xffffffff, f'Windows would not take the list of passkeys ({hresult_text(hr)})')


def cached_credentials() -> list[str]:
    """The websites of the passkeys Windows has listed for Keytap (for tests)."""
    dll = _dll()
    count, array = w.DWORD(), POINTER(_CredentialDetails)()
    hr = dll.WebAuthNPluginAuthenticatorGetAllCredentials(byref(_GUID.of(CLSID)), byref(count), byref(array))
    if hr:
        return [f'error {hresult_text(hr)}']
    try:
        return [array[i].pwszRpId for i in range(count.value)]
    finally:
        if array:
            dll.WebAuthNPluginAuthenticatorFreeCredentialDetailsArray(count, array)


def forget_credentials() -> None:
    try:
        _dll().WebAuthNPluginAuthenticatorRemoveAllCredentials(byref(_GUID.of(CLSID)))
    except OSError:
        pass


def verify_user(hwnd: int, transaction: uuid.UUID, user_name: str, hint: str) -> bool:
    """Windows Hello checks it is you, for this sign-in. False if you cancelled; OSError if
    Windows Hello can't (not set up, say)."""
    dll = _dll()
    guid = _GUID.of(transaction)
    request = _UserVerification(hwnd or None, ctypes.pointer(guid), user_name or None, hint or None)
    size, response = w.DWORD(), POINTER(c_ubyte)()
    hr = dll.WebAuthNPluginPerformUserVerification(byref(request), byref(size), byref(response))
    if response:
        dll.WebAuthNPluginFreeUserVerificationResponse(response)
    if hr == signed(NTE_USER_CANCELLED) or (hr & 0xffffffff) == NTE_USER_CANCELLED:
        return False
    if hr:
        raise OSError(hr & 0xffffffff, f'Windows Hello could not check it is you ({hresult_text(hr)})')
    return True


# --------------------------------------------------------------------------- requests come from Windows

_BCRYPT_RSAPUBLIC_MAGIC = 0x31415352
_BCRYPT_PAD_PSS = 8


class _PssPadding(Structure):
    _fields_ = [('pszAlgId', c_wchar_p), ('cbSalt', w.ULONG)]


def _signing_key() -> bytes:
    dll = _dll()
    size, key = w.DWORD(), POINTER(c_ubyte)()
    hr = dll.WebAuthNPluginGetOperationSigningPublicKey(byref(_GUID.of(CLSID)), byref(size), byref(key))
    if hr or not key:
        return b''
    try:
        return bytes(key[:size.value])
    finally:
        dll.WebAuthNPluginFreePublicKeyResponse(key)


def from_windows(data: bytes, signature: bytes) -> bool:
    """Whether Windows signed this request, with the key it keeps for Keytap's registration."""
    key = _signing_key()
    if not key or not signature:
        return False
    ncrypt = ctypes.WinDLL('ncrypt')
    provider, handle = c_void_p(), c_void_p()
    if ncrypt.NCryptOpenStorageProvider(byref(provider), None, 0):
        return False
    try:
        blob = _bytes(key)
        if ncrypt.NCryptImportKey(provider, None, c_wchar_p('PUBLICBLOB'), None, byref(handle), blob, len(key), 0):
            return False
        digest = hashlib.sha256(data).digest()
        magic = int.from_bytes(key[:4], 'little')
        padding, flags = (None, 0)
        if magic == _BCRYPT_RSAPUBLIC_MAGIC:
            padding, flags = byref(_PssPadding('SHA256', 32)), _BCRYPT_PAD_PSS
        status = ncrypt.NCryptVerifySignature(handle, padding, _bytes(digest), len(digest), _bytes(signature),
                                              len(signature), flags)
        return status == 0
    finally:
        if handle:
            ncrypt.NCryptFreeObject(handle)
        ncrypt.NCryptFreeObject(provider)


# --------------------------------------------------------------------------- the COM class

class _OperationRequest(Structure):
    _fields_ = [('hWnd', w.HWND), ('transactionId', _GUID), ('cbRequestSignature', w.DWORD),
                ('pbRequestSignature', POINTER(c_ubyte)), ('requestType', c_int),
                ('cbEncodedRequest', w.DWORD), ('pbEncodedRequest', POINTER(c_ubyte))]


class _OperationResponse(Structure):
    _fields_ = [('cbEncodedResponse', w.DWORD), ('pbEncodedResponse', POINTER(c_ubyte))]


class _CancelRequest(Structure):
    _fields_ = [('transactionId', _GUID), ('cbRequestSignature', w.DWORD), ('pbRequestSignature', POINTER(c_ubyte))]


class Operation:
    """One request from Windows: which window asked, and the CTAP2 message."""

    def __init__(self, raw: _OperationRequest):
        self.hwnd = int(raw.hWnd or 0)
        self.transaction = raw.transactionId.uuid()
        self.data = bytes(raw.pbEncodedRequest[:raw.cbEncodedRequest]) if raw.cbEncodedRequest else b''
        self.signature = bytes(raw.pbRequestSignature[:raw.cbRequestSignature]) if raw.cbRequestSignature else b''


def _server_classes(handler):
    """IPluginAuthenticator and its class, made here so comtypes loads only where it is used."""
    import comtypes
    from comtypes import COMMETHOD, GUID, HRESULT, COMObject, IUnknown

    class IPluginAuthenticator(IUnknown):
        _iid_ = GUID('{d26bcf6f-b54c-43ff-9f06-d5bf148625f7}')
        _methods_ = [
            COMMETHOD([], HRESULT, 'MakeCredential', (['in'], POINTER(_OperationRequest), 'request'),
                      (['out', 'retval'], POINTER(_OperationResponse), 'response')),
            COMMETHOD([], HRESULT, 'GetAssertion', (['in'], POINTER(_OperationRequest), 'request'),
                      (['out', 'retval'], POINTER(_OperationResponse), 'response')),
            COMMETHOD([], HRESULT, 'CancelOperation', (['in'], POINTER(_CancelRequest), 'request')),
            COMMETHOD([], HRESULT, 'GetLockStatus', (['out', 'retval'], POINTER(c_int), 'lockStatus')),
        ]

    ole32 = ctypes.WinDLL('ole32')
    ole32.CoTaskMemAlloc.restype = c_void_p
    ole32.CoTaskMemAlloc.argtypes = [ctypes.c_size_t]

    def answer_into(response, call, request) -> int:
        try:
            if not request or not response:
                return signed(0x80070057)            # E_INVALIDARG
            response[0].cbEncodedResponse = 0
            response[0].pbEncodedResponse = None
            data = call(Operation(request[0]))
            memory = ole32.CoTaskMemAlloc(len(data))      # COM frees it once Windows has it
            if not memory:
                return signed(0x8007000E)            # E_OUTOFMEMORY
            ctypes.memmove(memory, data, len(data))
            response[0].cbEncodedResponse = len(data)
            response[0].pbEncodedResponse = ctypes.cast(memory, POINTER(c_ubyte))
            return S_OK
        except Refusal as refusal:
            return signed(refusal.hr)
        except Exception:  # noqa: BLE001 - a COM call must answer, never raise
            traceback.print_exc()
            return signed(E_FAIL)

    class KeytapAuthenticator(COMObject):
        _com_interfaces_ = [IPluginAuthenticator]
        _reg_clsid_ = '{' + str(CLSID) + '}'
        _reg_clsctx_ = comtypes.CLSCTX_LOCAL_SERVER

        def MakeCredential(self, this, request, response):
            hr = answer_into(response, handler.make_credential, request)
            print(f'passkeys: MakeCredential -> {hresult_text(hr)}', flush=True)
            return hr

        def GetAssertion(self, this, request, response):
            hr = answer_into(response, handler.get_assertion, request)
            print(f'passkeys: GetAssertion -> {hresult_text(hr)}', flush=True)
            return hr

        def CancelOperation(self, this, request):
            try:
                if request:
                    handler.cancel(request[0].transactionId.uuid())
            except Exception:  # noqa: BLE001
                traceback.print_exc()
            return S_OK

        def GetLockStatus(self, this, status):
            print('passkeys: GetLockStatus', flush=True)
            try:
                if status:
                    status[0] = 1 if handler.unlocked() else 0       # PluginUnlocked, PluginLocked
            except Exception:  # noqa: BLE001
                traceback.print_exc()
                return signed(E_FAIL)
            return S_OK

    return KeytapAuthenticator


class Server:
    """Serves Keytap's COM class to Windows from a thread of its own, until stopped.

    handler: get_assertion(Operation) -> bytes, make_credential(Operation) -> bytes (both may
    raise Refusal), cancel(transaction), unlocked() -> bool. They are called on COM's threads."""

    def __init__(self, handler):
        self._handler = handler
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.failed = ''
        self.ready = threading.Event()

    def start(self) -> None:
        if self._thread is None:
            self._thread = threading.Thread(target=self._run, name='keytap-passkeys', daemon=True)
            self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    def _run(self) -> None:
        ole32 = ctypes.WinDLL('ole32')
        try:
            import sys
            sys.coinit_flags = 0                # COINIT_MULTITHREADED, if comtypes is first imported here
            from comtypes.server.localserver import ClassFactory
            ole32.CoInitializeEx(None, 0)       # this thread, whichever thread imported comtypes
            factory = ClassFactory(_server_classes(self._handler))   # registers the class with COM
        except Exception as error:  # noqa: BLE001
            traceback.print_exc()
            self.failed = str(error)
            self.ready.set()
            return
        print(f'passkeys: serving {CLSID} as {identity() or "no package"}', flush=True)
        self.ready.set()
        self._stop.wait()
        try:
            factory._revoke_class()
        except OSError:
            pass
        ole32.CoUninitialize()
