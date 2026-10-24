r"""Keytap's passkeys: CBOR, P-256 signing, reading Bitwarden's passkeys, and the answers Windows gets.

    %LOCALAPPDATA%\KeytapBuild\venv\Scripts\python.exe tests\test_passkeys.py

The answers are checked against Windows' own CTAP encoder (webauthn.dll) as
well as by verifying their signatures. Nothing is registered with Windows.
"""

import ctypes
import hashlib
import sys
import unittest
import uuid
from ctypes import POINTER, Structure, c_long, c_ubyte, c_void_p, c_wchar_p
from ctypes import wintypes as w
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'app'))

from keytap import cbor, p256, passkeys  # noqa: E402
from keytap.passkeys import NewRequest, Passkey, PasskeyError, Request  # noqa: E402
from keytap.vault import Login  # noqa: E402

D = 0xC9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721       # RFC 6979's P-256 test key
KEY = p256.pkcs8_from_private_key(D)
GUID = '4b9a3f0e-1c2d-4e5f-8a9b-0c1d2e3f4a5b'


def b64url(data: bytes) -> str:
    import base64
    return base64.urlsafe_b64encode(data).decode().rstrip('=')


def bitwarden_item(**fido):
    passkey = {'credentialId': GUID, 'keyType': 'public-key', 'keyAlgorithm': 'ECDSA', 'keyCurve': 'P-256',
               'keyValue': b64url(KEY), 'rpId': 'github.com', 'userHandle': b64url(b'user-1234'),
               'userName': 'blossqt', 'userDisplayName': 'Blossqt', 'rpName': 'GitHub', 'counter': '0',
               'discoverable': 'true', 'creationDate': '2026-01-01T00:00:00.000Z', **fido}
    return {'type': 1, 'id': 'item-1', 'name': 'GitHub', 'login': {'username': 'blossqt', 'password': 'x',
                                                                     'uris': [], 'fido2Credentials': [passkey]}}


def request_bytes(rp='github.com', allow=(), uv=True) -> bytes:
    message = {1: rp, 2: hashlib.sha256(b'client data').digest(), 5: {'up': True, 'uv': uv}}
    if allow:
        message[3] = [{'id': cid, 'type': 'public-key'} for cid in allow]
    return cbor.dumps(message)


def new_request_bytes(rp='github.com', algorithms=(-257, -7), exclude=(), rk=True) -> bytes:
    message = {1: hashlib.sha256(b'client data').digest(), 2: {'id': rp, 'name': 'GitHub'},
               3: {'id': b'user-1234', 'name': 'blossqt', 'displayName': 'Blossqt'},
               4: [{'alg': alg, 'type': 'public-key'} for alg in algorithms], 7: {'rk': rk, 'uv': True}}
    if exclude:
        message[5] = [{'id': cid, 'type': 'public-key'} for cid in exclude]
    return cbor.dumps(message)


class CborTests(unittest.TestCase):
    def test_canonical_and_round_trip(self):
        value = {'type': 'public-key', 'id': b'\x01\x02', 10: [-7, 0, 23, 24, 255, 256, 65536], 1: True, 2: None}
        data = cbor.dumps(value)
        self.assertEqual(cbor.loads(data), value)
        # CTAP2 canonical order: integer keys (shortest encodings) first, then shorter text keys.
        self.assertEqual(data[:3], bytes([0xa5, 0x01, 0xf5]))
        self.assertLess(data.index(b'bid'), data.index(b'dtype'))
        self.assertEqual(cbor.dumps(24), b'\x18\x18')
        self.assertEqual(cbor.dumps(-7), b'\x26')

    def test_rejects_what_ctap_never_sends(self):
        for bad in (b'\xa1\x01', b'\x5f', b'\xc1\x00', cbor.dumps(1) + b'\x00', b''):
            with self.assertRaises(cbor.CborError, msg=bad.hex()):
                cbor.loads(bad)


class P256Tests(unittest.TestCase):
    def test_rfc6979_vector(self):
        self.assertEqual(p256.public_key(D)[0], 0x60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6)
        r, s = p256.sign_raw(D, b'sample')
        self.assertEqual(r, 0xEFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716)
        self.assertEqual(s, 0xF7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8)

    def test_sign_verify_and_pkcs8(self):
        signature = p256.sign(D, b'hello')
        self.assertTrue(p256.verify(p256.public_key(D), b'hello', signature))
        self.assertFalse(p256.verify(p256.public_key(D), b'hullo', signature))
        self.assertEqual(p256.private_key_from_pkcs8(KEY), D)
        with self.assertRaises(p256.KeyFormatError):
            p256.private_key_from_pkcs8(b'\x30\x03\x02\x01\x00')


class PasskeyTests(unittest.TestCase):
    def setUp(self):
        self.login = Login.from_item(bitwarden_item())
        self.passkey = self.login.passkeys[0]

    def test_read_from_bitwarden(self):
        self.assertEqual(self.passkey.credential_id, uuid.UUID(GUID).bytes)
        self.assertEqual(self.passkey.credential_id[:2], bytes([0x4b, 0x9a]), "big-endian, as Bitwarden's")
        self.assertEqual((self.passkey.rp_id, self.passkey.user_handle, self.passkey.who),
                         ('github.com', b'user-1234', 'blossqt'))
        self.assertNotIn(b64url(KEY), repr(self.passkey), 'the key stays out of logs')
        imported = Login.from_item(bitwarden_item(credentialId='b64.' + b64url(b'\x01\x02\x03'))).passkeys[0]
        self.assertEqual(imported.credential_id, b'\x01\x02\x03')
        self.assertEqual(Login.from_item(bitwarden_item(keyCurve='P-384')).passkeys, (), 'only what it can sign')

    def test_which_passkeys_answer(self):
        other = Passkey('item-2', b'\x09' * 16, 'github.com', discoverable=False)
        elsewhere = Passkey('item-3', b'\x08' * 16, 'gist.github.com')
        keys = [self.passkey, other, elsewhere]
        self.assertEqual(passkeys.candidates(keys, Request.parse(request_bytes())), [self.passkey],
                         'the exact RP ID, and only passkeys it can find by itself')
        self.assertEqual(passkeys.candidates(keys, Request.parse(request_bytes(allow=[b'\x09' * 16]))), [other])

    def test_answer_signs_like_bitwarden(self):
        request = Request.parse(request_bytes())
        response = cbor.loads(passkeys.answer(self.passkey, request, verified=True))
        data = response[2]
        self.assertEqual(data[:32], hashlib.sha256(b'github.com').digest())
        self.assertEqual(data[32], 0x1d, 'present, verified, backup eligible and backed up')
        self.assertEqual(data[33:], b'\x00\x00\x00\x00', 'counter 0, as Bitwarden keeps it')
        self.assertTrue(p256.verify(p256.public_key(D), data + request.client_data_hash, response[3]))
        self.assertEqual(response[1], {'id': self.passkey.credential_id, 'type': 'public-key'})
        self.assertEqual(response[4], {'id': b'user-1234'})
        unverified = cbor.loads(passkeys.answer(self.passkey, request, verified=False))
        self.assertEqual(unverified[2][32], 0x19)
        counting = Login.from_item(bitwarden_item(counter='7')).passkeys[0]
        with self.assertRaises(PasskeyError):
            passkeys.answer(counting, request, verified=True)

    def test_a_new_passkey_is_made_and_kept_as_bitwarden_keeps_one(self):
        request = NewRequest.parse(new_request_bytes())
        self.assertEqual((request.rp_id, request.user_id, request.who, request.algorithms, request.resident),
                         ('github.com', b'user-1234', 'blossqt', (-257, -7), True))
        key = passkeys.make(request)
        self.assertEqual(len(key.credential_id), 16, 'a GUID, as Bitwarden makes')
        record = passkeys.record(key)
        self.assertEqual({k: record[k] for k in ('keyType', 'keyAlgorithm', 'keyCurve', 'counter', 'discoverable')},
                         {'keyType': 'public-key', 'keyAlgorithm': 'ECDSA', 'keyCurve': 'P-256', 'counter': '0',
                          'discoverable': 'true'})
        self.assertRegex(record['creationDate'], r'^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$')
        again = Passkey.from_bitwarden('item-9', record)                # as Keytap reads it back from the vault
        self.assertEqual((again.credential_id, again.key, again.user_handle, again.rp_name),
                         (key.credential_id, key.key, b'user-1234', 'GitHub'))
        self.assertEqual(p256.private_key_from_pkcs8(key.key), p256.private_key_from_pkcs8(again.key))
        with self.assertRaises(PasskeyError):
            passkeys.make(NewRequest.parse(new_request_bytes(algorithms=(-257,))))     # RSA only

    def test_a_new_passkeys_answer(self):
        request = NewRequest.parse(new_request_bytes())
        key = passkeys.make(request)
        response = cbor.loads(passkeys.attestation(key, verified=True))
        self.assertEqual((response[1], response[3]), ('none', {}))
        data = response[2]
        self.assertEqual(data[:32], hashlib.sha256(b'github.com').digest())
        self.assertEqual(data[32], 0x5d, 'present, verified, backup eligible, backed up, with the new key')
        self.assertEqual(data[33:37], b'\0\0\0\0')
        self.assertEqual(data[37:53], passkeys.AAGUID.bytes)
        self.assertEqual(int.from_bytes(data[53:55], 'big'), 16)
        self.assertEqual(data[55:71], key.credential_id)
        public = cbor.loads(data[71:])
        x, y = p256.public_key(p256.private_key_from_pkcs8(key.key))
        self.assertEqual(public, {1: 2, 3: -7, -1: 1, -2: x.to_bytes(32, 'big'), -3: y.to_bytes(32, 'big')})
        message = b'sign in later'
        self.assertTrue(p256.verify((x, y), message, p256.sign(p256.private_key_from_pkcs8(key.key), message)))

    def test_already_saved_for_this_account(self):
        request = NewRequest.parse(new_request_bytes(exclude=[uuid.UUID(GUID).bytes]))
        self.assertTrue(passkeys.excluded([self.passkey], request))
        self.assertFalse(passkeys.excluded([self.passkey], NewRequest.parse(new_request_bytes())))

    def test_new_requests_that_cant_be_read(self):
        with self.assertRaises(PasskeyError):
            NewRequest.parse(cbor.dumps({1: b'short', 2: {'id': 'github.com'}, 3: {'id': b'u'}}))
        with self.assertRaises(PasskeyError):
            NewRequest.parse(cbor.dumps({1: b'\0' * 32, 2: {'id': 'github.com'}}))          # no user

    def test_requests_windows_sends(self):
        with self.assertRaises(PasskeyError):
            Request.parse(b'\x02' + request_bytes())        # CTAP's command byte: Windows leaves it off
        with self.assertRaises(PasskeyError):
            Request.parse(cbor.dumps({1: 'github.com', 2: b'short'}))
        parsed = Request.parse(request_bytes(uv=False))
        self.assertEqual((parsed.rp_id, parsed.uv, parsed.allow), ('github.com', False, ()))


# --------------------------------------------------------------------------- Windows' own encoder

class _Credential(Structure):
    _fields_ = [('dwVersion', w.DWORD), ('cbId', w.DWORD), ('pbId', POINTER(c_ubyte)), ('pwszCredentialType', c_wchar_p)]


class _Extensions(Structure):
    _fields_ = [('cExtensions', w.DWORD), ('pExtensions', c_void_p)]


class _Assertion(Structure):
    _fields_ = [('dwVersion', w.DWORD), ('cbAuthenticatorData', w.DWORD), ('pbAuthenticatorData', POINTER(c_ubyte)),
                ('cbSignature', w.DWORD), ('pbSignature', POINTER(c_ubyte)), ('Credential', _Credential),
                ('cbUserId', w.DWORD), ('pbUserId', POINTER(c_ubyte)), ('Extensions', _Extensions),
                ('cbCredLargeBlob', w.DWORD), ('pbCredLargeBlob', POINTER(c_ubyte)), ('dwCredLargeBlobStatus', w.DWORD),
                ('pHmacSecret', c_void_p), ('dwUsedTransport', w.DWORD), ('cbUnsignedExtensionOutputs', w.DWORD),
                ('pbUnsignedExtensionOutputs', POINTER(c_ubyte)), ('cbClientDataJSON', w.DWORD),
                ('pbClientDataJSON', POINTER(c_ubyte)), ('cbAuthenticationResponseJSON', w.DWORD),
                ('pbAuthenticationResponseJSON', POINTER(c_ubyte))]


class _User(Structure):
    _fields_ = [('dwVersion', w.DWORD), ('cbId', w.DWORD), ('pbId', POINTER(c_ubyte)), ('pwszName', c_wchar_p),
                ('pwszIcon', c_wchar_p), ('pwszDisplayName', c_wchar_p)]


class _Response(Structure):
    _fields_ = [('WebAuthNAssertion', _Assertion), ('pUserInformation', POINTER(_User)),
                ('dwNumberOfCredentials', w.DWORD), ('lUserSelected', c_long), ('cbLargeBlobKey', w.DWORD),
                ('pbLargeBlobKey', POINTER(c_ubyte)), ('cbUnsignedExtensionOutputs', w.DWORD),
                ('pbUnsignedExtensionOutputs', POINTER(c_ubyte))]


def windows_encoding(response: dict) -> bytes:
    keep = []

    def buffer(data: bytes):
        array = (c_ubyte * len(data)).from_buffer_copy(data)
        keep.append(array)
        return len(data), array
    r = _Response()
    a = r.WebAuthNAssertion
    a.dwVersion = 6
    a.cbAuthenticatorData, a.pbAuthenticatorData = buffer(response[2])
    a.cbSignature, a.pbSignature = buffer(response[3])
    size, cid = buffer(response[1]['id'])
    a.Credential = _Credential(1, size, cid, 'public-key')
    a.cbUserId, a.pbUserId = buffer(response[4]['id'])
    user = _User(1, a.cbUserId, a.pbUserId, None, None, None)
    r.pUserInformation = ctypes.pointer(user)
    r.dwNumberOfCredentials = 1
    out_size, out = w.DWORD(), POINTER(c_ubyte)()
    hr = ctypes.WinDLL('webauthn.dll').WebAuthNEncodeGetAssertionResponse(ctypes.byref(r), ctypes.byref(out_size),
                                                                         ctypes.byref(out))
    if hr:
        raise OSError(hr & 0xffffffff, 'WebAuthNEncodeGetAssertionResponse')
    return bytes(out[:out_size.value])


class _Attestation(Structure):
    """WEBAUTHN_CREDENTIAL_ATTESTATION, version 8 - the one this Windows' encoder takes."""
    _fields_ = [('dwVersion', w.DWORD), ('pwszFormatType', c_wchar_p),
                ('cbAuthenticatorData', w.DWORD), ('pbAuthenticatorData', POINTER(c_ubyte)),
                ('cbAttestation', w.DWORD), ('pbAttestation', POINTER(c_ubyte)),
                ('dwAttestationDecodeType', w.DWORD), ('pvAttestationDecode', c_void_p),
                ('cbAttestationObject', w.DWORD), ('pbAttestationObject', POINTER(c_ubyte)),
                ('cbCredentialId', w.DWORD), ('pbCredentialId', POINTER(c_ubyte)),
                ('Extensions', _Extensions), ('dwUsedTransport', w.DWORD),
                ('bEpAtt', w.BOOL), ('bLargeBlobSupported', w.BOOL), ('bResidentKey', w.BOOL),
                ('bPrfEnabled', w.BOOL), ('cbUnsignedExtensionOutputs', w.DWORD),
                ('pbUnsignedExtensionOutputs', POINTER(c_ubyte)), ('pHmacSecret', c_void_p),
                ('bThirdPartyPayment', w.BOOL), ('dwTransports', w.DWORD), ('cbClientDataJSON', w.DWORD),
                ('pbClientDataJSON', POINTER(c_ubyte)), ('cbRegistrationResponseJSON', w.DWORD),
                ('pbRegistrationResponseJSON', POINTER(c_ubyte))]


def windows_attestation(data: bytes, credential_id: bytes) -> bytes:
    keep = [(c_ubyte * len(data)).from_buffer_copy(data), (c_ubyte * len(credential_id)).from_buffer_copy(credential_id)]
    a = _Attestation()
    a.dwVersion, a.pwszFormatType = 8, 'none'
    a.cbAuthenticatorData, a.pbAuthenticatorData = len(data), keep[0]
    a.cbCredentialId, a.pbCredentialId = len(credential_id), keep[1]
    out_size, out = w.DWORD(), POINTER(c_ubyte)()
    hr = ctypes.WinDLL('webauthn.dll').WebAuthNEncodeMakeCredentialResponse(ctypes.byref(a), ctypes.byref(out_size),
                                                                           ctypes.byref(out))
    if hr:
        raise OSError(hr & 0xffffffff, 'WebAuthNEncodeMakeCredentialResponse')
    return bytes(out[:out_size.value])


class WindowsEncodingTests(unittest.TestCase):
    def test_same_bytes_as_windows_encodes(self):
        passkey = Login.from_item(bitwarden_item()).passkeys[0]
        ours = passkeys.answer(passkey, Request.parse(request_bytes()), verified=True)
        self.assertEqual(ours, windows_encoding(cbor.loads(ours)))

    def test_a_new_passkeys_answer_is_what_windows_encodes(self):
        key = passkeys.make(NewRequest.parse(new_request_bytes()))
        ours = passkeys.attestation(key, verified=True)
        self.assertEqual(ours, windows_attestation(cbor.loads(ours)[2], key.credential_id))

    def test_windows_reads_our_new_request_encoding(self):
        data = new_request_bytes(exclude=[b'\x07' * 16])
        raw = (c_ubyte * len(data)).from_buffer_copy(data)
        decoded = c_void_p()
        dll = ctypes.WinDLL('webauthn.dll')
        self.assertEqual(dll.WebAuthNDecodeMakeCredentialRequest(len(data), raw, ctypes.byref(decoded)), 0)
        dll.WebAuthNFreeDecodedMakeCredentialRequest(decoded)

    def test_windows_reads_our_request_encoding(self):
        data = request_bytes(allow=[b'\x07' * 16])
        raw = (c_ubyte * len(data)).from_buffer_copy(data)
        decoded = c_void_p()
        dll = ctypes.WinDLL('webauthn.dll')
        self.assertEqual(dll.WebAuthNDecodeGetAssertionRequest(len(data), raw, ctypes.byref(decoded)), 0)
        dll.WebAuthNFreeDecodedGetAssertionRequest(decoded)


if __name__ == '__main__':
    unittest.main(verbosity=2)
