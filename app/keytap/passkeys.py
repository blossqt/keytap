"""Signing in with the passkeys in a Bitwarden vault, and saving new ones to it, as Bitwarden's
own apps do.

A passkey is a key pair a website holds the public half of. Signing in, the
website sends a challenge; the passkey's private key signs it. Windows asks
Keytap to do that through its passkey plugin interface (see provider.py),
with requests and answers in CTAP2's CBOR.

The answer is built exactly as Bitwarden builds it - the same flags (backed
up and eligible for it, as synced passkeys are), the same counter, the same
key - so a website cannot tell which Bitwarden app signed. Signing writes
nothing to the vault, so a passkey that counts its uses (a counter above 0, from an
import; Bitwarden's own stay at 0) is left to Bitwarden, which saves the
count: an unsaved count would look to the website like a copied key.

A new passkey (CTAP2's authenticatorMakeCredential) is made as Bitwarden makes
one - an ES256 key, a GUID for its id, counting nothing - and kept as Bitwarden
keeps it (record()); its answer attests nothing ("none"), as Bitwarden's does,
and names Keytap's AAGUID as the authenticator that made it.
"""

from __future__ import annotations

import base64
import datetime
import hashlib
import uuid
from dataclasses import dataclass, field

from . import cbor, p256

# Keytap's authenticator, as Windows lists it. Assertions don't carry it; new passkeys do.
AAGUID = uuid.UUID('5d6c5f1e-8a0b-4a53-9c1e-4b7a2f0e9d31')

FLAG_UP, FLAG_UV, FLAG_BE, FLAG_BS, FLAG_AT = 0x01, 0x04, 0x08, 0x10, 0x40
ES256 = -7                      # COSE's ECDSA with SHA-256 on P-256: the one kind of key Keytap makes


class PasskeyError(Exception):
    """Why a passkey cannot sign in, in words fit to show."""


def _b64url(text: str) -> bytes:
    text = (text or '').strip()
    return base64.urlsafe_b64decode(text + '=' * (-len(text) % 4))


def _b64url_text(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode('ascii').rstrip('=')


def credential_id_bytes(encoded: str) -> bytes:
    """A credential id as Bitwarden keeps it - a GUID, or "b64." and base64url for an imported
    passkey whose id is not one - as the bytes a website knows it by."""
    if encoded.startswith('b64.'):
        return _b64url(encoded[4:])
    return uuid.UUID(encoded).bytes       # big-endian, as Bitwarden's guidToRawFormat


@dataclass(frozen=True)
class Passkey:
    login_id: str
    credential_id: bytes
    rp_id: str
    user_handle: bytes = b''
    user_name: str = ''
    user_display_name: str = ''
    rp_name: str = ''
    counter: int = 0
    discoverable: bool = True
    key: bytes = field(default=b'', repr=False)       # PKCS#8 - the private key

    @classmethod
    def from_bitwarden(cls, login_id: str, fido: dict) -> Passkey | None:
        """One of login.fido2Credentials from `bw list items`; None if Keytap can't use it."""
        try:
            if (fido.get('keyAlgorithm') or 'ECDSA') != 'ECDSA' or (fido.get('keyCurve') or 'P-256') != 'P-256':
                return None
            return cls(login_id=login_id, credential_id=credential_id_bytes(str(fido['credentialId'])),
                       rp_id=str(fido.get('rpId') or ''), user_handle=_b64url(str(fido.get('userHandle') or '')),
                       user_name=str(fido.get('userName') or ''),
                       user_display_name=str(fido.get('userDisplayName') or ''),
                       rp_name=str(fido.get('rpName') or ''), counter=int(fido.get('counter') or 0),
                       discoverable=str(fido.get('discoverable')).lower() != 'false',
                       key=_b64url(str(fido['keyValue'])))
        except (KeyError, ValueError, TypeError):
            return None

    @property
    def who(self) -> str:
        return self.user_name or self.user_display_name or 'an account'


@dataclass(frozen=True)
class Request:
    """A website asking to be signed in to (CTAP2's authenticatorGetAssertion)."""
    rp_id: str
    client_data_hash: bytes
    allow: tuple[bytes, ...] = ()          # the credential ids it will take; none: any of its passkeys
    up: bool = True
    uv: bool = False                       # it wants the person verified (Windows Hello, say)

    @classmethod
    def parse(cls, data: bytes) -> Request:
        try:
            message = cbor.loads(data)
            options = message.get(5) or {}
            allow = tuple(bytes(item['id']) for item in message.get(3) or []
                          if isinstance(item, dict) and item.get('type', 'public-key') == 'public-key')
            request = cls(rp_id=str(message[1]), client_data_hash=bytes(message[2]), allow=allow,
                          up=options.get('up', True) is not False, uv=bool(options.get('uv', False)))
        except (cbor.CborError, KeyError, TypeError, AttributeError) as error:
            raise PasskeyError(f'Windows sent a passkey request Keytap could not read ({error}).') from error
        if not request.rp_id or len(request.client_data_hash) != 32:
            raise PasskeyError('Windows sent an incomplete passkey request.')
        return request


@dataclass(frozen=True)
class NewRequest:
    """A website asking for a new passkey (CTAP2's authenticatorMakeCredential)."""
    rp_id: str
    client_data_hash: bytes
    user_id: bytes
    rp_name: str = ''
    user_name: str = ''
    user_display_name: str = ''
    algorithms: tuple[int, ...] = ()       # the kinds of key it takes, best first
    exclude: tuple[bytes, ...] = ()        # passkeys it already has for this account
    resident: bool = True                  # one it can find by itself (discoverable)
    uv: bool = False

    @property
    def who(self) -> str:
        return self.user_name or self.user_display_name or 'an account'

    @classmethod
    def parse(cls, data: bytes) -> NewRequest:
        try:
            message = cbor.loads(data)
            rp, user = message[2], message[3]
            options = message.get(7) or {}
            algorithms = tuple(int(item['alg']) for item in message.get(4) or []
                               if isinstance(item, dict) and item.get('type', 'public-key') == 'public-key')
            exclude = tuple(bytes(item['id']) for item in message.get(5) or []
                            if isinstance(item, dict) and item.get('type', 'public-key') == 'public-key')
            request = cls(rp_id=str(rp['id']), client_data_hash=bytes(message[1]), user_id=bytes(user['id']),
                          rp_name=str(rp.get('name') or ''), user_name=str(user.get('name') or ''),
                          user_display_name=str(user.get('displayName') or ''), algorithms=algorithms,
                          exclude=exclude, resident=bool(options.get('rk', True)), uv=bool(options.get('uv', False)))
        except (cbor.CborError, KeyError, TypeError, ValueError, AttributeError) as error:
            raise PasskeyError(f'Windows sent a request for a new passkey Keytap could not read ({error}).') from error
        if not request.rp_id or len(request.client_data_hash) != 32 or not 0 < len(request.user_id) <= 64:
            raise PasskeyError('Windows sent an incomplete request for a new passkey.')
        return request


def make(request: NewRequest) -> Passkey:
    """A new passkey for the website, with a fresh key - not yet saved anywhere."""
    if ES256 not in request.algorithms:
        raise PasskeyError(f'{request.rp_id} asks for a kind of passkey Keytap cannot make.')
    d = p256.new_private_key()
    return Passkey(login_id='', credential_id=uuid.uuid4().bytes, rp_id=request.rp_id, user_handle=request.user_id,
                   user_name=request.user_name, user_display_name=request.user_display_name,
                   rp_name=request.rp_name, counter=0, discoverable=request.resident,
                   key=p256.pkcs8_from_private_key(d, with_public=True))


def record(passkey: Passkey, made: datetime.datetime | None = None) -> dict:
    """The passkey as Bitwarden keeps it, in a login's fido2Credentials - its key included."""
    made = made or datetime.datetime.now(datetime.timezone.utc)
    return {'credentialId': str(uuid.UUID(bytes=passkey.credential_id)), 'keyType': 'public-key',
            'keyAlgorithm': 'ECDSA', 'keyCurve': 'P-256', 'keyValue': _b64url_text(passkey.key),
            'rpId': passkey.rp_id, 'userHandle': _b64url_text(passkey.user_handle), 'userName': passkey.user_name,
            'counter': '0', 'rpName': passkey.rp_name, 'userDisplayName': passkey.user_display_name,
            'discoverable': 'true' if passkey.discoverable else 'false',
            'creationDate': made.strftime('%Y-%m-%dT%H:%M:%S.') + f'{made.microsecond // 1000:03d}Z'}


def excluded(passkeys, request: NewRequest) -> bool:
    """Whether the website already has one of these passkeys for this account."""
    return any(p.rp_id == request.rp_id and p.credential_id in request.exclude for p in passkeys)


def attestation(passkey: Passkey, verified: bool) -> bytes:
    """The answer for a new passkey: CTAP2's authenticatorMakeCredential response, as CBOR, with
    the new passkey's public key and attesting nothing more."""
    x, y = p256.public_key(p256.private_key_from_pkcs8(passkey.key))
    public = cbor.dumps({1: 2, 3: ES256, -1: 1, -2: x.to_bytes(32, 'big'), -3: y.to_bytes(32, 'big')})
    flags = FLAG_UP | FLAG_BE | FLAG_BS | FLAG_AT | (FLAG_UV if verified else 0)
    data = (hashlib.sha256(passkey.rp_id.encode('utf-8')).digest() + bytes([flags]) + (0).to_bytes(4, 'big')
            + AAGUID.bytes + len(passkey.credential_id).to_bytes(2, 'big') + passkey.credential_id + public)
    return cbor.dumps({1: 'none', 2: data, 3: {}})


def candidates(passkeys, request: Request) -> list[Passkey]:
    """The passkeys that can answer: for the website's exact RP ID and, if it names the ones it
    will take, among those; otherwise only those it can find by itself (discoverable)."""
    found = [p for p in passkeys if p.rp_id == request.rp_id]
    if request.allow:
        return [p for p in found if p.credential_id in request.allow]
    return [p for p in found if p.discoverable]


def authenticator_data(passkey: Passkey, verified: bool) -> bytes:
    flags = FLAG_UP | FLAG_BE | FLAG_BS | (FLAG_UV if verified else 0)
    return hashlib.sha256(passkey.rp_id.encode('utf-8')).digest() + bytes([flags]) + \
        passkey.counter.to_bytes(4, 'big')


def answer(passkey: Passkey, request: Request, verified: bool) -> bytes:
    """The signed answer to send back: CTAP2's authenticatorGetAssertion response, as CBOR."""
    if passkey.counter > 0:
        raise PasskeyError('This passkey counts its uses, and Keytap cannot save the count to your vault. '
                           "Sign in with it from Bitwarden's browser extension or app instead.")
    try:
        d = p256.private_key_from_pkcs8(passkey.key)
    except p256.KeyFormatError as error:
        raise PasskeyError(f'This passkey cannot sign: {error}.') from error
    data = authenticator_data(passkey, verified)
    response = {1: {'id': passkey.credential_id, 'type': 'public-key'}, 2: data,
                3: p256.sign(d, data + request.client_data_hash)}
    if passkey.user_handle:
        response[4] = {'id': passkey.user_handle}
    return cbor.dumps(response)


def authenticator_info() -> bytes:
    """What Keytap tells Windows it can do (CTAP2's authenticatorGetInfo): make and sign with
    ES256 keys it holds itself, for passkeys websites can find, checking it is you."""
    return cbor.dumps({1: ['FIDO_2_0', 'FIDO_2_1'], 3: AAGUID.bytes, 4: {'rk': True, 'up': True, 'uv': True},
                       9: ['internal'], 10: [{'alg': -7, 'type': 'public-key'}]})
