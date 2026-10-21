"""Signing in with the passkeys in a Bitwarden vault, as Bitwarden's own apps do.

A passkey is a key pair a website holds the public half of. Signing in, the
website sends a challenge; the passkey's private key signs it. Windows asks
Keytap to do that through its passkey plugin interface (see provider.py),
with requests and answers in CTAP2's CBOR.

The answer is built exactly as Bitwarden builds it - the same flags (backed
up and eligible for it, as synced passkeys are), the same counter, the same
key - so a website cannot tell which Bitwarden app signed. Keytap only reads
the vault, so a passkey that counts its uses (a counter above 0, from an
import; Bitwarden's own stay at 0) is left to Bitwarden, which saves the
count: an unsaved count would look to the website like a copied key.
"""

from __future__ import annotations

import base64
import hashlib
import uuid
from dataclasses import dataclass, field

from . import cbor, p256

# Keytap's authenticator, as Windows lists it. Assertions don't carry it; only new passkeys would.
AAGUID = uuid.UUID('5d6c5f1e-8a0b-4a53-9c1e-4b7a2f0e9d31')

FLAG_UP, FLAG_UV, FLAG_BE, FLAG_BS = 0x01, 0x04, 0x08, 0x10


class PasskeyError(Exception):
    """Why a passkey cannot sign in, in words fit to show."""


def _b64url(text: str) -> bytes:
    text = (text or '').strip()
    return base64.urlsafe_b64decode(text + '=' * (-len(text) % 4))


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
    """What Keytap tells Windows it can do (CTAP2's authenticatorGetInfo): sign with ES256 keys
    it holds itself, for passkeys websites can find, checking it is you."""
    return cbor.dumps({1: ['FIDO_2_0', 'FIDO_2_1'], 3: AAGUID.bytes, 4: {'rk': True, 'up': True, 'uv': True},
                       9: ['internal'], 10: [{'alg': -7, 'type': 'public-key'}]})
