"""Two-step login codes from a login's authenticator key, worked out here (RFC 6238).

Bitwarden stores the key as a bare base32 secret, an otpauth:// URI, or
steam://SECRET for Steam Guard's five-character codes.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import struct
import time
from dataclasses import dataclass
from urllib.parse import parse_qs, unquote, urlparse

_STEAM_CHARS = '23456789BCDFGHJKMNPQRTVWXY'
_ALGORITHMS = {'SHA1': hashlib.sha1, 'SHA256': hashlib.sha256, 'SHA512': hashlib.sha512}


class TotpError(ValueError):
    pass


@dataclass(frozen=True)
class TotpKey:
    secret: bytes
    digits: int = 6
    period: int = 30
    algorithm: str = 'SHA1'
    steam: bool = False


def _base32(text: str) -> bytes:
    cleaned = unquote(text).replace(' ', '').replace('-', '').upper().rstrip('=')
    if not cleaned:
        raise TotpError('the authenticator key is empty')
    try:
        return base64.b32decode(cleaned + '=' * (-len(cleaned) % 8))
    except ValueError as error:     # binascii.Error is one
        raise TotpError('the authenticator key is not valid base32') from error


def parse(key: str) -> TotpKey:
    key = (key or '').strip()
    if key.lower().startswith('steam://'):
        return TotpKey(_base32(key[8:]), digits=5, steam=True)
    if key.lower().startswith('otpauth://'):
        url = urlparse(key)
        query = {k.lower(): v[0] for k, v in parse_qs(url.query).items() if v}
        algorithm = query.get('algorithm', 'SHA1').upper()
        if algorithm not in _ALGORITHMS:
            raise TotpError(f'unsupported algorithm {algorithm}')
        try:
            digits = int(query.get('digits', 6))
            period = int(query.get('period', 30))
        except ValueError as error:
            raise TotpError('the authenticator URI has a bad number in it') from error
        if not 1 <= digits <= 10 or period <= 0:
            raise TotpError('the authenticator URI has a bad number in it')
        if 'secret' not in query:
            raise TotpError('the authenticator URI has no secret')
        steam = url.netloc.lower() == 'steam' or query.get('encoder', '').lower() == 'steam'
        return TotpKey(_base32(query['secret']), digits=5 if steam else digits, period=period,
                       algorithm=algorithm, steam=steam)
    return TotpKey(_base32(key))


def code(key: str | TotpKey, at: float | None = None) -> str:
    totp = parse(key) if isinstance(key, str) else key
    counter = int((time.time() if at is None else at) // totp.period)
    digest = hmac.new(totp.secret, struct.pack('>Q', counter), _ALGORITHMS[totp.algorithm]).digest()
    offset = digest[-1] & 0x0F
    value = struct.unpack('>I', digest[offset:offset + 4])[0] & 0x7FFFFFFF
    if totp.steam:
        chars = []
        for _ in range(5):
            chars.append(_STEAM_CHARS[value % len(_STEAM_CHARS)])
            value //= len(_STEAM_CHARS)
        return ''.join(chars)
    return str(value % 10 ** totp.digits).zfill(totp.digits)


def seconds_left(key: str | TotpKey, at: float | None = None) -> int:
    totp = parse(key) if isinstance(key, str) else key
    now = time.time() if at is None else at
    return int(totp.period - now % totp.period)
