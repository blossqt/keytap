"""ECDSA on the P-256 curve with SHA-256 (COSE's ES256): how a Bitwarden passkey signs.

Bitwarden keeps each passkey's private key as PKCS#8. Signing uses RFC 6979's
deterministic nonces, so a weak random number generator can never give the key
away. The arithmetic is plain Python integers: a sign-in signs once.
"""

from __future__ import annotations

import hashlib
import hmac

# The curve: y^2 = x^3 - 3x + b over the prime field p, with base point G of order n.
P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
A = P - 3
B = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
G = (0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296,
     0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5)

# DER object identifiers: id-ecPublicKey and prime256v1 (P-256).
_EC_PUBLIC_KEY = bytes.fromhex('2a8648ce3d0201')
_PRIME256V1 = bytes.fromhex('2a8648ce3d030107')


class KeyFormatError(ValueError):
    """A private key that is not a P-256 key in PKCS#8."""


# --------------------------------------------------------------------------- points (Jacobian)

def _double(point):
    x, y, z = point
    if not y:
        return 0, 1, 0
    yy = y * y % P
    s = 4 * x * yy % P
    m = 3 * (x - z * z) * (x + z * z) % P           # a = -3
    nx = (m * m - 2 * s) % P
    return nx, (m * (s - nx) - 8 * yy * yy) % P, 2 * y * z % P


def _add(p, q):
    if not p[2]:
        return q
    if not q[2]:
        return p
    z1z1, z2z2 = p[2] * p[2] % P, q[2] * q[2] % P
    u1, u2 = p[0] * z2z2 % P, q[0] * z1z1 % P
    s1, s2 = p[1] * q[2] * z2z2 % P, q[1] * p[2] * z1z1 % P
    if u1 == u2:
        return _double(p) if s1 == s2 else (0, 1, 0)
    h, r = (u2 - u1) % P, (s2 - s1) % P
    hh = h * h % P
    hhh = h * hh % P
    v = u1 * hh % P
    nx = (r * r - hhh - 2 * v) % P
    return nx, (r * (v - nx) - s1 * hhh) % P, h * p[2] * q[2] % P


def _multiply(k: int, point=G):
    result, addend = (0, 1, 0), (point[0], point[1], 1)
    while k:
        if k & 1:
            result = _add(result, addend)
        addend = _double(addend)
        k >>= 1
    x, y, z = result
    if not z:
        raise ValueError('the point at infinity')
    zi = pow(z, -1, P)
    return x * zi * zi % P, y * zi * zi * zi % P


def public_key(d: int) -> tuple[int, int]:
    return _multiply(d)


def on_curve(point) -> bool:
    x, y = point
    return 0 <= x < P and 0 <= y < P and (y * y - (x * x * x + A * x + B)) % P == 0


# --------------------------------------------------------------------------- keys

def _der(data: bytes, at: int, tag: int) -> tuple[bytes, int]:
    """One DER element with the given tag at `at`: its contents, and where the next one starts."""
    if at >= len(data) or data[at] != tag:
        raise KeyFormatError('not the DER this key should be')
    at += 1
    length = data[at]
    at += 1
    if length & 0x80:
        count = length & 0x7f
        length = int.from_bytes(data[at:at + count], 'big')
        at += count
    if at + length > len(data):
        raise KeyFormatError('a DER element runs past the end')
    return data[at:at + length], at + length


def private_key_from_pkcs8(der: bytes) -> int:
    """The private scalar of a P-256 key in PKCS#8 (RFC 5208 holding an RFC 5915 ECPrivateKey)."""
    info, _ = _der(der, 0, 0x30)
    _, at = _der(info, 0, 0x02)                                   # version
    algorithm, at = _der(info, at, 0x30)
    oid, after = _der(algorithm, 0, 0x06)
    curve, _ = _der(algorithm, after, 0x06)
    if oid != _EC_PUBLIC_KEY or curve != _PRIME256V1:
        raise KeyFormatError('the passkey is not a P-256 key')
    wrapped, _ = _der(info, at, 0x04)
    ec_key, _ = _der(wrapped, 0, 0x30)
    _, at = _der(ec_key, 0, 0x02)                                 # version 1
    secret, _ = _der(ec_key, at, 0x04)
    d = int.from_bytes(secret, 'big')
    if not 0 < d < N:
        raise KeyFormatError('the passkey has an impossible private key')
    return d


def pkcs8_from_private_key(d: int) -> bytes:
    """The other way round, for tests and for making keys: PKCS#8 without the optional public key."""
    def element(tag: int, content: bytes) -> bytes:
        size = len(content)
        length = bytes([size]) if size < 128 else bytes([0x81, size])
        return bytes([tag]) + length + content
    algorithm = element(0x30, element(0x06, _EC_PUBLIC_KEY) + element(0x06, _PRIME256V1))
    ec_key = element(0x30, element(0x02, b'\x01') + element(0x04, d.to_bytes(32, 'big')))
    return element(0x30, element(0x02, b'\x00') + algorithm + element(0x04, ec_key))


# --------------------------------------------------------------------------- signatures

def _nonce(d: int, digest: bytes) -> int:
    """RFC 6979 section 3.2, for SHA-256 and P-256."""
    x = d.to_bytes(32, 'big')
    h = (int.from_bytes(digest, 'big') % N).to_bytes(32, 'big')
    v, k = b'\x01' * 32, b'\x00' * 32
    k = hmac.new(k, v + b'\x00' + x + h, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    k = hmac.new(k, v + b'\x01' + x + h, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    while True:
        v = hmac.new(k, v, hashlib.sha256).digest()
        candidate = int.from_bytes(v, 'big')
        if 0 < candidate < N:
            return candidate
        k = hmac.new(k, v + b'\x00', hashlib.sha256).digest()
        v = hmac.new(k, v, hashlib.sha256).digest()


def sign_raw(d: int, message: bytes) -> tuple[int, int]:
    digest = hashlib.sha256(message).digest()
    e = int.from_bytes(digest, 'big')
    while True:
        k = _nonce(d, digest)
        r = _multiply(k)[0] % N
        s = pow(k, -1, N) * (e + r * d) % N
        if r and s:
            return r, s
        digest = hashlib.sha256(digest).digest()      # never in practice


def der_signature(r: int, s: int) -> bytes:
    """r and s as the DER SEQUENCE WebAuthn wants (rather than raw r || s)."""
    def integer(value: int) -> bytes:
        raw = value.to_bytes(32, 'big').lstrip(b'\x00') or b'\x00'
        if raw[0] & 0x80:
            raw = b'\x00' + raw
        return bytes([0x02, len(raw)]) + raw
    body = integer(r) + integer(s)
    return bytes([0x30, len(body)]) + body


def sign(d: int, message: bytes) -> bytes:
    return der_signature(*sign_raw(d, message))


def verify(public: tuple[int, int], message: bytes, signature: bytes) -> bool:
    """For tests: whether a DER signature is good."""
    try:
        body, _ = _der(signature, 0, 0x30)
        r_raw, at = _der(body, 0, 0x02)
        s_raw, _ = _der(body, at, 0x02)
    except KeyFormatError:
        return False
    r, s = int.from_bytes(r_raw, 'big'), int.from_bytes(s_raw, 'big')
    if not (0 < r < N and 0 < s < N) or not on_curve(public):
        return False
    e = int.from_bytes(hashlib.sha256(message).digest(), 'big')
    w = pow(s, -1, N)
    total = _add(_jacobian(_multiply(e * w % N)), _jacobian(_multiply(r * w % N, public)))
    if not total[2]:
        return False
    zi = pow(total[2], -1, P)
    return total[0] * zi * zi % P % N == r


def _jacobian(point):
    return point[0], point[1], 1
