"""New SSH keys for the vault, as Bitwarden makes them: Ed25519, in OpenSSH's own formats.

The key is made here, in memory, and goes nowhere but to bw: Windows' ssh-keygen would have
written it to a file first. The curve arithmetic follows RFC 8032 (as build/ed25519.py does); it
runs once a key.
"""

from __future__ import annotations

import base64
import hashlib
import secrets
import struct

_P = 2**255 - 19
_D = -121665 * pow(121666, _P - 2, _P) % _P
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)


def _inv(x: int) -> int:
    return pow(x, _P - 2, _P)


def _add(p, q):
    a = (p[1] - p[0]) * (q[1] - q[0]) % _P
    b = (p[1] + p[0]) * (q[1] + q[0]) % _P
    c = 2 * p[3] * q[3] * _D % _P
    d = 2 * p[2] * q[2] % _P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f, g * h, f * g, e * h)


def _mul(scalar: int, point):
    result = (0, 1, 1, 0)
    while scalar > 0:
        if scalar & 1:
            result = _add(result, point)
        point = _add(point, point)
        scalar >>= 1
    return result


def _base():
    y = 4 * _inv(5) % _P
    x2 = (y * y - 1) * _inv(_D * y * y + 1)
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P:
        x = x * _SQRT_M1 % _P
    if x & 1:
        x = _P - x
    return (x, y, 1, x * y % _P)


def public_key(seed: bytes) -> bytes:
    """The Ed25519 public key for a 32-byte private seed."""
    digest = hashlib.sha512(seed).digest()
    a = int.from_bytes(digest[:32], 'little')
    a &= (1 << 254) - 8
    a |= 1 << 254
    point = _mul(a, _base())
    zinv = _inv(point[2])
    x, y = point[0] * zinv % _P, point[1] * zinv % _P
    return int.to_bytes(y | ((x & 1) << 255), 32, 'little')


def _string(data: bytes) -> bytes:
    return struct.pack('>I', len(data)) + data


def fingerprint(public_line: str) -> str:
    """'SHA256:…' for a public key line ('ssh-ed25519 AAAA… comment'), as ssh-keygen -l gives it."""
    parts = (public_line or '').split()
    if len(parts) < 2:
        return ''
    try:
        blob = base64.b64decode(parts[1], validate=True)
    except ValueError:
        return ''
    return 'SHA256:' + base64.b64encode(hashlib.sha256(blob).digest()).decode('ascii').rstrip('=')


def new_key(comment: str = '') -> dict:
    """{'privateKey', 'publicKey', 'keyFingerprint'}: a new Ed25519 key, as Bitwarden keeps one."""
    seed = secrets.token_bytes(32)
    public = public_key(seed)
    blob = _string(b'ssh-ed25519') + _string(public)
    check = secrets.token_bytes(4)
    private = (check + check + _string(b'ssh-ed25519') + _string(public) + _string(seed + public) +
               _string(comment.encode('utf-8')))
    private += bytes(range(1, 8 - len(private) % 8 + 1)) if len(private) % 8 else b''
    body = (b'openssh-key-v1\0' + _string(b'none') + _string(b'none') + _string(b'') + struct.pack('>I', 1) +
            _string(blob) + _string(private))
    encoded = base64.b64encode(body).decode('ascii')
    lines = [encoded[n:n + 70] for n in range(0, len(encoded), 70)]
    public_line = 'ssh-ed25519 ' + base64.b64encode(blob).decode('ascii')
    return {'privateKey': '-----BEGIN OPENSSH PRIVATE KEY-----\n' + '\n'.join(lines) +
            '\n-----END OPENSSH PRIVATE KEY-----\n',
            'publicKey': public_line, 'keyFingerprint': fingerprint(public_line)}
