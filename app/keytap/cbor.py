"""The little CBOR that passkeys speak: integers, byte and text strings, arrays, maps,
booleans and null, written in CTAP2's canonical form (shortest lengths, map keys in order).

Windows hands a passkey request over as CBOR and takes the answer back the same way.
"""

from __future__ import annotations


class CborError(ValueError):
    pass


def _head(major: int, n: int) -> bytes:
    if n < 24:
        return bytes([major << 5 | n])
    for extra, size in ((24, 1), (25, 2), (26, 4), (27, 8)):
        if n < 1 << (8 * size):
            return bytes([major << 5 | extra]) + n.to_bytes(size, 'big')
    raise CborError('a number too big for CBOR')


def dumps(value) -> bytes:
    if value is None:
        return b'\xf6'
    if value is True:
        return b'\xf5'
    if value is False:
        return b'\xf4'
    if isinstance(value, int):
        return _head(0, value) if value >= 0 else _head(1, -1 - value)
    if isinstance(value, (bytes, bytearray)):
        return _head(2, len(value)) + bytes(value)
    if isinstance(value, str):
        data = value.encode('utf-8')
        return _head(3, len(data)) + data
    if isinstance(value, (list, tuple)):
        return _head(4, len(value)) + b''.join(dumps(item) for item in value)
    if isinstance(value, dict):
        # Canonical CTAP2 order: by the encoded key, shorter first, then byte by byte.
        pairs = sorted(((dumps(k), dumps(v)) for k, v in value.items()), key=lambda kv: (len(kv[0]), kv[0]))
        return _head(5, len(pairs)) + b''.join(k + v for k, v in pairs)
    raise CborError(f'cannot write {type(value).__name__} as CBOR')


def loads(data: bytes):
    value, end = _read(bytes(data), 0, 0)
    if end != len(data):
        raise CborError('extra bytes after the CBOR value')
    return value


def _read(data: bytes, at: int, depth: int):
    if depth > 16:
        raise CborError('CBOR nested too deep')
    if at >= len(data):
        raise CborError('CBOR cut short')
    first = data[at]
    major, info = first >> 5, first & 0x1f
    at += 1
    if major == 7:
        simple = {20: False, 21: True, 22: None}
        if info in simple:
            return simple[info], at
        raise CborError(f'unsupported CBOR simple value {info}')
    if info < 24:
        n = info
    elif info in (24, 25, 26, 27):
        size = 1 << (info - 24)
        if at + size > len(data):
            raise CborError('CBOR cut short')
        n = int.from_bytes(data[at:at + size], 'big')
        at += size
    else:
        raise CborError('indefinite-length CBOR is not used by CTAP2')
    if major == 0:
        return n, at
    if major == 1:
        return -1 - n, at
    if major in (2, 3):
        if at + n > len(data):
            raise CborError('CBOR cut short')
        raw = data[at:at + n]
        return (raw if major == 2 else raw.decode('utf-8')), at + n
    if major == 4:
        items = []
        for _ in range(n):
            item, at = _read(data, at, depth + 1)
            items.append(item)
        return items, at
    if major == 5:
        result = {}
        for _ in range(n):
            key, at = _read(data, at, depth + 1)
            value, at = _read(data, at, depth + 1)
            if isinstance(key, list):
                raise CborError('a CBOR map key must not be an array')
            result[key] = value
        return result, at
    raise CborError(f'unsupported CBOR type {major}')      # 6: tags
