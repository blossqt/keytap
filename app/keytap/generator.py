"""Bitwarden's generator, here: passwords, passphrases and usernames, from Windows' own randomness
(Python's secrets) - asking bw would take two seconds a time.

Passphrases come from EFF's long word list (eff.org/dice, CC BY 3.0 US), the one Bitwarden uses,
taken from Bitwarden's CLI into words.txt.
"""

from __future__ import annotations

import functools
import secrets
import string
from pathlib import Path

UPPER, LOWER, DIGITS = string.ascii_uppercase, string.ascii_lowercase, string.digits
SPECIAL = '!@#$%^&*'                         # Bitwarden's
AMBIGUOUS = frozenset('IlO01')
SEPARATOR = '-'

DEFAULTS = {
    'kind': 'password',
    'length': 14, 'upper': True, 'lower': True, 'digits': True, 'special': False,
    'min_digits': 1, 'min_special': 0, 'avoid_ambiguous': False,
    'words': 6, 'separator': SEPARATOR, 'capitalize': False, 'number': False,
    'username': 'word', 'email': '', 'domain': '', 'username_capitalize': False, 'username_number': False,
}
LIMITS = {'length': (5, 128), 'words': (3, 20), 'min_digits': (0, 9), 'min_special': (0, 9)}


@functools.cache
def words() -> tuple[str, ...]:
    return tuple(Path(__file__).with_name('words.txt').read_text(encoding='utf-8').split())


def settled(options: dict | None) -> dict:
    """options with anything missing or out of range put right."""
    out = dict(DEFAULTS)
    for key, value in (options or {}).items():
        if key in DEFAULTS and isinstance(value, type(DEFAULTS[key])):
            out[key] = value
    for key, (low, high) in LIMITS.items():
        out[key] = max(low, min(high, out[key]))
    if not any(out[key] for key in ('upper', 'lower', 'digits', 'special')):
        out['lower'] = True
    return out


def _pool(chars: str, avoid: bool) -> str:
    return ''.join(ch for ch in chars if ch not in AMBIGUOUS) if avoid else chars


def password(options: dict | None = None) -> str:
    """Bitwarden's way: at least one of each kind chosen (the minimums for digits and special
    characters), the rest from all of them, shuffled."""
    o = settled(options)
    avoid = o['avoid_ambiguous']
    kinds = [(_pool(chars, avoid), at_least) for chars, wanted, at_least in (
        (UPPER, o['upper'], 1), (LOWER, o['lower'], 1), (DIGITS, o['digits'], max(1, o['min_digits'])),
        (SPECIAL, o['special'], max(1, o['min_special']))) if wanted]
    chosen = [secrets.choice(pool) for pool, at_least in kinds for _ in range(at_least)]
    everything = ''.join(pool for pool, _ in kinds)
    length = max(o['length'], len(chosen))
    chosen += [secrets.choice(everything) for _ in range(length - len(chosen))]
    for n in range(len(chosen) - 1, 0, -1):         # Fisher-Yates, with secrets' randomness
        m = secrets.randbelow(n + 1)
        chosen[n], chosen[m] = chosen[m], chosen[n]
    return ''.join(chosen)


def passphrase(options: dict | None = None) -> str:
    o = settled(options)
    chosen = [secrets.choice(words()) for _ in range(o['words'])]
    if o['capitalize']:
        chosen = [word[:1].upper() + word[1:] for word in chosen]
    if o['number']:
        n = secrets.randbelow(len(chosen))
        chosen[n] += str(secrets.randbelow(10))
    return o['separator'].join(chosen)


def username(options: dict | None = None) -> str:
    """A random word; or an address: yours with +something before the @ (plus addressing), or
    something@ your own domain (a catch-all)."""
    o = settled(options)
    kind = o['username']
    if kind == 'plus':
        email = o['email'].strip()
        if '@' not in email:
            return ''
        local, _, domain = email.rpartition('@')
        return f'{local}+{_random(8)}@{domain}'
    if kind == 'catchall':
        domain = o['domain'].strip().lstrip('@')
        return f'{_random(8)}@{domain}' if domain else ''
    word = secrets.choice(words())
    if o['username_capitalize']:
        word = word[:1].upper() + word[1:]
    if o['username_number']:
        word += f'{secrets.randbelow(10000):04d}'
    return word


def _random(length: int) -> str:
    return ''.join(secrets.choice(LOWER + DIGITS) for _ in range(length))


def generate(options: dict | None = None) -> str:
    """What options' kind ('password', 'passphrase' or 'username') makes."""
    kind = settled(options)['kind']
    return {'passphrase': passphrase, 'username': username}.get(kind, password)(options)
