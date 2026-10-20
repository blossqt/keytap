"""Auto-type sequences: what to type, written the way KeePass writes them.

    {USERNAME}{TAB}{PASSWORD}{ENTER}

Placeholders: {USERNAME} {PASSWORD} {TOTP} {FIELD:name} (a custom field);
keys {TAB} {ENTER} {SPACE} {BACKSPACE} {DELETE} {ESC} {UP} {DOWN} {LEFT}
{RIGHT} {HOME} {END} {PGUP} {PGDN} {INSERT} {F1}-{F16}, each optionally with a
count ({TAB 2}); {CLEARFIELD} empties the field first; {DELAY 500} waits that
many milliseconds; {DELAY=50} sets the pause between keys from there on.
{{} and {}} type a brace. Anything else is typed as it is.
"""

from __future__ import annotations

import re
from collections.abc import Callable

DEFAULT = '{USERNAME}{TAB}{PASSWORD}{ENTER}'

KEYS = {
    'TAB': 0x09, 'ENTER': 0x0D, 'RETURN': 0x0D, 'SPACE': 0x20,
    'BACKSPACE': 0x08, 'BKSP': 0x08, 'BS': 0x08,
    'DELETE': 0x2E, 'DEL': 0x2E, 'ESC': 0x1B, 'ESCAPE': 0x1B,
    'UP': 0x26, 'DOWN': 0x28, 'LEFT': 0x25, 'RIGHT': 0x27,
    'HOME': 0x24, 'END': 0x23, 'PGUP': 0x21, 'PGDN': 0x22, 'INSERT': 0x2D, 'INS': 0x2D,
    **{f'F{n}': 0x6F + n for n in range(1, 17)},
}
VK_SHIFT = 0x10

# A step is ('text', str), ('key', vk), ('chord', (modifier vk, vk)),
# ('delay', ms) or ('keydelay', ms).
Step = tuple[str, object]

_TOKEN = re.compile(r'\{\{\}|\{\}\}|\{[^{}]*\}|[^{]+|\{')
_MAX_REPEAT = 100
_MAX_DELAY = 10_000


class SequenceError(ValueError):
    pass


def compile(sequence: str, login, totp_code: Callable[[], str] | None = None) -> list[Step]:  # noqa: A001
    """Turn a sequence into steps for one login. Secrets go in as text steps."""
    steps: list[Step] = []

    def text(value: str) -> None:
        if not value:
            return
        if steps and steps[-1][0] == 'text':
            steps[-1] = ('text', steps[-1][1] + value)
        else:
            steps.append(('text', value))

    for token in _TOKEN.findall(sequence or ''):
        if token == '{{}':
            text('{')
        elif token == '{}}':
            text('}')
        elif token == '{':
            raise SequenceError('a { is not closed - type {{} for a brace')
        elif token.startswith('{'):
            _placeholder(token[1:-1].strip(), login, totp_code, steps, text)
        else:
            text(token)
    return steps


def _placeholder(body: str, login, totp_code, steps: list[Step], text) -> None:
    upper = body.upper()
    if upper == 'USERNAME':
        text(login.username)
    elif upper == 'PASSWORD':
        text(login.password)
    elif upper in ('TOTP', 'OTP'):
        if not login.totp:
            raise SequenceError(f'“{login.name}” has no authenticator key for {{{body}}}')
        if totp_code is None:
            raise SequenceError('no code available')
        text(totp_code())
    elif upper.startswith(('FIELD:', 'S:')):
        name = body.split(':', 1)[1].strip()
        value = login.field_value(name)
        if value is None:
            raise SequenceError(f'“{login.name}” has no custom field called “{name}”')
        text(value)
    elif upper == 'CLEARFIELD':
        # As KeePass does it: to the start, select to the end, delete.
        steps.extend([('key', KEYS['HOME']), ('chord', (VK_SHIFT, KEYS['END'])), ('key', KEYS['DELETE'])])
    elif upper.startswith('DELAY='):
        steps.append(('keydelay', _number(body.split('=', 1)[1], body, _MAX_DELAY)))
    elif upper.startswith('DELAY'):
        steps.append(('delay', _number(body[5:], body, _MAX_DELAY)))
    else:
        name, _, count = upper.partition(' ')
        if name not in KEYS:
            raise SequenceError(f'Keytap does not know {{{body}}}')
        repeat = _number(count, body, _MAX_REPEAT) if count.strip() else 1
        if name == 'SPACE':
            text(' ' * repeat)
        else:
            steps.extend([('key', KEYS[name])] * repeat)


def _number(text: str, body: str, limit: int) -> int:
    try:
        value = int(text.strip())
    except ValueError:
        raise SequenceError(f'{{{body}}} needs a number') from None
    if not 0 <= value <= limit:
        raise SequenceError(f'{{{body}}} is out of range (0 to {limit})')
    return value


def for_login(login, default: str) -> str:
    """The sequence a login is typed with: its own, else the default.

    With no username, the default's leading {USERNAME}{TAB} is dropped, so a
    password-only login lands in the field the cursor is in.
    """
    own = login.sequence
    if own:
        return own
    sequence = default or DEFAULT
    if not login.username and sequence.upper().startswith('{USERNAME}{TAB}'):
        sequence = sequence[len('{USERNAME}{TAB}'):]
    return sequence


def from_password_box(sequence: str) -> str:
    """The part of a sequence that belongs in the password box, for when the
    cursor is already there: {USERNAME}{TAB}{PASSWORD}{ENTER} becomes
    {PASSWORD}{ENTER}."""
    upper = sequence.upper()
    if upper.startswith('{USERNAME}{TAB}'):
        return sequence[len('{USERNAME}{TAB}'):]
    if '{USERNAME}' in upper:
        return '{PASSWORD}' + ('{ENTER}' if upper.rstrip().endswith('{ENTER}') else '')
    return sequence


def check(sequence: str) -> str:
    """An error message for a sequence that can never work, else ''."""
    class _Probe:
        name = 'the login'
        username = password = 'x'
        totp = 'x'

        @staticmethod
        def field_value(name):
            return ''
    try:
        compile(sequence, _Probe(), lambda: '0')
    except SequenceError as error:
        return str(error)
    return ''
