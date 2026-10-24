"""A stand-in for Bitwarden's bw.exe, for Keytap's tests.

It answers the commands Keytap uses the way the real CLI does - same
output, same errors on stderr, same exit codes - from a JSON file named by
KEYTAP_FAKE_VAULT:

    {"email": ..., "password": ..., "signed_in": true, "items": [...]}

The session key it hands out is kept in that file too, so status reports
"unlocked" only to a caller holding it, as bw does.
"""

import base64
import json
import os
import secrets
import sys
import time
from pathlib import Path

STATE = Path(os.environ['KEYTAP_FAKE_VAULT'])


def load() -> dict:
    return json.loads(STATE.read_text(encoding='utf-8'))


def save(state: dict) -> None:
    STATE.write_text(json.dumps(state, indent=1), encoding='utf-8')


def fail(message: str) -> None:
    print(message, file=sys.stderr)
    sys.exit(1)


def log(args) -> None:
    with open(STATE.with_suffix('.log'), 'a', encoding='utf-8') as f:
        f.write(' '.join(a for a in args if a != '--nointeraction') + '\n')


def main(args: list[str]) -> None:
    log(args)
    args = [a for a in args if a != '--nointeraction']
    time.sleep(float(os.environ.get('KEYTAP_FAKE_DELAY', '0.15')))
    if args == ['--version']:
        print('2026.10.0')
        return
    state = load()
    session_ok = state.get('session') and os.environ.get('BW_SESSION') == state.get('session')
    command = args[0] if args else ''

    if command == 'status':
        status = ('unauthenticated' if not state.get('signed_in') else 'unlocked' if session_ok else 'locked')
        print(json.dumps({'serverUrl': state.get('server'), 'lastSync': '2026-10-19T10:00:00.000Z',
                          'userEmail': state.get('email') if state.get('signed_in') else None,
                          'status': status}))
    elif command == 'config':
        if state.get('signed_in'):
            fail('Logout required before server config update.')
        state['server'] = None if args[2] in ('null', 'bitwarden.com') else args[2]
        save(state)
        print('Saved setting `config`.')
    elif command == 'login':
        state['signed_in'] = True
        save(state)
        print('You are logged in!')
    elif not state.get('signed_in'):
        fail('You are not logged in.')
    elif command == 'unlock':
        name = args[args.index('--passwordenv') + 1]
        if os.environ.get(name) != state['password']:
            fail('Invalid master password.')
        state['session'] = secrets.token_urlsafe(48)
        save(state)
        print(state['session'])
    elif command == 'lock':
        state['session'] = None
        save(state)
        print('Your vault is locked.')
    elif command == 'logout':
        state.update(signed_in=False, session=None)
        save(state)
        print('You have logged out.')
    elif not session_ok:
        fail('Vault is locked.')
    elif args[:2] == ['list', 'items']:
        print(json.dumps(state['items']))
    elif args[:2] == ['list', 'folders']:
        print(json.dumps(state.get('folders', [])))
    elif args[:2] == ['get', 'item']:
        found = next((i for i in state['items'] if i.get('id') == args[2]), None)
        if found is None:
            fail('Not found.')
        print(json.dumps(found))
    elif args[:2] in (['create', 'item'], ['edit', 'item']):
        # As bw: the item, base64-encoded JSON, on the command line or else on standard input.
        encoded = args[3] if args[0] == 'edit' and len(args) > 3 else args[2] if args[0] == 'create' and len(args) > 2 \
            else sys.stdin.read()
        made = json.loads(base64.b64decode(encoded.strip()))
        if args[0] == 'edit':
            index = next((n for n, i in enumerate(state['items']) if i.get('id') == args[2]), None)
            if index is None:
                fail('Not found.')
            made['id'] = args[2]
            state['items'][index] = made
        else:
            made['id'] = f'made-{len(state["items"]) + 1}'
            state['items'].append(made)
        save(state)
        print(json.dumps(made))
    elif command == 'sync':
        print('Syncing complete.')
    else:
        fail(f'Unknown command: {command}')


if __name__ == '__main__':
    main(sys.argv[1:])
