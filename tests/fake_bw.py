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
    elif command == 'send':
        sends(state, args[1:])
    elif args[:2] == ['list', 'items']:
        if '--archived' in args and state.get('can_archive', True):
            print(json.dumps([i for i in state['items'] if i.get('archivedDate') and not i.get('deletedDate')]))
        elif '--trash' in args:
            print(json.dumps([i for i in state['items'] if i.get('deletedDate')]))
        else:
            print(json.dumps([i for i in state['items'] if not i.get('deletedDate') and not i.get('archivedDate')]))
    elif args[:2] == ['list', 'folders']:
        print(json.dumps(state.get('folders', [])))
    elif args[:2] == ['list', 'organizations']:
        print(json.dumps(state.get('organizations', [])))
    elif args[:2] == ['list', 'collections']:
        print(json.dumps(state.get('collections', [])))
    elif args[:2] == ['get', 'item']:
        print(json.dumps(item(state, args[2])))
    elif args[:2] in (['create', 'item'], ['edit', 'item']):
        # As bw: the item, base64-encoded JSON, on the command line or else on standard input.
        encoded = args[3] if args[0] == 'edit' and len(args) > 3 else args[2] if args[0] == 'create' and len(args) > 2 \
            else sys.stdin.read()
        made = json.loads(base64.b64decode(encoded.strip()))
        made['revisionDate'] = NOW
        if args[0] == 'edit':
            index = next((n for n, i in enumerate(state['items']) if i.get('id') == args[2]), None)
            if index is None:
                fail('Not found.')
            old = state['items'][index]
            made['id'] = args[2]
            old_password = (old.get('login') or {}).get('password')
            if old_password and old_password != (made.get('login') or {}).get('password'):
                made['passwordHistory'] = [{'lastUsedDate': NOW, 'password': old_password}] + \
                    (old.get('passwordHistory') or [])
            state['items'][index] = made
        else:
            made['id'] = f'made-{len(state["items"]) + 1}'
            made['creationDate'] = NOW
            state['items'].append(made)
        save(state)
        print(json.dumps(made))
    elif args[:2] == ['delete', 'item']:
        found = item(state, args[2])
        if '--permanent' in args:
            state['items'].remove(found)
        else:
            found['deletedDate'] = NOW
        save(state)
    elif args[:2] == ['restore', 'item']:
        found = item(state, args[2])
        found.pop('deletedDate' if found.get('deletedDate') else 'archivedDate', None)
        save(state)
    elif args[:2] == ['archive', 'item']:
        if not state.get('can_archive', True):
            fail('Premium status is required to use this feature.')
        item(state, args[2])['archivedDate'] = NOW
        save(state)
    elif args[:2] in (['create', 'folder'], ['edit', 'folder']):
        name = json.loads(base64.b64decode(sys.stdin.read().strip()))['name']
        folders = state.setdefault('folders', [])
        if args[0] == 'edit':
            folder = next((f for f in folders if f['id'] == args[2]), None)
            if folder is None:
                fail('Not found.')
            folder['name'] = name
        else:
            folder = {'object': 'folder', 'id': f'folder-{len(folders) + 1}', 'name': name}
            folders.append(folder)
        save(state)
        print(json.dumps(folder))
    elif args[:2] == ['delete', 'folder']:
        state['folders'] = [f for f in state.get('folders', []) if f['id'] != args[2]]
        for each in state['items']:
            if each.get('folderId') == args[2]:
                each['folderId'] = None
        save(state)
    elif command == 'move':
        found = item(state, args[1])
        found.update(organizationId=args[2], collectionIds=json.loads(base64.b64decode(sys.stdin.read().strip())))
        save(state)
        print(json.dumps(found))
    elif args[:2] == ['edit', 'item-collections']:
        found = item(state, args[2])
        found['collectionIds'] = json.loads(base64.b64decode(sys.stdin.read().strip()))
        save(state)
        print(json.dumps(found))
    elif args[:2] == ['create', 'attachment']:
        found = item(state, option(args, '--itemid'))
        path = Path(option(args, '--file'))
        data = path.read_bytes()
        found.setdefault('attachments', []).append({'id': f'att-{len(found["attachments"]) + 1}', 'fileName': path.name,
                                                    'size': str(len(data)), 'sizeName': f'{len(data)} Bytes'})
        state.setdefault('files', {})[found['attachments'][-1]['id']] = base64.b64encode(data).decode()
        save(state)
        print(json.dumps(found))
    elif args[:2] == ['get', 'attachment']:
        item(state, option(args, '--itemid'))
        Path(option(args, '--output')).write_bytes(base64.b64decode(state.get('files', {})[args[2]]))
        print(f'Saved {option(args, "--output")}')
    elif args[:2] == ['delete', 'attachment']:
        found = item(state, option(args, '--itemid'))
        found['attachments'] = [a for a in found.get('attachments', []) if a['id'] != args[2]]
        save(state)
    elif args[:2] == ['report', 'password-health']:
        passwords = [i['login']['password'] for i in state['items']
                     if i.get('type') == 1 and (i.get('login') or {}).get('password') and not i.get('deletedDate')]
        out = []
        for each in state['items']:
            password = (each.get('login') or {}).get('password') if each.get('type') == 1 else None
            if not password or each.get('deletedDate'):
                continue
            leaked = state.get('exposed', {}).get(password) if '--no-check-exposed' not in args else None
            out.append({'object': 'password-health', 'id': each['id'], 'name': each.get('name'),
                        'passwordStrength': min(4, len(password) // 4),
                        'reuseCount': passwords.count(password) if passwords.count(password) > 1 else None,
                        'exposed': bool(leaked), 'exposedCount': leaked or None, 'exposedError': None})
        print(json.dumps(out))
    elif command == 'export':
        live = [i for i in state['items'] if not i.get('deletedDate')]
        Path(option(args, '--output')).write_text(json.dumps({'encrypted': option(args, '--format') == 'encrypted_json',
                                                              'folders': state.get('folders', []), 'items': live}),
                                                  encoding='utf-8')
        print(f'Saved {option(args, "--output")}')
    elif args[:2] == ['import', '--formats']:
        print('bitwardencsv\nbitwardenjson\nchromecsv\nkeepass2xml')
    elif command == 'import':
        if os.environ.get(option(args, '--passwordenv') or '-', '') != state.get('import_password', ''):
            fail('Import file password is invalid.')
        found = json.loads(Path(args[2]).read_text(encoding='utf-8'))['items']
        for each in found:
            each['id'] = f'made-{len(state["items"]) + 1}'
            state['items'].append(each)
        save(state)
        print(f'Imported {args[2]}')
    elif command == 'sync':
        print('Syncing complete.')
    else:
        fail(f'Unknown command: {command}')


NOW = '2026-10-27T12:00:00.000Z'


def item(state: dict, item_id: str) -> dict:
    found = next((i for i in state['items'] if i.get('id') == item_id), None)
    if found is None:
        fail('Not found.')
    return found


def option(args: list[str], name: str) -> str:
    return args[args.index(name) + 1] if name in args and args.index(name) + 1 < len(args) else ''


def sends(state: dict, args: list[str]) -> None:
    made = state.setdefault('sends', [])
    if args[:1] == ['list']:
        print(json.dumps(made))
        return
    if args[:1] == ['delete']:
        state['sends'] = [s for s in made if s['id'] != args[1]]
        save(state)
        return
    if args[:1] == ['remove-password']:
        send = next(s for s in made if s['id'] == args[1])
        send['passwordSet'] = False
        save(state)
        print(json.dumps(send))
        return
    if args[:1] in (['create'], ['edit']):
        given = json.loads(base64.b64decode(sys.stdin.read().strip()))
        if given.get('type') == 1 and not Path((given.get('file') or {}).get('fileName') or '').is_file():
            fail('file path does not exist')
        password = given.pop('password', None)
        if args[0] == 'edit':
            send = next((s for s in made if s['id'] == option(args, '--itemid')), None)
            if send is None:
                fail('Send not found.')
            send.update(given)
        else:
            send = dict(given, id=f'send-{len(made) + 1}', accessId=f'access{len(made) + 1}', accessCount=0)
            send['accessUrl'] = f'https://send.bitwarden.com/#/{send["accessId"]}/key'
            if send.get('type') == 1:
                send['file'] = {'fileName': Path(send['file']['fileName']).name}
            made.append(send)
        if password:
            send['passwordSet'] = True
        save(state)
        print(json.dumps(send))
        return
    fail('Unknown send command.')


if __name__ == '__main__':
    main(sys.argv[1:])
