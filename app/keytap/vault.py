"""Bitwarden, through its own command-line tool (bw.exe).

Keytap never talks to Bitwarden's servers itself and never stores a password.
What it makes or changes in the vault - items, folders, Sends - goes through bw
too, on bw's standard input. bw keeps the encrypted vault on this PC (in Keytap's own data folder, so it
does not disturb a bw you use yourself); unlocking it gives a session key,
which Keytap holds in memory only and hands to bw through its environment -
never on a command line, where other programs could read it.
"""

from __future__ import annotations

import base64
import json
import os
import re
import shutil
import subprocess
import sys
import threading
from dataclasses import dataclass, field, fields
from pathlib import Path

from . import win32
from .passkeys import Passkey

SEQUENCE_FIELD_NAMES = ('autotype', 'auto-type', 'keytap')
_PASSWORD_ENV = 'KEYTAP_BW_PASSWORD'
_SESSION_KEY = re.compile(r'^[A-Za-z0-9+/=_-]{32,}$')

SERVERS = {
    'us': ('bitwarden.com', 'Bitwarden.com (US)'),
    'eu': ('https://vault.bitwarden.eu', 'Bitwarden.eu'),
}


class VaultError(Exception):
    """bw said no; the message is its own, fit to show."""


class NotSignedIn(VaultError):
    pass


def logins_to_json(logins: list[Login]) -> str:
    """Logins as JSON, keys and all (for hello's sealed copy) - logins_from_json reads it back."""
    def b64(data: bytes) -> str:
        return base64.b64encode(data).decode('ascii')

    def passkey(key: Passkey) -> dict:
        out = {f.name: getattr(key, f.name) for f in fields(Passkey)}
        out.update(credential_id=b64(key.credential_id), user_handle=b64(key.user_handle), key=b64(key.key))
        return out

    def login(item: Login) -> dict:
        out = {f.name: getattr(item, f.name) for f in fields(Login)}
        out.update(hidden=sorted(item.hidden), passkeys=[passkey(key) for key in item.passkeys])
        return out
    return json.dumps([login(item) for item in logins])


def logins_from_json(text: str) -> list[Login]:
    """What logins_to_json wrote. Raises ValueError, TypeError or KeyError if it doesn't fit."""
    def passkey(data: dict) -> Passkey:
        return Passkey(**{**data, 'credential_id': base64.b64decode(data['credential_id']),
                          'user_handle': base64.b64decode(data['user_handle']), 'key': base64.b64decode(data['key'])})

    def login(data: dict) -> Login:
        return Login(**{**data, 'uris': tuple(data['uris']), 'uri_match': tuple(data['uri_match']),
                        'fields': tuple(tuple(pair) for pair in data['fields']), 'hidden': frozenset(data['hidden']),
                        'passkeys': tuple(passkey(key) for key in data['passkeys'])})
    return [login(data) for data in json.loads(text)]


@dataclass(frozen=True)
class Login:
    id: str
    name: str
    username: str = ''
    password: str = field(default='', repr=False)
    totp: str = field(default='', repr=False)
    uris: tuple[str, ...] = ()
    # Bitwarden's match detection for each of uris, in step with it: None for the default
    # (the base domain), else 0-5 - domain, host, starts with, exact, regular expression, never.
    uri_match: tuple[int | None, ...] = ()
    fields: tuple[tuple[str, str], ...] = field(default=(), repr=False)
    reprompt: bool = False
    favorite: bool = False
    notes: str = field(default='', repr=False)
    folder_id: str = ''
    hidden: frozenset[str] = frozenset()     # the custom fields Bitwarden keeps hidden
    passkeys: tuple = field(default=(), repr=False)     # passkeys.Passkey: the login's passkeys, keys included

    @property
    def sequence(self) -> str:
        """The login's own auto-type sequence, from a custom field named autotype."""
        for name, value in self.fields:
            if name.strip().lower() in SEQUENCE_FIELD_NAMES and value.strip():
                return value.strip()
        return ''

    def field_value(self, name: str) -> str | None:
        for key, value in self.fields:
            if key == name:
                return value
        lowered = name.lower()
        for key, value in self.fields:
            if key.lower() == lowered:
                return value
        return None

    @classmethod
    def from_item(cls, item: dict, live_only: bool = True) -> Login | None:
        """A login from one item of `bw list items`; None for cards, notes and the like - and,
        live_only, for one in the trash or the archive, which nothing types."""
        if item.get('type') != 1 or (live_only and (item.get('deletedDate') or item.get('archivedDate'))):
            return None
        login = item.get('login') or {}
        entries = [u for u in (login.get('uris') or []) if u and u.get('uri')]
        uris = tuple(str(u.get('uri')) for u in entries)
        uri_match = tuple(u.get('match') if isinstance(u.get('match'), int) else None for u in entries)
        item_id = str(item.get('id') or '')
        keys = tuple(key for key in (Passkey.from_bitwarden(item_id, fido)
                                     for fido in (login.get('fido2Credentials') or []) if isinstance(fido, dict)) if key)
        # Text (0) and hidden (1) custom fields; booleans and linked fields have no text to type.
        kept = [f for f in (item.get('fields') or []) if f and f.get('type') in (0, 1)]
        fields = tuple((str(f.get('name') or ''), str(f.get('value') or '')) for f in kept)
        return cls(id=item_id, name=str(item.get('name') or '(no name)'),
                   username=str(login.get('username') or ''), password=str(login.get('password') or ''),
                   totp=str(login.get('totp') or ''), uris=uris, uri_match=uri_match, fields=fields,
                   reprompt=item.get('reprompt') == 1, favorite=bool(item.get('favorite')),
                   notes=str(item.get('notes') or ''), folder_id=str(item.get('folderId') or ''),
                   hidden=frozenset(str(f.get('name') or '') for f in kept if f.get('type') == 1), passkeys=keys)


@dataclass(frozen=True)
class Status:
    state: str          # 'unauthenticated', 'locked' or 'unlocked'
    email: str = ''
    server: str = ''
    last_sync: str = ''


def find_cli() -> list[str] | None:
    """The command that runs bw: the one shipped with Keytap, else one on PATH."""
    override = os.environ.get('KEYTAP_BW')
    if override:
        path = Path(override)
        return [sys.executable, str(path)] if path.suffix.lower() == '.py' else [str(path)]
    candidates = []
    if getattr(sys, 'frozen', False):
        candidates.append(Path(sys.executable).parent / 'tools' / 'bw' / 'bw.exe')
    else:
        local = os.environ.get('LOCALAPPDATA', '')
        if local:
            candidates.append(Path(local) / 'KeytapBuild' / 'components' / 'bw' / 'bw.exe')
    for candidate in candidates:
        if candidate.is_file():
            return [str(candidate)]
    found = shutil.which('bw')
    return [found] if found else None


def data_dir() -> Path:
    override = os.environ.get('KEYTAP_BW_DATA')
    return Path(override) if override else win32.app_data() / 'bw'


def _last_line(text: str) -> str:
    lines = [line.strip() for line in (text or '').splitlines() if line.strip()]
    return lines[-1] if lines else ''


def _json_from(text: str, opener: str):
    start = text.find(opener)
    if start < 0:
        raise VaultError('Bitwarden gave an answer Keytap could not read')
    try:
        return json.loads(text[start:])
    except json.JSONDecodeError as error:
        raise VaultError('Bitwarden gave an answer Keytap could not read') from error


def logins_of(items: list[dict]) -> list[Login]:
    """The logins among items from `bw list items`."""
    logins = [Login.from_item(item) for item in items if isinstance(item, dict)]
    return [login for login in logins if login is not None]


def _encoded(value) -> str:
    """JSON as bw takes it: base64, handed over on its standard input."""
    return base64.b64encode(json.dumps(value).encode('utf-8')).decode('ascii')


class Bitwarden:
    def __init__(self, command: list[str] | None = None, data: Path | None = None):
        self.command = command if command is not None else find_cli()
        self.data = data or data_dir()
        self._session = ''
        # One bw at a time: each writes its data file as it goes, and two at once could leave it
        # half one's and half the other's.
        self._one_at_a_time = threading.Lock()

    @property
    def available(self) -> bool:
        return bool(self.command)

    @property
    def unlocked(self) -> bool:
        return bool(self._session)

    def _env(self, session: str = '') -> dict[str, str]:
        env = dict(os.environ)
        env.pop('BW_SESSION', None)
        env.pop(_PASSWORD_ENV, None)
        env['BITWARDENCLI_APPDATA_DIR'] = str(self.data)
        env['BW_NOINTERACTION'] = 'true'
        env['NODE_NO_WARNINGS'] = '1'
        if session:
            env['BW_SESSION'] = session
        return env

    def _run(self, *args: str, password: str | None = None, session: bool | str = True,
             timeout: float = 120, given: str | None = None) -> str:
        """Run bw. `session` is True for the current session key, False for none,
        or a key of its own. `given` goes to bw on its standard input."""
        if not self.command:
            raise VaultError("Bitwarden's command-line tool is missing")
        self.data.mkdir(parents=True, exist_ok=True)
        env = self._env(self._session if session is True else (session or ''))
        if password is not None:
            env[_PASSWORD_ENV] = password
        try:
            with self._one_at_a_time:
                result = win32.run_hidden([*self.command, *args, '--nointeraction'], env=env,
                                          capture_output=True, text=True, encoding='utf-8', errors='replace',
                                          timeout=timeout, **({'input': given} if given is not None
                                                              else {'stdin': subprocess.DEVNULL}))
        except subprocess.TimeoutExpired as error:
            raise VaultError('Bitwarden took too long to answer') from error
        except OSError as error:
            raise VaultError(f"Bitwarden's command-line tool would not start: {error}") from error
        if result.returncode != 0:
            message = _last_line(result.stderr) or _last_line(result.stdout) or f'bw failed ({result.returncode})'
            if 'not logged in' in message.lower():
                raise NotSignedIn(message)
            raise VaultError(message)
        return result.stdout

    # ------------------------------------------------------------------ account

    def version(self) -> str:
        return _last_line(self._run('--version', session=False, timeout=60))

    def status(self) -> Status:
        data = _json_from(self._run('status'), '{')
        state = str(data.get('status') or 'unauthenticated')
        if state == 'unlocked' and not self._session:
            state = 'locked'
        return Status(state=state, email=str(data.get('userEmail') or ''),
                      server=str(data.get('serverUrl') or ''), last_sync=str(data.get('lastSync') or ''))

    def set_server(self, url: str) -> None:
        """Point bw at a Bitwarden server; only possible while signed out."""
        self._run('config', 'server', url.strip() or 'null', session=False)

    def sign_in_command(self) -> tuple[str, dict[str, str]]:
        """A console command line that runs `bw login`, for the person to answer."""
        return self._console_line('title Sign in to Bitwarden for Keytap & ' + self._quoted() +
                                  ' login & echo. & echo You can close this window now. & pause')

    def tool_console_command(self) -> tuple[str, dict[str, str]]:
        """A console with bw ready to use, for API key or single sign-on logins."""
        folder = str(Path(self.command[-1]).parent) if self.command else ''
        line, env = self._console_line(
            'title Bitwarden CLI for Keytap & echo Sign in with one of: & echo.'
            ' & echo   bw login --apikey & echo   bw login --sso & echo.'
            ' & echo Then close this window and unlock from Keytap. & echo.', keep=True)
        env['PATH'] = folder + os.pathsep + env.get('PATH', '')
        return line, env

    def _quoted(self) -> str:
        return ' '.join(f'"{part}"' for part in self.command or [])

    def _console_line(self, script: str, keep: bool = False) -> tuple[str, dict[str, str]]:
        env = self._env()
        env.pop('BW_NOINTERACTION', None)
        # cmd keeps the inner quotes when the whole script is wrapped in one more pair.
        return f'cmd.exe /d {"/k" if keep else "/c"} "{script}"', env

    def logout(self) -> None:
        self._session = ''
        self._run('logout', session=False)

    # ------------------------------------------------------------------ the vault

    def unlock(self, password: str, keep: bool = True) -> str:
        """Unlock bw; its session key, which this holds from now on unless not keep."""
        out = self._run('unlock', '--passwordenv', _PASSWORD_ENV, '--raw', password=password, session=False)
        key = _last_line(out)
        if not _SESSION_KEY.match(key):
            raise VaultError('Bitwarden did not unlock the vault')
        if keep:
            self._session = key
        return key

    def use_session(self, key: str) -> None:
        """Hold a session key unlock(keep=False) gave."""
        self._session = key

    def take_session(self) -> str:
        """Forget the session key at once, handing it back for lock()."""
        session, self._session = self._session, ''
        return session

    def lock(self, session: str) -> None:
        """Have bw destroy a session key it handed out (from take_session)."""
        if session and self.command:
            try:
                self._run('lock', session=session, timeout=30)
            except VaultError:
                pass

    def _unlocked(self, session: str = '') -> None:
        if not (session or self._session):
            raise VaultError('The vault is locked')

    def _list(self, *args: str, session: str = '') -> list[dict]:
        self._unlocked(session)
        found = _json_from(self._run('list', *args, session=session or True), '[')
        return [entry for entry in found if isinstance(entry, dict)]

    def items(self, session: str = '', trash: bool = False, archived: bool = False) -> list[dict]:
        """Everything in the vault - logins, cards, identities, notes, SSH keys - as bw gives it:
        what is in use, or else what is in the trash or the archive."""
        return self._list('items', *(['--trash'] if trash else []), *(['--archived'] if archived else []),
                          session=session)

    def logins(self, session: str = '') -> list[Login]:
        """The vault's logins - with the session key held, or one of its own."""
        return logins_of(self.items(session))

    def folders(self) -> dict[str, str]:
        """Folder names by id. Logins outside any folder have none."""
        return {str(f['id']): str(f.get('name') or '') for f in self._list('folders') if f.get('id')}

    def organizations(self) -> list[dict]:
        return self._list('organizations')

    def collections(self) -> list[dict]:
        """The organizations' collections this account can see."""
        return self._list('collections')

    def sync(self) -> None:
        self._run('sync')

    def item(self, item_id: str) -> dict:
        """One item, as `bw get item` gives it."""
        self._unlocked()
        return _json_from(self._run('get', 'item', item_id), '{')

    def _save(self, item: dict, item_id: str = '') -> dict:
        """Make an item - or, with item_id, change that one - giving bw the item on its standard
        input, encoded as it takes it: never on its command line, where other programs could read
        what is in it."""
        args = ('edit', 'item', item_id) if item_id else ('create', 'item')
        return _json_from(self._run(*args, given=_encoded(item)), '{')

    def save_item(self, item: dict, item_id: str = '') -> dict:
        """A new item, or (with item_id) that one changed: the item as bw saved it."""
        self._unlocked()
        return self._save(item, item_id)

    def delete_item(self, item_id: str, forever: bool = False) -> None:
        """Into the trash - or, forever, gone (from the trash too)."""
        self._unlocked()
        self._run('delete', 'item', item_id, *(['--permanent'] if forever else []))

    def restore_item(self, item_id: str) -> None:
        """Back out of the trash, or out of the archive."""
        self._unlocked()
        self._run('restore', 'item', item_id)

    def archive_item(self, item_id: str) -> None:
        self._unlocked()
        self._run('archive', 'item', item_id)

    def save_folder(self, name: str, folder_id: str = '') -> dict:
        """A new folder, or that one renamed."""
        self._unlocked()
        args = ('edit', 'folder', folder_id) if folder_id else ('create', 'folder')
        return _json_from(self._run(*args, given=_encoded({'name': name})), '{')

    def delete_folder(self, folder_id: str) -> None:
        """The folder goes; what was in it stays, in no folder."""
        self._unlocked()
        self._run('delete', 'folder', folder_id)

    def move_item(self, item_id: str, organization_id: str, collection_ids: list[str]) -> None:
        """Into an organization, in those of its collections: it is the organization's from then on."""
        self._unlocked()
        self._run('move', item_id, organization_id, given=_encoded(list(collection_ids)))

    def set_collections(self, item_id: str, collection_ids: list[str]) -> None:
        """Which of its organization's collections an item is in."""
        self._unlocked()
        self._run('edit', 'item-collections', item_id, given=_encoded(list(collection_ids)))

    # ------------------------------------------------------------------ attachments

    def add_attachment(self, item_id: str, path: str) -> dict:
        """A file attached to an item (Bitwarden asks for Premium): the item as it is now."""
        self._unlocked()
        return _json_from(self._run('create', 'attachment', '--file', path, '--itemid', item_id, timeout=600), '{')

    def save_attachment(self, item_id: str, attachment_id: str, path: str) -> None:
        """An attachment, decrypted, written to path."""
        self._unlocked()
        self._run('get', 'attachment', attachment_id, '--itemid', item_id, '--output', path, timeout=600)

    def delete_attachment(self, item_id: str, attachment_id: str) -> None:
        self._unlocked()
        self._run('delete', 'attachment', attachment_id, '--itemid', item_id)

    # ------------------------------------------------------------------ Send

    def sends(self) -> list[dict]:
        self._unlocked()
        found = _json_from(self._run('send', 'list'), '[')
        return [send for send in found if isinstance(send, dict)]

    def save_send(self, send: dict, send_id: str = '') -> dict:
        """A new Send, or (with send_id) that one changed. A file Send's file is send['file']['fileName'],
        a path; a password is in send['password'] - on bw's standard input, as an item is."""
        self._unlocked()
        args = ('send', 'edit', '--itemid', send_id) if send_id else ('send', 'create')
        return _json_from(self._run(*args, given=_encoded(send), timeout=600), '{')

    def delete_send(self, send_id: str) -> None:
        self._unlocked()
        self._run('send', 'delete', send_id)

    def remove_send_password(self, send_id: str) -> dict:
        self._unlocked()
        return _json_from(self._run('send', 'remove-password', send_id), '{')

    # ------------------------------------------------------------------ reports, export and import

    def health(self, check_exposed: bool = True) -> list[dict]:
        """Each login with a password: how strong it is (0-4), how many logins share it, and - asking
        Have I Been Pwned, which learns only the start of its hash - whether it has leaked."""
        self._unlocked()
        args = ('report', 'password-health', *([] if check_exposed else ['--no-check-exposed']))
        found = _json_from(self._run(*args, timeout=900), '[')
        return [entry for entry in found if isinstance(entry, dict)]

    def export(self, path: str, form: str) -> None:
        """The whole vault to a file: form is 'json', 'csv' (neither encrypted), 'encrypted_json' (with
        this account's key, so only it can import it) or 'zip' (with attachments)."""
        self._unlocked()
        self._run('export', '--format', form, '--output', path, timeout=900)

    def import_formats(self) -> list[str]:
        """The formats `bw import` reads, by name ('bitwardenjson', 'chromecsv', ...)."""
        self._unlocked()
        out = self._run('import', '--formats', '--raw')
        return [line.strip() for line in out.splitlines() if re.fullmatch(r'[a-z0-9]+', line.strip())]

    def import_file(self, form: str, path: str, password: str = '') -> str:
        """Another password manager's export (or Bitwarden's) into the vault: bw's own words on it.
        A protected file's password goes to bw through its environment."""
        self._unlocked()
        extra = ('--passwordenv', _PASSWORD_ENV) if password else ()
        return _last_line(self._run('import', form, path, *extra, password=password or None, timeout=900))

    def add_passkey(self, record: dict, login_id: str = '', name: str = '', site: str = '') -> str:
        """Save a new passkey (passkeys.record) to the login with login_id - which then has it in
        place of any it had - or, without one, as a new login named name, for https://site.
        The login's id."""
        if not self._session:
            raise VaultError('The vault is locked')
        if login_id:
            item = self.item(login_id)
            login = item.get('login')
            if not isinstance(login, dict):
                raise VaultError('That item is not a login')
            login['fido2Credentials'] = [record]
            saved = self._save(item, login_id)
        else:
            uri = [{'match': None, 'uri': f'https://{site}'}] if site else []
            saved = self._save({'type': 1, 'name': name or site, 'notes': None, 'favorite': False, 'fields': [],
                                'reprompt': 0, 'folderId': None, 'organizationId': None, 'collectionIds': [],
                                'login': {'username': record.get('userName') or None, 'password': None,
                                          'totp': None, 'uris': uri, 'fido2Credentials': [record]}})
        return str(saved.get('id') or login_id)
