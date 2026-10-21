"""Bitwarden, through its own command-line tool (bw.exe).

Keytap never talks to Bitwarden's servers itself and never stores a password.
bw keeps the encrypted vault on this PC (in Keytap's own data folder, so it
does not disturb a bw you use yourself); unlocking it gives a session key,
which Keytap holds in memory only and hands to bw through its environment -
never on a command line, where other programs could read it.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
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
    def from_item(cls, item: dict) -> Login | None:
        """A login from one item of `bw list items`; None for cards, notes and the like."""
        if item.get('type') != 1 or item.get('deletedDate') or item.get('archivedDate'):
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


class Bitwarden:
    def __init__(self, command: list[str] | None = None, data: Path | None = None):
        self.command = command if command is not None else find_cli()
        self.data = data or data_dir()
        self._session = ''

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
             timeout: float = 120) -> str:
        """Run bw. `session` is True for the current session key, False for none,
        or a key of its own."""
        if not self.command:
            raise VaultError("Bitwarden's command-line tool is missing")
        self.data.mkdir(parents=True, exist_ok=True)
        env = self._env(self._session if session is True else (session or ''))
        if password is not None:
            env[_PASSWORD_ENV] = password
        try:
            result = win32.run_hidden([*self.command, *args, '--nointeraction'], env=env,
                                      capture_output=True, text=True, encoding='utf-8', errors='replace',
                                      stdin=subprocess.DEVNULL, timeout=timeout)
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

    def unlock(self, password: str) -> None:
        out = self._run('unlock', '--passwordenv', _PASSWORD_ENV, '--raw', password=password, session=False)
        key = _last_line(out)
        if not _SESSION_KEY.match(key):
            raise VaultError('Bitwarden did not unlock the vault')
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

    def logins(self) -> list[Login]:
        if not self._session:
            raise VaultError('The vault is locked')
        items = _json_from(self._run('list', 'items'), '[')
        logins = [Login.from_item(item) for item in items if isinstance(item, dict)]
        return [login for login in logins if login is not None]

    def folders(self) -> dict[str, str]:
        """Folder names by id. Logins outside any folder have none."""
        if not self._session:
            raise VaultError('The vault is locked')
        found = _json_from(self._run('list', 'folders'), '[')
        return {str(f['id']): str(f.get('name') or '') for f in found if isinstance(f, dict) and f.get('id')}

    def sync(self) -> None:
        self._run('sync')
