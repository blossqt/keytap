"""Keytap's start-up, its tray icon, and the wiring from a hotkey to typed text.

Pressing the hotkey notes which window was in front, unlocks the vault if
needed, works out which login goes with that window (asking if unsure), and
types it there. Opening Keytap itself shows the vault (ui/vault_window.py);
started with Windows (--startup) it stays quietly in the background.
"""

from __future__ import annotations

import ctypes
import hashlib
import hmac
import json
import os
import sys
import time
import traceback
import uuid
from pathlib import Path
from types import SimpleNamespace

from PySide6.QtCore import QObject, QProcess, Qt, QTimer, QUrl
from PySide6.QtGui import QDesktopServices, QGuiApplication
from PySide6.QtNetwork import QLocalServer, QLocalSocket
from PySide6.QtWidgets import QApplication

from . import (APP_NAME, __version__, background, focus, hello, items, matching, package, passkeys, provider,
               sequence, suitelog, totp, typer, win32)
from .focus import FieldWatcher
from .hotkeys import Hotkeys, SessionWatcher
from .items import Item
from .settings import Settings
from .signins import PasskeySignIns, Relay
from .suitetray import SuiteTray
from .vault import Bitwarden, Login, NotSignedIn, Status, VaultError
from .ui import icons, theme
from .ui.dialogs import SettingsDialog, SignInDialog, WelcomeDialog, bring_up
from .ui.inline import InlineMenu
from .ui.picker import Picker
from .ui.toast import ToastStack
from .ui.unlock import UnlockCard
from .ui.vault_window import VaultWindow, private_mime, sample_controller

# Tests run a second copy beside a real one under a name of their own.
SERVER_NAME = os.environ.get('KEYTAP_INSTANCE') or f'keytap-{os.environ.get("USERNAME", "user")}'
APP_ID = 'Suite.Keytap'
DEV = os.environ.get('KEYTAP_DEV') == '1'
ASKED_TOO_LONG = 2000           # ms a connection to Keytap's socket gets to say what it wants
TOOL_WINDOWS = ('generator', 'sends', 'health', 'export', 'import')     # closed on locking
WARM_AFTER = 3000               # ms after Keytap starts: a card made unseen (_warm_up)
CLIPBOARD_SECONDS = 30
JUST_TYPED_SECONDS = 300           # a username-first sign-in's password page offers that login first
# A page address that says it is a sign-in: accounts.google.com/v3/signin/identifier, login.live.com
_SIGN_IN_WORDS = ('signin', 'sign-in', 'sign_in', 'login', 'log-in', 'logon', 'auth', 'identifier', 'account')
SYNC_MINUTES = 30

# Typed for each picker action ('all' uses the login's own sequence).
_ACTION_SEQUENCES = {'username': '{USERNAME}', 'password': '{PASSWORD}', 'totp': '{TOTP}'}
_COPY_LABELS = {'copy_username': 'username', 'copy_password': 'password', 'copy_totp': 'verification code'}


def _now() -> str:
    """This moment as bw writes one: '2026-10-27T12:00:00.000Z'."""
    return time.strftime('%Y-%m-%dT%H:%M:%S.000Z', time.gmtime())


def _verifier(password: str, salt: bytes | None = None) -> tuple[bytes, bytes]:
    """A salted hash of the master password, kept in memory while unlocked,
    so a login that asks for the password again can be checked here."""
    salt = salt or os.urandom(16)
    return salt, hashlib.scrypt(password.encode('utf-8'), salt=salt, n=2 ** 14, r=8, p=1, dklen=32)


class Controller(QObject):
    def __init__(self, startup: bool = False, serve_passkeys: bool = False):
        super().__init__()
        self.settings = Settings()
        self.vault = Bitwarden()
        self.status = Status('missing' if not self.vault.available else 'checking')
        self.cli_version = ''
        self.logins: list[Login] | None = None
        # The whole vault, for its window: every kind of item, the trash and the archive, folders,
        # and the organizations' collections. Cleared with the logins on locking.
        self.items: list[Item] | None = None
        self.trash: list[Item] = []
        self.archive: list[Item] = []
        self.can_archive = True
        self.folders: dict[str, str] = {}
        self.organizations: dict[str, str] = {}
        self.collections: list[dict] = []
        self.generated: list[tuple[str, float]] = []      # what the generator made since unlocking
        self.hotkey_problems: dict[str, str] = {}
        self.card = None               # the picker or unlock card on screen, if any
        self.typing = False
        self._check = None             # the master password's verifier while unlocked
        self._logins_key = None        # opens the copy of the logins Windows Hello keeps, once Hello opened it
        self._generation = 0           # one more each time Keytap locks
        self._pending = None           # (action, window) waiting for the vault to unlock
        self._windows: dict[str, object] = {}
        self._copied = ''
        self.toasts = ToastStack()
        self.field = None              # the login box that has the keyboard, if Keytap saw one
        self._dismissed = None         # a box whose pop-up was closed; not shown again until left
        self._inline_rect = None
        self.hello_supported = False   # Windows Hello set up on this PC; asked once, off the UI thread
        self._just_typed = None        # (hwnd, website, login id, when): typed into a username-first page

        self.hotkeys = Hotkeys(self)
        self.hotkeys.pressed.connect(self.hotkey)
        self.session = SessionWatcher(self)
        self.session.locking.connect(self._windows_locking)
        self._idle = QTimer(self, interval=15_000)
        self._idle.timeout.connect(self._check_idle)
        self._idle.start()
        self._syncer = QTimer(self, interval=SYNC_MINUTES * 60_000)
        self._syncer.timeout.connect(lambda: self.sync(quiet=True))
        self._clipboard = QTimer(self, singleShot=True, interval=CLIPBOARD_SECONDS * 1000)
        self._clipboard.timeout.connect(self._clear_clipboard)

        self.inline = InlineMenu()
        self.inline.chosen.connect(self._inline_chosen)
        self.inline.search.connect(self._inline_search)
        self.inline.unlock.connect(self._inline_unlock)
        self.inline.mute.connect(self._inline_mute)
        self.inline.dismiss.connect(self._inline_dismiss)
        self._inline_watch = QTimer(self, interval=100)
        self._inline_watch.timeout.connect(self._inline_tick)
        self.fields = FieldWatcher(self._field_wanted, self)
        self.fields.field.connect(self._field_changed)
        # Passkeys: only with the package identity Windows asks of passkey providers (see package.py).
        # Windows calls only a Keytap COM started (serve_passkeys; see hand_over); any other gets
        # its calls through a relay (signins.Relay), over the local socket.
        self.signins = PasskeySignIns(self)
        self.passkeys_on = bool(provider.identity()) and provider.supported()
        self.passkey_server = None
        if self.passkeys_on:
            if serve_passkeys:
                self.passkey_server = provider.Server(self.signins)
                self.passkey_server.start()
            background.run(lambda: provider.register(icons.app_icon_svg(), passkeys.authenticator_info()),
                           self._passkeys_registered)

        self._make_tray()
        self._listen()
        self.apply_hotkeys()
        self.apply_inline()
        background.run(hello.supported, lambda ok, e: setattr(self, 'hello_supported', bool(ok)))
        if self.vault.available:
            background.run(self.vault.version, lambda v, e: setattr(self, 'cli_version', v or ''))
            self.refresh_status(first=True)
        else:
            self._update_tray()
            self.toasts.show("Bitwarden's command-line tool is missing",
                             'Reinstall Keytap - it comes with it.', error=True)
        win32.refresh_start_with_windows()
        QTimer.singleShot(WARM_AFTER, self._warm_up)
        # Opened by hand: the vault. Started with Windows, or the very first time
        # (when the welcome comes up instead): just the tray and the hotkeys.
        if not startup and not DEV and self.settings.welcomed:
            QTimer.singleShot(0, self.show_vault)

    def _warm_up(self) -> None:
        """A picker made unseen, and dropped: the first card shown took three times as long as
        the rest (0.4 s more after the hotkey), as Qt read its style sheets and fonts then. Not
        while a game is in front: once it has gone."""
        if theme.quiet_now():
            QTimer.singleShot(WARM_AFTER, self._warm_up)
            return
        Picker([], [], '', '').deleteLater()

    # ------------------------------------------------------------------ account state

    @property
    def unlocked(self) -> bool:
        return self.logins is not None

    def refresh_status(self, first: bool = False) -> None:
        background.run(self.vault.status, lambda status, error: self._status_known(status, error, first))

    def _status_known(self, status: Status | None, error, first: bool) -> None:
        if error is not None:
            self.toasts.show('Could not reach Bitwarden', str(error), error=True)
            return
        if self.unlocked and status.state == 'locked':
            status = Status('unlocked', status.email, status.server, status.last_sync)
        self.status = status
        self._update_tray()
        self._refresh_vault()
        if first and not self.settings.welcomed and not DEV:
            self.settings.welcomed = True
            self.show_welcome()
        elif first and status.state == 'unauthenticated' and not DEV:
            self.toasts.show('Keytap is not signed in', 'Click to sign in to Bitwarden.',
                             action=('Sign in…', self.show_sign_in))

    def _set_state(self, state: str) -> None:
        s = self.status
        self.status = Status(state, s.email, s.server, s.last_sync)
        self._update_tray()
        self._refresh_vault()
        if state not in ('locked', 'unlocked'):
            self._hide_inline()

    def show_sign_in(self) -> None:
        if self._bring_back('signin'):
            return
        dialog = SignInDialog(self.vault, self.status)
        dialog.signed_in.connect(self._signed_in)
        self._keep('signin', dialog)

    def _signed_in(self, status: Status) -> None:
        self.status = Status('locked', status.email, status.server, status.last_sync)
        self._update_tray()
        self.show_unlock(None)

    def sign_out(self) -> None:
        self.lock()
        self._set_state('unauthenticated')
        background.run(hello.forget_logins)
        if self.passkeys_on:
            background.run(provider.forget_credentials)

        def done(_, error):
            if error and not isinstance(error, NotSignedIn):
                self.toasts.show('Could not sign out', str(error), error=True)
            self.refresh_status()
        background.run(self.vault.logout, done)

    # ------------------------------------------------------------------ hotkey to typing

    def hotkey(self, action: str) -> None:
        if action == 'escape':
            self._inline_dismiss()
            return
        if self.typing:
            return
        if self.card is not None:
            self.card.bring_back()
            return
        window = win32.foreground_window()
        if window is None or window.pid == os.getpid() or window.is_shell:
            self.toasts.show('Nothing to type into', 'Click into a box first, then press the hotkey.')
            return
        # Note the box first: a card of Keytap's may take the keyboard before anything is typed.
        self.fields.hold(window, lambda: self.begin(action, window))

    def begin(self, action: str, window) -> None:
        state = self.status.state
        if state == 'missing':
            self.toasts.show("Bitwarden's command-line tool is missing", 'Reinstall Keytap.', error=True)
        elif state == 'unauthenticated':
            self.show_sign_in()
        elif not self.unlocked:
            self._pending = (action, window)
            self.show_unlock(window)
        else:
            self._choose(action, window)

    def _choose(self, action: str, window) -> None:
        # In a login box on a web page (an app's built-in browser, say), the page's website decides.
        field = self.fields.current(window)
        page = field.page if field is not None and matching.page_site(field.page) else ''
        matches = matching.find(window, self.logins, self.settings.links, page, self._just(window, page))
        if action == 'type':
            login = matching.sure_choice(matches)
            if login is not None:
                self.use(login, 'all', window)
                return
        where = matching.describe(window, page)
        shared = window.exe in matching.SHARED_PROGRAMS and not page
        remember = (f'Always use this login {"on" if page else "in"} {where}' if not shared or window.title.strip()
                    else '')
        # In a program (not on a web page, which is a website already): its website's logins, all of them.
        picker = Picker(self.logins, matches, where, remember, site_choice=not page)
        picker.chosen.connect(lambda login, what, keep: self._picked(window, login, what, keep, page))
        picker.new_login.connect(lambda: self.new_login_for(window, page))
        self._show_card(picker, window.hwnd)

    def _picked(self, window, login: Login, what: str, remember: str, page: str = '') -> None:
        """remember: '' (no), 'login' (always this login) or 'site' (any login for its website)."""
        site = matching.main_site(login) if remember == 'site' else ''
        if remember:
            links = self.settings.links
            links[matching.link_key(window, page)] = matching.SITE_LINK + site if site else login.id
            self.settings.links = links
        self.use(login, what, window)

    def use(self, login: Login, what: str, window) -> None:
        if login.reprompt:
            self._confirm(login, lambda: self._use(login, what, window), window)
        else:
            self._use(login, what, window)

    def _use(self, login: Login, what: str, window) -> None:
        if what in _COPY_LABELS:
            try:
                value = {'copy_username': lambda: login.username, 'copy_password': lambda: login.password,
                         'copy_totp': lambda: totp.code(login.totp)}[what]()
            except totp.TotpError as error:
                self.toasts.show('No code to copy', f'“{login.name}”: {error}', error=True)
                return
            self.copy(value, _COPY_LABELS[what])
            return
        text = _ACTION_SEQUENCES.get(what) or sequence.for_login(login, self.settings.sequence)
        copy_code = (what in ('all', 'inline') and bool(login.totp)
                     and 'TOTP' not in text.upper() and 'OTP}' not in text.upper())
        plan = sequence.boxes(text) if what in ('all', 'inline', 'username', 'password') else None
        if plan is not None and (plan[0] and login.username or plan[1] and login.password):
            self._fill(window, login, what, text, plan, copy_code)
        else:
            self._keys(window, login, what, text, copy_code)

    def _fill(self, window, login: Login, what: str, text: str, plan, copy_code: bool) -> None:
        """Into the form's boxes by what they are, each set directly (filling.py); typed as before
        where the program shows no boxes."""
        if not win32.user32.IsWindow(window.hwnd):
            self.toasts.show('Nothing typed', 'That window has closed.')
            return
        if win32.runs_above_us(window.pid):
            self._typed(typer.BLOCKED, None, window, login, False)
            return
        self._hide_inline()
        win32.set_foreground(window.hwnd)
        self.typing = True
        wants_name, wants_password, send = plan
        username = login.username if wants_name and login.username else None
        password = login.password if wants_password and login.password else None
        field = self.field if self.field is not None and self.field.window.hwnd == window.hwnd else None

        def filled(result) -> None:
            self.typing = False
            if result is None:
                self.toasts.show('Nothing typed', f'{window.exe or "That program"} took too long to answer.',
                                 error=True, action=('Copy password', lambda: self.copy(login.password, 'password')))
            elif result.outcome == 'nothing':
                self._keys(window, login, what, text, copy_code)
            elif result.outcome == 'failed':
                self.toasts.show('Nothing typed', f'Keytap could not fill the {result.detail or "login"} box. Click '
                                 f'into it and press {self.settings.hotkeys["type"]} again.', error=True,
                                 action=('Copy password', lambda: self.copy(login.password, 'password')))
            else:
                if password is not None and result.username and not result.password and not login.sequence:
                    # The username now, the password on the next page - where this login is offered first.
                    self._just_typed = (window.hwnd, matching.page_site(field.page if field else ''), login.id,
                                        time.monotonic())
                if send and not result.submitted:
                    self.toasts.show('Filled in', 'Press Enter to sign in.')
                self._typed(typer.DONE, None, window, login, copy_code)
        self.fields.fill(window, username, password, send, (self.settings.compat_typing, self.settings.key_delay),
                         filled)

    def _keys(self, window, login: Login, what: str, text: str, copy_code: bool) -> None:
        """Typed where the keyboard is, key by key, as a sequence says."""
        if what in ('all', 'inline') and self._in_password_box(window):
            text = sequence.from_password_box(text)
        elif what in ('all', 'inline') and self._in_identifier_box(window) and not login.sequence:
            # The username now, the password on the next page - where this login is offered first.
            text = sequence.from_identifier_box(text)
            self._just_typed = (window.hwnd, matching.page_site(self.field.page), login.id, time.monotonic())
        try:
            steps = sequence.compile(text, login, lambda: totp.code(login.totp))
        except (sequence.SequenceError, totp.TotpError) as error:
            self.toasts.show('Nothing typed', str(error), error=True)
            return
        self._type(steps, window, login, copy_code=copy_code)

    def _type(self, steps, window, login: Login, copy_code: bool = False) -> None:
        if not win32.user32.IsWindow(window.hwnd):
            self.toasts.show('Nothing typed', 'That window has closed.')
            return
        self._hide_inline()
        win32.set_foreground(window.hwnd)
        self.typing = True
        compat, delay = self.settings.compat_typing, self.settings.key_delay

        def done(outcome, error):
            self.typing = False
            self._typed(outcome, error, window, login, copy_code)

        def given_back(ok: bool):
            if not ok:
                self.typing = False
                self.toasts.show('Nothing typed', 'Keytap could not put the keyboard back in that box. Click '
                                 f'into it and press {self.settings.hotkeys["type"]} again.', error=True)
                return
            background.run(lambda: typer.type_steps(steps, window.pid, compat=compat, key_delay_ms=delay), done)
        # Only into the box it came from: a program may put the keyboard somewhere else on coming back.
        self.fields.give_back(window, given_back)

    def _typed(self, outcome, error, window, login: Login, copy_code: bool) -> None:
        if error is not None:
            self.toasts.show('Typing failed', str(error), error=True)
        elif outcome == typer.FOCUS_LOST:
            self.toasts.show('Typing stopped', 'Another window came to the front before Keytap finished.',
                             error=True)
        elif outcome == typer.KEYS_HELD:
            self.toasts.show('Nothing typed', 'Let go of Ctrl, Alt and Shift once the hotkey is pressed.',
                             error=True)
        elif outcome == typer.BLOCKED:
            self.toasts.show('Windows will not let Keytap type there',
                             f'{window.exe or "That program"} runs as administrator.', error=True,
                             action=('Copy password', lambda: self.copy(login.password, 'password')))
        elif copy_code:
            # As Bitwarden does after filling: the code is ready to paste on the next screen.
            try:
                self.copy(totp.code(login.totp), 'verification code', quiet=True)
                self.toasts.show('Verification code copied', 'Paste it when asked. It clears in '
                                 f'{CLIPBOARD_SECONDS} seconds.')
            except totp.TotpError:
                pass

    # ------------------------------------------------------------------ unlocking

    def show_unlock(self, window, detail: str | None = None):
        if self.card is not None:
            self.card.bring_back()
            return None
        if detail is None:
            field = self.fields.current(window) if window else None
            detail = (f'to fill {matching.describe(window, field.page if field else "")}' if window
                      else self.status.email)
        card = UnlockCard('Unlock Keytap', detail, hello=self.hello_on())
        card.submitted.connect(lambda password: self._unlock(card, password))
        card.hello.connect(lambda: self._unlock(card, None))
        card.closed.connect(lambda: self._unlock_closed(card))
        self._show_card(card, window.hwnd if window else None)
        if self.hello_on():
            QTimer.singleShot(150, lambda: self._unlock(card, None) if self.card is card else None)
        return card

    def unlock_for(self, detail: str, near_hwnd: int, then, cancelled):
        """Unlock, then call then() - or cancelled() if the card is closed first. The card."""
        self._drop_pending()
        self._pending = ('call', then, cancelled)
        return self.show_unlock(SimpleNamespace(hwnd=near_hwnd) if near_hwnd else None, detail)

    def _drop_pending(self) -> None:
        pending, self._pending = self._pending, None
        if pending and pending[0] == 'call':
            pending[2]()

    def _unlock_closed(self, card: UnlockCard) -> None:
        if not card.succeeded:
            self._drop_pending()

    def _unlock(self, card: UnlockCard, password: str | None) -> None:
        """Unlock with the master password typed into card - or, given None, with Windows Hello."""
        if password is None:
            card.wait_for_hello()
        else:
            card.busy('Unlocking…')

        def work():
            if password is not None:
                self.vault.unlock(password)
                return items.of(self.vault.items()), _verifier(password), None, True
            opened = hello.open_seal()
            kept = hello.kept_logins(self.status.email, opened.logins_key)
            if kept is not None:
                # At once, from the copy Windows Hello keeps; bw unlocks meanwhile (_finish_unlock).
                return kept, _verifier(opened.password), opened, False
            self.vault.unlock(opened.password)
            return items.of(self.vault.items()), _verifier(opened.password), opened, True

        def done(result, error):
            if error is not None:
                if isinstance(error, NotSignedIn):
                    card.close()
                    self._set_state('unauthenticated')
                    self.show_sign_in()
                elif password is None and not isinstance(error, hello.HelloError) and                         'invalid master password' in str(error).lower():
                    # The master password changed since Windows Hello was turned on.
                    background.run(hello.turn_off)
                    card.fail('Your master password has changed since Windows Hello was turned on. Type it '
                              'here, then turn Windows Hello on again in Settings.')
                else:
                    card.fail('' if isinstance(error, hello.HelloCancelled) else str(error))
                return
            found, check, opened, ready = result
            self._unlocked(found, check, opened.logins_key if opened else None, ready)
            if not ready:
                self._finish_unlock(opened.password)
            card.finish()
            pending, self._pending = self._pending, None
            if pending and pending[0] == 'refocus':
                # Back to the login box, where the pop-up now lists the logins.
                window = pending[1]
                win32.set_foreground(window.hwnd)
                self.fields.give_back(window, lambda ok: QTimer.singleShot(150, self.fields.recheck))
            elif pending and pending[0] == 'call':
                QTimer.singleShot(0, pending[1])
            elif pending:
                action, window = pending
                QTimer.singleShot(0, lambda: self._choose(action, window))
            elif not getattr(card, 'quiet', False):
                self.toasts.show('Keytap is unlocked',
                                 f'Press {self.settings.hotkeys["type"]} in any program to type a login.')
        background.run(work, done)

    def unlock_in(self, page, password: str | None) -> None:
        """Unlock from the vault window's own lock screen (with Windows Hello, given None)."""
        self._pending = None
        self._unlock(page, password)

    # ------------------------------------------------------------------ Windows Hello

    def hello_on(self) -> bool:
        return hello.is_on()

    def turn_on_hello(self) -> None:
        """Ask for the master password, check it, and have Windows Hello keep it."""
        if not self.unlocked:
            self.toasts.show('Unlock Keytap first', 'Then turn on Windows Hello in Settings.')
            return
        if self.card is not None:
            self.card.bring_back()
            return
        card = UnlockCard('Turn on Windows Hello', 'Your master password, for Windows Hello to keep',
                          button='Turn on')

        def submitted(password: str):
            card.busy('Checking…')
            salt, expected = self._check or (b'', b'')
            background.run(lambda: _verifier(password, salt)[1] if salt else b'',
                           lambda digest, error: checked(password, digest))

        def checked(password: str, digest):
            if not (self._check and digest and hmac.compare_digest(digest, self._check[1])):
                card.fail('That is not your master password.')
                return
            card.wait_for_hello()
            background.run(lambda: hello.turn_on(password), turned_on)

        def turned_on(logins_key, error):
            if error is not None:
                card.fail('' if isinstance(error, hello.HelloCancelled) else str(error))
                return
            self._logins_key = logins_key
            self._keep_logins()
            card.finish()
            self.toasts.show('Windows Hello is on', 'Unlock Keytap with your fingerprint, face or PIN.')
        card.submitted.connect(submitted)
        self._show_card(card, None)

    def turn_off_hello(self) -> None:
        self._logins_key = None
        background.run(hello.turn_off, lambda _, error: self.toasts.show(
            'Windows Hello is off', 'Keytap asks for your master password again.'))

    def _unlocked(self, found: list, check, logins_key: bytes | None = None, ready: bool = True) -> None:
        """Unlocked, with the vault's items from bw - or, not ready, with the logins Windows Hello keeps
        a copy of, while bw unlocks (_finish_unlock)."""
        if ready:
            self._take_items(found)
        else:
            self.logins = found
            self.items = [Item.from_login(login) for login in found]
        self._check = check
        self._logins_key = logins_key
        self._set_state('unlocked')
        self._sync_passkeys()
        if ready:
            self._vault_ready()

    def _vault_ready(self) -> None:
        self._keep_logins()
        self._syncer.start()
        self.sync(quiet=True)

    def _finish_unlock(self, password: str) -> None:
        """Unlocked from the copy of the logins Windows Hello keeps: now bw, for its session key and
        the logins as they are. Should bw say no, Keytap locks again, as unlocking would have failed."""
        generation = self._generation

        def work():
            key = self.vault.unlock(password, keep=False)
            try:
                return key, items.of(self.vault.items(session=key))
            except VaultError:
                self.vault.lock(key)
                raise

        def done(result, error):
            if generation != self._generation or not self.unlocked:
                if result:                          # locked meanwhile: bw forgets this key too
                    background.run(lambda: self.vault.lock(result[0]))
                return
            if error is not None:
                self.lock()
                if isinstance(error, NotSignedIn):
                    self._set_state('unauthenticated')
                    self.show_sign_in()
                elif 'invalid master password' in str(error).lower():
                    background.run(hello.turn_off)
                    self.toasts.show('Keytap is locked', 'Your master password has changed since Windows Hello '
                                     'was turned on. Unlock with it, then turn Windows Hello on again in Settings.',
                                     error=True)
                else:
                    self.toasts.show('Keytap is locked', f'Bitwarden did not unlock: {error}', error=True)
                return
            key, found = result
            self.vault.use_session(key)
            self._take_items(found)
            self._refresh_vault()
            self._sync_passkeys()
            self._vault_ready()
        background.run(work, done)

    def _keep_logins(self) -> None:
        """Seal a copy of the logins for Windows Hello to open at once next time - possible only
        once Windows Hello has opened the copy's key, in this unlock."""
        key, logins, account = self._logins_key, self.logins, self.status.email
        if key and logins is not None and account and hello.is_on():
            background.run(lambda: hello.keep_logins(logins, account, key))

    # ------------------------------------------------------------------ passkeys

    def _passkeys_registered(self, _, error) -> None:
        if error is not None:
            self.toasts.show('Passkeys are not working', str(error), error=True)
            return
        state = provider.state()
        if state == 'disabled' and not self.settings.passkeys_told:
            self.settings.passkeys_told = True
            self.toasts.show('Turn Keytap on for passkeys', 'In Windows Settings: Accounts, Passkeys, Advanced '
                             'options - then sites can use the passkeys in your vault, and save new ones to it.',
                             action=('Open', self.open_passkey_settings))

    @staticmethod
    def passkey_status() -> dict:
        """Where setting up passkeys stands (off the UI thread: it asks Windows and PowerShell)."""
        why = package.unavailable()
        status = {'why': why, 'identity': bool(provider.identity()), 'trusted': False, 'registered': False,
                  'state': 'unregistered'}
        if not why:
            status['trusted'] = package.certificate_trusted()
            try:
                status['registered'] = status['identity'] or package.registered() is not None
            except package.SetupError:
                pass
        if status['identity']:
            status['state'] = provider.state()
        return status

    def set_up_passkeys(self) -> None:
        """Trust Keytap's certificate (Windows asks an administrator, once), register Keytap's
        package for this folder, and start again as it."""
        def work():
            if not package.certificate_trusted() and not package.trust_certificate():
                return 'declined'
            if not provider.identity() and package.needs_registering():
                package.register()
            return 'done'

        def done(result, error):
            if error is not None:
                self.toasts.show('Passkeys are not set up', str(error), error=True)
            elif result == 'declined':
                self.toasts.show('Passkeys are not set up', 'Windows needs to trust Keytap\'s certificate, '
                                 'once - choose Yes when it asks.', error=True)
            elif provider.identity():
                self.open_passkey_settings()
            else:
                self.toasts.show('Keytap starts again', 'Now as a passkey provider.')
                QTimer.singleShot(1500, self.restart)
        self.toasts.show('Setting up passkeys', 'Windows asks once whether to trust Keytap\'s certificate.')
        background.run(work, done)

    def turn_off_passkeys(self) -> None:
        def work():
            if provider.identity():
                provider.forget_credentials()
                provider.unregister()
            package.unregister()

        def done(_, error):
            if error is not None:
                self.toasts.show('Passkeys are still on', str(error), error=True)
                return
            self.toasts.show('Passkeys are off', 'Keytap is no longer a passkey provider.')
            if provider.identity():
                QTimer.singleShot(1500, self.restart)
        background.run(work, done)

    def restart(self) -> None:
        if getattr(sys, 'frozen', False):
            QProcess.startDetached(sys.executable, ['--restart'])
        else:
            QProcess.startDetached(sys.executable, [sys.argv[0], '--restart'])
        self.quit()

    @staticmethod
    def open_passkey_settings() -> None:
        QDesktopServices.openUrl(QUrl('ms-settings:passkeys-advancedoptions'))

    def _sync_passkeys(self) -> None:
        """Tell Windows which passkeys the vault has (names, not keys), for its passkey window."""
        if not self.passkeys_on or not self.unlocked:
            return
        keys = [key for login in self.logins or [] for key in login.passkeys]

        def done(_, error):
            print(f'passkeys: {len(keys)} handed to Windows' if error is None else
                  f'passkeys: Windows did not take the list: {error}', flush=True)
        background.run(lambda: provider.sync_credentials(keys), done)

    def _load_extras(self) -> None:
        """What the vault window shows besides the items in use: folders, the trash, the archive, the
        organizations and their collections - after the items, as each is a bw call of its own."""
        generation = self._generation

        def folders(found, error):           # first, as the window lists them
            if error is None and generation == self._generation and self.unlocked:
                self.folders = found
                self._refresh_vault()
                background.run(work, done)

        def work():
            found = {}
            for name, call in (('trash', lambda: items.of(self.vault.items(trash=True))),
                               ('archive', lambda: items.of(self.vault.items(archived=True))),
                               ('organizations', self.vault.organizations), ('collections', self.vault.collections)):
                try:
                    found[name] = call()
                except VaultError as error:          # an older server, say: the rest still comes
                    print(f'vault: no {name}: {error}', flush=True)
            return found

        def done(found, error):
            if error is not None or generation != self._generation or not self.unlocked:
                return
            self.trash = found.get('trash', [])
            archived = found.get('archive')
            if archived is not None:
                # Without Premium, bw ignores --archived and lists what is in use instead.
                self.can_archive = all(item.archived for item in archived)
                self.archive = archived if self.can_archive else []
            self.organizations = {str(o['id']): str(o.get('name') or '') for o in found.get('organizations', [])
                                  if o.get('id')}
            self.collections = found.get('collections', [])
            self._refresh_vault()
        background.run(self.vault.folders, folders)

    def _take_items(self, found: list[Item]) -> None:
        """The vault's items as bw listed them (made into Items off the UI thread: 3,000 took 20 ms):
        the window's, and the logins auto-type uses."""
        self.items = found
        self.logins = [item.login for item in found if item.login is not None and not item.deleted
                       and not item.archived]

    def _changed(self) -> None:
        """Something in the vault was made or changed here: everything that follows the vault, now."""
        self._take_items(self.items or [])
        self._refresh_vault()
        self._sync_passkeys()
        self._keep_logins()

    def _replace(self, saved: dict) -> Item:
        """An item bw has just saved, in place of what was there."""
        made = Item(saved)
        self.items = [item for item in self.items or [] if item.id != made.id]
        self.archive = [item for item in self.archive if item.id != made.id]
        (self.archive if made.archived else self.items).append(made)
        self._changed()
        return made

    def _vault_job(self, work, then, done) -> None:
        """work() off the UI thread; then(result) here, if Keytap is still unlocked; done(result,
        error) either way - error only for what failed."""
        generation = self._generation

        def finished(result, error):
            if error is None and generation == self._generation and self.unlocked:
                result = then(result) if then is not None else result
            elif error is None:
                error = VaultError('Keytap locked before Bitwarden finished')
            if done is not None:
                done(result, error)
        background.run(work, finished)

    def save_item(self, raw: dict, item_id: str, done=None) -> None:
        """A new item or a changed one, to bw; done(Item, error)."""
        self._vault_job(lambda: self.vault.save_item(raw, item_id), self._replace, done)

    def delete_item(self, item: Item, forever: bool, done=None) -> None:
        def gone(_):
            self.items = [i for i in self.items or [] if i.id != item.id]
            self.archive = [i for i in self.archive if i.id != item.id]
            self.trash = [i for i in self.trash if i.id != item.id]
            if not forever:
                self.trash.append(Item(dict(item.raw, deletedDate=_now())))
            self._changed()
        self._vault_job(lambda: self.vault.delete_item(item.id, forever), gone, done)

    def restore_item(self, item: Item, done=None) -> None:
        """Out of the trash or the archive."""
        def back(_):
            raw = dict(item.raw)
            raw.pop('deletedDate' if item.deleted else 'archivedDate', None)
            self.trash = [i for i in self.trash if i.id != item.id]
            self.archive = [i for i in self.archive if i.id != item.id]
            restored = Item(raw)
            (self.archive if restored.archived else self.items).append(restored)
            self._changed()
        self._vault_job(lambda: self.vault.restore_item(item.id), back, done)

    def archive_item(self, item: Item, done=None) -> None:
        def archived(_):
            self.items = [i for i in self.items or [] if i.id != item.id]
            self.archive.append(Item(dict(item.raw, archivedDate=_now())))
            self._changed()
        self._vault_job(lambda: self.vault.archive_item(item.id), archived, done)

    def _then_reread(self, item: Item, work, done) -> None:
        """work(), which bw answers without the item, then the item as it is now."""
        def both():
            work()
            return self.vault.item(item.id)
        self._vault_job(both, self._replace, done)

    def move_item(self, item: Item, organization_id: str, collection_ids: list[str], done=None) -> None:
        self._then_reread(item, lambda: self.vault.move_item(item.id, organization_id, collection_ids), done)

    def set_collections(self, item: Item, collection_ids: list[str], done=None) -> None:
        self._then_reread(item, lambda: self.vault.set_collections(item.id, collection_ids), done)

    def add_attachment(self, item: Item, path: str, done=None) -> None:
        self.toasts.show('Attaching…', Path(path).name)
        self._vault_job(lambda: self.vault.add_attachment(item.id, path), self._replace, done)

    def save_attachment(self, item: Item, attachment: dict, path: str, done=None) -> None:
        def saved(_):
            self.toasts.show('Saved', f'{attachment.get("fileName")} - decrypted, so anyone who opens it can read it.')
        self._vault_job(lambda: self.vault.save_attachment(item.id, str(attachment['id']), path), saved, done)

    def delete_attachment(self, item: Item, attachment: dict, done=None) -> None:
        self._then_reread(item, lambda: self.vault.delete_attachment(item.id, str(attachment['id'])), done)

    def save_folder(self, name: str, folder_id: str = '', done=None) -> None:
        def saved(folder):
            self.folders = dict(self.folders, **{str(folder.get('id') or folder_id): name})
            self._refresh_vault()
            return folder
        self._vault_job(lambda: self.vault.save_folder(name, folder_id), saved, done)

    def delete_folder(self, folder_id: str, done=None) -> None:
        def gone(_):
            self.folders = {key: value for key, value in self.folders.items() if key != folder_id}
            self.items = [Item(dict(i.raw, folderId=None)) if i.folder_id == folder_id else i
                          for i in self.items or []]
            self._changed()
        self._vault_job(lambda: self.vault.delete_folder(folder_id), gone, done)

    def remember_generated(self, value: str) -> None:
        """What the generator made, for its history - kept only until Keytap locks."""
        self.generated = [(value, time.time())] + [entry for entry in self.generated if entry[0] != value][:49]

    def new_login_for(self, window, page: str = '') -> None:
        """The vault window's editor, for a new login for that window's program or web page."""
        site = matching.page_site(page) if page else ''
        if site:
            name, uris = site, (f'https://{site}',)
        elif window is not None and window.exe:
            name = Path(window.exe).stem.replace('_', ' ').replace('-', ' ').strip().title() or window.exe
            uris = (f'app://{window.exe}',)
        else:
            name, uris = '', ()
        self.show_vault()
        vault_window = self._windows.get('vault')
        if vault_window is not None:
            vault_window.new_item(items.LOGIN, name, uris)

    def _tool_window(self, name: str, make) -> None:
        """One of the vault window's tools (the generator, Send...), while unlocked."""
        if not self.unlocked:
            self.show_vault()
            return
        if not self._bring_back(name):
            self._keep(name, make())

    def show_generator(self) -> None:
        from .ui.tools import GeneratorWindow
        self._tool_window('generator', lambda: GeneratorWindow(self))

    def show_sends(self) -> None:
        from .ui.tools import SendsWindow
        self._tool_window('sends', lambda: SendsWindow(self))

    def show_health(self) -> None:
        from .ui.tools import HealthWindow
        self._tool_window('health', lambda: HealthWindow(self))

    def show_export(self) -> None:
        from .ui.tools import ExportDialog
        self._tool_window('export', lambda: ExportDialog(self))

    def show_import(self) -> None:
        from .ui.tools import ImportDialog
        self._tool_window('import', lambda: ImportDialog(self))

    def run_vault(self, work, then=None, done=None) -> None:
        """For the tools: bw work off the UI thread, as the items' own changes are."""
        self._vault_job(work, then, done)

    def reload(self) -> None:
        """Everything read again from bw (after an import, say)."""
        def found(read):
            self.items = read
            self._changed()
            self._load_extras()
        self._vault_job(lambda: items.of(self.vault.items()), found, None)

    def confirm(self, login: Login | None, then, near_hwnd: int | None = None, cancelled=None, detail: str = ''):
        """Ask for the master password again - for a login that wants it, say - then go on; or
        cancelled() if the card is closed first. The card."""
        return self._confirm(login, then, SimpleNamespace(hwnd=near_hwnd) if near_hwnd else None, cancelled, detail)

    def _confirm(self, login: Login | None, then, window, cancelled=None, detail: str = ''):
        if self.card is not None:
            self.card.bring_back()
            if cancelled is not None:
                cancelled()
            return None
        card = UnlockCard("Confirm it's you", detail or f'“{login.name}” asks for your master password',
                          button='Confirm')
        if cancelled is not None:
            card.closed.connect(lambda: None if card.succeeded else cancelled())

        def submitted(password: str):
            card.busy('Checking…')
            salt, expected = self._check or (b'', b'')
            background.run(lambda: _verifier(password, salt)[1] if salt else b'',
                           lambda digest, error: confirmed(digest))

        def confirmed(digest):
            if self._check and digest and hmac.compare_digest(digest, self._check[1]):
                card.finish()
                QTimer.singleShot(0, then)
            else:
                card.fail('That is not your master password.')
        card.submitted.connect(submitted)
        self._show_card(card, window.hwnd if window else None)
        return card

    def lock(self) -> None:
        if not self.unlocked and not self.vault.unlocked:
            return
        session = self.vault.take_session()
        self.logins = None
        self.items = None
        self.trash, self.archive, self.collections, self.generated = [], [], [], []
        self.folders, self.organizations = {}, {}
        for name in TOOL_WINDOWS:          # the generator's history, Sends, the health report...
            window = self._windows.pop(name, None)
            if window is not None:
                try:
                    window.close()
                except RuntimeError:
                    pass
        self._check = None
        self._logins_key = None
        self._generation += 1           # an unlock still finishing in the background is dropped
        self._drop_pending()
        self._syncer.stop()
        self._hide_inline()
        if self.card is not None:
            self.card.close()
        self._clear_clipboard()
        if self.status.state == 'unlocked':
            self._set_state('locked')
        background.run(lambda: self.vault.lock(session))

    def sync(self, quiet: bool = False) -> None:
        if not self.unlocked:
            return

        generation = self._generation

        def work():
            self.vault.sync()
            return items.of(self.vault.items())

        def done(found, error):
            if generation != self._generation or not self.unlocked:
                return
            if error is not None:
                if not quiet:
                    self.toasts.show('Could not sync', f'{error} - using the copy on this PC.', error=True)
                self._load_extras()            # from the copy on this PC, then
                return
            self._take_items(found)
            self._refresh_vault()
            self._load_extras()
            self._sync_passkeys()
            self._keep_logins()
            if not quiet:
                self.toasts.show('Synced', f'{len(self.items)} items in your vault.')
        background.run(work, done)

    def link_target(self, value: str) -> str:
        """What a remembered choice (a login's id, or matching.SITE_LINK and a website) ties to, in words."""
        if value.startswith(matching.SITE_LINK):
            return f'any login for {value[len(matching.SITE_LINK):]}'
        return self.login_name(value)

    def login_site(self, login_id: str) -> str:
        """The website a login is first saved for - '' for none, or while locked."""
        return next((matching.main_site(login) for login in self.logins or [] if login.id == login_id), '')

    def login_name(self, login_id: str) -> str:
        for login in self.logins or []:
            if login.id == login_id:
                return login.name
        return 'a login (unlock to see which)' if not self.unlocked else 'a login no longer in your vault'

    def _windows_locking(self) -> None:
        if self.settings.lock_with_windows:
            self.lock()

    def _check_idle(self) -> None:
        minutes = self.settings.idle_minutes
        if self.unlocked and minutes and not self.typing and win32.idle_seconds() >= minutes * 60:
            self.lock()

    # ------------------------------------------------------------------ the pop-up in login boxes

    def apply_inline(self) -> None:
        if self.settings.inline:
            self.fields.start()
        else:
            self.fields.stop()
            self._hide_inline()

    def _toggle_inline(self, on: bool) -> None:
        self.settings.inline = on
        self.apply_inline()
        self._update_tray()

    def _field_wanted(self, window) -> bool:
        return (self.status.state in ('locked', 'unlocked') and self.card is None and not self.typing
                and window.exe not in matching.BROWSERS and window.exe not in self.settings.inline_muted)

    def _in_password_box(self, window) -> bool:
        return (self.field is not None and self.field.kind == 'password'
                and self.field.window.hwnd == window.hwnd)

    def _in_identifier_box(self, window) -> bool:
        return (self.field is not None and self.field.kind == 'identifier'
                and self.field.window.hwnd == window.hwnd)

    def _just(self, window, page: str) -> str:
        """The login typed into this window's username-first page a moment ago, while its
        password page follows."""
        if self._just_typed is None or not page:
            return ''
        hwnd, site, login_id, when = self._just_typed
        fresh = time.monotonic() - when < JUST_TYPED_SECONDS
        return login_id if fresh and hwnd == window.hwnd and site == matching.page_site(page) else ''

    def _identifier_wanted(self, field, page: str) -> bool:
        """Whether a username box with no password box beside it is a sign-in's first step: on a
        page whose address says so, or on a website the vault has a login for."""
        address = field.page.lower()
        if any(word in address for word in _SIGN_IN_WORDS):
            return True
        return self.unlocked and any(m.strength == matching.PAGE
                                     for m in matching.find(field.window, self.logins, {}, page))

    def _field_changed(self, field) -> None:
        if self.typing:
            return
        self.field = field
        if field is None:
            self._dismissed = None
            self._hide_inline()
            return
        if self._dismissed == field.key:
            return
        self._dismissed = None
        matches = None
        page = field.page if matching.page_site(field.page) else ''
        if field.kind == 'identifier' and not (page and self._identifier_wanted(field, page)):
            self._hide_inline()             # an email box for a newsletter, say
            return
        if self.unlocked:
            matches = [(m.login, m.strength) for m in matching.find(
                field.window, self.logins, self.settings.links, page, self._just(field.window, page))]
        program = field.window.exe or 'this program'
        self.inline.present(field, matches, matching.page_site(page) or program, program)
        self._inline_rect = win32.window_rect(field.window.hwnd)
        self._inline_watch.start()
        self.hotkeys.take_escape(True)

    def _hide_inline(self) -> None:
        self._inline_watch.stop()
        self.hotkeys.take_escape(False)
        if self.inline.isVisible():
            self.inline.hide()

    def _inline_tick(self) -> None:
        field = self.inline.field
        if not self.inline.isVisible() or field is None:
            self._inline_watch.stop()
            return
        if win32.foreground_pid() not in (field.window.pid, os.getpid()):
            self._hide_inline()
        elif win32.window_rect(field.window.hwnd) != self._inline_rect:     # moved or closed
            self._hide_inline()

    def _inline_dismiss(self) -> None:
        if self.inline.field is not None:
            self._dismissed = self.inline.field.key
        self._hide_inline()

    # The pop-up never takes the keyboard, so the box still has it here: note it, for handing back.

    def _inline_chosen(self, login: Login) -> None:
        field = self.inline.field
        self._hide_inline()
        if field is not None:
            self.fields.hold(field.window, lambda: self.use(login, 'inline', field.window))

    def _inline_search(self) -> None:
        field = self.inline.field
        self._hide_inline()
        if field is not None:
            self.fields.hold(field.window, lambda: self._choose('pick', field.window))

    def _inline_unlock(self) -> None:
        field = self.inline.field
        self._hide_inline()
        if field is not None:
            self._pending = ('refocus', field.window)
            self.fields.hold(field.window, lambda: self.show_unlock(field.window))

    def _inline_mute(self) -> None:
        field = self.inline.field
        self._hide_inline()
        if field is None or not field.window.exe:
            return
        program = field.window.exe
        self.settings.inline_muted = self.settings.inline_muted + [program]

        def undo():
            self.settings.inline_muted = [p for p in self.settings.inline_muted if p != program]
        self.toasts.show(f'Keytap will not pop up in {program}',
                         f'{self.settings.hotkeys["type"]} still types there.', action=('Undo', undo))

    # ------------------------------------------------------------------ clipboard

    def copy(self, text: str, label: str, quiet: bool = False) -> None:
        QGuiApplication.clipboard().setMimeData(private_mime(text))
        self._copied = text
        self._clipboard.start()
        if not quiet:
            self.toasts.show(f'Copied the {label}', f'It clears from the clipboard in {CLIPBOARD_SECONDS} seconds.')

    def _clear_clipboard(self) -> None:
        if self._copied and QGuiApplication.clipboard().text() == self._copied:
            QGuiApplication.clipboard().clear()
        self._copied = ''

    # ------------------------------------------------------------------ windows and cards

    def show_card(self, card, near_hwnd) -> None:
        self._show_card(card, near_hwnd)

    def _show_card(self, card, near_hwnd) -> None:
        self._hide_inline()
        self.card = card
        card.closed.connect(lambda c=card: self._card_closed(c))
        card.present(near_hwnd)

    def _card_closed(self, card) -> None:
        if self.card is card:
            self.card = None

    def _keep(self, name: str, dialog) -> None:
        self._windows[name] = dialog
        dialog.setAttribute(Qt.WA_DeleteOnClose)
        dialog.destroyed.connect(lambda *_: self._windows.pop(name, None))
        bring_up(dialog)

    def _bring_back(self, name: str) -> bool:
        dialog = self._windows.get(name)
        if dialog is None:
            return False
        try:
            bring_up(dialog)
        except RuntimeError:        # already deleted
            self._windows.pop(name, None)
            return False
        return True

    def show_vault(self) -> None:
        """Keytap's own window: the vault, or its lock screen."""
        if self._bring_back('vault'):
            self._refresh_vault()
            return
        self._keep('vault', VaultWindow(self))
        window = self._windows.get('vault')
        if window is not None and self.status.state == 'locked' and self.hello_on():
            # Opened by hand while locked: straight to Windows Hello, as Bitwarden's app does.
            QTimer.singleShot(300, lambda: self.unlock_in(window.lock_page, None)
                              if window.pages.currentWidget() is window.lock_page else None)

    def _refresh_vault(self) -> None:
        window = self._windows.get('vault')
        if window is not None:
            try:
                window.refresh()
            except RuntimeError:            # closed and deleted a moment ago
                self._windows.pop('vault', None)

    def show_settings(self) -> None:
        if self._bring_back('settings'):
            return
        dialog = SettingsDialog(self)
        dialog.accepted.connect(self.apply_hotkeys)
        dialog.accepted.connect(self.apply_inline)
        dialog.accepted.connect(self._update_tray)
        self._keep('settings', dialog)

    def show_welcome(self) -> None:
        if self._bring_back('welcome'):
            return
        dialog = WelcomeDialog(self.settings.hotkeys, self.status.state not in ('unauthenticated', 'missing'))
        dialog.sign_in.connect(lambda: QTimer.singleShot(0, self.show_sign_in))
        self._keep('welcome', dialog)

    def apply_hotkeys(self) -> None:
        self.hotkey_problems = self.hotkeys.set(self.settings.hotkeys)
        for problem in self.hotkey_problems.values():
            self.toasts.show('A hotkey is not working', problem, error=True,
                             action=('Settings…', self.show_settings))

    # ------------------------------------------------------------------ tray

    def _make_tray(self) -> None:
        # In Hanami's cherry-blossom icon while Hanami runs, else an icon of its own.
        self.tray = SuiteTray(APP_NAME, icons.app_icon(), self)
        self.tray.clicked.connect(self._tray_clicked)
        self.tray.set_shown(self.settings.tray_shown)
        self._update_tray()

    def _update_tray(self) -> None:
        state = self.status.state
        key = self.settings.hotkeys.get('type') or ''
        words = {'missing': "Bitwarden's tool is missing", 'checking': 'Starting…',
                 'unauthenticated': 'Not signed in', 'locked': 'Locked',
                 'unlocked': f'Unlocked - press {key} to type' if key else 'Unlocked'}
        items = [{'text': words.get(state, state.capitalize()), 'enabled': False}, {'separator': True},
                 {'id': 'open', 'text': 'Open Keytap', 'default': True}]
        if state == 'unauthenticated':
            items.append({'id': 'signin', 'text': 'Sign in to Bitwarden…'})
        else:
            items.append({'id': 'lock', 'text': 'Lock' if self.unlocked else 'Unlock…',
                          'enabled': state in ('locked', 'unlocked')})
            items.append({'id': 'sync', 'text': 'Sync now', 'enabled': self.unlocked})
        items += [{'id': 'inline', 'text': 'Pop up in login boxes', 'checkable': True,
                   'checked': self.settings.inline},
                  {'separator': True},
                  {'id': 'welcome', 'text': 'How it works'},
                  {'id': 'settings', 'text': 'Settings…'},
                  {'separator': True},
                  {'id': 'quit', 'text': 'Quit Keytap'}]
        self.tray.set_menu(items, f'{APP_NAME} - {words.get(state, state)}')

    def _lock_or_unlock(self) -> None:
        if self.unlocked:
            self.lock()
        else:
            self.show_unlock(None)

    def _tray_clicked(self, item: str) -> None:
        actions = {'open': self.show_vault, 'signin': self.show_sign_in, 'lock': self._lock_or_unlock,
                   'sync': self.sync,
                   'inline': lambda: self._toggle_inline(not self.settings.inline),
                   'welcome': self.show_welcome, 'settings': self.show_settings, 'quit': self.quit}
        if item in actions:
            actions[item]()

    def set_tray_shown(self, shown: bool) -> None:
        self.settings.tray_shown = shown
        self.tray.set_shown(shown)

    def quit(self) -> None:
        self.hotkeys.take_escape(False)
        self.hotkeys.clear()
        self.fields.stop()
        session = self.vault.take_session()
        self.logins = None
        self._clear_clipboard()
        self.tray.stop()
        if session:
            self.vault.lock(session)     # bw forgets the key before Keytap goes
        QApplication.quit()

    # ------------------------------------------------------------------ one copy at a time

    def _listen(self) -> None:
        QLocalServer.removeServer(SERVER_NAME)
        self._server = QLocalServer(self)
        self._server.setSocketOptions(QLocalServer.UserAccessOption)
        self._server.newConnection.connect(self._connection)
        self._server.listen(SERVER_NAME)

    def _connection(self) -> None:
        """Someone at Keytap's socket - a second start of it, Hanami, or a passkey relay: what it
        says is read once it has arrived. Waited for here, one that took its time froze Keytap."""
        while self._server.hasPendingConnections():
            socket = self._server.nextPendingConnection()
            socket.readyRead.connect(lambda s=socket: self._asked(s))
            # Through Qt once it has gone, so PySide forgets it too - and only then, so a reply
            # still on its way isn't cut off.
            socket.disconnected.connect(socket.deleteLater)
            QTimer.singleShot(ASKED_TOO_LONG, socket, lambda s=socket: s.property('asked') or s.abort())
            if socket.bytesAvailable():
                self._asked(socket)

    def _asked(self, socket) -> None:
        if socket.property('asked'):
            return
        socket.setProperty('asked', True)
        message = bytes(socket.readAll()).decode('utf-8', 'replace').strip()
        if message.startswith('passkey '):
            # A relay, for Windows: answered once the person has done their part, not here.
            self.signins.serve_relay(socket, message[len('passkey '):])
            return
        reply = self.command(message)
        if reply:
            socket.write(reply.encode('utf-8'))
        socket.disconnectFromServer()               # once what was written has gone

    def command(self, message: str) -> str:
        words = message.split()
        if not words or words[0] == 'show':
            # Opening Keytap again - from Start, Hanami, or its exe.
            self.show_vault()
        elif words[0] == 'startup':
            pass                            # started with Windows, while already running: nothing to show
        elif words[0] == 'quit':
            QTimer.singleShot(0, self.quit)
        elif words[0] == 'lock':
            self.lock()
        elif words[0] == 'ping':
            pass                            # a relay asking whether Keytap runs
        elif words[0] == 'passkey-locked':
            return 'unlocked' if self.unlocked else 'locked'
        elif words[0] == 'passkey-cancel' and len(words) > 1:
            try:
                self.signins.cancel(uuid.UUID(words[1]))
            except ValueError:
                pass
        elif DEV and words[0] == 'state':
            # Development only (tests/): what Keytap is doing, never any secret.
            card = type(self.card).__name__ if self.card is not None else ''
            return json.dumps({'state': self.status.state, 'logins': len(self.logins or []),
                               'card': card, 'typing': self.typing, 'pid': os.getpid(),
                               'toasts': self.toasts.titles(), 'links': self.settings.links,
                               'hotkey_problems': self.hotkey_problems, 'inline': self.inline.describe(),
                               'field': self.field.kind if self.field else '',
                               'watching': self.fields.running, 'watch_error': self.fields.failed,
                               'vault_window': self._vault_window_state(), 'hello': self.hello_on(),
                               'passkeys': {'identity': provider.identity(), 'server': (
                                   'off' if self.passkey_server is None else
                                   self.passkey_server.failed or ('ok' if self.passkey_server.ready.is_set()
                                                                  else 'starting'))}})
        elif DEV and words[0] == 'inline-point' and len(words) > 1:
            x, y = self.inline.row_point(int(words[1]))
            return f'{x} {y}'
        elif DEV and words[0] == 'window-unlock' and len(words) > 1 and 'vault' in self._windows:
            # Tests: the master password, as if typed into the vault window's lock screen.
            self._windows['vault'].lock_page.submitted.emit(message.split(' ', 1)[1])
        elif DEV and words[0] == 'card-submit' and len(words) > 1 and isinstance(self.card, UnlockCard):
            # Tests: the master password, as if typed into the card on screen.
            self.card.submitted.emit(message.split(' ', 1)[1])
        elif DEV and words[0] == 'hello-on':
            self.turn_on_hello()
        elif DEV and words[0] == 'passkeys-cache':
            return json.dumps(provider.cached_credentials())
        elif DEV and words[0] == 'reload':
            self.settings = Settings()
            self.apply_hotkeys()
            self.apply_inline()
        return ''


    def _vault_window_state(self) -> dict:
        window = self._windows.get('vault')
        try:
            if window is None or not window.isVisible():
                return {'visible': False}
            page = {window.vault_page: 'vault', window.lock_page: 'locked'}.get(window.pages.currentWidget(), 'notice')
            return {'visible': True, 'page': page, 'listed': window.list.count(),
                    'filters': window.filters.count(), 'shown': window.details.item.name
                    if window.details.item is not None else ''}
        except RuntimeError:
            return {'visible': False}


def send(message: str, reply: bool = False) -> str | None:
    """Hand a message to the copy of Keytap already running, if there is one."""
    socket = QLocalSocket()
    socket.connectToServer(SERVER_NAME)
    if not socket.waitForConnected(400):
        return None
    socket.write(message.encode('utf-8'))
    socket.waitForBytesWritten(500)
    answer = ''
    if reply and socket.waitForReadyRead(3000):
        answer = bytes(socket.readAll()).decode('utf-8', 'replace')
    socket.disconnectFromServer()
    return answer


def hand_over(message: str) -> bool:
    """With passkeys set up, the Keytap that runs is one COM started, as the package's "Passkeys"
    app: the only kind Windows calls for a passkey, and it keeps calling the one that runs. So a
    Keytap started from its exe (from Start, with Windows, by Hanami) has COM start that one,
    passes on what it was started for, and leaves. False when it can't: then it is Keytap itself."""
    if DEV or not getattr(sys, 'frozen', False) or not provider.identity() or not provider.supported():
        return False
    if package.outdated():
        return False            # a package from before "Passkeys": Windows would end both Keytaps
    if not provider.start_server():
        return False
    deadline = time.monotonic() + 20       # it serves COM a moment before its local socket listens
    while send(message) is None and time.monotonic() < deadline:
        time.sleep(0.2)
    return True


def run_relay(app) -> int:
    """Serve Windows' passkey calls by passing them to the Keytap that runs, for as long as it
    runs: Windows was seen to end that Keytap too when the one it started for a passkey ended."""
    relay = Relay(SERVER_NAME)
    server = provider.Server(relay)
    server.start()
    print('passkeys: relaying to the running Keytap', flush=True)
    alive = QTimer(interval=5000)
    alive.timeout.connect(lambda: app.quit() if not relay.busy and send('ping') is None else None)
    alive.start()
    return app.exec()


def self_test(argv: list[str]) -> int:
    """Load what a real start loads and answer with the versions - the build's check."""
    target = argv[argv.index('--self-test') + 1] if len(argv) > argv.index('--self-test') + 1 else ''
    app = QApplication(argv[:1])
    theme.install(app)
    # Any failure is answered rather than raised: the windowed exe would show
    # an error box on the desktop of whoever is building.
    try:
        icons.render_app_icon(32)
        sample = [Login('1', 'Example', 'someone@example.com', 'not-a-real-password')]
        Picker(sample, matching.find(win32.WindowInfo(0, 'Example', '', 0, ''), sample, {}),
               'a test').adjustSize()
        UnlockCard('Unlock Keytap').adjustSize()
        Hotkeys()
        InlineMenu().grab()            # painted, never shown
        VaultWindow(sample_controller(sample)).grab()
        # The editor and the generator: its word list came along, and an SSH key can be made.
        from . import generator, sshkey
        from .ui.editor import ItemEditor
        ItemEditor(sample_controller(sample), items.blank(items.LOGIN, 'Example')).grab()
        if len(generator.passphrase().split('-')) != 6 or not sshkey.new_key()['keyFingerprint']:
            raise RuntimeError('the generator is broken')
        problem = focus.probe()
        if problem:
            raise RuntimeError(f'UI Automation: {problem}')
        # Windows Hello's WinRT modules came along (whether this PC has Windows Hello or not).
        from winrt.windows.security.credentials import KeyCredentialManager  # noqa: F401
        from winrt.windows.security.cryptography import CryptographicBuffer  # noqa: F401
        # Passkeys: COM's local server came along, and a passkey can sign.
        import comtypes.server.localserver  # noqa: F401
        from . import p256
        if not p256.verify(p256.public_key(7), b'self-test', p256.sign(7, b'self-test')):
            raise RuntimeError('passkey signing is broken')
        vault = Bitwarden()
        if not vault.available:
            raise RuntimeError("Bitwarden's CLI is not bundled")
        answer = f'{__version__} (Bitwarden CLI {vault.version()})'
    except Exception as error:  # noqa: BLE001
        if target:
            Path(target).write_text(f'FAILED {type(error).__name__}: {error}', encoding='utf-8')
        return 1
    if target:
        Path(target).write_text(answer, encoding='utf-8')
    else:
        print(answer)
    app.quit()
    return 0


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv if argv is None else argv)
    suitelog.start(APP_NAME)          # a crash inside a call from Windows leaves its stack there
    if '--self-test' in argv:
        return self_test(argv)
    try:
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(APP_ID)
    except (AttributeError, OSError):
        pass

    app = QApplication(argv[:1])
    theme.install(app)
    app.setApplicationName(APP_NAME)
    app.setApplicationVersion(__version__)
    app.setQuitOnLastWindowClosed(False)
    app.setWindowIcon(icons.app_icon())

    if '--restart' in argv:
        # Started again by the copy that is quitting (to run as its package, say): wait for it to go.
        deadline = time.monotonic() + 20
        while send('still-there') is not None and time.monotonic() < deadline:
            time.sleep(0.25)
    if '-Embedding' in argv and send('ping') is not None:
        # Windows started this Keytap for a passkey, and one is running already: relay to it.
        return run_relay(app)
    # Started by Windows for a passkey (COM, with --passkeys), with Windows, or again: no window.
    quiet = any(flag in argv for flag in ('--startup', '--passkeys', '--restart'))
    message = argv[argv.index('--send') + 1] if '--send' in argv and len(argv) > argv.index('--send') + 1 else \
        'startup' if quiet else 'show'
    answer = send(message, reply='--send' in argv)
    if answer is not None:
        if answer:
            print(answer)
        return 0
    if '--send' in argv:
        print('Keytap is not running', file=sys.stderr)
        return 1
    if '-Embedding' not in argv and not DEV and '--package-updated' not in argv and package.outdated():
        # This Keytap brought a newer package: update it once this Keytap is gone, and start again.
        try:
            Settings().passkeys_told = False        # say so again should Windows have turned Keytap off
            package.update_and_restart(argv[1:] + ['--package-updated'])
            return 0
        except (package.SetupError, OSError):
            traceback.print_exc()
    if '-Embedding' not in argv and hand_over(message):
        return 0

    controller = Controller(startup=quiet, serve_passkeys='-Embedding' in argv)  # noqa: F841 - lives on
    app.styleHints().colorSchemeChanged.connect(lambda *_: icons.clear_cache())
    return app.exec()
