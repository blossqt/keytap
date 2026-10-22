"""Keytap's ordinary windows: signing in to Bitwarden, settings, and how it works."""

from __future__ import annotations

from PySide6.QtCore import Qt, QTimer, Signal
from PySide6.QtGui import QFont, QKeySequence
from PySide6.QtWidgets import (QCheckBox, QComboBox, QDialog, QDialogButtonBox, QFormLayout,
                               QHBoxLayout, QKeySequenceEdit, QLabel, QLineEdit, QListWidget,
                               QListWidgetItem, QMessageBox, QPushButton, QSpinBox, QTabWidget,
                               QVBoxLayout, QWidget)

from .. import __version__, background, hotkeys, matching, sequence, win32
from ..settings import IDLE_CHOICES
from ..vault import SERVERS, Bitwarden, Status
from . import icons


def _heading(text: str) -> QLabel:
    label = QLabel(text)
    font = label.font()
    font.setWeight(QFont.DemiBold)
    label.setFont(font)
    return label


def _note(text: str) -> QLabel:
    label = QLabel(text)
    label.setWordWrap(True)
    label.setEnabled(False)
    return label


def _page(tabs: QTabWidget, title: str) -> tuple[QWidget, QVBoxLayout]:
    page = QWidget()
    layout = QVBoxLayout(page)
    layout.setContentsMargins(14, 14, 14, 10)
    tabs.addTab(page, title)
    return page, layout


def bring_up(dialog: QDialog) -> None:
    dialog.show()
    dialog.raise_()
    dialog.activateWindow()
    win32.set_foreground(int(dialog.winId()))


# --------------------------------------------------------------------------- signing in


class SignInDialog(QDialog):
    """Signing in happens in a console running Bitwarden's own `bw login`.

    That way every kind of two-step login, new-device code and password
    prompt works exactly as Bitwarden made it, and Keytap never handles the
    sign-in itself. Afterwards the vault is locked, ready to unlock in Keytap.
    """
    signed_in = Signal(object)    # Status

    def __init__(self, vault: Bitwarden, status: Status, parent=None):
        super().__init__(parent)
        self.vault = vault
        self._console = None
        self.setWindowTitle('Sign in to Bitwarden')
        self.setWindowIcon(icons.app_icon())
        self.setMinimumWidth(460)
        layout = QVBoxLayout(self)

        top = QHBoxLayout()
        logo = QLabel()
        logo.setPixmap(icons.render_app_icon(48))
        top.addWidget(logo, 0, Qt.AlignTop)
        top.addWidget(QLabel('<b style="font-size:13pt">Sign in to Bitwarden</b><br>'
                             'Keytap types logins from your Bitwarden vault.'), 1)
        layout.addLayout(top)
        layout.addSpacing(4)

        form = QFormLayout()
        self.server = QComboBox()
        for key, (_, label) in SERVERS.items():
            self.server.addItem(label, key)
        self.server.addItem('Self-hosted', 'self')
        self.url = QLineEdit()
        self.url.setPlaceholderText('https://bitwarden.example.com')
        current = (status.server or '').rstrip('/')
        if current and current not in ('https://bitwarden.com', 'https://vault.bitwarden.com'):
            if current == SERVERS['eu'][0]:
                self.server.setCurrentIndex(1)
            else:
                self.server.setCurrentIndex(2)
                self.url.setText(current)
        self.server.currentIndexChanged.connect(self._server_changed)
        form.addRow('Server:', self.server)
        form.addRow('', self.url)
        layout.addLayout(form)
        self._server_changed()

        layout.addWidget(_note(
            'A Bitwarden window opens for your email, master password and any two-step login '
            'code. When it says you are logged in, close it and unlock Keytap.'))
        self.state = QLabel()
        self.state.setWordWrap(True)
        layout.addWidget(self.state)

        other = QLabel('<a href="#">Use an API key or single sign-on instead</a>')
        other.linkActivated.connect(self._tool_console)
        layout.addWidget(other)

        buttons = QDialogButtonBox()
        self.go = buttons.addButton('Sign in…', QDialogButtonBox.ActionRole)
        self.go.setDefault(True)
        self.check = buttons.addButton("I've signed in", QDialogButtonBox.ActionRole)
        self.check.hide()
        close = buttons.addButton(QDialogButtonBox.Cancel)
        self.go.clicked.connect(self._start)
        self.check.clicked.connect(self._check)
        close.clicked.connect(self.reject)
        layout.addWidget(buttons)

        self._watch = QTimer(self, interval=700)
        self._watch.timeout.connect(self._watch_console)

    def _server_changed(self) -> None:
        self.url.setVisible(self.server.currentData() == 'self')

    def _server_url(self) -> str:
        key = self.server.currentData()
        if key == 'self':
            return self.url.text().strip()
        return SERVERS[key][0]

    def _start(self) -> None:
        url = self._server_url()
        if not url:
            self.url.setFocus()
            return
        self.go.setEnabled(False)
        self.state.setText('Setting up…')
        background.run(lambda: self.vault.set_server('' if url == SERVERS['us'][0] else url), self._ready)

    def _ready(self, _, error) -> None:
        if error:
            self.go.setEnabled(True)
            self.state.setText(f'Could not use that server: {error}')
            return
        line, env = self.vault.sign_in_command()
        self._console = win32.open_console(line, env)
        self.state.setText('Finish signing in in the Bitwarden window.')
        self.check.show()
        self._watch.start()

    def _tool_console(self) -> None:
        line, env = self.vault.tool_console_command()
        self._console = win32.open_console(line, env)
        self.state.setText('Sign in in the Bitwarden window, then close it.')
        self.check.show()
        self._watch.start()

    def _watch_console(self) -> None:
        if self._console is not None and self._console.poll() is not None:
            self._console = None
            self._watch.stop()
            self._check()

    def _check(self) -> None:
        self.check.setEnabled(False)
        background.run(self.vault.status, self._checked)

    def _checked(self, status, error) -> None:
        self.check.setEnabled(True)
        self.go.setEnabled(True)
        if error or status is None or status.state == 'unauthenticated':
            self.state.setText('Not signed in yet.' if not error else f'Could not ask Bitwarden: {error}')
            return
        self.signed_in.emit(status)
        self.accept()


# --------------------------------------------------------------------------- settings


class SettingsDialog(QDialog):
    def __init__(self, controller, parent=None):
        super().__init__(parent)
        self.controller = controller
        self.settings = controller.settings
        self.setWindowTitle('Keytap settings')
        self.setWindowIcon(icons.app_icon())
        self.setMinimumWidth(540)
        outer = QVBoxLayout(self)
        tabs = QTabWidget()
        outer.addWidget(tabs)

        # ---------------------------------------------------------------- general
        page, layout = _page(tabs, 'General')
        status = controller.status
        words = {'missing': "Bitwarden's command-line tool is missing", 'checking': 'Starting…',
                 'unauthenticated': 'Not signed in to Bitwarden', 'locked': 'Locked',
                 'unlocked': 'Unlocked'}
        layout.addWidget(_heading(words.get(status.state, status.state)))
        row = QHBoxLayout()
        if status.state in ('locked', 'unlocked'):
            lock = QPushButton('Lock now' if controller.unlocked else 'Unlock…')
            lock.clicked.connect(lambda: (self.reject(), controller._lock_or_unlock()))
            row.addWidget(lock)
            sync = QPushButton('Sync now')
            sync.setEnabled(controller.unlocked)
            sync.clicked.connect(lambda: controller.sync())
            row.addWidget(sync)
        welcome = QPushButton('How it works')
        welcome.clicked.connect(controller.show_welcome)
        row.addWidget(welcome)
        row.addStretch(1)
        quit_button = QPushButton('Quit Keytap')
        quit_button.clicked.connect(lambda: (self.reject(), controller.quit()))
        row.addWidget(quit_button)
        layout.addLayout(row)

        layout.addSpacing(10)
        layout.addWidget(_heading('Tray'))
        self._tray = QCheckBox('Show Keytap in the tray')
        self._tray.setChecked(self.settings.tray_shown)
        layout.addWidget(self._tray)
        layout.addWidget(_note('In Hanami\'s cherry blossom while Hanami runs, otherwise an icon of its own. '
                               'Turned off, open Keytap again - from Start or Hanami - to come back here.'))
        self._startup = QCheckBox('Start Keytap when I sign in to Windows')
        self._startup.setChecked(win32.starts_with_windows())
        layout.addWidget(self._startup)

        layout.addSpacing(10)
        layout.addWidget(_heading('Bitwarden'))
        if status.state == 'unauthenticated':
            account = 'Not signed in'
        else:
            account = f'Signed in as {status.email or "?"}'
            if status.server:
                account += f' on {status.server}'
        row = QHBoxLayout()
        row.addWidget(QLabel(account), 1)
        if status.state not in ('unauthenticated', 'missing'):
            sign_out = QPushButton('Sign out')
            sign_out.clicked.connect(self._sign_out)
            row.addWidget(sign_out)
        else:
            sign_in = QPushButton('Sign in…')
            sign_in.clicked.connect(lambda: (self.reject(), controller.show_sign_in()))
            row.addWidget(sign_in)
        layout.addLayout(row)
        layout.addStretch(1)

        # ---------------------------------------------------------------- typing
        page, layout = _page(tabs, 'Typing')
        layout.addWidget(_heading('Hotkeys'))
        form = QFormLayout()
        current = self.settings.hotkeys
        self._keys = {}
        for action, label in (('type', 'Type the login for this window:'),
                              ('pick', 'Choose a login to type:')):
            edit = QKeySequenceEdit(QKeySequence(current[action]))
            edit.setMaximumSequenceLength(1)
            edit.setClearButtonEnabled(True)
            self._keys[action] = edit
            form.addRow(label, edit)
        layout.addLayout(form)
        problems = controller.hotkey_problems
        if problems:
            layout.addWidget(_note('<span style="color:#c62828">' +
                                   '<br>'.join(problems.values()) + '</span>'))

        layout.addSpacing(10)
        layout.addWidget(_heading('What gets typed'))
        form = QFormLayout()
        self._sequence = QLineEdit(self.settings.sequence)
        form.addRow('Type:', self._sequence)
        layout.addLayout(form)
        layout.addWidget(_note(
            '{USERNAME} {PASSWORD} {TOTP} {TAB} {ENTER} {DELAY 500} and more. A login can have its '
            'own: add a custom field named <i>autotype</i>. To tie a login to a program, give it the '
            'URI <i>app://program.exe</i>, or <i>title://text</i> for a window title.'))
        self._compat = QCheckBox('Type as key presses, for games, remote desktops and virtual machines')
        self._compat.setChecked(self.settings.compat_typing)
        layout.addWidget(self._compat)
        row = QHBoxLayout()
        row.addWidget(QLabel('Pause between keys:'))
        self._delay = QSpinBox()
        self._delay.setRange(0, 500)
        self._delay.setSuffix(' ms')
        self._delay.setValue(self.settings.key_delay)
        row.addWidget(self._delay)
        row.addStretch(1)
        layout.addLayout(row)
        layout.addStretch(1)

        # ---------------------------------------------------------------- pop-up and programs
        page, layout = _page(tabs, 'Programs')
        layout.addWidget(_heading('Pop-up in login boxes'))
        self._inline = QCheckBox('List my logins when I click into a login box')
        self._inline.setChecked(self.settings.inline)
        layout.addWidget(self._inline)
        layout.addWidget(_note('Not in browsers - the Bitwarden extension does that there. Games that draw '
                               'their own screens cannot show it; the hotkey still works in them.'))
        self._muted = QListWidget()
        self._muted.setMaximumHeight(80)
        for program in self.settings.inline_muted:
            self._muted.addItem(program)
        unmute = QPushButton('Pop up again')
        unmute.clicked.connect(lambda: [self._muted.takeItem(self._muted.row(i))
                                        for i in self._muted.selectedItems()])
        if not self._muted.count():
            self._muted.addItem("Programs you choose “Don't pop up in” for are listed here")
            self._muted.setEnabled(False)
            unmute.setEnabled(False)
        row = QHBoxLayout()
        row.addWidget(self._muted, 1)
        row.addWidget(unmute, 0, Qt.AlignTop)
        layout.addLayout(row)

        layout.addSpacing(10)
        layout.addWidget(_heading('Remembered programs'))
        self._links = QListWidget()
        self._links.setMaximumHeight(120)
        self._links.setSelectionMode(QListWidget.ExtendedSelection)
        for key, value in sorted(self.settings.links.items()):
            item = QListWidgetItem()
            item.setData(Qt.UserRole, (key, value))
            self._show_link(item)
            self._links.addItem(item)
        forget = QPushButton('Forget')
        forget.clicked.connect(lambda: [self._links.takeItem(self._links.row(i))
                                        for i in self._links.selectedItems()])
        whole_site = QPushButton('Any login for\nits website')
        whole_site.setToolTip('Other accounts on the same website count too, not only the login you chose')
        whole_site.clicked.connect(self._links_to_sites)
        if not self._links.count():
            self._links.addItem('None yet - tick “Always use” in the picker')
            self._links.setEnabled(False)
            forget.setEnabled(False)
            whole_site.setEnabled(False)
        buttons = QVBoxLayout()
        buttons.addWidget(forget)
        buttons.addWidget(whole_site)
        buttons.addStretch(1)
        row = QHBoxLayout()
        row.addWidget(self._links, 1)
        row.addLayout(buttons)
        layout.addLayout(row)
        layout.addStretch(1)

        # ---------------------------------------------------------------- locking
        page, layout = _page(tabs, 'Locking')
        self._with_windows = QCheckBox('Lock when Windows locks or goes to sleep')
        self._with_windows.setChecked(self.settings.lock_with_windows)
        layout.addWidget(self._with_windows)
        row = QHBoxLayout()
        row.addWidget(QLabel('Lock after the PC is idle for:'))
        self._idle = QComboBox()
        for minutes in IDLE_CHOICES:
            self._idle.addItem('Never' if not minutes else
                               f'{minutes // 60} hours' if minutes >= 120 else
                               '1 hour' if minutes == 60 else f'{minutes} minutes', minutes)
        self._idle.setCurrentIndex(IDLE_CHOICES.index(self.settings.idle_minutes))
        row.addWidget(self._idle)
        row.addStretch(1)
        layout.addLayout(row)
        layout.addWidget(_note('Locking forgets your logins until you unlock again, and has Bitwarden '
                               'destroy the session key. Quitting Keytap locks it too.'))

        layout.addSpacing(10)
        layout.addWidget(_heading('Windows Hello'))
        row = QHBoxLayout()
        self._hello_state = QLabel()
        row.addWidget(self._hello_state, 1)
        self._hello = QPushButton()
        self._hello.clicked.connect(self._toggle_hello)
        row.addWidget(self._hello)
        layout.addLayout(row)
        if not controller.hello_supported and not controller.hello_on():
            why = ('Windows Hello is not set up on this PC. Set up a PIN, fingerprint or face in Windows '
                   'Settings → Accounts → Sign-in options, then come back here.')
        else:
            why = ("Unlock with your fingerprint, face or PIN instead of your master password. As in "
                   "Bitwarden's desktop app, Keytap keeps your master password sealed so that only Windows "
                   'Hello, on your Windows account, can open it.')
        layout.addWidget(_note(why))
        self._show_hello()
        layout.addStretch(1)

        # ---------------------------------------------------------------- passkeys
        page, layout = _page(tabs, 'Passkeys')
        layout.addWidget(_heading('Sign in with the passkeys in your vault'))
        layout.addWidget(_note(
            "When a website or app asks for a passkey, Windows' passkey window can offer Keytap. Keytap signs "
            'in with the passkeys already in your Bitwarden vault, checking it is you with Windows Hello. It '
            "doesn't save new passkeys: save those with Bitwarden's browser extension or app."))
        layout.addSpacing(6)
        self._passkey_steps = QLabel('Checking…')
        self._passkey_steps.setTextFormat(Qt.RichText)
        layout.addWidget(self._passkey_steps)
        row = QHBoxLayout()
        self._passkey_setup = QPushButton('Set up passkeys…')
        self._passkey_setup.clicked.connect(lambda: (self.reject(), controller.set_up_passkeys()))
        self._passkey_windows = QPushButton('Open Windows passkey settings')
        self._passkey_windows.clicked.connect(controller.open_passkey_settings)
        self._passkey_off = QPushButton('Turn off passkeys')
        self._passkey_off.clicked.connect(self._turn_off_passkeys)
        for button in (self._passkey_setup, self._passkey_windows, self._passkey_off):
            button.hide()
            row.addWidget(button)
        row.addStretch(1)
        layout.addLayout(row)
        layout.addWidget(_note('Setting up asks Windows, once, to trust Keytap\'s certificate (an administrator '
                               'prompt): Windows takes passkey providers only from signed app packages, and '
                               'Keytap\'s gives it that identity without moving any of its files.'))
        layout.addStretch(1)
        background.run(controller.passkey_status, self._show_passkeys)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self._save)
        buttons.rejected.connect(self.reject)
        cli = controller.cli_version
        about = QLabel(f'Keytap {__version__}' + (f'  ·  Bitwarden CLI {cli}' if cli else ''))
        about.setEnabled(False)
        bottom = QHBoxLayout()
        bottom.addWidget(about)
        bottom.addStretch(1)
        bottom.addWidget(buttons)
        outer.addLayout(bottom)

    def _show_passkeys(self, status, error) -> None:
        try:
            if error is not None or status is None:
                self._passkey_steps.setText(f'Could not check: {error}')
                return
            if status['why']:
                self._passkey_steps.setText(status['why'])
                return
            steps = [('Windows trusts Keytap\'s certificate', status['trusted']),
                     ('Keytap\'s package is registered for this folder', status['registered']),
                     ('Keytap runs as its package', status['identity']),
                     ('Switched on in Windows\' passkey settings', status['state'] == 'enabled')]
            self._passkey_steps.setText('<br>'.join(
                f'{"✓" if done else "○"}&nbsp;&nbsp;{text}' for text, done in steps))
            ready = status['trusted'] and status['registered'] and status['identity']
            self._passkey_setup.setVisible(not ready)
            self._passkey_windows.setVisible(status['identity'] and status['state'] != 'enabled')
            self._passkey_off.setVisible(status['identity'] or status['registered'])
        except RuntimeError:            # the dialog closed first
            pass

    def _turn_off_passkeys(self) -> None:
        answer = QMessageBox.question(self, 'Keytap', 'Stop Keytap being a passkey provider? Your passkeys stay in '
                                      'your vault; Keytap restarts.')
        if answer == QMessageBox.Yes:
            self.reject()
            self.controller.turn_off_passkeys()

    def _show_hello(self, on: bool | None = None) -> None:
        controller = self.controller
        on = controller.hello_on() if on is None else on
        self._hello_state.setText('On - unlock with your fingerprint, face or PIN' if on else 'Off')
        self._hello.setText('Turn off' if on else 'Turn on…')
        self._hello.setEnabled(on or (controller.hello_supported and controller.unlocked))
        self._hello.setToolTip('' if on or controller.unlocked else 'Unlock Keytap first')

    def _toggle_hello(self) -> None:
        if self.controller.hello_on():
            self.controller.turn_off_hello()
            self._show_hello(False)
        else:
            self.reject()                   # the master password is asked for on a card of its own
            self.controller.turn_on_hello()

    def _sign_out(self) -> None:
        answer = QMessageBox.question(self, 'Keytap', 'Sign out of Bitwarden on this PC? '
                                      'You will need to sign in again to use Keytap.')
        if answer == QMessageBox.Yes:
            self.controller.sign_out()
            self.reject()

    def _show_link(self, item: QListWidgetItem) -> None:
        key, value = item.data(Qt.UserRole)
        program, _, title = key.partition('|')
        if title.startswith('site:'):         # a web page in the program, by its website
            where = f'{title[5:]} in {program}'
        else:
            where = f'{program}, “{title}”' if title else program
        item.setText(f'{where}  →  {self.controller.link_target(value)}')

    def _links_to_sites(self) -> None:
        """The chosen remembered programs: any login for the website of the login each was tied to."""
        items = self._links.selectedItems()
        if not items:
            QMessageBox.information(self, 'Keytap', 'Choose a remembered program in the list first.')
            return
        stuck = False
        for item in items:
            key, value = item.data(Qt.UserRole)
            if value.startswith(matching.SITE_LINK):
                continue
            site = self.controller.login_site(value)
            if site:
                item.setData(Qt.UserRole, (key, matching.SITE_LINK + site))
                self._show_link(item)
            else:
                stuck = True
        if stuck:
            QMessageBox.information(self, 'Keytap', 'Unlock Keytap first, so it can see which website the login is '
                                    'for.' if not self.controller.unlocked else
                                    'That login has no website saved in Bitwarden. Add the website to it there, '
                                    'or choose another login in the picker.')

    def _save(self) -> None:
        keys = {}
        for action, edit in self._keys.items():
            text = edit.keySequence().toString(QKeySequence.PortableText)
            if text:
                try:
                    text = hotkeys.normalize(text)
                except hotkeys.HotkeyError as error:
                    QMessageBox.warning(self, 'Keytap', f'{text}: {error}.')
                    return
            keys[action] = text
        if keys['type'] and keys['type'] == keys['pick']:
            QMessageBox.warning(self, 'Keytap', 'The two hotkeys must be different.')
            return
        problem = sequence.check(self._sequence.text())
        if problem:
            QMessageBox.warning(self, 'Keytap', f'The typing sequence will not work: {problem}.')
            return
        self.settings.hotkeys = keys
        self.settings.sequence = self._sequence.text()
        self.settings.compat_typing = self._compat.isChecked()
        self.settings.key_delay = self._delay.value()
        self.settings.lock_with_windows = self._with_windows.isChecked()
        self.settings.idle_minutes = self._idle.currentData()
        self.settings.inline = self._inline.isChecked()
        if self._muted.isEnabled():
            self.settings.inline_muted = [self._muted.item(i).text() for i in range(self._muted.count())]
        if self._links.isEnabled():
            self.settings.links = dict(self._links.item(i).data(Qt.UserRole) for i in range(self._links.count()))
        if self._startup.isChecked() != win32.starts_with_windows():
            win32.set_start_with_windows(self._startup.isChecked())
        if self._tray.isChecked() != self.settings.tray_shown:
            self.controller.set_tray_shown(self._tray.isChecked())
        self.accept()


# --------------------------------------------------------------------------- how it works


class WelcomeDialog(QDialog):
    sign_in = Signal()

    def __init__(self, hotkeys_now: dict[str, str], signed_in: bool, parent=None):
        super().__init__(parent)
        self.setWindowTitle('Keytap')
        self.setWindowIcon(icons.app_icon())
        self.setMinimumWidth(460)
        layout = QVBoxLayout(self)
        top = QHBoxLayout()
        logo = QLabel()
        logo.setPixmap(icons.render_app_icon(48))
        top.addWidget(logo, 0, Qt.AlignTop)
        top.addWidget(QLabel('<b style="font-size:14pt">Keytap is running</b><br>'
                             'It lives in the tray, by the clock.'), 1)
        layout.addLayout(top)
        layout.addSpacing(6)
        type_key = hotkeys_now.get('type') or 'its hotkey'
        pick_key = hotkeys_now.get('pick') or 'the other hotkey'
        steps = [
            '<b>1.</b> Click into the username box of any program - a game launcher, an app, '
            'a remote desktop.',
            f'<b>2.</b> Press <b>{type_key}</b>. Keytap types the login that goes with that '
            'program, then presses Enter. If it is not sure which, it asks.',
            f'<b>3.</b> In the list, tick <i>Always use</i> and it will not ask again for that '
            f'program. <b>{pick_key}</b> always lets you choose.',
            '<b>Or just click into a login box</b> - in most programs Keytap lists your logins '
            'right under it, as Bitwarden does in a browser.',
        ]
        text = QLabel('<br><br>'.join(steps))
        text.setWordWrap(True)
        text.setTextFormat(Qt.RichText)
        layout.addWidget(text)
        layout.addWidget(_note('Keytap reads your vault through Bitwarden\'s own command-line tool. '
                               'Passwords are kept in memory only while it is unlocked.'))
        self.startup = QCheckBox('Start Keytap when I sign in to Windows')
        self.startup.setChecked(True)
        layout.addWidget(self.startup)
        buttons = QDialogButtonBox()
        if signed_in:
            ok = buttons.addButton('Got it', QDialogButtonBox.AcceptRole)
        else:
            ok = buttons.addButton('Sign in to Bitwarden…', QDialogButtonBox.AcceptRole)
            later = buttons.addButton('Later', QDialogButtonBox.RejectRole)
            later.clicked.connect(self.reject)
            ok.clicked.connect(self.sign_in.emit)
        ok.setDefault(True)
        buttons.accepted.connect(self.accept)
        layout.addWidget(buttons)
        self.finished.connect(self._apply)

    def _apply(self, _) -> None:
        if self.startup.isChecked() != win32.starts_with_windows():
            win32.set_start_with_windows(self.startup.isChecked())
