"""The vault window's tools, as Bitwarden's apps have them: the generator, Send, the vault's health
report, and exporting and importing. Each is a window of its own, closed when Keytap locks."""

from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtGui import QFont, QIcon
from PySide6.QtWidgets import (QButtonGroup, QCheckBox, QComboBox, QDialog, QFileDialog, QFormLayout, QFrame,
                               QHBoxLayout, QLabel, QLineEdit, QListWidget, QListWidgetItem, QMessageBox,
                               QPlainTextEdit, QPushButton, QRadioButton, QSlider, QSpinBox, QStackedWidget,
                               QTabWidget, QVBoxLayout, QWidget)

from .. import generator
from .editor import Secret
from . import icons, theme


def _title(text: str, size: float = 13) -> QLabel:
    label = QLabel(text)
    label.setFont(theme.font(size, QFont.DemiBold))
    return label


def _dim(text: str) -> QLabel:
    label = QLabel(text)
    label.setProperty('role', 'dim')
    label.setWordWrap(True)
    return label


def _button(text: str, glyph: str = '', primary: bool = False) -> QPushButton:
    button = QPushButton(text)
    if glyph:
        button.setIcon(QIcon(icons.glyph(glyph, theme.ON_ACCENT if primary else theme.colors().text, 16, 1.7)))
    if primary:
        button.setProperty('role', 'primary')
    button.setCursor(Qt.PointingHandCursor)
    return button


class _Window(QWidget):
    def __init__(self, controller, title: str, width: int, height: int):
        super().__init__()
        self.controller = controller
        self.setWindowTitle(f'{title} - Keytap')
        self.setWindowIcon(icons.app_icon())
        theme.frost(self)
        theme.restyle(self, lambda: theme.card_style() + theme.panel_css('QFrame#sectionBox', 10) +
                      ' QListWidget::item { padding: 5px 6px; }')
        self.resize(width, height)


# --------------------------------------------------------------------------- the generator

class GeneratorWindow(_Window):
    """Passwords, passphrases and usernames, as Bitwarden's generator makes them. Its choices are
    kept (in Keytap's settings); what it made is listed below until Keytap locks."""

    def __init__(self, controller):
        super().__init__(controller, 'Generator', 520, 640)
        self.options = generator.settled(controller.settings.generator)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(22, 18, 22, 18)
        layout.setSpacing(12)
        layout.addWidget(_title('Generator'))

        kinds = QHBoxLayout()
        self.kind = QButtonGroup(self)
        for n, (key, label) in enumerate((('password', 'Password'), ('passphrase', 'Passphrase'),
                                          ('username', 'Username'))):
            choice = QRadioButton(label)
            choice.setProperty('key', key)
            choice.setChecked(self.options['kind'] == key)
            self.kind.addButton(choice, n)
            kinds.addWidget(choice)
        kinds.addStretch(1)
        layout.addLayout(kinds)

        out = QFrame()
        out.setObjectName('sectionBox')
        row = QHBoxLayout(out)
        row.setContentsMargins(14, 10, 8, 10)
        from .vault_window import _mono
        self.output = QLineEdit()
        self.output.setReadOnly(True)
        self.output.setFrame(False)
        self.output.setFont(_mono(12))
        self.output.setStyleSheet('background: transparent; border: none;')
        row.addWidget(self.output, 1)
        again = _button('', 'refresh')
        again.setToolTip('Make another')
        again.clicked.connect(self.make)
        row.addWidget(again)
        copy = _button('Copy', 'copy', primary=True)
        copy.clicked.connect(self._copy)
        row.addWidget(copy)
        layout.addWidget(out)

        self.pages = QStackedWidget()
        self.pages.addWidget(self._password_page())
        self.pages.addWidget(self._passphrase_page())
        self.pages.addWidget(self._username_page())
        layout.addWidget(self.pages)

        layout.addWidget(_dim('Made since Keytap unlocked (double-click one to copy it):'))
        self.history = QListWidget()
        from .vault_window import _mono as mono
        self.history.setFont(mono(9))
        self.history.itemDoubleClicked.connect(lambda entry: self.controller.copy(entry.data(Qt.UserRole), 'password'))
        layout.addWidget(self.history, 1)
        self.kind.idToggled.connect(lambda n, on: on and self._changed())
        self._show_page()
        self.make()

    def _check(self, form: QFormLayout, label: str, key: str) -> QCheckBox:
        box = QCheckBox(label)
        box.setChecked(bool(self.options[key]))
        box.toggled.connect(lambda on: self._set(key, on))
        form.addRow(box)
        return box

    def _spin(self, form: QFormLayout, label: str, key: str) -> QSpinBox:
        low, high = generator.LIMITS[key]
        spin = QSpinBox()
        spin.setRange(low, high)
        spin.setValue(self.options[key])
        spin.setFixedWidth(80)
        spin.valueChanged.connect(lambda value: self._set(key, value))
        form.addRow(label, spin)
        return spin

    def _password_page(self) -> QWidget:
        page = QWidget()
        form = QFormLayout(page)
        form.setContentsMargins(0, 0, 0, 0)
        length = QHBoxLayout()
        slider = QSlider(Qt.Horizontal)
        slider.setRange(*generator.LIMITS['length'])
        slider.setValue(self.options['length'])
        number = QSpinBox()
        number.setRange(*generator.LIMITS['length'])
        number.setValue(self.options['length'])
        slider.valueChanged.connect(number.setValue)
        number.valueChanged.connect(slider.setValue)
        number.valueChanged.connect(lambda value: self._set('length', value))
        length.addWidget(slider, 1)
        length.addWidget(number)
        form.addRow('Length', length)
        self._check(form, 'A-Z', 'upper')
        self._check(form, 'a-z', 'lower')
        self._check(form, '0-9', 'digits')
        self._check(form, generator.SPECIAL, 'special')
        self._spin(form, 'Fewest numbers', 'min_digits')
        self._spin(form, 'Fewest special characters', 'min_special')
        self._check(form, 'Avoid characters that look alike (I, l, O, 0, 1)', 'avoid_ambiguous')
        return page

    def _passphrase_page(self) -> QWidget:
        page = QWidget()
        form = QFormLayout(page)
        form.setContentsMargins(0, 0, 0, 0)
        self._spin(form, 'Words', 'words')
        separator = QLineEdit(self.options['separator'])
        separator.setMaxLength(1)
        separator.setFixedWidth(60)
        separator.textChanged.connect(lambda text: self._set('separator', text))
        form.addRow('Between words', separator)
        self._check(form, 'Capitalise', 'capitalize')
        self._check(form, 'Include a number', 'number')
        return page

    def _username_page(self) -> QWidget:
        page = QWidget()
        form = QFormLayout(page)
        form.setContentsMargins(0, 0, 0, 0)
        kind = QComboBox()
        for key, label in (('word', 'A random word'), ('plus', 'Your email, plus-addressed'),
                           ('catchall', 'An address at your own domain (catch-all)')):
            kind.addItem(label, key)
        kind.setCurrentIndex(max(0, kind.findData(self.options['username'])))
        form.addRow('Kind', kind)
        email = QLineEdit(self.options['email'])
        email.setPlaceholderText('you@example.com')
        email.textChanged.connect(lambda text: self._set('email', text.strip()))
        form.addRow('Your email', email)
        domain = QLineEdit(self.options['domain'])
        domain.setPlaceholderText('example.com')
        domain.textChanged.connect(lambda text: self._set('domain', text.strip()))
        form.addRow('Your domain', domain)
        capitalize = QCheckBox('Capitalise')
        capitalize.setChecked(self.options['username_capitalize'])
        capitalize.toggled.connect(lambda on: self._set('username_capitalize', on))
        form.addRow(capitalize)
        number = QCheckBox('Include a number')
        number.setChecked(self.options['username_number'])
        number.toggled.connect(lambda on: self._set('username_number', on))
        form.addRow(number)

        def shown():
            which = kind.currentData()
            for widget, wanted in ((email, which == 'plus'), (domain, which == 'catchall'),
                                   (capitalize, which == 'word'), (number, which == 'word')):
                widget.setVisible(wanted)
                label = form.labelForField(widget)
                if label is not None:
                    label.setVisible(wanted)
        kind.currentIndexChanged.connect(lambda _: (self._set('username', kind.currentData()), shown()))
        shown()
        return page

    def _set(self, key: str, value) -> None:
        self.options[key] = value
        self._changed()

    def _changed(self) -> None:
        button = self.kind.checkedButton()
        self.options['kind'] = button.property('key') if button is not None else 'password'
        self.options = generator.settled(self.options)
        self.controller.settings.generator = self.options
        self._show_page()
        self.make()

    def _show_page(self) -> None:
        self.pages.setCurrentIndex(('password', 'passphrase', 'username').index(self.options['kind']))

    def make(self) -> None:
        made = generator.generate(self.options)
        self.output.setText(made)
        if not made:
            self.output.setPlaceholderText('Give your email (or domain) first')
            return
        self.controller.remember_generated(made)
        self._fill_history()

    def _fill_history(self) -> None:
        self.history.clear()
        for value, when in self.controller.generated:
            entry = QListWidgetItem(f'{time.strftime("%H:%M", time.localtime(when))}   {value}')
            entry.setData(Qt.UserRole, value)
            self.history.addItem(entry)

    def _copy(self) -> None:
        if self.output.text():
            self.controller.copy(self.output.text(), {'password': 'password', 'passphrase': 'passphrase'}.get(
                self.options['kind'], 'username'))


# --------------------------------------------------------------------------- Send

DAYS = ((1 / 24, '1 hour'), (1, '1 day'), (2, '2 days'), (3, '3 days'), (7, '7 days'), (14, '14 days'),
        (30, '30 days'))


def _in_days(days: float) -> str:
    moment = datetime.now(timezone.utc) + timedelta(days=days)
    return moment.strftime('%Y-%m-%dT%H:%M:%S.000Z')


def _shown_date(stamp) -> str:
    from ..items import when
    return when(str(stamp or ''))


class SendsWindow(_Window):
    """Bitwarden Send: a text or a file shared through a link, deleted after a while. Keytap lists,
    makes, changes and deletes them through bw, which encrypts each before it leaves this PC."""

    def __init__(self, controller):
        super().__init__(controller, 'Send', 820, 600)
        self.sends: list[dict] = []
        self.current: dict | None = None
        outer = QHBoxLayout(self)
        outer.setContentsMargins(18, 16, 18, 16)
        outer.setSpacing(16)

        left = QVBoxLayout()
        left.addWidget(_title('Send'))
        self.list = QListWidget()
        self.list.currentRowChanged.connect(self._chosen)
        left.addWidget(self.list, 1)
        new_text = _button('New text Send', 'plus')
        new_text.clicked.connect(lambda: self._new(0))
        new_file = _button('New file Send', 'clip')
        new_file.clicked.connect(lambda: self._new(1))
        left.addWidget(new_text)
        left.addWidget(new_file)
        self.state = _dim('Asking Bitwarden for your Sends…')
        left.addWidget(self.state)
        outer.addLayout(left, 2)

        right = QVBoxLayout()
        form = QFormLayout()
        self.name = QLineEdit()
        form.addRow('Name', self.name)
        self.text = QPlainTextEdit()
        self.text.setFixedHeight(110)
        form.addRow('Text', self.text)
        self.hidden = QCheckBox('Hide the text until it is clicked')
        form.addRow('', self.hidden)
        file_row = QHBoxLayout()
        self.file = QLabel()
        self.file.setWordWrap(True)
        self.choose = _button('Choose…')
        self.choose.clicked.connect(self._choose_file)
        file_row.addWidget(self.file, 1)
        file_row.addWidget(self.choose)
        form.addRow('File', file_row)
        self._file_row = file_row
        self.deletes = QComboBox()
        form.addRow('Deleted after', self.deletes)
        self.expires = QComboBox()
        form.addRow('Link stops working', self.expires)
        self.views = QSpinBox()
        self.views.setRange(0, 1_000_000)
        self.views.setSpecialValueText('No limit')
        form.addRow('Most views', self.views)
        self.password = Secret(mono=False, placeholder='Optional: needed to open the link')
        form.addRow('Password', self.password)
        self.remove_password = _button('Remove its password')
        self.remove_password.clicked.connect(self._remove_password)
        form.addRow('', self.remove_password)
        self.hide_email = QCheckBox('Hide my email address from whoever opens it')
        form.addRow('', self.hide_email)
        self.notes = QPlainTextEdit()
        self.notes.setFixedHeight(60)
        form.addRow('Private notes', self.notes)
        self.disabled = QCheckBox('Turned off: no one can open it')
        form.addRow('', self.disabled)
        self._form = form
        right.addLayout(form)
        self.link = QLineEdit()
        self.link.setReadOnly(True)
        right.addWidget(self.link)
        buttons = QHBoxLayout()
        self.message = QLabel()
        self.message.setProperty('role', 'error')
        self.message.setWordWrap(True)
        buttons.addWidget(self.message, 1)
        self.delete = _button('Delete', 'trash')
        self.delete.clicked.connect(self._delete)
        self.copy_link = _button('Copy link', 'link')
        self.copy_link.clicked.connect(lambda: self.controller.copy(self.link.text(), 'link'))
        self.save = _button('Save', primary=True)
        self.save.clicked.connect(self._save)
        for button in (self.delete, self.copy_link, self.save):
            buttons.addWidget(button)
        right.addLayout(buttons)
        right.addStretch(1)
        self.form_box = QWidget()
        self.form_box.setLayout(right)
        outer.addWidget(self.form_box, 3)
        self.form_box.setEnabled(False)
        self._load()

    def _load(self, choose: str = '') -> None:
        def loaded(sends, error):
            if error is not None:
                self.state.setText(f'Bitwarden did not list your Sends: {error}')
                return
            self.sends = sends
            self.state.setText(f'{len(sends)} Send{"s" if len(sends) != 1 else ""}' if sends else 'No Sends yet.')
            self.list.blockSignals(True)
            self.list.clear()
            for send in sends:
                kind = 'File' if send.get('type') == 1 else 'Text'
                entry = QListWidgetItem(f'{send.get("name") or "(no name)"}\n{kind} · deleted '
                                        f'{_shown_date(send.get("deletionDate"))}')
                entry.setData(Qt.UserRole, send.get('id'))
                self.list.addItem(entry)
            self.list.blockSignals(False)
            ids = [send.get('id') for send in sends]
            if choose in ids:
                self.list.setCurrentRow(ids.index(choose))
        self.controller.run_vault(self.controller.vault.sends, None, loaded)

    def _chosen(self, row: int) -> None:
        if 0 <= row < len(self.sends):
            self._show(self.sends[row])

    def _new(self, kind: int) -> None:
        self.list.blockSignals(True)
        self.list.clearSelection()
        self.list.setCurrentRow(-1)
        self.list.blockSignals(False)
        self._show({'type': kind, 'name': '', 'text': {'text': '', 'hidden': False} if kind == 0 else None,
                    'file': {'fileName': ''} if kind == 1 else None, 'deletionDate': None, 'expirationDate': None,
                    'maxAccessCount': None, 'disabled': False, 'hideEmail': False, 'notes': None})
        self.name.setFocus()

    def _show(self, send: dict) -> None:
        self.current = send
        self.form_box.setEnabled(True)
        existing = bool(send.get('id'))
        is_file = send.get('type') == 1
        self.name.setText(str(send.get('name') or ''))
        text = send.get('text') or {}
        self.text.setPlainText(str(text.get('text') or ''))
        self.hidden.setChecked(bool(text.get('hidden')))
        self._file_path = ''
        self.file.setText(str((send.get('file') or {}).get('fileName') or '') or 'No file chosen')
        for widget, wanted in ((self.text, not is_file), (self.hidden, not is_file), (self._file_row, is_file)):
            if isinstance(widget, QWidget):
                widget.setVisible(wanted)
            label = self._form.labelForField(widget)
            if label is not None:
                label.setVisible(wanted)
        self.file.setVisible(is_file)
        self.choose.setVisible(is_file and not existing)
        self.deletes.clear()
        self.expires.clear()
        if existing:
            self.deletes.addItem(f'As it is ({_shown_date(send.get("deletionDate"))})', None)
            self.expires.addItem(f'As it is ({_shown_date(send.get("expirationDate")) or "never"})', None)
        else:
            self.expires.addItem('Never', 0)
        for days, label in DAYS:
            self.deletes.addItem(label, days)
            self.expires.addItem(label, days)
        if not existing:
            self.deletes.setCurrentIndex(self.deletes.findData(7))
        self.views.setValue(int(send.get('maxAccessCount') or 0))
        self.password.set_text('')
        self.password.edit.setPlaceholderText('A new password' if send.get('passwordSet') else
                                              'Optional: needed to open the link')
        self.remove_password.setVisible(bool(send.get('passwordSet')))
        self.hide_email.setChecked(bool(send.get('hideEmail')))
        self.notes.setPlainText(str(send.get('notes') or ''))
        self.disabled.setChecked(bool(send.get('disabled')))
        self.link.setText(str(send.get('accessUrl') or ''))
        self.link.setVisible(existing)
        self.copy_link.setEnabled(existing)
        self.delete.setEnabled(existing)
        self.message.setText('')

    def _choose_file(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, 'Choose the file to send')
        if path:
            self._file_path = path
            self.file.setText(Path(path).name)
            if not self.name.text().strip():
                self.name.setText(Path(path).name)

    def _collect(self) -> dict:
        send = dict(self.current or {})
        send['object'] = 'send'
        send['name'] = self.name.text().strip()
        send['notes'] = self.notes.toPlainText().strip() or None
        if send.get('type') == 1:
            if not send.get('id'):
                send['file'] = {'fileName': self._file_path}
            send['text'] = None
        else:
            send['text'] = {'text': self.text.toPlainText(), 'hidden': self.hidden.isChecked()}
            send['file'] = None
        deletes, expires = self.deletes.currentData(), self.expires.currentData()
        if deletes is not None:
            send['deletionDate'] = _in_days(deletes)
        if expires is not None:
            send['expirationDate'] = _in_days(expires) if expires else None
        send['maxAccessCount'] = self.views.value() or None
        send['password'] = self.password.text() or None
        send['hideEmail'] = self.hide_email.isChecked()
        send['disabled'] = self.disabled.isChecked()
        for key in ('accessUrl', 'passwordSet', 'accessCount', 'revisionDate'):
            send.pop(key, None)
        return send

    def _save(self) -> None:
        send = self._collect()
        if not send['name']:
            self.message.setText('Give it a name.')
            return
        if send.get('type') == 1 and not send.get('id') and not self._file_path:
            self.message.setText('Choose the file to send.')
            return
        if send.get('type') != 1 and not (send['text'] or {}).get('text'):
            self.message.setText('Write the text to send.')
            return
        self.save.setEnabled(False)
        self.save.setText('Saving…')
        send_id = str(send.get('id') or '')

        def saved(made, error):
            try:
                self.save.setEnabled(True)
                self.save.setText('Save')
            except RuntimeError:
                return
            if error is not None:
                self.message.setText(f'Bitwarden did not save it: {error}')
                return
            if made.get('accessUrl'):
                self.controller.copy(made['accessUrl'], 'link to the Send')
            self._load(choose=str(made.get('id') or send_id))
        self.controller.run_vault(lambda: self.controller.vault.save_send(send, send_id), None, saved)

    def _remove_password(self) -> None:
        send_id = str((self.current or {}).get('id') or '')
        if send_id:
            self.controller.run_vault(lambda: self.controller.vault.remove_send_password(send_id), None,
                                      lambda _, error: self._after(error, send_id))

    def _delete(self) -> None:
        send = self.current or {}
        if not send.get('id'):
            return
        answer = QMessageBox.question(self, 'Keytap', f'Delete the Send “{send.get("name")}”? Its link stops working.',
                                      QMessageBox.Yes | QMessageBox.Cancel, QMessageBox.Cancel)
        if answer == QMessageBox.Yes:
            send_id = str(send['id'])
            self.controller.run_vault(lambda: self.controller.vault.delete_send(send_id), None,
                                      lambda _, error: self._after(error))

    def _after(self, error, choose: str = '') -> None:
        if error is not None:
            self.message.setText(str(error))
            return
        if not choose:
            self.current = None
            self.form_box.setEnabled(False)
        self._load(choose)


# --------------------------------------------------------------------------- vault health

STRENGTH = {0: 'Very weak', 1: 'Very weak', 2: 'Weak', 3: 'Good', 4: 'Strong'}


class HealthWindow(_Window):
    """Bitwarden's reports: passwords that leaked in a breach, are used more than once, or are weak,
    and logins whose website isn't https. The first three come from bw's own report."""

    def __init__(self, controller):
        super().__init__(controller, 'Vault health', 640, 600)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(22, 18, 22, 18)
        layout.setSpacing(10)
        layout.addWidget(_title('Vault health'))
        self.exposed = QCheckBox("Check for leaked passwords with Have I Been Pwned (it gets only the start of each "
                                 "password's hash)")
        self.exposed.setChecked(True)
        layout.addWidget(self.exposed)
        row = QHBoxLayout()
        self.go = _button('Check my vault', 'shield', primary=True)
        self.go.clicked.connect(self.check)
        row.addWidget(self.go)
        self.state = _dim('')
        row.addWidget(self.state, 1)
        layout.addLayout(row)
        self.tabs = QTabWidget()
        self.lists = {}
        for key, title in (('exposed', 'Exposed'), ('reused', 'Reused'), ('weak', 'Weak'),
                           ('unsecured', 'Not https')):
            shown = QListWidget()
            shown.itemDoubleClicked.connect(self._open)
            self.lists[key] = shown
            self.tabs.addTab(shown, title)
        layout.addWidget(self.tabs, 1)
        layout.addWidget(_dim('Double-click a login to open it in Keytap.'))
        self._unsecured()

    def check(self) -> None:
        self.go.setEnabled(False)
        self.state.setText('Checking… (with Have I Been Pwned, about a second a login)' if self.exposed.isChecked()
                           else 'Checking…')
        exposed = self.exposed.isChecked()
        self.controller.run_vault(lambda: self.controller.vault.health(exposed), None, self._checked)

    def _checked(self, report, error) -> None:
        try:
            self.go.setEnabled(True)
        except RuntimeError:
            return
        if error is not None:
            self.state.setText(f'Bitwarden did not check it: {error}')
            return
        names = {item.id: item for item in self.controller.items or []}
        found = {'exposed': [], 'reused': [], 'weak': []}
        for entry in report:
            item = names.get(str(entry.get('id') or ''))
            who = item.subtitle if item is not None else ''
            name = str(entry.get('name') or (item.name if item else ''))
            if entry.get('exposed'):
                found['exposed'].append((name, who, f'seen {entry.get("exposedCount") or "some"} times in data '
                                                    'breaches', entry.get('id')))
            if entry.get('reuseCount'):
                found['reused'].append((name, who, f'the same password is in {entry["reuseCount"]} logins',
                                        entry.get('id')))
            strength = entry.get('passwordStrength')
            if isinstance(strength, int) and strength <= 2:
                found['weak'].append((name, who, STRENGTH.get(strength, 'Weak'), entry.get('id')))
        for key, rows in found.items():
            self._fill(key, sorted(rows, key=lambda row: row[0].lower()))
        errors = [entry.get('exposedError') for entry in report if entry.get('exposedError')]
        words = ', '.join(f'{len(found[k])} {k}' for k in found)
        self.state.setText(f'{len(report)} logins checked: {words}.' +
                           (f' Have I Been Pwned could not be asked for {len(errors)}.' if errors else ''))

    def _unsecured(self) -> None:
        rows = []
        for item in self.controller.items or []:
            login = item.login
            if login is not None and any(uri.lower().startswith('http://') for uri in login.uris):
                rows.append((item.name, item.subtitle, 'its website starts with http://', item.id))
        self._fill('unsecured', sorted(rows, key=lambda row: row[0].lower()))

    def _fill(self, key: str, rows) -> None:
        shown = self.lists[key]
        shown.clear()
        for name, who, why, item_id in rows:
            entry = QListWidgetItem(f'{name}{"  ·  " + who if who else ""}\n{why}')
            entry.setData(Qt.UserRole, item_id)
            shown.addItem(entry)
        index = list(self.lists).index(key)
        self.tabs.setTabText(index, f'{self.tabs.tabText(index).split(" (")[0]} ({len(rows)})')

    def _open(self, entry) -> None:
        item_id = entry.data(Qt.UserRole)
        self.controller.show_vault()
        window = self.controller._windows.get('vault')
        if window is not None and item_id:
            window.show_item(str(item_id))


# --------------------------------------------------------------------------- export and import

EXPORTS = (('encrypted_json', 'Bitwarden (.json), encrypted with your account', 'json'),
           ('json', 'Bitwarden (.json)', 'json'), ('csv', 'Comma-separated (.csv)', 'csv'),
           ('zip', 'Bitwarden (.zip), with attachments', 'zip'))

FORMAT_NAMES = {
    'bitwardenjson': 'Bitwarden (json)', 'bitwardencsv': 'Bitwarden (csv)', 'bitwardenpasswordprotected':
    'Bitwarden, password-protected (json)', 'chromecsv': 'Chrome, Edge, Brave, Opera, Vivaldi (csv)',
    'firefoxcsv': 'Firefox (csv)', 'safaricsv': 'Safari and macOS (csv)', 'lastpasscsv': 'LastPass (csv)',
    '1password1pux': '1Password (1pux)', '1passwordwincsv': '1Password 6 and 7 Windows (csv)',
    'keepass2xml': 'KeePass 2 (xml)', 'keepassxcsv': 'KeePassX (csv)', 'dashlanecsv': 'Dashlane (csv)',
    'dashlanejson': 'Dashlane (json)', 'protonpass': 'Proton Pass (zip or json)', 'nordpasscsv': 'NordPass (csv)',
    'enpasscsv': 'Enpass (csv)', 'enpassjson': 'Enpass (json)', 'keepercsv': 'Keeper (csv)',
    'roboformcsv': 'RoboForm (csv)', 'avirajson': 'Avira (json)', 'zohovaultcsv': 'Zoho Vault (csv)',
}


class ExportDialog(QDialog):
    def __init__(self, controller):
        super().__init__()
        self.controller = controller
        theme.frost(self)
        theme.restyle(self, theme.card_style)
        self.setWindowTitle('Export vault - Keytap')
        self.setWindowIcon(icons.app_icon())
        self.setMinimumWidth(480)
        layout = QVBoxLayout(self)
        layout.setSpacing(10)
        layout.addWidget(_title('Export vault', 12))
        self.choice = QButtonGroup(self)
        for n, (key, label, _) in enumerate(EXPORTS):
            radio = QRadioButton(label)
            radio.setChecked(n == 0)
            self.choice.addButton(radio, n)
            layout.addWidget(radio)
        self.warning = _dim('')
        layout.addWidget(self.warning)
        self.choice.idToggled.connect(lambda *_: self._explain())
        self._explain()
        row = QHBoxLayout()
        self.message = _dim('')
        row.addWidget(self.message, 1)
        cancel = _button('Close')
        cancel.clicked.connect(self.close)
        self.go = _button('Export…', 'download', primary=True)
        self.go.clicked.connect(self._export)
        row.addWidget(cancel)
        row.addWidget(self.go)
        layout.addLayout(row)

    def _explain(self) -> None:
        key = EXPORTS[self.choice.checkedId()][0]
        self.warning.setText('Only your Bitwarden account can import it again.' if key == 'encrypted_json' else
                             'The file is not encrypted: anyone who opens it can read every password in it. '
                             'Delete it once you are done with it.')

    def _export(self) -> None:
        key, _, extension = EXPORTS[self.choice.checkedId()]
        name = f'bitwarden_export_{time.strftime("%Y%m%d%H%M%S")}.{extension}'
        path, _ = QFileDialog.getSaveFileName(self, 'Export vault', str(Path.home() / 'Documents' / name))
        if not path:
            return
        self.go.setEnabled(False)
        self.message.setText('Exporting…')

        def done(_, error):
            try:
                self.go.setEnabled(True)
            except RuntimeError:
                return
            self.message.setText(f'Bitwarden did not export it: {error}' if error is not None else
                                 f'Exported to {path}')
        self.controller.run_vault(lambda: self.controller.vault.export(path, key), None, done)


class ImportDialog(QDialog):
    def __init__(self, controller):
        super().__init__()
        self.controller = controller
        theme.frost(self)
        theme.restyle(self, theme.card_style)
        self.setWindowTitle('Import data - Keytap')
        self.setWindowIcon(icons.app_icon())
        self.setMinimumWidth(480)
        layout = QVBoxLayout(self)
        layout.setSpacing(10)
        layout.addWidget(_title('Import data', 12))
        layout.addWidget(_dim('From another password manager, or a Bitwarden export, into your vault.'))
        form = QFormLayout()
        self.form_ = QComboBox()
        self.form_.addItem('Asking Bitwarden…', '')
        form.addRow('From', self.form_)
        file_row = QHBoxLayout()
        self.file = QLineEdit()
        self.file.setPlaceholderText('The file it exported')
        browse = _button('Choose…')
        browse.clicked.connect(self._browse)
        file_row.addWidget(self.file, 1)
        file_row.addWidget(browse)
        form.addRow('File', file_row)
        self.password = Secret(mono=False, placeholder='Only for a password-protected file')
        form.addRow('Its password', self.password)
        layout.addLayout(form)
        row = QHBoxLayout()
        self.message = _dim('')
        row.addWidget(self.message, 1)
        cancel = _button('Close')
        cancel.clicked.connect(self.close)
        self.go = _button('Import', 'upload', primary=True)
        self.go.clicked.connect(self._import)
        self.go.setEnabled(False)
        row.addWidget(cancel)
        row.addWidget(self.go)
        layout.addLayout(row)
        self.controller.run_vault(self.controller.vault.import_formats, None, self._formats)

    def _formats(self, found, error) -> None:
        try:
            self.form_.clear()
        except RuntimeError:
            return
        if error is not None:
            self.message.setText(f'Bitwarden did not say what it can import: {error}')
            return
        known = sorted((FORMAT_NAMES.get(key, key), key) for key in found)
        for label, key in known:
            self.form_.addItem(label, key)
        self.form_.setCurrentIndex(max(0, self.form_.findData('bitwardenjson')))
        self.go.setEnabled(True)

    def _browse(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, 'Choose the file to import')
        if path:
            self.file.setText(path)

    def _import(self) -> None:
        form, path, password = self.form_.currentData(), self.file.text().strip(), self.password.text()
        if not path or not Path(path).is_file():
            self.message.setText('Choose the file to import.')
            return
        self.go.setEnabled(False)
        self.message.setText('Importing…')

        def done(said, error):
            try:
                self.go.setEnabled(True)
            except RuntimeError:
                return
            if error is not None:
                self.message.setText(f'Bitwarden did not import it: {error}')
                return
            self.message.setText(said or 'Imported.')
            self.controller.reload()
        self.controller.run_vault(lambda: self.controller.vault.import_file(form, path, password), None, done)
