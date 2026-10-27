"""Making and changing an item of the vault - any kind - laid out as Bitwarden's own editor is.

The editor works on a copy of the item as bw gave it, so whatever Keytap doesn't show (a login's
password history, an organization's settings) goes back to bw as it came. Saving hands the item to
the controller, which gives it to bw on its standard input.
"""

from __future__ import annotations

import json

from PySide6.QtCore import QSize, Qt, Signal
from PySide6.QtGui import QFont, QIcon, QKeySequence, QShortcut
from PySide6.QtWidgets import (QCheckBox, QComboBox, QDialog, QFormLayout, QFrame, QHBoxLayout, QLabel, QLineEdit,
                               QListWidget, QListWidgetItem, QMenu, QMessageBox, QPlainTextEdit, QPushButton,
                               QScrollArea, QSizePolicy, QToolButton, QVBoxLayout, QWidget)

from .. import generator, items, sshkey
from ..items import CARD, IDENTITY, LOGIN, NOTE, SSH_KEY
from . import icons, theme

MONTHS = ('January', 'February', 'March', 'April', 'May', 'June', 'July', 'August', 'September', 'October',
          'November', 'December')


def _text(value) -> str:
    return '' if value is None else str(value)


def _or_none(text: str):
    return text if text.strip() else None


def _tool(glyph: str, tip: str, action=None) -> QToolButton:
    button = QToolButton()
    button.setIcon(QIcon(icons.glyph(glyph, theme.colors().text, 17, 1.7)))
    button.setIconSize(QSize(17, 17))
    button.setFixedSize(30, 30)
    button.setToolTip(tip)
    button.setCursor(Qt.PointingHandCursor)
    if action is not None:
        button.clicked.connect(lambda: action())
    return button


class Secret(QWidget):
    """A line that stays hidden until shown, with buttons of its own beside it (generate, say)."""

    def __init__(self, value: str = '', mono: bool = True, placeholder: str = ''):
        super().__init__()
        row = QHBoxLayout(self)
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(2)
        self.edit = QLineEdit(value)
        self.edit.setEchoMode(QLineEdit.Password)
        self.edit.setPlaceholderText(placeholder)
        if mono:
            from .vault_window import _mono
            self.edit.setFont(_mono(10))
        row.addWidget(self.edit, 1)
        self.eye = _tool('eye', 'Show', self.toggle)
        row.addWidget(self.eye)
        self.row = row

    def add(self, button: QToolButton) -> QToolButton:
        self.row.addWidget(button)
        return button

    def text(self) -> str:
        return self.edit.text()

    def set_text(self, value: str, show: bool = False) -> None:
        self.edit.setText(value)
        if show and self.edit.echoMode() == QLineEdit.Password:
            self.toggle()

    def toggle(self) -> None:
        shown = self.edit.echoMode() == QLineEdit.Password
        self.edit.setEchoMode(QLineEdit.Normal if shown else QLineEdit.Password)
        self.eye.setIcon(QIcon(icons.glyph('eye_off' if shown else 'eye', theme.colors().text, 17, 1.7)))
        self.eye.setToolTip('Hide' if shown else 'Show')


class _Section(QFrame):
    def __init__(self, title: str):
        super().__init__()
        self.setObjectName('section')
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(6)
        heading = QLabel(title.upper())
        heading.setFont(theme.font(7.75, QFont.DemiBold))
        heading.setProperty('role', 'dim')
        outer.addWidget(heading)
        self.box = QFrame()
        self.box.setObjectName('sectionBox')
        self.layout_ = QVBoxLayout(self.box)
        self.layout_.setContentsMargins(14, 12, 14, 12)
        self.layout_.setSpacing(8)
        self.form = QFormLayout()
        self.form.setLabelAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        self.form.setFieldGrowthPolicy(QFormLayout.AllNonFixedFieldsGrow)
        self.form.setHorizontalSpacing(14)
        self.form.setVerticalSpacing(8)
        self.layout_.addLayout(self.form)
        outer.addWidget(self.box)

    def row(self, label: str, widget: QWidget) -> QWidget:
        self.form.addRow(label, widget)
        return widget

    def add(self, widget) -> None:
        if isinstance(widget, QWidget):
            self.layout_.addWidget(widget)
        else:
            self.layout_.addLayout(widget)


class _UriRow(QWidget):
    def __init__(self, uri: str, match, remove):
        super().__init__()
        row = QHBoxLayout(self)
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(6)
        self.uri = QLineEdit(uri)
        self.uri.setPlaceholderText('https://example.com, or app://program.exe')
        row.addWidget(self.uri, 1)
        self.match = QComboBox()
        for value, label in items.MATCHES:
            self.match.addItem(label, value)
        self.match.setCurrentIndex(max(0, self.match.findData(match)))
        self.match.setToolTip('Match detection: which addresses this login is offered on')
        row.addWidget(self.match)
        row.addWidget(_tool('close_x', 'Remove this website', lambda: remove(self)))

    def value(self) -> dict | None:
        uri = self.uri.text().strip()
        return {'match': self.match.currentData(), 'uri': uri} if uri else None


class _FieldRow(QWidget):
    """A custom field: its name, its value as its kind has it, and a button to take it away."""

    def __init__(self, field: dict, links: dict[int, str], remove):
        super().__init__()
        self.kind = field.get('type') if field.get('type') in items.FIELD_KINDS else items.TEXT
        row = QHBoxLayout(self)
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(6)
        self.name = QLineEdit(_text(field.get('name')))
        self.name.setPlaceholderText(f'{items.FIELD_KINDS[self.kind]} field name')
        row.addWidget(self.name, 2)
        value = _text(field.get('value'))
        if self.kind == items.BOOLEAN:
            self.value = QCheckBox()
            self.value.setChecked(value.lower() == 'true')
            row.addWidget(self.value, 3)
        elif self.kind == items.LINKED:
            self.value = QComboBox()
            for linked_id, label in links.items():
                self.value.addItem(label, linked_id)
            self.value.setCurrentIndex(max(0, self.value.findData(field.get('linkedId'))))
            row.addWidget(self.value, 3)
        elif self.kind == items.HIDDEN:
            self.value = Secret(value)
            row.addWidget(self.value, 3)
        else:
            self.value = QLineEdit(value)
            row.addWidget(self.value, 3)
        row.addWidget(_tool('close_x', 'Remove this field', lambda: remove(self)))

    def field(self) -> dict | None:
        name = self.name.text().strip()
        if self.kind == items.BOOLEAN:
            value, linked = ('true' if self.value.isChecked() else 'false'), None
        elif self.kind == items.LINKED:
            value, linked = None, self.value.currentData()
        else:
            value, linked = _or_none(self.value.text()), None
        if not name and value in (None, 'false') and linked is None:
            return None
        return {'name': name, 'value': value, 'type': self.kind, 'linkedId': linked}


class ItemEditor(QDialog):
    """A new item (no item_id) or a change to one. saved(Item) once bw has it."""

    saved = Signal(object)

    def __init__(self, controller, raw: dict, item_id: str = '', parent=None):
        super().__init__(parent)
        self.controller = controller
        self.item_id = item_id
        self.raw = json.loads(json.dumps(raw))             # a copy: nothing shown is changed until saved
        self.kind = self.raw.get('type') if self.raw.get('type') in items.KINDS else NOTE
        self._saving = False
        theme.frost(self)
        theme.restyle(self, self._style)
        self.setWindowTitle(('Edit ' if item_id else 'New ') + items.NAMES[self.kind].lower())
        self.setWindowIcon(icons.app_icon())
        self.setWindowModality(Qt.WindowModal)
        self.resize(600, 700)

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        page = QWidget()
        self.page = QVBoxLayout(page)
        self.page.setContentsMargins(24, 20, 24, 12)
        self.page.setSpacing(16)
        scroll.setWidget(page)
        outer.addWidget(scroll, 1)

        self._details()
        builder = {LOGIN: self._login, CARD: self._card, IDENTITY: self._identity, SSH_KEY: self._ssh_key}
        if self.kind in builder:
            builder[self.kind]()
        self._fields()
        self._notes_and_options()
        self.page.addStretch(1)

        foot = QHBoxLayout()
        foot.setContentsMargins(24, 10, 24, 16)
        self.message = QLabel()
        self.message.setProperty('role', 'error')
        self.message.setWordWrap(True)
        foot.addWidget(self.message, 1)
        self.save_button = QPushButton('Save')
        self.save_button.setProperty('role', 'primary')
        self.save_button.setDefault(True)
        self.save_button.setCursor(Qt.PointingHandCursor)
        self.save_button.clicked.connect(self._save)
        cancel = QPushButton('Cancel')
        cancel.setCursor(Qt.PointingHandCursor)
        cancel.clicked.connect(self.reject)
        foot.addWidget(cancel)
        foot.addWidget(self.save_button)
        outer.addLayout(foot)
        QShortcut(QKeySequence('Ctrl+S'), self, activated=self._save)
        self._original = self._collect()
        self.name.setFocus()

    def _style(self) -> str:
        return theme.card_style() + theme.panel_css('QFrame#sectionBox', 10) + """
            QScrollArea, QScrollArea > QWidget > QWidget { background: transparent; }
        """

    # ------------------------------------------------------------------ the parts

    def _details(self) -> None:
        part = _Section('Item details')
        self.name = part.row('Name', QLineEdit(_text(self.raw.get('name'))))
        self.folder = QComboBox()
        self.folder.addItem('No folder', '')
        for folder_id, name in sorted((self.controller.folders or {}).items(), key=lambda f: f[1].lower()):
            self.folder.addItem(name, folder_id)
        self.folder.setCurrentIndex(max(0, self.folder.findData(_text(self.raw.get('folderId')))))
        part.row('Folder', self.folder)
        organizations = getattr(self.controller, 'organizations', {}) or {}
        self.owner = None
        if organizations and not self.item_id:
            # Who owns a new item: you, or one of your organizations (in at least one of its collections).
            self.owner = QComboBox()
            self.owner.addItem('You', '')
            for org_id, name in organizations.items():
                self.owner.addItem(name, org_id)
            self.owner.setCurrentIndex(max(0, self.owner.findData(_text(self.raw.get('organizationId')))))
            part.row('Owner', self.owner)
            self.collections = QListWidget()
            self.collections.setFixedHeight(96)
            part.row('Collections', self.collections)
            self._owner_form = part.form
            self.owner.currentIndexChanged.connect(self._show_collections)
            self._show_collections()
        self.favorite = QCheckBox('Favourite')
        self.favorite.setChecked(bool(self.raw.get('favorite')))
        part.row('', self.favorite)
        self.page.addWidget(part)

    def _show_collections(self) -> None:
        org = self.owner.currentData()
        chosen = set(self.raw.get('collectionIds') or [])
        self.collections.clear()
        for collection in getattr(self.controller, 'collections', []) or []:
            if collection.get('organizationId') != org:
                continue
            entry = QListWidgetItem(_text(collection.get('name')))
            entry.setData(Qt.UserRole, collection.get('id'))
            entry.setFlags(entry.flags() | Qt.ItemIsUserCheckable)
            entry.setCheckState(Qt.Checked if collection.get('id') in chosen else Qt.Unchecked)
            self.collections.addItem(entry)
        self.collections.setVisible(bool(org))
        title = self._owner_form.labelForField(self.collections)
        if title is not None:
            title.setVisible(bool(org))

    def _login(self) -> None:
        login = self.raw.setdefault('login', {})
        part = _Section('Login credentials')
        user = QWidget()
        row = QHBoxLayout(user)
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(2)
        self.username = QLineEdit(_text(login.get('username')))
        row.addWidget(self.username, 1)
        row.addWidget(_tool('dice', 'Make up a username (as the generator is set)', self._new_username))
        part.row('Username', user)
        self.password = Secret(_text(login.get('password')))
        self.password.add(_tool('dice', 'Generate a password (as the generator is set)', self._new_password))
        part.row('Password', self.password)
        self.totp = Secret(_text(login.get('totp')), placeholder='The key a site shows to set up two-step login')
        part.row('Authenticator key', self.totp)
        keys = [key for key in login.get('fido2Credentials') or [] if isinstance(key, dict)]
        self._passkeys = keys
        if keys:
            who = keys[0].get('userName') or keys[0].get('userDisplayName') or 'a passkey'
            line = QWidget()
            passkey = QHBoxLayout(line)
            passkey.setContentsMargins(0, 0, 0, 0)
            label = QLabel(f'{who} on {keys[0].get("rpId") or "its site"}')
            passkey.addWidget(label, 1)
            remove = QPushButton('Remove')
            remove.setCursor(Qt.PointingHandCursor)

            def take_away():
                self._passkeys = []
                label.setText('Removed when you save')
                remove.setEnabled(False)
            remove.clicked.connect(take_away)
            passkey.addWidget(remove)
            part.row('Passkey', line)
        self.page.addWidget(part)

        sites = _Section('Websites and programs')
        self.uris = QVBoxLayout()
        self.uris.setSpacing(6)
        sites.add(self.uris)
        for entry in login.get('uris') or []:
            if isinstance(entry, dict):
                self._add_uri(_text(entry.get('uri')), entry.get('match'))
        add = QPushButton('Add website or program')
        add.setIcon(QIcon(icons.glyph('plus', theme.colors().text, 16, 1.8)))
        add.setCursor(Qt.PointingHandCursor)
        add.clicked.connect(lambda: self._add_uri('', None).uri.setFocus())
        sites.add(add)
        self.page.addWidget(sites)

    def _add_uri(self, uri: str, match) -> _UriRow:
        row = _UriRow(uri, match, self._remove_row)
        self.uris.addWidget(row)
        return row

    @staticmethod
    def _remove_row(row: QWidget) -> None:
        row.hide()
        row.setParent(None)
        row.deleteLater()

    def _card(self) -> None:
        card = self.raw.setdefault('card', {})
        part = _Section('Card details')
        self.card = {}
        self.card['cardholderName'] = part.row('Cardholder name', QLineEdit(_text(card.get('cardholderName'))))
        self.card['number'] = part.row('Number', Secret(_text(card.get('number'))))
        brand = QComboBox()
        brand.addItem('-- Choose --', '')
        for name in items.CARD_BRANDS:
            brand.addItem(name, name)
        brand.setCurrentIndex(max(0, brand.findData(_text(card.get('brand')))))
        self.card['brand'] = part.row('Brand', brand)

        def guess():
            if not brand.currentData():
                found = items.brand_of(self.card['number'].text())
                if found:
                    brand.setCurrentIndex(brand.findData(found))
        self.card['number'].edit.editingFinished.connect(guess)
        month = QComboBox()
        month.addItem('-- Month --', '')
        for n, name in enumerate(MONTHS, 1):
            month.addItem(f'{n:02d} - {name}', str(n))
        stored = _text(card.get('expMonth')).lstrip('0')
        month.setCurrentIndex(max(0, month.findData(stored)))
        self.card['expMonth'] = part.row('Expiry month', month)
        year = QLineEdit(_text(card.get('expYear')))
        year.setPlaceholderText('2030')
        year.setMaxLength(4)
        self.card['expYear'] = part.row('Expiry year', year)
        self.card['code'] = part.row('Security code', Secret(_text(card.get('code'))))
        self.page.addWidget(part)

    def _identity(self) -> None:
        identity = self.raw.setdefault('identity', {})
        self.identity = {}
        for title, parts in items.IDENTITY_PARTS:
            part = _Section(title)
            for key, label in parts:
                if key == 'title':
                    widget = QComboBox()
                    widget.addItem('-- Choose --', '')
                    for name in items.TITLES:
                        widget.addItem(name, name)
                    current = _text(identity.get('title'))
                    if current and widget.findData(current) < 0:
                        widget.addItem(current, current)
                    widget.setCurrentIndex(max(0, widget.findData(current)))
                elif key in items.SECRET_IDENTITY:
                    widget = Secret(_text(identity.get(key)), mono=False)
                else:
                    widget = QLineEdit(_text(identity.get(key)))
                self.identity[key] = part.row(label, widget)
            self.page.addWidget(part)

    def _ssh_key(self) -> None:
        key = self.raw.setdefault('sshKey', {})
        if not key.get('privateKey') and not self.item_id:
            key.update(sshkey.new_key())          # as Bitwarden does: a new SSH key item comes with a key
        part = _Section('SSH key')
        from .vault_window import _mono
        self.private_key = QPlainTextEdit(_text(key.get('privateKey')))
        self.private_key.setFont(_mono(9))
        self.private_key.setFixedHeight(120)
        self.private_key.setLineWrapMode(QPlainTextEdit.NoWrap)
        part.row('Private key', self.private_key)
        self.public_key = QLineEdit(_text(key.get('publicKey')))
        self.public_key.setFont(_mono(9))
        part.row('Public key', self.public_key)
        self.fingerprint = QLabel(_text(key.get('keyFingerprint')))
        self.fingerprint.setFont(_mono(9))
        self.fingerprint.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.fingerprint.setWordWrap(True)
        part.row('Fingerprint', self.fingerprint)
        self.public_key.textChanged.connect(lambda text: self.fingerprint.setText(sshkey.fingerprint(text)))
        again = QPushButton('Make a new key')
        again.setIcon(QIcon(icons.glyph('refresh', theme.colors().text, 16, 1.7)))
        again.setCursor(Qt.PointingHandCursor)
        again.setToolTip('An Ed25519 key, in place of this one. Paste one of your own above instead, if you like.')

        def renew():
            made = sshkey.new_key()
            self.private_key.setPlainText(made['privateKey'])
            self.public_key.setText(made['publicKey'])
        again.clicked.connect(renew)
        part.add(again)
        self.page.addWidget(part)

    def _fields(self) -> None:
        part = _Section('Custom fields')
        self.field_rows = QVBoxLayout()
        self.field_rows.setSpacing(6)
        part.add(self.field_rows)
        self._links = items.LINKS.get(self.kind, {})
        for field in self.raw.get('fields') or []:
            if isinstance(field, dict):
                self.field_rows.addWidget(_FieldRow(field, self._links, self._remove_row))
        add = QPushButton('Add field')
        add.setIcon(QIcon(icons.glyph('plus', theme.colors().text, 16, 1.8)))
        add.setCursor(Qt.PointingHandCursor)
        menu = QMenu(add)
        for kind, label in items.FIELD_KINDS.items():
            if kind == items.LINKED and not self._links:
                continue
            menu.addAction(label, lambda k=kind: self._add_field(k))
        add.setMenu(menu)
        part.add(add)
        self.page.addWidget(part)

    def _add_field(self, kind: int) -> None:
        row = _FieldRow({'type': kind}, self._links, self._remove_row)
        self.field_rows.addWidget(row)
        row.name.setFocus()

    def _notes_and_options(self) -> None:
        part = _Section('Additional options')
        self.notes = QPlainTextEdit(_text(self.raw.get('notes')))
        self.notes.setMinimumHeight(110 if self.kind == NOTE else 80)
        self.notes.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        part.row('Notes', self.notes)
        self.reprompt = QCheckBox('Ask for my master password before showing or typing it')
        self.reprompt.setChecked(self.raw.get('reprompt') == 1)
        part.row('', self.reprompt)
        self.page.addWidget(part)

    # ------------------------------------------------------------------ generating

    def _new_password(self) -> None:
        options = dict(self.controller.settings.generator)
        if generator.settled(options)['kind'] == 'username':
            options['kind'] = 'password'
        made = generator.generate(options)
        self.controller.remember_generated(made)
        self.password.set_text(made, show=True)

    def _new_username(self) -> None:
        options = dict(self.controller.settings.generator, kind='username')
        made = generator.generate(options)
        if not made:
            self.message.setText('Set up the username generator first: Tools, Generator, Username.')
            return
        self.controller.remember_generated(made)
        self.username.setText(made)

    # ------------------------------------------------------------------ saving

    def _rows(self, layout: QVBoxLayout) -> list[QWidget]:
        found = [layout.itemAt(n).widget() for n in range(layout.count())]
        return [row for row in found if row is not None and row.parent() is not None]

    def _collect(self) -> dict:
        item = json.loads(json.dumps(self.raw))
        item['name'] = self.name.text().strip()
        item['folderId'] = self.folder.currentData() or None
        item['favorite'] = self.favorite.isChecked()
        item['reprompt'] = 1 if self.reprompt.isChecked() else 0
        item['notes'] = _or_none(self.notes.toPlainText())
        item['fields'] = [f for f in (row.field() for row in self._rows(self.field_rows)) if f is not None]
        if self.owner is not None:
            org = self.owner.currentData()
            item['organizationId'] = org or None
            item['collectionIds'] = [self.collections.item(n).data(Qt.UserRole) for n in range(self.collections.count())
                                     if org and self.collections.item(n).checkState() == Qt.Checked]
        if self.kind == LOGIN:
            login = item.setdefault('login', {})
            login['username'] = _or_none(self.username.text())
            login['password'] = _or_none(self.password.text())
            login['totp'] = _or_none(self.totp.text().strip())
            login['uris'] = [u for u in (row.value() for row in self._rows(self.uris)) if u is not None]
            if login.get('fido2Credentials') or self._passkeys:
                login['fido2Credentials'] = self._passkeys
        elif self.kind == CARD:
            card = item.setdefault('card', {})
            for key, widget in self.card.items():
                value = widget.currentData() if isinstance(widget, QComboBox) else widget.text()
                card[key] = _or_none(value.strip() if key != 'code' else value)
        elif self.kind == IDENTITY:
            identity = item.setdefault('identity', {})
            for key, widget in self.identity.items():
                value = widget.currentData() if isinstance(widget, QComboBox) else widget.text()
                identity[key] = _or_none(value.strip())
        elif self.kind == SSH_KEY:
            key = item.setdefault('sshKey', {})
            key['privateKey'] = _or_none(self.private_key.toPlainText().strip() + '\n')
            key['publicKey'] = _or_none(self.public_key.text().strip())
            key['keyFingerprint'] = _or_none(sshkey.fingerprint(self.public_key.text()))
        return item

    def _problem(self, item: dict) -> str:
        if not item['name']:
            self.name.setFocus()
            return 'Give it a name.'
        if self.kind == SSH_KEY and not (item['sshKey'].get('privateKey') or '').strip():
            return 'An SSH key item needs its private key.'
        if item.get('organizationId') and not item.get('collectionIds'):
            return 'Choose at least one of the organization\'s collections.'
        if self.kind == CARD and item['card'].get('expYear') and not str(item['card']['expYear']).isdigit():
            return 'The expiry year is a number, such as 2030.'
        return ''

    def _save(self) -> None:
        if self._saving:
            return
        item = self._collect()
        problem = self._problem(item)
        if problem:
            self.message.setText(problem)
            return
        self._saving = True
        self.message.setText('')
        self.save_button.setEnabled(False)
        self.save_button.setText('Saving…')
        self.controller.save_item(item, self.item_id, self._saved)

    def _saved(self, saved, error) -> None:
        self._saving = False
        try:
            self.save_button.setEnabled(True)
            self.save_button.setText('Save')
        except RuntimeError:            # closed meanwhile (Keytap locked, say)
            return
        if error is not None:
            self.message.setText(f'Bitwarden did not save it: {error}')
            return
        self._original = self._collect()
        self.saved.emit(saved)
        self.accept()

    def reject(self) -> None:
        if self._saving:
            return
        if self._collect() != self._original and self.isVisible():
            answer = QMessageBox.question(self, 'Keytap', 'Throw away your changes?',
                                          QMessageBox.Discard | QMessageBox.Cancel, QMessageBox.Cancel)
            if answer != QMessageBox.Discard:
                return
        super().reject()

    def discard(self) -> None:
        """Closed without asking - Keytap is locking."""
        self._saving = False
        super().reject()
