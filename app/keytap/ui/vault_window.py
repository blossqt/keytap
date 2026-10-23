"""Keytap's own window: the vault, laid out the way Bitwarden's apps show it.

Opening Keytap - from Start, from Hanami, or by starting it a second time -
brings this up. On the left are filters (all logins, favourites, those with a
verification code, each folder); in the middle the logins, with a search box;
on the right the chosen login in full:

- the password and hidden custom fields stay hidden until shown, and a login
  that asks for the master password again shows nothing until it is given;
- each part has a button to copy it. Copies go through Keytap's clipboard,
  which keeps them out of Windows' clipboard history and clears them after 30
  seconds;
- the verification code counts down to the next one.

Keytap only reads the vault. Changes are made in Bitwarden, which "Edit in
Bitwarden" opens at that login. While the vault is locked the window shows
Bitwarden's lock screen instead, and locking - by hand, when idle, or with
Windows - clears every login off it at once.
"""

from __future__ import annotations

import math
from types import SimpleNamespace

from PySide6.QtCore import QByteArray, QEvent, QMimeData, QRect, QRectF, QSize, Qt, QTimer, QUrl, Signal
from PySide6.QtGui import (QColor, QDesktopServices, QFont, QFontMetrics, QIcon, QKeySequence, QPainter, QPixmap,
                           QShortcut, QTextDocument, QTextOption)
from PySide6.QtWidgets import (QFrame, QHBoxLayout, QLabel, QLineEdit, QListWidget, QListWidgetItem, QPushButton,
                               QScrollArea, QSizePolicy, QStackedWidget, QStyle, QStyledItemDelegate, QTextEdit,
                               QToolButton, QVBoxLayout, QWidget)

from .. import totp
from . import icons, theme

DOTS = '•' * 12           # the same length whatever the password's, which a screen would otherwise give away
ROW_HEIGHT = 52


def _label(text: str = '', size: float = 9.5, weight=QFont.Normal, role: str = '') -> QLabel:
    label = QLabel(text)
    label.setFont(theme.font(size, weight))
    if role:
        label.setProperty('role', role)
    return label


def private_mime(text: str) -> QMimeData:
    """Text for the clipboard that stays out of Windows' clipboard history and cloud clipboard."""
    mime = QMimeData()
    mime.setText(text)
    for name, value in (('ExcludeClipboardContentFromMonitorProcessing', b'\x01\x00\x00\x00'),
                        ('CanIncludeInClipboardHistory', b'\x00\x00\x00\x00'),
                        ('CanUploadToCloudClipboard', b'\x00\x00\x00\x00')):
        mime.setData(f'application/x-qt-windows-mime;value="{name}"', QByteArray(value))
    return mime


_BREAK = '\u200b'                       # zero-width space: somewhere a line may break
_BREAK_AFTER = str.maketrans({ch: ch + _BREAK for ch in './@_=&'})


def _mono(size: float) -> QFont:
    font = QFont('Cascadia Mono')
    if not font.exactMatch():
        font = QFont('Consolas')
    font.setPointSizeF(size)
    return font


class _Text(QTextEdit):
    """A login's text, selectable like a label's, that wraps anywhere: a long address or
    password carries on onto the next line rather than pushing the pane wider than the window.
    Lines may also break after the dots and slashes of addresses (Windows' own rules keep
    "instagram.com" in one piece), and what is copied from it is kept private."""

    def __init__(self, text: str = '', font: QFont | None = None, margins: tuple[int, ...] = (0, 0, 0, 0)):
        super().__init__()
        self._heights: dict[int, int] = {}      # its height at each width it has been asked about
        self.setObjectName('text')
        self.setReadOnly(True)
        self.setFrameShape(QFrame.NoFrame)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.setWordWrapMode(QTextOption.WrapAtWordBoundaryOrAnywhere)
        self.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.setFocusPolicy(Qt.ClickFocus)
        self.setTabChangesFocus(True)
        policy = QSizePolicy(QSizePolicy.Ignored, QSizePolicy.Preferred)
        policy.setHeightForWidth(True)          # its height follows its width, in the same layout pass
        self.setSizePolicy(policy)
        self.setViewportMargins(*margins)
        # A document of its own, held here: asking Qt for the one a QTextEdit makes can hand back
        # a stale Python wrapper for whatever object last lived at that address (seen: a QLocalSocket).
        self._document = QTextDocument(self)
        self.setDocument(self._document)
        self._document.setDocumentMargin(0)
        self.setFont(font or theme.font(10.5))
        self.setText(text)

    def setText(self, text: str) -> None:       # always plain: nothing in a vault is markup
        self.setPlainText(text.translate(_BREAK_AFTER))
        self._heights.clear()
        self.updateGeometry()

    def text(self) -> str:
        return self.toPlainText().replace(_BREAK, '')

    def createMimeDataFromSelection(self) -> QMimeData:
        selected = self.textCursor().selectedText().replace('\u2029', '\n').replace(_BREAK, '')
        return private_mime(selected)

    def hasHeightForWidth(self) -> bool:
        return True

    def heightForWidth(self, width: int) -> int:
        if width not in self._heights:
            margins = self.viewportMargins()
            layout = self._document.clone()     # laid out at that width without disturbing the one shown
            layout.setDefaultFont(self.font())
            layout.setTextWidth(max(1, width - margins.left() - margins.right()))
            height = math.ceil(layout.size().height()) + margins.top() + margins.bottom()
            self._heights[width] = max(height, QFontMetrics(self.font()).height())
        return self._heights[width]

    def changeEvent(self, event):
        if event.type() == QEvent.FontChange:
            self._heights.clear()
            self.updateGeometry()
        super().changeEvent(event)

    def minimumSizeHint(self) -> QSize:
        return QSize(0, QFontMetrics(self.font()).height())

    def sizeHint(self) -> QSize:
        width = max(self.width(), 1)
        return QSize(QFontMetrics(self.font()).horizontalAdvance(self.toPlainText()[:40]), self.heightForWidth(width))

    def wheelEvent(self, event):
        event.ignore()                          # the pane scrolls, not the text


def avatar(name: str, size: int, on_pink: bool = False) -> QPixmap:
    """A login's stand-in for a website icon: its initial in the suite's pink. Keytap fetches no
    icons, so no website learns what is in the vault. On a pink row it turns pale, to stand out."""
    ratio = 2.0
    pixmap = QPixmap(round(size * ratio), round(size * ratio))
    pixmap.setDevicePixelRatio(ratio)
    pixmap.fill(Qt.transparent)
    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.Antialiasing)
    painter.setPen(Qt.NoPen)
    painter.setBrush(QColor(255, 255, 255, 200) if on_pink else QColor(theme.ACCENT))
    painter.drawRoundedRect(QRectF(0, 0, size, size), size * 0.28, size * 0.28)
    painter.setPen(QColor(theme.ON_ACCENT))
    painter.setFont(theme.font(size * 0.36, QFont.DemiBold))
    initial = next((ch for ch in name if ch.isalnum()), '?').upper()
    painter.drawText(QRectF(0, 0, size, size), Qt.AlignCenter, initial)
    painter.end()
    return pixmap


def web_vault(server: str) -> str:
    """Where the web vault is, for the server bw is signed in to."""
    server = (server or '').strip().rstrip('/')
    if not server or 'bitwarden.com' in server:
        return 'https://vault.bitwarden.com'
    if 'bitwarden.eu' in server:
        return 'https://vault.bitwarden.eu'
    return server


def matches_search(login, words: list[str]) -> bool:
    haystack = ' '.join((login.name, login.username, *login.uris)).lower()
    return all(word in haystack for word in words)


def spaced(code: str) -> str:
    """'123 456' - easier to read off and type in by hand."""
    if code.isdigit() and len(code) in (6, 8):
        half = len(code) // 2
        return f'{code[:half]} {code[half:]}'
    return code


# --------------------------------------------------------------------------- the list

class _LoginDelegate(QStyledItemDelegate):
    def sizeHint(self, option, index):
        return QSize(option.rect.width(), ROW_HEIGHT)

    def paint(self, painter, option, index):
        login = index.data(Qt.UserRole)
        c = theme.colors()
        selected = bool(option.state & QStyle.State_Selected)
        hovered = bool(option.state & QStyle.State_MouseOver)
        rect = QRect(option.rect).adjusted(6, 2, -6, -2)
        painter.save()
        painter.setRenderHint(QPainter.Antialiasing)
        if selected or hovered:
            painter.setPen(Qt.NoPen)
            painter.setBrush(c.selected if selected else c.hover)
            painter.drawRoundedRect(rect, 9, 9)
        text, dim = (c.selected_text, c.selected_text) if selected else (c.text, c.dim)
        painter.drawPixmap(rect.left() + 10, rect.center().y() - 15, avatar(login.name, 30, on_pink=selected))
        right = rect.right() - 10
        for wanted, name in ((login.reprompt, 'lock'), (login.favorite, 'star')):
            if wanted:
                painter.drawPixmap(right - 14, rect.center().y() - 7, icons.glyph(name, dim, 14, 1.8))
                right -= 20
        left = rect.left() + 50
        width = max(20, right - left)
        painter.setFont(theme.font(9.75, QFont.DemiBold))
        painter.setPen(text)
        painter.drawText(QRect(left, rect.top() + 7, width, 19), Qt.AlignVCenter,
                         QFontMetrics(painter.font()).elidedText(login.name, Qt.ElideRight, width))
        painter.setFont(theme.font(8.5))
        painter.setPen(dim)
        detail = login.username or ('no username' if login.password else '')
        painter.drawText(QRect(left, rect.top() + 26, width, 17), Qt.AlignVCenter,
                         QFontMetrics(painter.font()).elidedText(detail, Qt.ElideRight, width))
        painter.restore()


# --------------------------------------------------------------------------- one login, in full

class _Field(QWidget):
    """One part of a login: what it is, its value, and buttons to show, copy or open it."""

    def __init__(self, label: str, value: str, *, secret: bool = False, mono: bool = False,
                 copy=None, open_url: str = '', tip: str = ''):
        super().__init__()
        self._value, self._secret, self._shown = value, secret, False
        row = QHBoxLayout(self)
        row.setContentsMargins(14, 8, 8, 8)
        row.setSpacing(4)
        text = QVBoxLayout()
        text.setSpacing(1)
        text.addWidget(_label(label, 8, role='dim'))
        self.value = _Text('', _mono(10.5) if mono else None)
        self.value.setToolTip(tip)
        text.addWidget(self.value)
        row.addLayout(text, 1)
        if secret:
            self.reveal = self._button('eye', 'Show')
            self.reveal.clicked.connect(lambda: self.toggle())
            row.addWidget(self.reveal)
        if open_url:
            launch = self._button('external', 'Open in your browser')
            launch.clicked.connect(lambda: QDesktopServices.openUrl(QUrl(open_url)))
            row.addWidget(launch)
        if copy is not None:
            button = self._button('copy', f'Copy the {label.lower()}')
            button.clicked.connect(lambda: copy())       # clicked's own argument never reaches copy
            row.addWidget(button)
        self._paint()

    @staticmethod
    def _button(glyph: str, tip: str) -> QToolButton:
        button = QToolButton()
        button.setIcon(QIcon(icons.glyph(glyph, theme.colors().text, 18, 1.7)))
        button.setIconSize(QSize(18, 18))
        button.setToolTip(tip)
        button.setCursor(Qt.PointingHandCursor)
        button.setFixedSize(32, 32)
        return button

    def set_value(self, value: str) -> None:
        self._value = value
        self._paint()

    def toggle(self) -> None:
        self._shown = not self._shown
        self.reveal.setIcon(QIcon(icons.glyph('eye_off' if self._shown else 'eye', theme.colors().text, 18, 1.7)))
        self.reveal.setToolTip('Hide' if self._shown else 'Show')
        self._paint()

    def _paint(self) -> None:
        if self._secret and not self._shown:
            self.value.setText(DOTS if self._value else '')
        else:
            self.value.setText(self._value)


class _Section(QFrame):
    """A rounded group of fields, as Bitwarden draws its item details."""

    def __init__(self, title: str):
        super().__init__()
        self.setObjectName('section')
        outer = QVBoxLayout()
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(6)
        outer.addWidget(_label(title.upper(), 7.75, QFont.DemiBold, role='dim'))
        self.box = QFrame()
        self.box.setObjectName('sectionBox')
        self.rows = QVBoxLayout(self.box)
        self.rows.setContentsMargins(0, 2, 0, 2)
        self.rows.setSpacing(0)
        outer.addWidget(self.box)
        self.setLayout(outer)

    def add(self, widget: QWidget) -> QWidget:
        if self.rows.count():
            line = QFrame()
            line.setObjectName('rule')
            line.setFixedHeight(1)
            self.rows.addWidget(line)
        self.rows.addWidget(widget)
        return widget


class Details(QScrollArea):
    """The chosen login, in full."""

    confirm = Signal(object)          # a login that asks for the master password first

    def __init__(self, owner):
        super().__init__()
        self.owner = owner            # the VaultWindow: copying, hotkeys, Bitwarden's address
        self.setWidgetResizable(True)
        self.setFrameShape(QFrame.NoFrame)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.login = None
        self.confirmed = ''           # the login, by id, whose master password was given while it is shown
        self._code = None
        self._clock = QTimer(self, interval=1000)
        self._clock.timeout.connect(self._tick)
        self.show_login(None)

    def clear(self) -> None:
        self.login, self.confirmed, self._code = None, '', None
        self._clock.stop()
        self._build(self._placeholder('Choose a login to see it here.'))

    def show_login(self, login, folder: str = '') -> None:
        if login is None:
            self.clear()
            return
        if self.login is None or login.id != self.login.id:
            self.confirmed = ''       # as Bitwarden does: asked again each time it is opened
        self.login, self._code = login, None
        self._clock.stop()
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(28, 24, 28, 24)
        layout.setSpacing(18)

        head = QHBoxLayout()
        head.setSpacing(14)
        picture = QLabel()
        picture.setPixmap(avatar(login.name, 48))
        head.addWidget(picture, 0, Qt.AlignTop)
        names = QVBoxLayout()
        names.setSpacing(2)
        names.addStretch(1)
        names.addWidget(_Text(login.name, theme.font(15, QFont.DemiBold)))
        where = ' · '.join(part for part in ('★ Favourite' if login.favorite else '', folder) if part)
        if where:
            folder_line = _label(where, 8.5, role='dim')
            folder_line.setWordWrap(True)
            names.addWidget(folder_line)
        names.addStretch(1)
        head.addLayout(names, 1)
        layout.addLayout(head)

        if login.reprompt and self.confirmed != login.id:
            layout.addWidget(self._asks(login))
            layout.addStretch(1)
            self._build(page)
            return

        copy = self.owner.copy
        part = _Section('Login')
        if login.username:
            part.add(_Field('Username', login.username, copy=lambda: copy(login.username, 'username')))
        if login.password:
            part.add(_Field('Password', login.password, secret=True, mono=True,
                            copy=lambda: copy(login.password, 'password')))
        if login.totp:
            self._code = part.add(_Field('Verification code', '', mono=True, copy=self._copy_code))
            self._tick()
            self._clock.start()
        if part.rows.count():
            layout.addWidget(part)

        if login.passkeys:
            keys = _Section('Passkey')
            for key in login.passkeys:
                keys.add(_Field('Passkey', f'{key.who} on {key.rp_id}',
                                tip='Sign in with it from the website or app: choose Keytap in Windows\' passkey window'))
            layout.addWidget(keys)

        if login.uris:
            sites = _Section('Websites and programs')
            for uri in login.uris:
                sites.add(self._uri_field(uri, copy))
            layout.addWidget(sites)

        if login.fields:
            extra = _Section('Custom fields')
            for name, value in login.fields:
                hidden = name in login.hidden
                extra.add(_Field(name or '(no name)', value, secret=hidden, mono=hidden,
                                 copy=lambda v=value, n=name: copy(v, n or 'field')))
            layout.addWidget(extra)

        if login.notes:
            notes = _Section('Notes')
            notes.add(_Text(login.notes, theme.font(9.5), margins=(14, 10, 14, 10)))
            layout.addWidget(notes)

        edit = QPushButton('Edit in Bitwarden')
        edit.setIcon(QIcon(icons.glyph('external', theme.colors().text, 16, 1.7)))
        edit.setCursor(Qt.PointingHandCursor)
        edit.setToolTip('Keytap only reads your vault - changes are made in Bitwarden')
        edit.clicked.connect(lambda: QDesktopServices.openUrl(QUrl(self.owner.edit_url(login))))
        layout.addWidget(edit, 0, Qt.AlignLeft)
        keys = self.owner.hotkeys()
        hint = _label(f'Press {keys.get("type", "")} in a program to type this login there.', 8.25, role='dim')
        hint.setWordWrap(True)
        layout.addWidget(hint)
        layout.addStretch(1)
        self._build(page)

    def _uri_field(self, uri: str, copy) -> _Field:
        lower = uri.lower()
        for scheme, label in (('app://', 'Program'), ('app:', 'Program'), ('title://', 'Window title'),
                              ('title:', 'Window title')):
            if lower.startswith(scheme):
                return _Field(label, uri[len(scheme):], copy=lambda: copy(uri, 'address'))
        if lower.endswith('.exe') and '://' not in lower:
            return _Field('Program', uri, copy=lambda: copy(uri, 'address'))
        if lower.startswith(('androidapp://', 'android://')):
            # androidapp://com.instagram.android, or as Chrome saves it, android://<app's key>@<app>
            app = uri.split('://', 1)[1].rsplit('@', 1)[-1].strip('/')
            return _Field('Android app', app, copy=lambda: copy(uri, 'address'), tip=uri)
        web = lower.startswith(('http://', 'https://')) or ('://' not in lower and '.' in lower)
        url = uri if '://' in lower else f'https://{uri}'
        return _Field('Website' if web else 'Address', uri, copy=lambda: copy(uri, 'address'),
                      open_url=url if web else '', tip=uri)

    def _asks(self, login) -> QWidget:
        box = QFrame()
        box.setObjectName('sectionBox')
        layout = QVBoxLayout(box)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(10)
        lock = QLabel()
        lock.setPixmap(icons.glyph('lock', theme.colors().text, 28, 1.6))
        layout.addWidget(lock, 0, Qt.AlignHCenter)
        note = _label('This login asks for your master password before it is shown.', 9.5)
        note.setWordWrap(True)
        note.setAlignment(Qt.AlignCenter)
        layout.addWidget(note)
        ask = QPushButton("Confirm it's you")
        ask.setProperty('role', 'primary')
        ask.setCursor(Qt.PointingHandCursor)
        ask.clicked.connect(lambda: self.confirm.emit(login))
        layout.addWidget(ask, 0, Qt.AlignHCenter)
        return box

    def _copy_code(self) -> None:
        try:
            self.owner.copy(totp.code(self.login.totp), 'verification code')
        except totp.TotpError as error:
            self.owner.problem('No code to copy', str(error))

    def _tick(self) -> None:
        if self._code is None or self.login is None:
            self._clock.stop()
            return
        try:
            left = totp.seconds_left(self.login.totp)
            self._code.set_value(f'{spaced(totp.code(self.login.totp))}   ·  {left}s')
        except totp.TotpError as error:
            self._code.set_value(f'(the key is unusable: {error})')
            self._clock.stop()

    @staticmethod
    def _placeholder(words: str) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.addStretch(1)
        icon = QLabel()
        icon.setPixmap(icons.glyph('key', theme.colors().dim, 40, 1.4))
        layout.addWidget(icon, 0, Qt.AlignHCenter)
        layout.addWidget(_label(words, 9.5, role='dim'), 0, Qt.AlignHCenter)
        layout.addStretch(2)
        return page

    def _build(self, page: QWidget) -> None:
        old = self.takeWidget()
        if old is not None:
            old.deleteLater()      # its labels held the last login's details
        self.setWidget(page)


# --------------------------------------------------------------------------- locked, signed out

class _LockPage(QWidget):
    """Bitwarden's lock screen. Also what the controller's unlocking reports to (busy, fail, finish)."""

    submitted = Signal(str)
    hello = Signal()              # unlock with Windows Hello instead
    quiet = True                  # unlocking here needs no "Keytap is unlocked" toast

    def __init__(self):
        super().__init__()
        self.succeeded = False
        outer = QVBoxLayout(self)
        outer.addStretch(2)
        column = QVBoxLayout()
        column.setSpacing(10)
        icon = QLabel()
        icon.setPixmap(icons.render_app_icon(64))
        column.addWidget(icon, 0, Qt.AlignHCenter)
        column.addSpacing(6)
        column.addWidget(_label('Your vault is locked', 15, QFont.DemiBold), 0, Qt.AlignHCenter)
        self.who = _label('', 9.5, role='dim')
        column.addWidget(self.who, 0, Qt.AlignHCenter)
        column.addSpacing(8)
        self.password = QLineEdit()
        self.password.setEchoMode(QLineEdit.Password)
        self.password.setPlaceholderText('Master password')
        self.password.setFixedWidth(320)
        self.password.returnPressed.connect(self._submit)
        column.addWidget(self.password, 0, Qt.AlignHCenter)
        self.message = _label('', 9, role='error')
        self.message.setWordWrap(True)
        self.message.setAlignment(Qt.AlignCenter)
        self.message.setFixedWidth(320)
        self.message.hide()
        column.addWidget(self.message, 0, Qt.AlignHCenter)
        self.button = QPushButton('Unlock')
        self.button.setProperty('role', 'primary')
        self.button.setFixedWidth(320)
        self.button.setCursor(Qt.PointingHandCursor)
        self.button.clicked.connect(self._submit)
        column.addWidget(self.button, 0, Qt.AlignHCenter)
        self.hello_button = QPushButton('Unlock with Windows Hello')
        self.hello_button.setFixedWidth(320)
        self.hello_button.setCursor(Qt.PointingHandCursor)
        self.hello_button.setToolTip('Your fingerprint, face or PIN')
        self.hello_button.clicked.connect(self.hello.emit)
        self.hello_button.hide()
        column.addWidget(self.hello_button, 0, Qt.AlignHCenter)
        outer.addLayout(column)
        outer.addStretch(3)

    def reset(self, email: str, hello: bool = False) -> None:
        self.succeeded = False
        self.who.setText(f'Signed in as {email}' if email else '')
        self.password.clear()
        self.password.setEnabled(True)
        self.button.setEnabled(True)
        self.button.setText('Unlock')
        self.hello_button.setEnabled(True)
        self.hello_button.setVisible(hello)
        self.message.hide()

    def _submit(self) -> None:
        if self.password.text() and self.button.isEnabled():
            self.submitted.emit(self.password.text())

    def busy(self, text: str) -> None:
        self.password.setEnabled(False)
        self.button.setEnabled(False)
        self.hello_button.setEnabled(False)
        self.button.setText(text)
        self.message.hide()

    def wait_for_hello(self) -> None:
        self.busy('Waiting for Windows Hello…')

    def fail(self, message: str) -> None:
        self.password.setEnabled(True)
        self.button.setEnabled(True)
        self.hello_button.setEnabled(True)
        self.button.setText('Unlock')
        self.message.setText(message)
        self.message.setVisible(bool(message))
        self.password.selectAll()
        self.password.setFocus()

    def finish(self) -> None:
        self.succeeded = True
        self.password.clear()

    def close(self) -> bool:      # the controller closes a card it gives up on; here, just start over
        self.fail('')
        self.message.hide()
        return True


class _NoticePage(QWidget):
    def __init__(self):
        super().__init__()
        outer = QVBoxLayout(self)
        outer.addStretch(2)
        icon = QLabel()
        icon.setPixmap(icons.render_app_icon(64))
        outer.addWidget(icon, 0, Qt.AlignHCenter)
        outer.addSpacing(8)
        self.title = _label('', 15, QFont.DemiBold)
        outer.addWidget(self.title, 0, Qt.AlignHCenter)
        self.text = _label('', 9.5, role='dim')
        self.text.setWordWrap(True)
        self.text.setAlignment(Qt.AlignCenter)
        self.text.setFixedWidth(380)
        outer.addWidget(self.text, 0, Qt.AlignHCenter)
        outer.addSpacing(8)
        self.button = QPushButton()
        self.button.setProperty('role', 'primary')
        self.button.setCursor(Qt.PointingHandCursor)
        outer.addWidget(self.button, 0, Qt.AlignHCenter)
        outer.addStretch(3)
        self._action = None
        self.button.clicked.connect(lambda: self._action and self._action())

    def say(self, title: str, text: str, button: str = '', action=None) -> None:
        self.title.setText(title)
        self.text.setText(text)
        self.button.setText(button)
        self.button.setVisible(bool(button))
        self._action = action


# --------------------------------------------------------------------------- the window

class VaultWindow(QWidget):
    def __init__(self, controller):
        super().__init__()
        self.controller = controller
        self.setWindowTitle('Keytap')
        self.setWindowIcon(icons.app_icon())
        self.setObjectName('vault')
        theme.frost(self)
        self.resize(1000, 640)
        self.setMinimumSize(740, 480)
        self._apply_style()
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)
        outer.addWidget(self._header())
        self.pages = QStackedWidget()
        outer.addWidget(self.pages, 1)

        self.lock_page = _LockPage()
        self.lock_page.submitted.connect(lambda password: controller.unlock_in(self.lock_page, password))
        self.lock_page.hello.connect(lambda: controller.unlock_in(self.lock_page, None))     # None: Windows Hello
        self.notice = _NoticePage()
        self.vault_page = self._vault_page()
        for page in (self.vault_page, self.lock_page, self.notice):
            self.pages.addWidget(page)

        for keys, action in (('Ctrl+F', self._focus_search), ('Ctrl+U', lambda: self._copy_part('username')),
                             ('Ctrl+P', lambda: self._copy_part('password')),
                             ('Ctrl+T', lambda: self._copy_part('totp')), ('Ctrl+L', lambda: controller.lock()),
                             ('Ctrl+R', lambda: controller.sync())):
            QShortcut(QKeySequence(keys), self).activated.connect(action)
        self.refresh()

    # ------------------------------------------------------------------ building

    def _apply_style(self) -> None:
        c = theme.colors()
        border = c.border.name(QColor.HexArgb)
        self.setStyleSheet(theme.card_style() + f"""
            QWidget#vault {{ background: {theme.css(c.card)}; }}
            QWidget#header {{ background: {theme.css(c.card)}; border-bottom: 1px solid {border}; }}
            QWidget#sidebar {{ background: {theme.css(c.tile)}; border-right: 1px solid {border}; }}
            QWidget#listPane {{ border-right: 1px solid {border}; }}
            QScrollArea, QScrollArea > QWidget > QWidget {{ background: transparent; }}
            QFrame#sectionBox {{ background: {theme.css(c.tile)}; border: 1px solid {border}; border-radius: 10px; }}
            QFrame#rule {{ background: {border}; border: none; margin: 0 12px; }}
            QListWidget#filters {{ background: transparent; border: none; outline: none; }}
            QListWidget#filters::item {{ color: {c.text.name()}; padding: 7px 8px; border-radius: 8px; }}
            QListWidget#filters::item:selected {{ background: {c.selected.name()}; color: {c.selected_text.name()}; }}
            QListWidget#filters::item:hover:!selected {{ background: {theme.css(c.hover)}; }}
            QListWidget#logins {{ background: transparent; border: none; outline: none; }}
            QTextEdit#text {{ color: {c.text.name()}; background: transparent; border: none;
                              selection-background-color: {theme.ACCENT}; selection-color: {theme.ON_ACCENT}; }}
        """)

    def _header(self) -> QWidget:
        bar = QWidget()
        bar.setObjectName('header')
        bar.setAttribute(Qt.WA_StyledBackground)
        row = QHBoxLayout(bar)
        row.setContentsMargins(18, 10, 12, 10)
        row.setSpacing(10)
        logo = QLabel()
        logo.setPixmap(icons.render_app_icon(30))
        row.addWidget(logo)
        names = QVBoxLayout()
        names.setSpacing(0)
        names.addWidget(_label('Keytap', 12.5, QFont.DemiBold))
        self.account = _label('', 8.25, role='dim')
        names.addWidget(self.account)
        row.addLayout(names, 1)
        self.sync_button = self._tool('refresh', 'Sync now (Ctrl+R)', lambda: self.controller.sync())
        self.lock_button = self._tool('lock', 'Lock (Ctrl+L)', lambda: self.controller.lock())
        settings = self._tool('sliders', 'Settings', lambda: self.controller.show_settings())
        for button in (self.sync_button, self.lock_button, settings):
            row.addWidget(button)
        return bar

    @staticmethod
    def _tool(glyph: str, tip: str, action) -> QToolButton:
        button = QToolButton()
        button.setIcon(QIcon(icons.glyph(glyph, theme.colors().text, 18, 1.7)))
        button.setIconSize(QSize(18, 18))
        button.setFixedSize(34, 34)
        button.setToolTip(tip)
        button.setCursor(Qt.PointingHandCursor)
        button.clicked.connect(action)
        return button

    def _vault_page(self) -> QWidget:
        page = QWidget()
        row = QHBoxLayout(page)
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(0)

        self.sidebar = side = QWidget()
        side.setObjectName('sidebar')
        side.setAttribute(Qt.WA_StyledBackground)
        column = QVBoxLayout(side)
        column.setContentsMargins(10, 14, 10, 10)
        self.filters = QListWidget()
        self.filters.setObjectName('filters')
        self.filters.setIconSize(QSize(16, 16))
        self.filters.setFont(theme.font(9.25))
        self.filters.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)     # a long folder name is cut short
        self.filters.currentRowChanged.connect(lambda _: self._fill_list())
        column.addWidget(self.filters)
        row.addWidget(side)

        self.middle = middle = QWidget()
        middle.setObjectName('listPane')
        middle.setAttribute(Qt.WA_StyledBackground)
        column = QVBoxLayout(middle)
        column.setContentsMargins(10, 12, 10, 6)
        column.setSpacing(8)
        self.search = QLineEdit()
        self.search.setPlaceholderText('Search your vault')
        self.search.setClearButtonEnabled(True)
        self.search.addAction(QIcon(icons.glyph('search', theme.colors().dim, 16, 1.8)), QLineEdit.LeadingPosition)
        self.search.textChanged.connect(lambda _: self._fill_list())
        self.search.installEventFilter(self)
        column.addWidget(self.search)
        self.list = QListWidget()
        self.list.setObjectName('logins')
        self.list.setItemDelegate(_LoginDelegate(self.list))
        self.list.setMouseTracking(True)
        self.list.setUniformItemSizes(True)
        self.list.setVerticalScrollMode(QListWidget.ScrollPerPixel)
        self.list.currentItemChanged.connect(lambda *_: self._show_current())
        column.addWidget(self.list, 1)
        self.count = _label('', 8, role='dim')
        column.addWidget(self.count)
        row.addWidget(middle)

        self.details = Details(self)
        self.details.confirm.connect(self._confirm)
        row.addWidget(self.details, 1)
        self._fit_panes()
        return page

    def _fit_panes(self) -> None:
        """In a narrower window the filters and the list narrow too, so the login keeps room."""
        width = self.width()
        self.sidebar.setFixedWidth(round(min(210, max(180, width * 0.2))))
        self.middle.setFixedWidth(round(min(330, max(250, width * 0.32))))

    def resizeEvent(self, event):
        self._fit_panes()
        super().resizeEvent(event)

    # ------------------------------------------------------------------ keeping up with the vault

    def refresh(self) -> None:
        """Show what the controller knows now: the vault, the lock screen, or why neither."""
        controller = self.controller
        state = controller.status.state
        self.account.setText(controller.status.email or 'Bitwarden auto-type')
        self.sync_button.setEnabled(controller.unlocked)
        self.lock_button.setEnabled(controller.unlocked)
        if controller.unlocked:
            if self.pages.currentWidget() is not self.vault_page:
                self.pages.setCurrentWidget(self.vault_page)
                self.search.setFocus()
            self._fill_filters()
            self._fill_list()
            return
        self._forget()
        if state == 'locked':
            if self.pages.currentWidget() is not self.lock_page:
                self.lock_page.reset(controller.status.email, hello=controller.hello_on())
                self.pages.setCurrentWidget(self.lock_page)
            self.lock_page.password.setFocus()
        elif state == 'unauthenticated':
            self.notice.say('Sign in to Bitwarden', 'Keytap reads your vault through Bitwarden\'s own '
                            'command-line tool, signed in on this PC.', 'Sign in…', controller.show_sign_in)
            self.pages.setCurrentWidget(self.notice)
        elif state == 'missing':
            self.notice.say("Bitwarden's tool is missing", 'Keytap comes with it - reinstall Keytap.')
            self.pages.setCurrentWidget(self.notice)
        else:
            self.notice.say('Starting…', 'Asking Bitwarden how your vault is.')
            self.pages.setCurrentWidget(self.notice)

    def _forget(self) -> None:
        """Locked: nothing of the vault may stay on screen, or in the widgets behind it."""
        self.filters.blockSignals(True)
        self.filters.clear()          # folder names and counts say something about the vault too
        self.filters.blockSignals(False)
        self.list.clear()
        self.details.clear()
        self.search.clear()

    def _fill_filters(self) -> None:
        logins = self.controller.logins or []
        chosen = self._filter()
        folders = getattr(self.controller, 'folders', {}) or {}
        used = {login.folder_id for login in logins if login.folder_id}
        entries = [(('all', ''), 'grid', 'All logins', len(logins)),
                   (('favorites', ''), 'star_line', 'Favourites', sum(login.favorite for login in logins)),
                   (('codes', ''), 'clock', 'Verification codes', sum(bool(login.totp) for login in logins))]
        for folder_id, name in sorted(folders.items(), key=lambda item: item[1].lower()):
            if folder_id in used:
                entries.append((('folder', folder_id), 'folder', name,
                                sum(login.folder_id == folder_id for login in logins)))
        if used and any(not login.folder_id for login in logins):
            entries.append((('folder', ''), 'folder', 'No folder', sum(not login.folder_id for login in logins)))
        self.filters.blockSignals(True)
        self.filters.clear()
        dim = theme.colors().dim
        for key, glyph, name, count in entries:
            if key[0] == 'folder' and self.filters.count() == 3:
                heading = QListWidgetItem('FOLDERS')
                heading.setFlags(Qt.NoItemFlags)
                heading.setFont(theme.font(7.75, QFont.DemiBold))
                heading.setForeground(dim)
                self.filters.addItem(heading)
            item = QListWidgetItem(QIcon(icons.glyph(glyph, dim, 16, 1.8)), f'{name}   {count}')
            item.setData(Qt.UserRole, key)
            self.filters.addItem(item)
        rows = [tuple(self.filters.item(i).data(Qt.UserRole) or ()) for i in range(self.filters.count())]
        self.filters.setCurrentRow(rows.index(chosen) if chosen in rows else 0)
        self.filters.blockSignals(False)

    def _filter(self) -> tuple:
        item = self.filters.currentItem()
        key = item.data(Qt.UserRole) if item is not None else None
        return tuple(key) if key else ('all', '')

    def _fill_list(self) -> None:
        logins = self.controller.logins or []
        kind, folder = self._filter()
        keep = {'all': lambda login: True, 'favorites': lambda login: login.favorite,
                'codes': lambda login: bool(login.totp),
                'folder': lambda login: login.folder_id == folder}.get(kind, lambda login: True)
        words = self.search.text().lower().split()
        shown = sorted((login for login in logins if keep(login) and matches_search(login, words)),
                       key=lambda login: (login.name.lower(), login.username.lower()))
        current = self.details.login.id if self.details.login is not None else ''
        self.list.blockSignals(True)
        self.list.clear()
        chosen = None
        for login in shown:
            item = QListWidgetItem()
            item.setData(Qt.UserRole, login)
            self.list.addItem(item)
            if login.id == current:
                chosen = item
        if chosen is None and self.list.count():
            chosen = self.list.item(0)
        self.list.setCurrentItem(chosen)
        self.list.blockSignals(False)
        total = len(logins)
        self.count.setText(f'{len(shown)} of {total} logins' if len(shown) != total else f'{total} logins')
        self._show_current()

    def _show_current(self) -> None:
        item = self.list.currentItem()
        login = item.data(Qt.UserRole) if item is not None else None
        folders = getattr(self.controller, 'folders', {}) or {}
        self.details.show_login(login, folders.get(login.folder_id, '') if login else '')

    # ------------------------------------------------------------------ acting

    def copy(self, value: str, label: str) -> None:
        self.controller.copy(value, label)

    def problem(self, title: str, text: str) -> None:
        self.controller.toasts.show(title, text, error=True)

    def hotkeys(self) -> dict:
        return self.controller.settings.hotkeys

    def edit_url(self, login) -> str:
        return f'{web_vault(self.controller.status.server)}/#/vault?itemId={login.id}'

    def _confirm(self, login) -> None:
        def shown():
            self.details.confirmed = login.id
            if self.details.login is not None and self.details.login.id == login.id:
                self.details.show_login(login, (getattr(self.controller, 'folders', {}) or {}).get(login.folder_id, ''))
        self.controller.confirm(login, shown, int(self.winId()))

    def _copy_part(self, part: str) -> None:
        login = self.details.login
        if login is None or self.pages.currentWidget() is not self.vault_page:
            return
        if login.reprompt and self.details.confirmed != login.id:
            self._confirm(login)
            return
        if part == 'username' and login.username:
            self.copy(login.username, 'username')
        elif part == 'password' and login.password:
            self.copy(login.password, 'password')
        elif part == 'totp' and login.totp:
            self.details._copy_code()

    def _focus_search(self) -> None:
        if self.pages.currentWidget() is self.vault_page:
            self.search.setFocus()
            self.search.selectAll()

    def eventFilter(self, watched, event):
        # Up and down from the search box move through the list, as in Bitwarden.
        if watched is self.search and event.type() == QEvent.KeyPress and \
                event.key() in (Qt.Key_Up, Qt.Key_Down) and self.list.count():
            step = -1 if event.key() == Qt.Key_Up else 1
            row = max(0, min(self.list.count() - 1, self.list.currentRow() + step))
            self.list.setCurrentRow(row)
            return True
        return super().eventFilter(watched, event)

    def closeEvent(self, event):
        self._forget()            # nothing of the vault stays in a closed window
        super().closeEvent(event)


def sample_controller(logins, folders=None):
    """A stand-in controller, for the build's self-test and for drawing the window in tests."""
    status = SimpleNamespace(state='unlocked', email='someone@example.com', server='')
    noop = lambda *a, **k: None   # noqa: E731
    return SimpleNamespace(status=status, unlocked=True, logins=logins, folders=folders or {},
                           settings=SimpleNamespace(hotkeys={'type': 'Ctrl+Alt+A', 'pick': 'Ctrl+Alt+Shift+A'}),
                           copy=noop, lock=noop, sync=noop, show_settings=noop, show_sign_in=noop,
                           unlock_in=noop, confirm=noop, toasts=SimpleNamespace(show=noop),
                           hello_on=lambda: False)
