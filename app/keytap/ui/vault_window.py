"""Keytap's own window: the vault, laid out the way Bitwarden's apps show it.

Opening Keytap - from Start, from Hanami, or by starting it a second time -
brings this up. On the left are filters (everything, favourites, those with a
verification code, each kind of item, each folder and collection, the archive
and the trash); in the middle the items, with a search box; on the right the
chosen item in full:

- passwords, card numbers and hidden custom fields stay hidden until shown,
  and an item that asks for the master password again shows nothing until it
  is given;
- each part has a button to copy it. Copies go through Keytap's clipboard,
  which keeps them out of Windows' clipboard history and clears them after 30
  seconds;
- the verification code counts down to the next one.

Everything Bitwarden's own apps do to an item is here too: New makes any kind,
Edit opens it in the editor (ui/editor.py), and its buttons favourite, clone,
archive, move to an organization, attach files to or delete it. Tools holds the
generator, Send, the vault's health report, and export and import. While the
vault is locked the window shows Bitwarden's lock screen instead, and locking -
by hand, when idle, or with Windows - clears every item off it at once.
"""

from __future__ import annotations

import math
from types import SimpleNamespace

from PySide6.QtCore import (QAbstractListModel, QByteArray, QEvent, QMimeData, QModelIndex, QRect, QRectF, QSize, Qt,
                            QTimer, QUrl, Signal)
from PySide6.QtGui import (QColor, QDesktopServices, QFont, QFontMetrics, QIcon, QKeySequence, QPainter, QPixmap,
                           QShortcut, QTextDocument, QTextOption)
from PySide6.QtWidgets import (QAbstractItemView, QComboBox, QDialog, QDialogButtonBox, QFileDialog, QFrame, QHBoxLayout, QInputDialog, QLabel, QLineEdit,
                               QListView, QListWidget, QListWidgetItem, QMenu, QMessageBox, QPushButton,
                               QScrollArea, QSizePolicy, QStackedWidget, QStyle, QStyledItemDelegate, QTextEdit,
                               QToolButton, QVBoxLayout, QWidget)

from .. import items as kinds
from .. import totp
from ..items import CARD, IDENTITY, LOGIN, NOTE, SSH_KEY, Item
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


def avatar(name: str, size: int, on_pink: bool = False, kind: int = LOGIN, quiet: bool = False) -> QPixmap:
    """An item's stand-in for a website icon: a login's initial, or its kind's drawing, in the suite's
    pink. Keytap fetches no icons, so no website learns what is in the vault. On a pink row it turns
    pale, to stand out; quiet, in a list row not chosen, it is grey, so the chosen row is the pink one."""
    ratio = 2.0
    pixmap = QPixmap(round(size * ratio), round(size * ratio))
    pixmap.setDevicePixelRatio(ratio)
    pixmap.fill(Qt.transparent)
    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.Antialiasing)
    painter.setPen(Qt.NoPen)
    c = theme.colors()
    painter.setBrush(QColor(255, 255, 255, 200) if on_pink else c.chip if quiet else QColor(theme.ACCENT))
    ink = c.dim if quiet and not on_pink else QColor(theme.ON_ACCENT)
    painter.drawRoundedRect(QRectF(0, 0, size, size), size * 0.28, size * 0.28)
    if kind != LOGIN:
        inner = round(size * 0.56)
        offset = (size - inner) / 2
        painter.drawPixmap(QRectF(offset, offset, inner, inner).toRect(),
                           icons.glyph(kinds.GLYPHS[kind], ink, inner, 1.9))
        painter.end()
        return pixmap
    painter.setPen(ink)
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


def spaced(code: str) -> str:
    """'123 456' - easier to read off and type in by hand."""
    if code.isdigit() and len(code) in (6, 8):
        half = len(code) // 2
        return f'{code[:half]} {code[half:]}'
    return code


# --------------------------------------------------------------------------- the list

class _Items(QAbstractListModel):
    """The items listed: a list of Python's own, the view asking only for the rows in sight. A
    QListWidget's items each held a login, and as it was filled or cleared each took Python's lock
    back: with another thread busy then (as after an unlock or a sync), 3,000 logins froze Keytap
    for seconds (until 2026-10-26)."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.items: list = []

    def rowCount(self, parent=QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self.items)

    def data(self, index, role=Qt.DisplayRole):
        if not index.isValid() or not 0 <= index.row() < len(self.items):
            return None
        item = self.items[index.row()]
        if role == Qt.UserRole:
            return item
        if role == Qt.AccessibleTextRole:
            return f'{item.name} {item.subtitle}'.strip()
        return None

    def show(self, shown: list) -> None:
        self.beginResetModel()
        self.items = list(shown)
        self.endResetModel()


class _Row:
    """A row of the list, as a QListWidgetItem would give it."""

    def __init__(self, item):
        self.item = item

    def data(self, role):
        return self.item if role == Qt.UserRole else None


class _ItemList(QListView):
    """The list of items (_Items), answering as a QListWidget would: count, item, the current row."""
    currentItemChanged = Signal()

    def __init__(self):
        super().__init__()
        self.model_ = _Items(self)
        self.setModel(self.model_)
        self.selectionModel().currentChanged.connect(lambda *_: self.currentItemChanged.emit())

    def show_items(self, shown: list, current_id: str = '') -> None:
        """These items, the one with current_id (else the first) chosen."""
        self.model_.show(shown)
        row = next((i for i, item in enumerate(shown) if item.id == current_id), 0 if shown else -1)
        self.setCurrentRow(row)

    def clear(self) -> None:
        self.model_.show([])

    def count(self) -> int:
        return len(self.model_.items)

    def item(self, row: int) -> _Row | None:
        return _Row(self.model_.items[row]) if 0 <= row < self.count() else None

    def currentRow(self) -> int:
        index = self.currentIndex()
        return index.row() if index.isValid() else -1

    def currentItem(self) -> _Row | None:
        return self.item(self.currentRow())

    def setCurrentRow(self, row: int) -> None:
        self.setCurrentIndex(self.model_.index(row, 0) if 0 <= row < self.count() else QModelIndex())


class _ItemDelegate(QStyledItemDelegate):
    def sizeHint(self, option, index):
        return QSize(option.rect.width(), ROW_HEIGHT)

    def paint(self, painter, option, index):
        item = index.data(Qt.UserRole)
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
        painter.drawPixmap(rect.left() + 10, rect.center().y() - 15, avatar(item.name, 30, selected, item.type, quiet=True))
        right = rect.right() - 10
        for wanted, name in ((item.reprompt, 'lock'), (item.favorite, 'star'), (bool(item.attachments), 'clip')):
            if wanted:
                painter.drawPixmap(right - 14, rect.center().y() - 7, icons.glyph(name, dim, 14, 1.8))
                right -= 20
        left = rect.left() + 50
        width = max(20, right - left)
        painter.setFont(theme.font(9.75, QFont.DemiBold))
        painter.setPen(text)
        painter.drawText(QRect(left, rect.top() + 7, width, 19), Qt.AlignVCenter,
                         QFontMetrics(painter.font()).elidedText(item.name, Qt.ElideRight, width))
        painter.setFont(theme.font(8.5))
        painter.setPen(dim)
        detail = item.subtitle
        if not detail and item.type == LOGIN and item.login is not None and item.login.password:
            detail = 'no username'
        painter.drawText(QRect(left, rect.top() + 26, width, 17), Qt.AlignVCenter,
                         QFontMetrics(painter.font()).elidedText(detail, Qt.ElideRight, width))
        painter.restore()

# --------------------------------------------------------------------------- one item, in full

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
        outer.addWidget(_label(title, 8.5, QFont.DemiBold, role='dim'))
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
    """The chosen item, in full, with what can be done to it."""

    confirm = Signal(object)          # an item that asks for the master password first

    def __init__(self, owner):
        super().__init__()
        self.owner = owner            # the VaultWindow: copying, acting on items, hotkeys
        self.setWidgetResizable(True)
        self.setFrameShape(QFrame.NoFrame)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.item = None
        self.confirmed = ''           # the item, by id, whose master password was given while it is shown
        self._code = None
        self._clock = QTimer(self, interval=1000)
        self._clock.timeout.connect(self._tick)
        self.show_item(None)

    @property
    def login(self):
        """The login shown, if what is shown is one."""
        return self.item.login if self.item is not None else None

    def clear(self) -> None:
        self.item, self.confirmed, self._code = None, '', None
        self._clock.stop()
        self._build(self._placeholder('Choose an item to see it here.'))

    def show_item(self, item, folder: str = '', owner: str = '') -> None:
        if item is None:
            self.clear()
            return
        if self.item is None or item.id != self.item.id:
            self.confirmed = ''       # as Bitwarden does: asked again each time it is opened
        self.item, self._code = item, None
        self._clock.stop()
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(28, 24, 28, 24)
        layout.setSpacing(18)

        head = QHBoxLayout()
        head.setSpacing(14)
        picture = QLabel()
        picture.setPixmap(avatar(item.name, 48, kind=item.type))
        head.addWidget(picture, 0, Qt.AlignTop)
        names = QVBoxLayout()
        names.setSpacing(2)
        names.addStretch(1)
        names.addWidget(_Text(item.name, theme.font(15, QFont.DemiBold)))
        state = 'In the trash' if item.deleted else 'Archived' if item.archived else ''
        where = ' · '.join(part for part in (state, '★ Favourite' if item.favorite else '', folder, owner) if part)
        if where:
            folder_line = _label(where, 8.5, role='dim')
            folder_line.setWordWrap(True)
            names.addWidget(folder_line)
        names.addStretch(1)
        head.addLayout(names, 1)
        layout.addLayout(head)
        if not item.partial:
            layout.addLayout(self._actions(item))

        if item.reprompt and self.confirmed != item.id:
            layout.addWidget(self._asks(item))
            layout.addStretch(1)
            self._build(page)
            return

        copy = self.owner.copy
        build = {LOGIN: self._login, CARD: self._card, IDENTITY: self._identity, SSH_KEY: self._ssh_key}
        if item.type in build:
            for section in build[item.type](item, copy):
                layout.addWidget(section)
        for section in (self._fields(item, copy), self._notes(item), self._attachments(item),
                        self._history(item, copy), self._dates(item)):
            if section is not None:
                layout.addWidget(section)

        if item.type == LOGIN and not item.deleted and not item.archived:
            keys = self.owner.hotkeys()
            hint = _label(f'Press {keys.get("type", "")} in a program to type this login there.', 8.25, role='dim')
            hint.setWordWrap(True)
            layout.addWidget(hint)
        layout.addStretch(1)
        self._build(page)

    # ------------------------------------------------------------------ what can be done

    def _actions(self, item) -> QHBoxLayout:
        row = QHBoxLayout()
        row.setSpacing(6)
        act = self.owner.act

        def button(text: str, glyph: str, name: str, primary: bool = False, tip: str = '') -> QPushButton:
            made = QPushButton(text)
            made.setIcon(QIcon(icons.glyph(glyph, theme.ON_ACCENT if primary else theme.colors().text, 16, 1.7)))
            made.setCursor(Qt.PointingHandCursor)
            if primary:
                made.setProperty('role', 'primary')
            made.setToolTip(tip)
            made.clicked.connect(lambda: act(name, item))
            row.addWidget(made)
            return made

        if item.deleted:
            button('Restore', 'restore', 'restore', primary=True, tip='Back out of the trash')
            button('Delete forever', 'trash', 'delete_forever')
            row.addStretch(1)
            return row
        button('Edit', 'edit', 'edit', primary=True, tip='Ctrl+E')
        if item.archived:
            button('Unarchive', 'restore', 'unarchive', tip='Back among your items')
        else:
            star = button('Unfavourite' if item.favorite else 'Favourite',
                          'star' if item.favorite else 'star_line', 'favorite')
            star.setToolTip('Take it out of your favourites' if item.favorite else 'Add it to your favourites')
        more = QToolButton()
        more.setIcon(QIcon(icons.glyph('more', theme.colors().text, 18, 1.8)))
        more.setIconSize(QSize(18, 18))
        more.setFixedSize(34, 34)
        more.setToolTip('More')
        more.setCursor(Qt.PointingHandCursor)
        more.setPopupMode(QToolButton.InstantPopup)
        menu = QMenu(more)
        menu.addAction(QIcon(icons.glyph('copy', theme.colors().text, 16, 1.7)), 'Clone', lambda: act('clone', item))
        if not item.archived:
            menu.addAction(QIcon(icons.glyph('archive', theme.colors().text, 16, 1.7)), 'Archive',
                           lambda: act('archive', item))
        menu.addAction(QIcon(icons.glyph('clip', theme.colors().text, 16, 1.7)), 'Attach a file…',
                       lambda: act('attach', item))
        if item.organization_id:
            menu.addAction('Collections…', lambda: act('collections', item))
        elif getattr(self.owner.controller, 'organizations', None):
            menu.addAction('Move to an organization…', lambda: act('move', item))
        menu.addAction(QIcon(icons.glyph('external', theme.colors().text, 16, 1.7)), "Open in Bitwarden's web vault",
                       lambda: act('web', item))
        menu.addSeparator()
        menu.addAction(QIcon(icons.glyph('trash', theme.colors().text, 16, 1.7)), 'Delete', lambda: act('delete', item))
        more.setMenu(menu)
        row.addWidget(more)
        row.addStretch(1)
        return row

    # ------------------------------------------------------------------ each kind's parts

    def _login(self, item, copy) -> list[QWidget]:
        login = item.login
        out = []
        part = _Section('Login credentials')
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
            out.append(part)
        if login.passkeys:
            keys = _Section('Passkey')
            for key in login.passkeys:
                keys.add(_Field('Passkey', f'{key.who} on {key.rp_id}',
                                tip='Sign in with it from the website or app: choose Keytap in Windows\' passkey window'))
            out.append(keys)
        if login.uris:
            sites = _Section('Websites and programs')
            for uri in login.uris:
                sites.add(self._uri_field(uri, copy))
            out.append(sites)
        return out

    def _card(self, item, copy) -> list[QWidget]:
        card = item.card
        part = _Section('Card details')
        name, number, code = (str(card.get(k) or '') for k in ('cardholderName', 'number', 'code'))
        if name:
            part.add(_Field('Cardholder name', name, copy=lambda: copy(name, 'cardholder name')))
        if number:
            part.add(_Field('Number', number, secret=True, mono=True, copy=lambda: copy(number, 'card number')))
        if card.get('brand'):
            part.add(_Field('Brand', str(card['brand'])))
        month, year = str(card.get('expMonth') or ''), str(card.get('expYear') or '')
        if month or year:
            expiry = f'{month.zfill(2) if month else "--"} / {year or "----"}'
            part.add(_Field('Expiry', expiry, copy=lambda: copy(expiry.replace(' ', ''), 'expiry date')))
        if code:
            part.add(_Field('Security code', code, secret=True, mono=True, copy=lambda: copy(code, 'security code')))
        return [part] if part.rows.count() else []

    def _identity(self, item, copy) -> list[QWidget]:
        identity = item.identity
        out = []
        for title, parts in kinds.IDENTITY_PARTS:
            section = _Section(title)
            if title == 'Personal details' and item.full_name():
                full = item.full_name()
                section.add(_Field('Name', full, copy=lambda v=full: copy(v, 'name')))
            for key, label in parts:
                if key in ('title', 'firstName', 'middleName', 'lastName'):
                    continue
                value = str(identity.get(key) or '')
                if not value:
                    continue
                if key.startswith('address') or key in ('city', 'state', 'postalCode', 'country'):
                    continue                    # together below, as an address is written
                section.add(_Field(label, value, secret=key in kinds.SECRET_IDENTITY,
                                   copy=lambda v=value, n=label: copy(v, n.lower())))
            if title == 'Contact info':
                lines = [str(identity.get(k) or '') for k in ('address1', 'address2', 'address3')]
                town = ' '.join(str(identity.get(k) or '') for k in ('city', 'state', 'postalCode') if identity.get(k))
                address = '\n'.join(line for line in (*lines, town, str(identity.get('country') or '')) if line)
                if address:
                    section.add(_Field('Address', address, copy=lambda v=address: copy(v, 'address')))
            if section.rows.count():
                out.append(section)
        return out

    def _ssh_key(self, item, copy) -> list[QWidget]:
        key = item.ssh_key
        part = _Section('SSH key')
        private, public, print_ = (str(key.get(k) or '') for k in ('privateKey', 'publicKey', 'keyFingerprint'))
        if private:
            part.add(_Field('Private key', private, secret=True, mono=True, copy=lambda: copy(private, 'private key')))
        if public:
            part.add(_Field('Public key', public, mono=True, copy=lambda: copy(public, 'public key')))
        if print_:
            part.add(_Field('Fingerprint', print_, mono=True, copy=lambda: copy(print_, 'fingerprint')))
        return [part] if part.rows.count() else []

    def _fields(self, item, copy) -> QWidget | None:
        found = item.fields
        if not found:
            return None
        extra = _Section('Custom fields')
        links = kinds.LINKS.get(item.type, {})
        for field in found:
            name = str(field.get('name') or '') or '(no name)'
            value = '' if field.get('value') is None else str(field['value'])
            kind = field.get('type')
            if kind == kinds.BOOLEAN:
                extra.add(_Field(name, '✓ Yes' if value.lower() == 'true' else '✗ No'))
            elif kind == kinds.LINKED:
                extra.add(_Field(name, f'Linked to {links.get(field.get("linkedId"), "nothing")}'))
            else:
                hidden = kind == kinds.HIDDEN
                extra.add(_Field(name, value, secret=hidden, mono=hidden, copy=lambda v=value, n=name: copy(v, n)))
        return extra

    def _notes(self, item) -> QWidget | None:
        if not item.notes:
            return None
        notes = _Section('Notes')
        notes.add(_Text(item.notes, theme.font(9.5), margins=(14, 10, 14, 10)))
        return notes

    def _attachments(self, item) -> QWidget | None:
        found = item.attachments
        if not found:
            return None
        part = _Section('Attachments')
        for attachment in found:
            row = QWidget()
            line = QHBoxLayout(row)
            line.setContentsMargins(14, 6, 8, 6)
            line.setSpacing(4)
            line.addWidget(_label(str(attachment.get('fileName') or 'file'), 9.5), 1)
            line.addWidget(_label(str(attachment.get('sizeName') or ''), 8.5, role='dim'))
            save = _Field._button('download', 'Save a copy…')
            save.clicked.connect(lambda _=False, a=attachment: self.owner.act('save_attachment', item, a))
            line.addWidget(save)
            if not item.deleted:
                remove = _Field._button('trash', 'Delete it')
                remove.clicked.connect(lambda _=False, a=attachment: self.owner.act('delete_attachment', item, a))
                line.addWidget(remove)
            part.add(row)
        return part

    def _history(self, item, copy) -> QWidget | None:
        """A login's earlier passwords, behind a button: Bitwarden's password history."""
        past = item.password_history
        if not past:
            return None
        part = _Section('Password history')
        button = QPushButton(f'Show {len(past)} earlier password{"s" if len(past) != 1 else ""}')
        button.setCursor(Qt.PointingHandCursor)
        holder = QWidget()
        holder.setLayout(QVBoxLayout())
        holder.layout().setContentsMargins(0, 0, 0, 0)
        holder.layout().addWidget(button, 0, Qt.AlignLeft)

        def shown():
            button.hide()
            for entry in past:
                used = kinds.when(str(entry.get('lastUsedDate') or ''))
                password = str(entry['password'])
                holder.layout().addWidget(_Field(f'Until {used}' if used else 'Earlier', password, secret=True, mono=True,
                                                 copy=lambda v=password: copy(v, 'old password')))
        button.clicked.connect(shown)
        wrap = QWidget()
        wrap.setLayout(QVBoxLayout())
        wrap.layout().setContentsMargins(14, 8, 8, 8)
        wrap.layout().addWidget(holder)
        part.add(wrap)
        return part

    def _dates(self, item) -> QWidget | None:
        raw = item.raw
        lines = [(label, kinds.when(str(raw.get(key) or ''))) for label, key in (
            ('Created', 'creationDate'), ('Last edited', 'revisionDate'), ('Archived', 'archivedDate'),
            ('Deleted', 'deletedDate'))]
        if item.login is not None:
            lines.append(('Password updated', kinds.when(str((raw.get('login') or {}).get('passwordRevisionDate') or ''))))
        words = '\n'.join(f'{label}: {stamp}' for label, stamp in lines if stamp)
        if not words:
            return None
        label = _label(words, 8.25, role='dim')
        label.setWordWrap(True)
        return label

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

    def _asks(self, item) -> QWidget:
        box = QFrame()
        box.setObjectName('sectionBox')
        layout = QVBoxLayout(box)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(10)
        lock = QLabel()
        lock.setPixmap(icons.glyph('lock', theme.colors().text, 28, 1.6))
        layout.addWidget(lock, 0, Qt.AlignHCenter)
        note = _label(f'This {kinds.NAMES[item.type].lower()} asks for your master password before it is shown.',
                      9.5)
        note.setWordWrap(True)
        note.setAlignment(Qt.AlignCenter)
        layout.addWidget(note)
        ask = QPushButton("Confirm it's you")
        ask.setProperty('role', 'primary')
        ask.setCursor(Qt.PointingHandCursor)
        ask.clicked.connect(lambda: self.confirm.emit(item))
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
            old.deleteLater()      # its labels held the last item's details
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


# --------------------------------------------------------------------------- choosing collections

class CollectionsDialog(QDialog):
    """Which collections an item is in - or, moving it, which organization's and which of them."""

    def __init__(self, controller, item, moving: bool, parent=None):
        super().__init__(parent)
        theme.frost(self)
        theme.restyle(self, theme.card_style)
        self.controller = controller
        self.setWindowTitle('Move to an organization' if moving else 'Collections')
        self.setWindowIcon(icons.app_icon())
        self.setWindowModality(Qt.WindowModal)
        self.setMinimumWidth(420)
        layout = QVBoxLayout(self)
        layout.setSpacing(10)
        words = (f'“{item.name}” goes to the organization: it is theirs from then on, and its members '
                 'in those collections can see it.' if moving else f'The collections “{item.name}” is in.')
        note = _label(words, 9.25)
        note.setWordWrap(True)
        layout.addWidget(note)
        self.org = QComboBox()
        organizations = controller.organizations or {}
        for org_id, name in organizations.items():
            self.org.addItem(name, org_id)
        self.org.setCurrentIndex(max(0, self.org.findData(item.organization_id)))
        self.org.setVisible(moving)
        layout.addWidget(self.org)
        self.list = QListWidget()
        layout.addWidget(self.list, 1)
        self._chosen = set(item.collection_ids)
        self.org.currentIndexChanged.connect(self._fill)
        self._fill()
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.button(QDialogButtonBox.Ok).setText('Move' if moving else 'Save')
        buttons.accepted.connect(self._done)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        self.message = _label('', 9, role='error')
        layout.addWidget(self.message)

    def _fill(self) -> None:
        org = self.org.currentData() or ''
        self.list.clear()
        for collection in self.controller.collections or []:
            if collection.get('organizationId') != org:
                continue
            entry = QListWidgetItem(str(collection.get('name') or ''))
            entry.setData(Qt.UserRole, collection.get('id'))
            entry.setFlags(entry.flags() | Qt.ItemIsUserCheckable)
            entry.setCheckState(Qt.Checked if collection.get('id') in self._chosen else Qt.Unchecked)
            self.list.addItem(entry)

    def chosen(self) -> tuple[str, list[str]]:
        ids = [self.list.item(n).data(Qt.UserRole) for n in range(self.list.count())
               if self.list.item(n).checkState() == Qt.Checked]
        return self.org.currentData() or '', ids

    def _done(self) -> None:
        if not self.chosen()[1]:
            self.message.setText('Choose at least one collection.')
            return
        self.accept()


# --------------------------------------------------------------------------- the window

class VaultWindow(QWidget):
    def __init__(self, controller):
        super().__init__()
        self.controller = controller
        self._want = ''               # an item to choose once it is listed (one just made, say)
        self._shown = None            # (item, folder, owner) on the right
        self.setWindowTitle('Keytap')
        self.setWindowIcon(icons.app_icon())
        self.setObjectName('vault')
        theme.frost(self, backdrop=theme.BACKDROP)
        self.resize(1040, 680)
        self.setMinimumSize(760, 500)
        theme.restyle(self, self._style)
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
                             ('Ctrl+R', lambda: controller.sync()), ('Ctrl+N', lambda: self.new_item(LOGIN)),
                             ('Ctrl+E', lambda: self._on_current('edit'))):
            QShortcut(QKeySequence(keys), self).activated.connect(action)
        QShortcut(QKeySequence.Delete, self.list, context=Qt.WidgetShortcut).activated.connect(
            lambda: self._on_current('delete_forever' if self._filter()[0] == 'trash' else 'delete'))
        self.refresh()

    # ------------------------------------------------------------------ building

    def _style(self) -> str:
        c = theme.colors()
        border = c.border.name(QColor.HexArgb)
        pill = 14 if theme.liquid_controls_css() else 8
        return theme.card_style() + theme.panel_css('QFrame#sectionBox', 10) + f"""
            QWidget#vault {{ background: {theme.css(c.card)}; }}
            QWidget#header {{ background: {theme.css(c.card)}; border-bottom: 1px solid {border}; }}
            QWidget#sidebar {{ background: {theme.css(c.tile)}; border-right: 1px solid {border}; }}
            QWidget#listPane {{ border-right: 1px solid {border}; }}
            QScrollArea, QScrollArea > QWidget > QWidget {{ background: transparent; }}
            QFrame#rule {{ background: {border}; border: none; margin: 0 12px; }}
            QListWidget#filters {{ background: transparent; border: none; outline: none; }}
            QListWidget#filters::item {{ color: {c.text.name()}; padding: 0px 8px; border-radius: {pill}px; }}
            QListWidget#filters::item:selected {{ background: {c.selected.name()}; color: {c.selected_text.name()}; }}
            QListWidget#filters::item:hover:!selected {{ background: {theme.css(c.hover)}; }}
            QListView#items {{ background: transparent; border: none; outline: none; }}
            QTextEdit#text {{ color: {c.text.name()}; background: transparent; border: none;
                              selection-background-color: {theme.ACCENT}; selection-color: {theme.ON_ACCENT}; }}
        """

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

        self.new_button = QPushButton('New')
        self.new_button.setProperty('role', 'primary')
        self.new_button.setIcon(QIcon(icons.glyph('plus', theme.ON_ACCENT, 16, 2)))
        self.new_button.setCursor(Qt.PointingHandCursor)
        self.new_button.setToolTip('A new login (Ctrl+N), card, identity, note, SSH key or folder')
        menu = QMenu(self.new_button)
        for kind in kinds.KINDS:
            menu.addAction(QIcon(icons.glyph(kinds.GLYPHS[kind], theme.colors().text, 16, 1.7)), kinds.NAMES[kind],
                           lambda k=kind: self.new_item(k))
        menu.addSeparator()
        menu.addAction(QIcon(icons.glyph('folder', theme.colors().text, 16, 1.7)), 'Folder…', self.new_folder)
        self.new_button.setMenu(menu)
        row.addWidget(self.new_button)

        self.tools_button = self._tool('more', 'Tools: generator, Send, vault health, export and import', None)
        self.tools_button.setPopupMode(QToolButton.InstantPopup)
        tools = QMenu(self.tools_button)
        controller = self.controller
        for glyph, words, action in (('dice', 'Generator', 'show_generator'), ('send', 'Send', 'show_sends'),
                                     ('shield', 'Vault health', 'show_health'), (None, None, None),
                                     ('download', 'Export vault…', 'show_export'),
                                     ('upload', 'Import data…', 'show_import')):
            if glyph is None:
                tools.addSeparator()
                continue
            tools.addAction(QIcon(icons.glyph(glyph, theme.colors().text, 16, 1.7)), words,
                            lambda a=action: getattr(controller, a)())
        self.tools_button.setMenu(tools)
        self.sync_button = self._tool('refresh', 'Sync now (Ctrl+R)', lambda: self.controller.sync())
        self.lock_button = self._tool('lock', 'Lock (Ctrl+L)', lambda: self.controller.lock())
        settings = self._tool('sliders', 'Settings', lambda: self.controller.show_settings())
        for button in (self.tools_button, self.sync_button, self.lock_button, settings):
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
        if action is not None:
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
        self.filters.currentRowChanged.connect(lambda _: self._filter_changed())
        self.filters.setContextMenuPolicy(Qt.CustomContextMenu)
        self.filters.customContextMenuRequested.connect(self._filter_menu)
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
        self.list = _ItemList()
        self.list.setObjectName('items')
        self.list.setItemDelegate(_ItemDelegate(self.list))
        self.list.setMouseTracking(True)
        self.list.setUniformItemSizes(True)
        self.list.setVerticalScrollMode(QAbstractItemView.ScrollPerPixel)
        self.list.currentItemChanged.connect(lambda *_: self._show_current())
        self.list.doubleClicked.connect(lambda _: self._on_current('edit'))
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
        """In a narrower window the filters and the list narrow too, so the item keeps room."""
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
        for button in (self.sync_button, self.lock_button, self.new_button, self.tools_button):
            button.setEnabled(controller.unlocked)
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
            self.notice.say('Sign in to Bitwarden', 'Keytap reaches your vault through Bitwarden\'s own '
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
        from .editor import ItemEditor
        for editor in self.findChildren(ItemEditor):
            editor.discard()
        for dialog in self.findChildren(CollectionsDialog):
            dialog.reject()
        self.filters.blockSignals(True)
        self.filters.clear()          # folder names and counts say something about the vault too
        self.filters.blockSignals(False)
        self.list.clear()
        self.details.clear()
        self._shown = None
        self.search.clear()

    def _live(self) -> list:
        return list(self.controller.items or [])

    def _fill_filters(self) -> None:
        c = self.controller
        live = self._live()
        chosen = self._filter()
        folders = c.folders or {}
        entries = [(('all', ''), 'grid', 'All items', len(live)),
                   (('favorites', ''), 'star_line', 'Favourites', sum(item.favorite for item in live)),
                   (('codes', ''), 'clock', 'Verification codes', sum(item.has_code for item in live)),
                   'Types']
        for kind in kinds.KINDS:
            entries.append((('kind', str(kind)), kinds.GLYPHS[kind], kinds.PLURALS[kind],
                            sum(item.type == kind for item in live)))
        if folders:
            entries.append('Folders')
            for folder_id, name in sorted(folders.items(), key=lambda entry: entry[1].lower()):
                entries.append((('folder', folder_id), 'folder', name, sum(i.folder_id == folder_id for i in live)))
            entries.append((('folder', ''), 'folder', 'No folder', sum(not item.folder_id for item in live)))
        collections = c.collections or []
        if collections:
            entries.append('Collections')
            several = len(c.organizations or {}) > 1
            for collection in sorted(collections, key=lambda entry: str(entry.get('name') or '').lower()):
                cid = str(collection.get('id') or '')
                name = str(collection.get('name') or '')
                if several:
                    name += f'  ({(c.organizations or {}).get(collection.get("organizationId"), "")})'
                entries.append((('collection', cid), 'grid', name, sum(cid in item.collection_ids for item in live)))
        entries.append('')
        if getattr(c, 'can_archive', True) or c.archive:
            entries.append((('archive', ''), 'archive', 'Archive', len(c.archive or [])))
        entries.append((('trash', ''), 'trash', 'Trash', len(c.trash or [])))

        self.filters.blockSignals(True)
        self.filters.clear()
        dim = theme.colors().dim
        for entry in entries:
            if isinstance(entry, str):
                heading = QListWidgetItem(entry)
                heading.setFlags(Qt.NoItemFlags)
                heading.setFont(theme.font(8.5, QFont.DemiBold))
                heading.setForeground(dim)
                heading.setTextAlignment(Qt.AlignLeft | Qt.AlignBottom)       # nearer its own rows than those above
                heading.setSizeHint(QSize(10, 32 if entry else 8))
                self.filters.addItem(heading)
                continue
            key, glyph, name, count = entry
            item = QListWidgetItem(QIcon(icons.glyph(glyph, dim, 16, 1.8)), f'{name}   {count}')
            item.setData(Qt.UserRole, key)
            item.setSizeHint(QSize(10, 34))
            self.filters.addItem(item)
        rows = [tuple(self.filters.item(i).data(Qt.UserRole) or ()) for i in range(self.filters.count())]
        self.filters.setCurrentRow(rows.index(chosen) if chosen in rows else 0)
        self.filters.blockSignals(False)

    def _filter(self) -> tuple:
        item = self.filters.currentItem()
        key = item.data(Qt.UserRole) if item is not None else None
        return tuple(key) if key else ('all', '')

    def _filter_changed(self) -> None:
        self._fill_list()

    def _fill_list(self) -> None:
        c = self.controller
        kind, value = self._filter()
        source = (c.trash or []) if kind == 'trash' else (c.archive or []) if kind == 'archive' else self._live()
        keep = {'favorites': lambda item: item.favorite, 'codes': lambda item: item.has_code,
                'kind': lambda item: str(item.type) == value, 'folder': lambda item: item.folder_id == value,
                'collection': lambda item: value in item.collection_ids}.get(kind, lambda item: True)
        words = self.search.text().lower().split()
        shown = sorted((item for item in source if keep(item) and item.matches(words)),
                       key=lambda item: (item.name.lower(), item.subtitle.lower()))
        current = self._want or (self.details.item.id if self.details.item is not None else '')
        self.list.blockSignals(True)
        self.list.show_items(shown, current)
        self.list.blockSignals(False)
        if self._want and any(item.id == self._want for item in shown):
            self._want = ''
        total = len(source)
        noun = 'item' if total == 1 else 'items'
        self.count.setText(f'{len(shown)} of {total} {noun}' if len(shown) != total else f'{total} {noun}')
        self._show_current()

    def _show_current(self, again: bool = False) -> None:
        """The chosen item, on the right. One already shown as it is now is left be (unless again):
        a refresh after a sync, say, would otherwise hide a password just shown, and redraw it all."""
        row = self.list.currentItem()
        item = row.data(Qt.UserRole) if row is not None else None
        c = self.controller
        folder = (c.folders or {}).get(item.folder_id, '') if item else ''
        owner = (c.organizations or {}).get(item.organization_id, '') if item and item.organization_id else ''
        shown = (item, folder, owner)
        if not again and item is not None and self._shown == shown:
            return
        self._shown = shown
        self.details.show_item(item, folder, owner)

    def show_item(self, item_id: str) -> None:
        """Choose that item - among everything, should the filter or search leave it out."""
        self._want = item_id
        self._fill_list()
        if self._want:                        # not listed: show everything (or the trash) instead
            where = ('trash', '') if any(i.id == item_id for i in self.controller.trash or []) else \
                ('archive', '') if any(i.id == item_id for i in self.controller.archive or []) else ('all', '')
            self.search.blockSignals(True)
            self.search.clear()
            self.search.blockSignals(False)
            rows = [tuple(self.filters.item(i).data(Qt.UserRole) or ()) for i in range(self.filters.count())]
            if where in rows:
                self.filters.setCurrentRow(rows.index(where))
            self._fill_list()
            self._want = ''

    # ------------------------------------------------------------------ acting

    def copy(self, value: str, label: str) -> None:
        self.controller.copy(value, label)

    def problem(self, title: str, text: str) -> None:
        self.controller.toasts.show(title, text, error=True)

    def hotkeys(self) -> dict:
        return self.controller.settings.hotkeys

    def edit_url(self, item) -> str:
        return f'{web_vault(self.controller.status.server)}/#/vault?itemId={item.id}'

    def _confirm(self, item, then=None) -> None:
        def shown():
            self.details.confirmed = item.id
            if self.details.item is not None and self.details.item.id == item.id:
                self._show_current(again=True)
            if then is not None:
                then()
        self.controller.confirm(item, shown, int(self.winId()))

    def _confirmed(self, item, then) -> None:
        """then() - once the master password is given, for an item that asks for it."""
        if item.reprompt and self.details.confirmed != item.id:
            self._confirm(item, then)
        else:
            then()

    def _on_current(self, name: str) -> None:
        if self.pages.currentWidget() is self.vault_page and self.details.item is not None:
            if name == 'edit' and self.details.item.deleted:
                return
            self.act(name, self.details.item)

    def _done(self, what: str):
        """A controller callback: a toast should it go wrong."""
        def done(_, error):
            if error is not None:
                self.problem(f'Could not {what}', str(error))
        return done

    def act(self, name: str, item, extra=None) -> None:
        """What the details' buttons ask for."""
        c = self.controller
        if item.partial:
            self.problem('One moment', 'Bitwarden is still unlocking - try again in a few seconds.')
            return
        if name == 'edit':
            self._confirmed(item, lambda: self._edit(item.editable(), item.id))
        elif name == 'clone':
            self._confirmed(item, lambda: self._edit(item.clone(), ''))
        elif name == 'favorite':
            raw = item.editable()
            raw['favorite'] = not item.favorite
            c.save_item(raw, item.id, self._done('change it'))
        elif name == 'archive':
            c.archive_item(item, self._done('archive it'))
        elif name == 'unarchive' or name == 'restore':
            c.restore_item(item, self._done('restore it'))
        elif name == 'delete':
            if self._ask(f'Send “{item.name}” to the trash?', 'You can restore it from the trash.', 'Delete'):
                c.delete_item(item, False, self._done('delete it'))
        elif name == 'delete_forever':
            if self._ask(f'Delete “{item.name}” forever?', 'It cannot be restored.', 'Delete forever'):
                c.delete_item(item, True, self._done('delete it'))
        elif name == 'attach':
            path, _ = QFileDialog.getOpenFileName(self, f'Attach a file to “{item.name}”')
            if path:
                c.add_attachment(item, path, self._done('attach it'))
        elif name == 'save_attachment':
            def save():
                path, _ = QFileDialog.getSaveFileName(self, 'Save the attachment', str(extra.get('fileName') or ''))
                if path:
                    c.save_attachment(item, extra, path, self._done('save it'))
            self._confirmed(item, save)
        elif name == 'delete_attachment':
            if self._ask(f'Delete “{extra.get("fileName")}”?', 'The attachment goes for good.', 'Delete'):
                c.delete_attachment(item, extra, self._done('delete it'))
        elif name in ('move', 'collections'):
            dialog = CollectionsDialog(c, item, moving=name == 'move', parent=self)
            dialog.setAttribute(Qt.WA_DeleteOnClose)

            def chosen():
                org, collections = dialog.chosen()
                if name == 'move':
                    c.move_item(item, org, collections, self._done('move it'))
                else:
                    c.set_collections(item, collections, self._done('change its collections'))
            dialog.accepted.connect(chosen)
            dialog.show()
        elif name == 'web':
            QDesktopServices.openUrl(QUrl(self.edit_url(item)))

    def _ask(self, question: str, detail: str, yes: str) -> bool:
        box = QMessageBox(QMessageBox.Question, 'Keytap', question, QMessageBox.Cancel, self)
        box.setInformativeText(detail)
        go = box.addButton(yes, QMessageBox.DestructiveRole)
        box.exec()
        return box.clickedButton() is go

    def _edit(self, raw: dict, item_id: str) -> None:
        from .editor import ItemEditor
        editor = ItemEditor(self.controller, raw, item_id, parent=self)
        editor.setAttribute(Qt.WA_DeleteOnClose)
        editor.saved.connect(lambda saved: self.show_item(saved.id))
        editor.show()
        editor.raise_()
        editor.activateWindow()

    def new_item(self, kind: int, name: str = '', uris: tuple[str, ...] = ()) -> None:
        """The editor, for a new item of that kind - in the folder chosen on the left, if one is."""
        if not self.controller.unlocked:
            return
        where, value = self._filter()
        raw = kinds.blank(kind, name, value if where == 'folder' else '')
        if where == 'favorites':
            raw['favorite'] = True
        if kind == LOGIN and uris:
            raw['login']['uris'] = [{'match': None, 'uri': uri} for uri in uris]
        self._edit(raw, '')

    def new_folder(self) -> None:
        name, ok = QInputDialog.getText(self, 'New folder', 'Name:')
        if ok and name.strip():
            self.controller.save_folder(name.strip(), '', self._done('make the folder'))

    def _filter_menu(self, pos) -> None:
        if not self.controller.unlocked:
            return
        entry = self.filters.itemAt(pos)
        key = tuple(entry.data(Qt.UserRole) or ()) if entry is not None else ()
        menu = QMenu(self)
        menu.addAction('New folder…', self.new_folder)
        if key and key[0] == 'folder' and key[1]:
            name = (self.controller.folders or {}).get(key[1], '')
            menu.addAction('Rename…', lambda: self._rename_folder(key[1], name))
            menu.addAction('Delete…', lambda: self._delete_folder(key[1], name))
        menu.exec(self.filters.viewport().mapToGlobal(pos))
        menu.deleteLater()

    def _rename_folder(self, folder_id: str, name: str) -> None:
        new, ok = QInputDialog.getText(self, 'Rename folder', 'Name:', text=name)
        if ok and new.strip() and new.strip() != name:
            self.controller.save_folder(new.strip(), folder_id, self._done('rename the folder'))

    def _delete_folder(self, folder_id: str, name: str) -> None:
        if self._ask(f'Delete the folder “{name}”?', 'What is in it stays in your vault, in no folder.', 'Delete'):
            self.controller.delete_folder(folder_id, self._done('delete the folder'))

    def _copy_part(self, part: str) -> None:
        item = self.details.item
        login = self.details.login
        if login is None or self.pages.currentWidget() is not self.vault_page:
            return
        if item.reprompt and self.details.confirmed != item.id:
            self._confirm(item)
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
                           items=[Item.from_login(login) for login in logins], trash=[], archive=[],
                           can_archive=True, organizations={}, collections=[],
                           settings=SimpleNamespace(hotkeys={'type': 'Ctrl+Alt+A', 'pick': 'Ctrl+Alt+Shift+A'},
                                                    generator={}),
                           copy=noop, lock=noop, sync=noop, show_settings=noop, show_sign_in=noop,
                           unlock_in=noop, confirm=noop, toasts=SimpleNamespace(show=noop),
                           hello_on=lambda: False, remember_generated=noop)
