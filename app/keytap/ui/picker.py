"""The login picker: search the vault, then type or copy what's chosen."""

from __future__ import annotations

from PySide6.QtCore import QEvent, QRect, QSize, Qt, Signal
from PySide6.QtGui import QColor, QFont, QFontMetrics, QKeySequence, QShortcut
from PySide6.QtWidgets import (QCheckBox, QLabel, QLineEdit, QListWidget, QListWidgetItem, QMenu,
                               QStyle, QStyledItemDelegate)

from ..matching import HINT, LINKED, PAGE, SITE, URI
from . import icons, theme
from .card import Card

ROW_HEIGHT = 46
VISIBLE_ROWS = 7
MAX_ROWS = 300
_TAGS = {LINKED: 'Always', URI: 'Matches', PAGE: 'Matches', SITE: 'Same site', HINT: 'Suggested'}

# (action, menu label, shortcut) - the shortcuts work while the search box has the keyboard.
ACTIONS = (
    ('all', 'Type it all', 'Return'),
    ('username', 'Type the username', 'Ctrl+U'),
    ('password', 'Type the password', 'Ctrl+P'),
    ('totp', 'Type the verification code', 'Ctrl+T'),
    (None, None, None),
    ('copy_username', 'Copy the username', 'Ctrl+Shift+U'),
    ('copy_password', 'Copy the password', 'Ctrl+Shift+C'),
    ('copy_totp', 'Copy the verification code', 'Ctrl+Shift+T'),
)


class _Delegate(QStyledItemDelegate):
    def sizeHint(self, option, index):
        return QSize(option.rect.width(), ROW_HEIGHT)

    def paint(self, painter, option, index):
        login, strength = index.data(Qt.UserRole)
        c = theme.colors()
        selected = bool(option.state & QStyle.State_Selected)
        hovered = bool(option.state & QStyle.State_MouseOver)
        rect = QRect(option.rect).adjusted(0, 1, -2, -1)
        painter.save()
        painter.setRenderHint(painter.RenderHint.Antialiasing)
        if selected or hovered:
            painter.setPen(Qt.NoPen)
            painter.setBrush(c.selected if selected else c.hover)
            painter.drawRoundedRect(rect, 8, 8)
        text, dim = (c.selected_text, c.selected_text) if selected else (c.text, c.dim)

        right = rect.right() - 10
        tag = _TAGS.get(strength, '')
        if tag:
            painter.setFont(theme.font(8, QFont.DemiBold))
            width = QFontMetrics(painter.font()).horizontalAdvance(tag) + 14
            chip = QRect(right - width, rect.center().y() - 10, width, 20)
            painter.setPen(Qt.NoPen)
            painter.setBrush(c.chip if not selected else QColor(255, 255, 255, 50))
            painter.drawRoundedRect(chip, 10, 10)
            painter.setPen(text)
            painter.drawText(chip, Qt.AlignCenter, tag)
            right = chip.left() - 8
        if login.reprompt:
            painter.drawPixmap(right - 16, rect.center().y() - 8, icons.glyph('lock', dim, 16, 1.8))
            right -= 22

        left = rect.left() + 12
        width = max(20, right - left)
        painter.setFont(theme.font(9.75, QFont.DemiBold))
        painter.setPen(text)
        name = QFontMetrics(painter.font()).elidedText(login.name, Qt.ElideRight, width)
        painter.drawText(QRect(left, rect.top() + 5, width, 19), Qt.AlignVCenter, name)
        painter.setFont(theme.font(8.5))
        painter.setPen(dim)
        detail = login.username or ('no username' if login.password else 'no username or password')
        detail = QFontMetrics(painter.font()).elidedText(detail, Qt.ElideRight, width)
        painter.drawText(QRect(left, rect.top() + 23, width, 17), Qt.AlignVCenter, detail)
        painter.restore()


class Picker(Card):
    """chosen(login, action, remember) - action is one of ACTIONS' names."""
    chosen = Signal(object, str, bool)

    def __init__(self, logins, matches, target_label: str, remember_label: str = ''):
        super().__init__(460)
        self._logins = sorted(logins, key=lambda l: (not l.favorite, l.name.lower(), l.username.lower()))
        self._matches = matches
        self._strength = {m.login.id: m.strength for m in matches}
        self._done = False
        self._menu_open = False
        self.header('Choose a login', f'to fill {target_label}' if target_label else '')

        self.search = QLineEdit()
        self.search.setPlaceholderText('Search your vault')
        self.search.setClearButtonEnabled(True)
        self.search.textChanged.connect(self._refill)
        self.search.installEventFilter(self)
        self.body.addWidget(self.search)

        self.list = QListWidget()
        self.list.setItemDelegate(_Delegate(self.list))
        self.list.setMouseTracking(True)
        self.list.setFixedHeight(ROW_HEIGHT * VISIBLE_ROWS + 4)
        self.list.setVerticalScrollMode(QListWidget.ScrollPerPixel)
        self.list.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.list.setFocusPolicy(Qt.NoFocus)
        self.list.itemDoubleClicked.connect(lambda item: self._choose('all'))
        self.list.setContextMenuPolicy(Qt.CustomContextMenu)
        self.list.customContextMenuRequested.connect(self._menu)
        self.body.addWidget(self.list)

        self.empty = QLabel()
        self.empty.setProperty('role', 'dim')
        self.empty.setAlignment(Qt.AlignCenter)
        self.empty.hide()
        self.body.addWidget(self.empty)

        self.remember = QCheckBox(f'{remember_label}  (Alt+A)' if remember_label else '')
        self.remember.setVisible(bool(remember_label))
        self.remember.setFocusPolicy(Qt.NoFocus)
        self.body.addWidget(self.remember)
        if remember_label:
            QShortcut(QKeySequence('Alt+A'), self, activated=self.remember.toggle)

        hint = QLabel('Enter types it all  ·  Ctrl+U username  ·  Ctrl+P password  ·  Ctrl+T code\n'
                      'Right-click a login to copy from it instead')
        hint.setProperty('role', 'dim')
        hint.setFont(theme.font(8))
        hint.setWordWrap(True)
        self.body.addWidget(hint)

        for action, _, keys in ACTIONS:
            if action and keys != 'Return':
                QShortcut(QKeySequence(keys), self, activated=lambda a=action: self._choose(a))
        self._refill()

    # ------------------------------------------------------------------ the list

    def _rows(self, query: str):
        words = query.lower().split()
        if not words:
            suggested = [m.login for m in self._matches]
            ids = {login.id for login in suggested}
            return suggested + [login for login in self._logins if login.id not in ids]

        def hit(login) -> bool:
            haystack = ' '.join((login.name, login.username, *login.uris)).lower()
            return all(word in haystack for word in words)
        suggested = [m.login for m in self._matches if hit(m.login)]
        ids = {login.id for login in suggested}
        return suggested + [login for login in self._logins if login.id not in ids and hit(login)]

    def _refill(self) -> None:
        self.list.clear()
        rows = self._rows(self.search.text())[:MAX_ROWS]
        for login in rows:
            item = QListWidgetItem()
            item.setData(Qt.UserRole, (login, self._strength.get(login.id, '')))
            item.setData(Qt.AccessibleTextRole, f'{login.name} {login.username}')
            self.list.addItem(item)
        if rows:
            self.list.setCurrentRow(0)
        self.list.setVisible(bool(rows))
        self.empty.setVisible(not rows)
        if not rows:
            query = self.search.text().strip()
            self.empty.setText(f'Nothing in your vault matches “{query}”' if query
                               else 'Your vault has no logins yet')
            self.empty.setFixedHeight(ROW_HEIGHT * VISIBLE_ROWS + 4)

    def current(self):
        item = self.list.currentItem()
        return item.data(Qt.UserRole)[0] if item else None

    # ------------------------------------------------------------------ choosing

    def _choose(self, action: str) -> None:
        login = self.current()
        if login is None or self._done:
            return
        self._done = True
        remember = self.remember.isVisible() and self.remember.isChecked()
        self.hide()
        self.chosen.emit(login, action, remember)
        self.close()

    def _menu(self, pos) -> None:
        item = self.list.itemAt(pos)
        if item is None:
            return
        self.list.setCurrentItem(item)
        login = self.current()
        menu = QMenu(self)
        for action, label, keys in ACTIONS:
            if action is None:
                menu.addSeparator()
                continue
            entry = menu.addAction(label, lambda a=action: self._choose(a))
            entry.setShortcut(QKeySequence(keys))
            if action.endswith('totp') and not login.totp:
                entry.setEnabled(False)
            if action.endswith('username') and not login.username:
                entry.setEnabled(False)
            if action.endswith('password') and not login.password:
                entry.setEnabled(False)
        self._menu_open = True
        try:
            menu.exec(self.list.viewport().mapToGlobal(pos))
        finally:
            self._menu_open = False
            menu.deleteLater()

    def eventFilter(self, watched, event):
        if watched is self.search and event.type() == QEvent.KeyPress:
            key = event.key()
            if key in (Qt.Key_Return, Qt.Key_Enter):
                self._choose('all')
                return True
            if key in (Qt.Key_Up, Qt.Key_Down, Qt.Key_PageUp, Qt.Key_PageDown):
                step = {Qt.Key_Up: -1, Qt.Key_Down: 1, Qt.Key_PageUp: -VISIBLE_ROWS,
                        Qt.Key_PageDown: VISIBLE_ROWS}[key]
                row = max(0, min(self.list.count() - 1, self.list.currentRow() + step))
                self.list.setCurrentRow(row)
                return True
        return super().eventFilter(watched, event)

    def changeEvent(self, event):
        # Clicking anywhere else dismisses the picker, as a menu would.
        if event.type() == QEvent.ActivationChange and not self.isActiveWindow() and self.isVisible():
            if not self._done and not self._menu_open:
                self.close()
        super().changeEvent(event)

    def showEvent(self, event):
        super().showEvent(event)
        self.search.setFocus()
