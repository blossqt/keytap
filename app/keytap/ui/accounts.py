"""Choosing which account to sign in as, when a website has several passkeys in the vault."""

from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import QHBoxLayout, QListWidget, QListWidgetItem, QPushButton

from . import theme
from .card import Card


class AccountCard(Card):
    chosen = Signal(object)         # a passkeys.Passkey

    def __init__(self, site: str, keys, names: dict[str, str]):
        """names: each login's name, by its id, to tell apart accounts with the same user name."""
        super().__init__(380)
        self.succeeded = False
        self.header('Sign in with a passkey', f'Which account on {site}?')
        self.list = QListWidget()
        self.list.setFont(theme.font(9.5))
        for key in keys:
            who = key.user_name or key.user_display_name or '(no user name)'
            name = names.get(key.login_id, '')
            item = QListWidgetItem(f'{who}  ·  {name}' if name and name != who else who)
            item.setData(Qt.UserRole, key)
            self.list.addItem(item)
        self.list.setCurrentRow(0)
        self.list.setFixedHeight(min(6, len(keys)) * 30 + 6)
        self.list.itemActivated.connect(lambda _: self._choose())
        self.body.addWidget(self.list)
        row = QHBoxLayout()
        row.addStretch(1)
        cancel = QPushButton('Cancel')
        cancel.clicked.connect(self.close)
        sign_in = QPushButton('Sign in')
        sign_in.setProperty('role', 'primary')
        sign_in.setDefault(True)
        sign_in.clicked.connect(self._choose)
        row.addWidget(cancel)
        row.addWidget(sign_in)
        self.body.addLayout(row)

    def showEvent(self, event):
        super().showEvent(event)
        self.list.setFocus()

    def keyPressEvent(self, event):
        if event.key() in (Qt.Key_Return, Qt.Key_Enter):
            self._choose()
            return
        super().keyPressEvent(event)

    def _choose(self) -> None:
        item = self.list.currentItem()
        if item is None:
            return
        self.succeeded = True
        self.chosen.emit(item.data(Qt.UserRole))
        self.close()
