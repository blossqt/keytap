"""The master password prompt: unlocking the vault, or confirming it's you."""

from __future__ import annotations

from PySide6.QtCore import QEvent, Qt, Signal
from PySide6.QtWidgets import QHBoxLayout, QLabel, QLineEdit, QPushButton

from .. import win32
from .card import Card


class UnlockCard(Card):
    submitted = Signal(str)
    hello = Signal()                  # unlock with Windows Hello instead

    def __init__(self, title: str, detail: str = '', button: str = 'Unlock', hello: bool = False):
        super().__init__(380)
        self.succeeded = False
        self._button_text = button
        self.header(title, detail)

        self.password = QLineEdit()
        self.password.setEchoMode(QLineEdit.Password)
        self.password.setPlaceholderText('Master password')
        self.password.returnPressed.connect(self._submit)
        self.password.installEventFilter(self)
        self.body.addWidget(self.password)

        self.caps = QLabel('Caps Lock is on')
        self.caps.setProperty('role', 'error')
        self.caps.setVisible(win32.caps_lock_on())
        self.body.addWidget(self.caps)
        self.error = QLabel()
        self.error.setProperty('role', 'error')
        self.error.setWordWrap(True)
        self.error.hide()
        self.body.addWidget(self.error)

        row = QHBoxLayout()
        self.hello_button = QPushButton('Windows Hello')
        self.hello_button.setToolTip('Unlock with your fingerprint, face or PIN')
        self.hello_button.clicked.connect(self.hello.emit)
        self.hello_button.setVisible(hello)
        row.addWidget(self.hello_button)
        row.addStretch(1)
        self.cancel = QPushButton('Cancel')
        self.cancel.clicked.connect(self.close)
        self.button = QPushButton(button)
        self.button.setProperty('role', 'primary')
        self.button.setDefault(True)
        self.button.clicked.connect(self._submit)
        row.addWidget(self.cancel)
        row.addWidget(self.button)
        self.body.addLayout(row)

    def showEvent(self, event):
        super().showEvent(event)
        self.password.setFocus()

    def eventFilter(self, watched, event):
        if watched is self.password and event.type() in (QEvent.KeyRelease, QEvent.FocusIn):
            self.caps.setVisible(win32.caps_lock_on())
        return super().eventFilter(watched, event)

    def _submit(self) -> None:
        password = self.password.text()
        if not password or not self.password.isEnabled():
            return
        self.error.hide()
        self.submitted.emit(password)

    def busy(self, text: str) -> None:
        self.password.setEnabled(False)
        self.button.setEnabled(False)
        self.hello_button.setEnabled(False)
        self.button.setText(text)

    def fail(self, message: str) -> None:
        self.password.setEnabled(True)
        self.button.setEnabled(True)
        self.hello_button.setEnabled(True)
        self.button.setText(self._button_text)
        self.error.setText(message)
        self.error.setVisible(bool(message))
        self.adjustSize()
        self.password.selectAll()
        self.password.setFocus()
        self.bring_back()

    def finish(self) -> None:
        """Close after success - closed listeners can tell from `succeeded`."""
        self.succeeded = True
        self.password.clear()
        self.close()
