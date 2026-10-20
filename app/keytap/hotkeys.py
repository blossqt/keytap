"""System-wide hotkeys (RegisterHotKey), and Windows' lock and sleep messages.

Hotkeys are registered for the main thread with no window, so WM_HOTKEY
arrives as a thread message; Qt's event loop shows every message to native
event filters before dispatching it, which is where Keytap picks it up.
"""

from __future__ import annotations

from ctypes import wintypes

from PySide6.QtCore import QAbstractNativeEventFilter, QCoreApplication, QObject, Signal
from PySide6.QtGui import QWindow

from . import win32

MOD_ALT, MOD_CONTROL, MOD_SHIFT, MOD_WIN, MOD_NOREPEAT = 0x1, 0x2, 0x4, 0x8, 0x4000

_MODIFIERS = {'ctrl': MOD_CONTROL, 'control': MOD_CONTROL, 'alt': MOD_ALT, 'shift': MOD_SHIFT,
              'win': MOD_WIN, 'meta': MOD_WIN}
_MODIFIER_NAMES = ((MOD_CONTROL, 'Ctrl'), (MOD_ALT, 'Alt'), (MOD_SHIFT, 'Shift'), (MOD_WIN, 'Win'))

_KEYS = {
    **{chr(c): c for c in range(ord('A'), ord('Z') + 1)},
    **{str(d): 0x30 + d for d in range(10)},
    **{f'F{n}': 0x6F + n for n in range(1, 25)},
    'Space': 0x20, 'Insert': 0x2D, 'Ins': 0x2D, 'Delete': 0x2E, 'Del': 0x2E, 'Home': 0x24, 'End': 0x23,
    'PgUp': 0x21, 'PageUp': 0x21, 'PgDown': 0x22, 'PageDown': 0x22, 'Left': 0x25, 'Up': 0x26,
    'Right': 0x27, 'Down': 0x28, 'Pause': 0x13, 'ScrollLock': 0x91, 'Backspace': 0x08, 'Return': 0x0D,
    'Enter': 0x0D, 'Tab': 0x09,
    ';': 0xBA, '=': 0xBB, ',': 0xBC, '-': 0xBD, '.': 0xBE, '/': 0xBF, '`': 0xC0,
    '[': 0xDB, '\\': 0xDC, ']': 0xDD, "'": 0xDE,
}
_LOOKUP = {name.lower(): vk for name, vk in _KEYS.items()}
_CANONICAL = {'Ins': 'Insert', 'Del': 'Delete', 'PageUp': 'PgUp', 'PageDown': 'PgDown', 'Return': 'Enter'}


_ESCAPE_ID = 0x7E00     # apart from the numbered hotkeys set() registers


class HotkeyError(ValueError):
    pass


def parse(text: str) -> tuple[int, int]:
    """'Ctrl+Alt+A' -> (modifiers, virtual key)."""
    parts = [p.strip() for p in (text or '').replace(' ', '').split('+')]
    if text.strip().endswith('++'):
        parts = parts[:-2] + ['=']      # Qt writes Ctrl++ for the key that has + on it
    if not parts[-1]:
        raise HotkeyError('a hotkey needs a key and at least one of Ctrl, Alt or Win')
    modifiers = 0
    for part in parts[:-1]:
        bit = _MODIFIERS.get(part.lower())
        if bit is None:
            raise HotkeyError(f'“{part}” is not Ctrl, Alt, Shift or Win')
        modifiers |= bit
    key = parts[-1]
    vk = _LOOKUP.get(key.lower())
    if vk is None:
        raise HotkeyError(f'Keytap cannot use {key} in a hotkey')
    if not modifiers & (MOD_CONTROL | MOD_ALT | MOD_WIN) and not 0x70 <= vk <= 0x87:
        raise HotkeyError('a hotkey needs Ctrl, Alt or Win, or an F key, or it would get in the way of typing')
    return modifiers, vk


def normalize(text: str) -> str:
    """The hotkey written the one way Keytap shows it: 'Ctrl+Alt+A'."""
    modifiers, vk = parse(text)
    key = next(k for k, v in _KEYS.items() if v == vk and k not in _CANONICAL)
    return '+'.join([name for bit, name in _MODIFIER_NAMES if modifiers & bit] + [key])


class _Filter(QAbstractNativeEventFilter):
    def __init__(self, handler):
        super().__init__()
        self._handler = handler

    def nativeEventFilter(self, event_type, message):
        if bytes(event_type) == b'windows_generic_MSG':
            msg = wintypes.MSG.from_address(int(message))
            if self._handler(msg):
                return True, 0
        return False, 0


class Hotkeys(QObject):
    """Registers hotkeys by action name and says when one is pressed."""
    pressed = Signal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._ids: dict[int, str] = {}
        self._escape = False
        self._filter = _Filter(self._message)
        QCoreApplication.instance().installNativeEventFilter(self._filter)

    def set(self, bindings: dict[str, str]) -> dict[str, str]:
        """Register {action: 'Ctrl+Alt+A'}; returns {action: problem} for those that failed."""
        self.clear()
        problems = {}
        for number, (action, text) in enumerate(bindings.items(), start=1):
            if not text:
                continue
            try:
                modifiers, vk = parse(text)
            except HotkeyError as error:
                problems[action] = str(error)
                continue
            if win32.user32.RegisterHotKey(None, number, modifiers | MOD_NOREPEAT, vk):
                self._ids[number] = action
            else:
                problems[action] = f'{normalize(text)} is already taken by another program'
        return problems

    def clear(self) -> None:
        for number in self._ids:
            win32.user32.UnregisterHotKey(None, number)
        self._ids.clear()

    def take_escape(self, take: bool) -> None:
        """Have Esc, on its own, come to Keytap ('escape') - only while the pop-up shows.

        Watching the key's state would miss a quick press; as a hotkey it is
        never missed. Esc then closes the pop-up instead of reaching the
        program, as with Bitwarden's in a browser.
        """
        if take and not self._escape:
            self._escape = bool(win32.user32.RegisterHotKey(None, _ESCAPE_ID, MOD_NOREPEAT, 0x1B))
        elif not take and self._escape:
            win32.user32.UnregisterHotKey(None, _ESCAPE_ID)
            self._escape = False

    def _message(self, msg) -> bool:
        if msg.message != win32.WM_HOTKEY or msg.hWnd:
            return False
        if msg.wParam == _ESCAPE_ID and self._escape:
            self.pressed.emit('escape')
            return True
        if msg.wParam in self._ids:
            self.pressed.emit(self._ids[msg.wParam])
            return True
        return False


class SessionWatcher(QObject):
    """Says when Windows locks or goes to sleep."""
    locking = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        # A window that is never shown, only there to receive the messages.
        self._window = QWindow()
        self._hwnd = int(self._window.winId())
        win32.watch_session(self._hwnd)
        self._filter = _Filter(self._message)
        QCoreApplication.instance().installNativeEventFilter(self._filter)

    def _message(self, msg) -> bool:
        if msg.hWnd != self._hwnd:
            return False
        if msg.message == win32.WM_WTSSESSION_CHANGE and msg.wParam == win32.WTS_SESSION_LOCK:
            self.locking.emit()
        elif msg.message == win32.WM_POWERBROADCAST and msg.wParam == win32.PBT_APMSUSPEND:
            self.locking.emit()
        return False
