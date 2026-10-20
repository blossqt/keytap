"""Noticing when a login box gets the keyboard, in any program.

Two layers, so programs Keytap has no business with are never disturbed:

1. Windows' focus WinEvents, which every program sends anyway and which cost
   nothing to listen to, say which window the keyboard went to.
2. Only for a window that passes the controller's filter (not a browser, not
   muted, the vault signed in) does Keytap ask UI Automation - the interface
   screen readers use - about the focused element: is it a password box, or
   a text box with a password box beside it? Asking can make Chromium-based
   apps switch on their accessibility support, which costs them a little;
   browsers are never asked.

The UI Automation calls run on a thread of their own (COM's multithreaded
apartment), since another program can take its time answering.
"""

from __future__ import annotations

import ctypes
import queue
import sys
import threading
import traceback
from collections.abc import Callable
from ctypes import wintypes
from dataclasses import dataclass

from PySide6.QtCore import QObject, QTimer, Signal

from . import win32

EVENT_SYSTEM_FOREGROUND = 0x0003
EVENT_OBJECT_FOCUS = 0x8005
WINEVENT_OUTOFCONTEXT = 0x0000
WINEVENT_SKIPOWNPROCESS = 0x0002

UIA_CONTROL_TYPE_PROPERTY = 30003
UIA_IS_PASSWORD_PROPERTY = 30019
UIA_EDIT = 50004
UIA_DOCUMENT, UIA_PANE, UIA_CUSTOM, UIA_GROUP = 50030, 50033, 50025, 50026
TREE_SCOPE_DESCENDANTS = 4
_ANCESTORS_TO_SEARCH = 3        # how far up from a text box to look for its password box
_NOT_LOGIN_WORDS = ('search', 'find', 'filter', 'chat', 'message', 'comment', 'url', 'address')
_CHROMIUM_CLASSES = ('Chrome_RenderWidgetHostHWND', 'Chrome_WidgetWin_1', 'Chrome_WidgetWin_0')

WINEVENTPROC = ctypes.WINFUNCTYPE(None, wintypes.HANDLE, wintypes.DWORD, wintypes.HWND, wintypes.LONG,
                                  wintypes.LONG, wintypes.DWORD, wintypes.DWORD)
win32.user32.SetWinEventHook.argtypes = [wintypes.DWORD, wintypes.DWORD, wintypes.HMODULE, WINEVENTPROC,
                                         wintypes.DWORD, wintypes.DWORD, wintypes.DWORD]
win32.user32.SetWinEventHook.restype = wintypes.HANDLE
win32.user32.UnhookWinEvent.argtypes = [wintypes.HANDLE]
win32.user32.UnhookWinEvent.restype = wintypes.BOOL


@dataclass(frozen=True)
class LoginField:
    window: win32.WindowInfo
    kind: str                           # 'password' or 'username'
    rect: tuple[int, int, int, int]     # the box, in physical screen pixels
    key: tuple                          # UI Automation's id for the box, to know it again


def _automation():
    """UI Automation for the calling thread, which it puts in COM's multithreaded apartment."""
    sys.coinit_flags = 0        # COINIT_MULTITHREADED, read when comtypes is first imported
    import atexit

    import comtypes
    import comtypes.client
    # comtypes would undo COM's setup at exit on the main thread - Qt's thread,
    # which it never set up. Keep only its other job: telling leftover COM
    # pointers not to call into COM while Python shuts down.
    if getattr(comtypes, '_shutdown', None) is not None and not getattr(_automation, 'patched', False):
        atexit.unregister(comtypes._shutdown)

        def quiet_exit():
            meta = getattr(comtypes, '_cominterface_meta', None)
            if meta is not None:
                meta._com_shutting_down = True
        atexit.register(quiet_exit)
        _automation.patched = True
    try:
        from comtypes.gen import UIAutomationClient as uia
    except ImportError:
        uia = comtypes.client.GetModule('UIAutomationCore.dll')
    automation = comtypes.client.CreateObject(uia.CUIAutomation, interface=uia.IUIAutomation)
    try:
        tuned = automation.QueryInterface(uia.IUIAutomation2)
        tuned.ConnectionTimeout = 1500
        tuned.TransactionTimeout = 2000
    except Exception:  # noqa: BLE001 - older Windows: default timeouts
        pass
    return automation, automation.CreatePropertyCondition(UIA_IS_PASSWORD_PROPERTY, True)


def probe() -> str:
    """'' if UI Automation can be set up here, else why not (the build's self-test)."""
    problem = []

    def run():
        try:
            automation, _ = _automation()
            automation.GetRootElement()
        except Exception as error:  # noqa: BLE001
            problem.append(f'{type(error).__name__}: {error}')
    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    thread.join(20)
    return problem[0] if problem else ('' if not thread.is_alive() else 'UI Automation did not answer')


class _Relay(QObject):
    found = Signal(int, object)         # generation, LoginField or None


class FieldWatcher(QObject):
    """field(LoginField) when a login box gets the keyboard; field(None) when it leaves."""
    field = Signal(object)

    def __init__(self, wanted: Callable[[win32.WindowInfo], bool], parent=None):
        super().__init__(parent)
        self._wanted = wanted
        self._hooks: list = []
        self._proc = WINEVENTPROC(self._event)
        self._generation = 0
        self._target: win32.WindowInfo | None = None
        self._requests: queue.Queue = queue.Queue()
        self._relay = _Relay()
        self._relay.found.connect(self._found)
        self._settle = QTimer(self, singleShot=True, interval=80)
        self._settle.timeout.connect(self._ask)
        self._thread: threading.Thread | None = None
        self.failed = ''

    # ------------------------------------------------------------------ on and off

    def start(self) -> None:
        if self._hooks:
            return
        if self._thread is None:
            self._thread = threading.Thread(target=self._work, name='keytap-uia', daemon=True)
            self._thread.start()
        for event in (EVENT_SYSTEM_FOREGROUND, EVENT_OBJECT_FOCUS):
            hook = win32.user32.SetWinEventHook(event, event, None, self._proc, 0, 0,
                                                WINEVENT_OUTOFCONTEXT | WINEVENT_SKIPOWNPROCESS)
            if hook:
                self._hooks.append(hook)

    def stop(self) -> None:
        for hook in self._hooks:
            win32.user32.UnhookWinEvent(hook)
        self._hooks.clear()
        self._generation += 1
        self._target = None
        self.field.emit(None)

    @property
    def running(self) -> bool:
        return bool(self._hooks)

    def recheck(self) -> None:
        """Look at whatever has the keyboard now (after unlocking, say)."""
        hwnd = win32.user32.GetForegroundWindow()
        if hwnd:
            self._event(None, EVENT_OBJECT_FOCUS, hwnd, 0, 0, 0, 0)

    # ------------------------------------------------------------------ WinEvents (UI thread)

    def _event(self, hook, event, hwnd, id_object, id_child, thread, when) -> None:
        try:
            window = win32.window_info(hwnd)
            self._generation += 1
            if window is None or window.pid == 0 or window.is_shell or not self._wanted(window):
                self._target = None
                self._settle.stop()
                self.field.emit(None)
                return
            self._target = window
            self._settle.start()        # focus events come in bursts; ask once they settle
        except Exception:  # noqa: BLE001 - a callback from Windows must never raise
            traceback.print_exc()

    def _ask(self) -> None:
        if self._target is not None:
            self._requests.put((self._generation, self._target, 0))

    def _found(self, generation: int, field) -> None:
        if generation == self._generation and self._hooks:
            self.field.emit(field)

    # ------------------------------------------------------------------ UI Automation (its own thread)

    def _work(self) -> None:
        try:
            automation, password_box = _automation()
        except Exception as error:  # noqa: BLE001
            traceback.print_exc()
            self.failed = str(error)
            return

        while True:
            generation, window, attempt = self._requests.get()
            while not self._requests.empty():           # only the latest matters
                generation, window, attempt = self._requests.get()
            try:
                field, retry = self._inspect(automation, password_box, window)
            except Exception:  # noqa: BLE001 - the program went away, or would not answer
                field, retry = None, False
            if retry and attempt == 0:
                # A Chromium app builds its accessibility tree only when first
                # asked, so the first answer can be the page rather than the box.
                threading.Timer(0.5, lambda g=generation, w=window: self._requests.put((g, w, 1))).start()
                continue
            self._relay.found.emit(generation, field)

    @staticmethod
    def _inspect(automation, password_box, window) -> tuple[LoginField | None, bool]:
        element = automation.GetFocusedElement()
        if element is None or element.CurrentProcessId != window.pid:
            return None, False
        control = element.CurrentControlType
        if control != UIA_EDIT:
            chromium = window.class_name in _CHROMIUM_CLASSES
            return None, chromium and control in (UIA_DOCUMENT, UIA_PANE, UIA_CUSTOM, UIA_GROUP)
        if not element.CurrentIsEnabled:
            return None, False
        rect = element.CurrentBoundingRectangle
        box = (rect.left, rect.top, rect.right, rect.bottom)
        if box[2] - box[0] < 20 or box[3] - box[1] < 8:
            return None, False
        key = tuple(element.GetRuntimeId() or ())
        if element.CurrentIsPassword:
            return LoginField(window, 'password', box, key), False
        words = f'{element.CurrentName} {element.CurrentAutomationId}'.lower()
        if any(word in words for word in _NOT_LOGIN_WORDS):
            return None, False
        walker = automation.ControlViewWalker
        node = element
        for _ in range(_ANCESTORS_TO_SEARCH):
            node = walker.GetParentElement(node)
            if node is None or node.CurrentProcessId != window.pid:
                break
            if node.FindFirst(TREE_SCOPE_DESCENDANTS, password_box):
                return LoginField(window, 'username', box, key), False
        return None, False
