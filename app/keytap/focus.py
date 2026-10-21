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

A box on a web page inside a program - an app's built-in browser, or an app
made of web pages, like Discord - also says which page: Chromium gives each
page's document its address as its value. Keytap then goes by that website,
as Bitwarden's extension would in a browser.

Before typing after one of Keytap's own cards had the keyboard (the picker, an
unlock), the box it came from gets it back, and Keytap types only once that
box has it. Some programs put the keyboard elsewhere on coming back: Claude's
desktop app puts it on its own page rather than in the box in its browser.

The UI Automation calls run on a thread of their own (COM's multithreaded
apartment), since another program can take its time answering.
"""

from __future__ import annotations

import ctypes
import itertools
import queue
import sys
import threading
import time
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
UIA_FRAMEWORK_ID_PROPERTY = 30024
UIA_VALUE_PATTERN = 10002
UIA_EDIT = 50004
UIA_DOCUMENT, UIA_PANE, UIA_CUSTOM, UIA_GROUP = 50030, 50033, 50025, 50026
TREE_SCOPE_DESCENDANTS = 4
_ANCESTORS_TO_SEARCH = 3        # how far up from a text box to look for its password box
_NOT_LOGIN_WORDS = ('search', 'find', 'filter', 'chat', 'message', 'comment', 'url', 'address')
# ...unless it says it is for signing in: "Username or email address" is a login box.
_LOGIN_WORDS = ('user', 'email', 'e-mail', 'login', 'log in', 'sign in', 'account', 'phone')
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
    page: str = ''                      # the address of the web page it is on, if it is on one


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


def is_login_name(words: str) -> bool:
    """Whether a text box's name and id leave it possibly a login box: not a search, chat or
    address box - unless it also says it is for signing in."""
    words = words.lower()
    return any(word in words for word in _LOGIN_WORDS) or not any(word in words for word in _NOT_LOGIN_WORDS)


def page_address(automation, element) -> str:
    """The address of the web page a box is on, or '' if it is not on one.

    Only Chromium's pages count (Chrome, Edge, Electron, WebView2, CEF): their
    documents' value is the page's address. Another program's document - a
    rich text box, say - has its text as its value instead. A page that will
    not say counts as none: the box is still offered, by its program."""
    try:
        pages = automation.CreateAndCondition(
            automation.CreatePropertyCondition(UIA_CONTROL_TYPE_PROPERTY, UIA_DOCUMENT),
            automation.CreatePropertyCondition(UIA_FRAMEWORK_ID_PROPERTY, 'Chrome'))
        # The nearest page around the box: for a box in a frame, the frame's own page.
        page = automation.CreateTreeWalker(pages).GetParentElement(element)
        if not page or page.CurrentProcessId != element.CurrentProcessId:     # comtypes: NULL is falsy
            return ''
        from comtypes.gen import UIAutomationClient as uia
        pattern = page.GetCurrentPattern(UIA_VALUE_PATTERN)
        if not pattern:
            return ''
        address = str(pattern.QueryInterface(uia.IUIAutomationValuePattern).CurrentValue or '').strip()
    except Exception:  # noqa: BLE001 - the program went away, or would not answer
        return ''
    return address if address.lower().startswith(('https://', 'http://')) else ''


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
    answered = Signal(int, object)      # a hold or give-back request's number, and its answer


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
        self._relay.answered.connect(self._reply)
        self._settle = QTimer(self, singleShot=True, interval=80)
        self._settle.timeout.connect(self._ask)
        self._thread: threading.Thread | None = None
        self._last: LoginField | None = None       # the latest answer, while nothing has moved since
        self._answered = -1
        self._waiting: dict[int, Callable] = {}    # hold and give-back requests, by number
        self._numbers = itertools.count(1)
        self.failed = ''

    # ------------------------------------------------------------------ on and off

    def _ensure_thread(self) -> None:
        if self._thread is None:
            self._thread = threading.Thread(target=self._work, name='keytap-uia', daemon=True)
            self._thread.start()

    def start(self) -> None:
        if self._hooks:
            return
        self._ensure_thread()
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
        self._last = None
        self.field.emit(None)

    @property
    def running(self) -> bool:
        return bool(self._hooks)

    def current(self, window) -> LoginField | None:
        """The login box in this window that has the keyboard, if Keytap knows of one and the
        keyboard has not moved since it last looked: a hotkey goes by its web page."""
        field = self._last
        if field is None or self._answered != self._generation or field.window.hwnd != window.hwnd:
            return None
        return field

    # ------------------------------------------------------------------ handing the keyboard back

    def hold(self, window, then: Callable[[], None]) -> None:
        """Note which box in this window has the keyboard, before a card of Keytap's takes it,
        so give_back can return it to that same box. then() runs once it is noted."""
        self._request('hold', window, lambda _: then(), wait_ms=700, fallback=None)

    def give_back(self, window, then: Callable[[bool], None]) -> None:
        """Hand the keyboard back to the box hold() noted in this window (the window is already in
        front), and say whether that box has it. then(False) if the box is gone or the keyboard
        went elsewhere: Claude's app, say, puts it on its own page rather than back in the box
        in its browser, and typing there would send a password to the wrong place."""
        self._request('give', window, then, wait_ms=3000, fallback=False)

    def _request(self, kind: str, window, then, wait_ms: int, fallback) -> None:
        if self.failed:                 # no UI Automation here at all: nothing to note or check
            QTimer.singleShot(0, lambda: then(None if kind == 'hold' else True))
            return
        self._ensure_thread()
        number = next(self._numbers)
        self._waiting[number] = then
        self._requests.put((kind, number, window))
        # A program slow to answer - or UI Automation turned out not to start, and can't check.
        QTimer.singleShot(wait_ms, lambda: self._reply(number, True if kind == 'give' and self.failed else fallback))

    def _reply(self, number: int, answer) -> None:
        then = self._waiting.pop(number, None)
        if then is not None:
            then(answer)

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
                self._last = None
                self._settle.stop()
                self.field.emit(None)
                return
            self._target = window
            self._settle.start()        # focus events come in bursts; ask once they settle
        except Exception:  # noqa: BLE001 - a callback from Windows must never raise
            traceback.print_exc()

    def _ask(self) -> None:
        if self._target is not None:
            self._requests.put(('look', self._generation, self._target, 0))

    def _found(self, generation: int, field) -> None:
        if generation == self._generation and self._hooks:
            self._last, self._answered = field, generation
            self.field.emit(field)

    # ------------------------------------------------------------------ UI Automation (its own thread)

    def _work(self) -> None:
        try:
            automation, password_box = _automation()
        except Exception as error:  # noqa: BLE001
            traceback.print_exc()
            self.failed = str(error)
            return

        held = None                 # (hwnd, element): the box a card of Keytap's took the keyboard from
        while True:
            requests = [self._requests.get()]
            while not self._requests.empty():
                requests.append(self._requests.get())
            for kind, number, window in (r for r in requests if r[0] != 'look'):     # in order
                if kind == 'hold':
                    held = self._hold(automation, window)
                    self._relay.answered.emit(number, None)
                else:
                    self._relay.answered.emit(number, self._give(automation, window, held))
            looks = [r for r in requests if r[0] == 'look']
            if not looks:
                continue
            _, generation, window, attempt = looks[-1]      # only the latest matters
            try:
                field, retry = self._inspect(automation, password_box, window)
            except Exception:  # noqa: BLE001 - the program went away, or would not answer
                field, retry = None, False
            if retry and attempt == 0:
                # A Chromium app builds its accessibility tree only when first
                # asked, so the first answer can be the page rather than the box.
                threading.Timer(0.5, lambda g=generation, w=window: self._requests.put(('look', g, w, 1))).start()
                continue
            self._relay.found.emit(generation, field)

    @staticmethod
    def _hold(automation, window):
        try:
            element = automation.GetFocusedElement()
            if element and element.CurrentProcessId == window.pid:
                return window.hwnd, element
        except Exception:  # noqa: BLE001 - the program went away, or would not answer
            pass
        return None

    @staticmethod
    def _give(automation, window, held) -> bool:
        if held is None or held[0] != window.hwnd:
            return True             # nothing noted for this window (a program UI Automation can't see): as before
        element = held[1]
        try:
            if automation.CompareElements(automation.GetFocusedElement(), element):
                return True
            element.SetFocus()
            deadline = time.monotonic() + 0.8          # a web page moves its focus a moment later
            while time.monotonic() < deadline:
                if automation.CompareElements(automation.GetFocusedElement(), element):
                    return True
                time.sleep(0.05)
        except Exception:  # noqa: BLE001 - the box, or its program, is gone
            pass
        return False

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
            return LoginField(window, 'password', box, key, page_address(automation, element)), False
        words = f'{element.CurrentName} {element.CurrentAutomationId}'.lower()
        if not is_login_name(words):
            return None, False
        walker = automation.ControlViewWalker
        node = element
        for _ in range(_ANCESTORS_TO_SEARCH):
            node = walker.GetParentElement(node)
            if node is None or node.CurrentProcessId != window.pid:
                break
            if node.FindFirst(TREE_SCOPE_DESCENDANTS, password_box):
                return LoginField(window, 'username', box, key, page_address(automation, element)), False
        return None, False
