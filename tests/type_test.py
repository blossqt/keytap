"""Keytap end to end, with real keystrokes.

    %LOCALAPPDATA%\\KeytapBuild\\venv\\Scripts\\python.exe tests\\type_test.py [--now] [--inline]

--inline runs only the pop-up checks (about 30 seconds).

Runs Keytap from source against a fake vault (tests/fake_bw.py), opens login
windows of its own (tests/target_window.py) and presses Keytap's hotkeys,
types into its cards, and checks what lands in the boxes. It takes the
keyboard and mouse for about a minute.

Every keystroke and click first checks that one of the test's own windows is
in front, and the test stops if anything else is. It waits until the PC has
been idle for 20 seconds before it starts, unless given --now, and will not
start over a full-screen program (a game). The hotkeys are moved to
Ctrl+Alt+Shift+F11/F12 so a real Keytap's are left alone.
"""

import ctypes
import json
import os
import secrets
import shutil
import subprocess
import sys
import time
from ctypes import wintypes
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT / 'app'))

from PySide6.QtCore import QCoreApplication  # noqa: E402
from PySide6.QtNetwork import QLocalSocket   # noqa: E402

from keytap import totp, typer, win32         # noqa: E402

WORK = ROOT / '.dev' / 'typetest'
INSTANCE = 'keytap-type-test'
VK_ESCAPE, VK_RETURN, VK_F11, VK_F12, VK_A = 0x1B, 0x0D, 0x7A, 0x7B, 0x41
HOTKEY_MODS = (win32.VK_CONTROL, win32.VK_MENU, win32.VK_SHIFT)
RFC_SHA1 = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'
UNICODE_PASSWORD = 'pä$$ wörd €😀{}+^%~'

user32 = win32.user32
user32.SetCursorPos.argtypes = [ctypes.c_int, ctypes.c_int]
user32.GetCursorPos.argtypes = [ctypes.POINTER(wintypes.POINT)]
user32.WindowFromPoint.argtypes = [wintypes.POINT]
user32.WindowFromPoint.restype = wintypes.HWND
user32.ClientToScreen.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.POINT)]
user32.mouse_event.argtypes = [wintypes.DWORD, wintypes.DWORD, wintypes.DWORD, wintypes.DWORD, ctypes.c_size_t]
user32.MonitorFromWindow.argtypes = [wintypes.HWND, wintypes.DWORD]
user32.MonitorFromWindow.restype = wintypes.HANDLE


class MONITORINFO(ctypes.Structure):
    _fields_ = [('cbSize', wintypes.DWORD), ('rcMonitor', wintypes.RECT), ('rcWork', wintypes.RECT),
                ('dwFlags', wintypes.DWORD)]


user32.GetMonitorInfoW.argtypes = [wintypes.HANDLE, ctypes.POINTER(MONITORINFO)]


class Abort(Exception):
    pass


def describe_at(point) -> str:
    hwnd = user32.WindowFromPoint(point)
    info = win32.window_info(hwnd) if hwnd else None
    return f'{info.exe} “{info.title}” ({info.class_name}, pid {info.pid})' if info else 'nothing'


MOUSEEVENTF_LEFTDOWN, MOUSEEVENTF_LEFTUP = 0x0002, 0x0004


def click_here() -> None:
    """A left click wherever the pointer is now - which the caller has checked."""
    events = []
    for button in (MOUSEEVENTF_LEFTDOWN, MOUSEEVENTF_LEFTUP):
        event = typer.INPUT(type=0)
        event.mi = typer.MOUSEINPUT(0, 0, 0, button, 0, 0)
        events.append(event)
    array = (typer.INPUT * 2)(*events)
    user32.SendInput(2, array, ctypes.sizeof(typer.INPUT))


def item(id, name, username, password, uris=(), totp_key='', fields=(), reprompt=0):
    return {'object': 'item', 'id': id, 'type': 1, 'reprompt': reprompt, 'name': name, 'favorite': False,
            'fields': [{'name': n, 'value': v, 'type': 0} for n, v in fields],
            'login': {'uris': [{'uri': u, 'match': None} for u in uris], 'username': username,
                      'password': password, 'totp': totp_key or None}, 'deletedDate': None}


class Run:
    def __init__(self):
        shutil.rmtree(WORK, ignore_errors=True)
        WORK.mkdir(parents=True)
        self.password = 'test-' + secrets.token_hex(6)     # the fake vault's, made up here
        self.vault = WORK / 'vault.json'
        self.vault.write_text(json.dumps({
            'email': 'test@example.com', 'password': self.password, 'signed_in': True, 'items': [
                item('1', 'Login form', 'ada@example.com', 'S3cret-pass!', ['title://Keytap Login Test']),
                item('2', 'Unicode', 'unicode-user', UNICODE_PASSWORD),
                item('3', 'Code login', 'otp-user', 'otp-pass', ['title://Keytap Code Test'], RFC_SHA1,
                     [('autotype', '{USERNAME}{TAB}{PASSWORD}{TAB}{TOTP}{ENTER}')], reprompt=1),
                item('4', 'Remember me', 'rem-user', 'rem-pass'),
                item('5', 'Compat', 'compat-user', 'Abc!@#123 xyz', ['title://Keytap Compat Test']),
                item('6', 'Inline login', 'inline-user', 'inline-pass', ['title://Keytap Inline Test']),
            ]}, ensure_ascii=False), encoding='utf-8')
        self.settings = WORK / 'settings.ini'
        self.write_settings(compat=False)
        self.keyboard = typer._Keyboard(None, compat=False)
        self.keytap_pid = 0
        self.target = None          # (pid, hwnd, result path, process)
        self.process = None

    def write_settings(self, compat: bool) -> None:
        self.settings.write_text('[hotkeys]\ntype=Ctrl+Alt+Shift+F11\npick=Ctrl+Alt+Shift+F12\n'
                                 f'[typing]\ncompat={"true" if compat else "false"}\nkey_delay=5\n'
                                 '[lock]\nidle_minutes=30\nwith_windows=true\n', encoding='utf-8')

    # ------------------------------------------------------------------ Keytap

    def start(self) -> None:
        env = dict(os.environ, KEYTAP_DEV='1', KEYTAP_INSTANCE=INSTANCE,
                   KEYTAP_BW=str(HERE / 'fake_bw.py'), KEYTAP_FAKE_VAULT=str(self.vault),
                   KEYTAP_FAKE_DELAY='0.3', KEYTAP_BW_DATA=str(WORK / 'bw'),
                   KEYTAP_SETTINGS=str(self.settings))
        self.process = subprocess.Popen([sys.executable, str(ROOT / 'app' / 'main.py')], env=env,
                                        stdout=open(WORK / 'keytap.log', 'w'), stderr=subprocess.STDOUT)
        self.wait(lambda: self.state().get('state') == 'locked', 20, 'Keytap to start')
        self.keytap_pid = self.state()['pid']

    def send(self, message: str) -> str:
        socket = QLocalSocket()
        socket.connectToServer(INSTANCE)
        if not socket.waitForConnected(1000):
            return ''
        socket.write(message.encode())
        socket.waitForBytesWritten(1000)
        answer = bytes(socket.readAll()).decode() if socket.waitForReadyRead(3000) else ''
        socket.disconnectFromServer()
        return answer

    def state(self) -> dict:
        answer = self.send('state')
        return json.loads(answer) if answer else {}

    def stop(self) -> None:
        if self.process and self.process.poll() is None:
            self.send('quit')
            try:
                self.process.wait(10)
            except subprocess.TimeoutExpired:
                self.process.kill()

    @staticmethod
    def wait(check, seconds: float, what: str):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            result = check()
            if result:
                return result
            time.sleep(0.1)
        raise AssertionError(f'timed out waiting for {what}')

    # ------------------------------------------------------------------ the test's own windows

    def open_target(self, title: str, boxes: int | str = 2, click: int = 0) -> None:
        self.close_target()
        result = WORK / f'result-{secrets.token_hex(3)}.json'
        process = subprocess.Popen([sys.executable, str(HERE / 'target_window.py'), title, str(boxes), str(result)])
        ready = Path(str(result) + '.ready')
        self.wait(ready.exists, 15, f'the “{title}” window')
        time.sleep(0.3)
        info = json.loads(ready.read_text())
        self.target = (info['pid'], info['hwnd'], result, process)
        self.boxes = info['boxes']
        if click:
            # The window may already have the keyboard in its first box, with the
            # pop-up under it covering the next box - Esc it away, as a person would.
            time.sleep(0.6)
            if (self.state().get('inline') or {}).get('visible'):
                self.key(VK_ESCAPE)
                self.wait(lambda: not self.state()['inline']['visible'], 5, 'Esc to close the pop-up')
        self.click_into_target(click)

    def close_target(self) -> None:
        # By the window's own process id: the venv's python.exe is only a
        # launcher, and killing it would leave the window up.
        if self.target:
            try:
                os.kill(self.target[0], 15)
            except OSError:
                pass
            self.target[3].wait(10)
        self.target = None

    def ours(self) -> bool:
        pid = win32.foreground_pid()
        return pid in (self.keytap_pid, self.target[0] if self.target else -1)

    def guard(self) -> None:
        if not self.ours():
            front = win32.foreground_window()
            raise Abort(f'another program is in front ({front.exe if front else "?"}) - stopped')

    def click_into_target(self, box: int = 0) -> None:
        pid = self.target[0]
        self.click_on(self.boxes[box], pid)
        deadline = time.monotonic() + 5
        while win32.foreground_pid() != pid:
            if time.monotonic() > deadline:
                raise Abort('the test window did not come to the front - stopped')
            time.sleep(0.1)

    def click_on(self, xy, pid: int) -> None:
        """Click a screen point, only if a window of process pid is under it."""
        point = wintypes.POINT(*xy)
        deadline = time.monotonic() + 3            # a new window can take a moment to settle
        while win32.window_pid(user32.WindowFromPoint(point)) != pid:
            if time.monotonic() > deadline:
                raise Abort(f'the test window is covered at {xy} by {describe_at(point)} - stopped')
            time.sleep(0.1)
        saved = wintypes.POINT()
        user32.GetCursorPos(ctypes.byref(saved))
        user32.SetCursorPos(point.x, point.y)
        time.sleep(0.1)
        # Click only if the pointer really is where it was put, over this window.
        now = wintypes.POINT()
        user32.GetCursorPos(ctypes.byref(now))
        under = user32.WindowFromPoint(now)
        drifted = abs(now.x - point.x) > 8 or abs(now.y - point.y) > 8      # a nudged mouse, say
        if drifted or not under or win32.window_pid(under) != pid:
            user32.SetCursorPos(saved.x, saved.y)
            raise Abort(f'the pointer is at {(now.x, now.y)}, not {xy}, over {describe_at(now)}'
                        ' - stopped without clicking')
        click_here()
        time.sleep(0.4)        # Windows acts on the click before the pointer goes back
        user32.SetCursorPos(saved.x, saved.y)

    def inline_up(self, kind: str, first_row: str) -> None:
        def ready():
            inline = self.state().get('inline') or {}
            return (inline.get('visible') and inline.get('kind') == kind
                    and inline.get('rows', [''])[0] == first_row)
        self.wait(ready, 10, f'the pop-up under the {kind} box')

    def click_inline(self, row: int) -> None:
        x, y = map(int, self.send(f'inline-point {row}').split())
        self.click_on((x, y), self.keytap_pid)

    def result(self, seconds: float = 15) -> list[str]:
        path = self.target[2]
        self.wait(path.exists, seconds, 'the test window to be filled in')
        return json.loads(path.read_text(encoding='utf-8'))

    # ------------------------------------------------------------------ keys

    def hotkey(self, vk: int) -> None:
        self.guard()
        self.keyboard.press(vk, HOTKEY_MODS)

    def type(self, text: str) -> None:
        for char in text:
            self.guard()
            self.keyboard.character(char)
            time.sleep(0.01)

    def key(self, vk: int, modifiers=()) -> None:
        self.guard()
        self.keyboard.press(vk, modifiers)

    def card_up(self, name: str) -> None:
        self.wait(lambda: self.state().get('card') == name, 10, f'Keytap’s {name}')
        self.wait(lambda: win32.foreground_pid() == self.keytap_pid, 5, f'the {name} to take the keyboard')
        time.sleep(0.25)


# ---------------------------------------------------------------------- the checks


def check_unlock_then_type(run: Run) -> None:
    run.open_target('Keytap Login Test')
    run.hotkey(VK_F11)
    run.card_up('UnlockCard')
    run.type('wrong password')
    run.key(VK_RETURN)
    time.sleep(1.5)
    assert run.state()['card'] == 'UnlockCard', 'a wrong password closed the unlock card'
    assert run.state()['state'] == 'locked'
    run.key(0x41, (win32.VK_CONTROL,))      # select all, then type over it
    run.type(run.password)
    run.key(VK_RETURN)
    assert run.result() == ['ada@example.com', 'S3cret-pass!'], run.result()
    assert run.state()['state'] == 'unlocked'


def check_picker_and_unicode(run: Run) -> None:
    run.open_target('Keytap Picker Test')
    run.hotkey(VK_F11)                       # nothing matches, so it asks
    run.card_up('Picker')
    run.type('unicode')
    run.key(VK_RETURN)
    got = run.result()
    assert got == ['unicode-user', UNICODE_PASSWORD], got


def check_reprompt_totp_and_own_sequence(run: Run) -> None:
    run.open_target('Keytap Code Test', boxes=3)
    run.hotkey(VK_F11)
    run.card_up('UnlockCard')                # the login asks for the master password again
    run.type(run.password)
    run.key(VK_RETURN)
    got = run.result()
    now = time.time()
    codes = {totp.code(RFC_SHA1, at=now), totp.code(RFC_SHA1, at=now - 30)}
    assert got[:2] == ['otp-user', 'otp-pass'] and got[2] in codes, got


def check_remember(run: Run) -> None:
    run.open_target('Keytap Remember Test')
    run.hotkey(VK_F12)                       # always asks
    run.card_up('Picker')
    run.type('remember')
    run.key(VK_A, (win32.VK_MENU,))          # Alt+A ticks "Always use"
    run.key(VK_RETURN)
    assert run.result() == ['rem-user', 'rem-pass']
    links = run.state()['links']
    assert links.get('python.exe|Keytap Remember Test') == '4', links
    run.open_target('Keytap Remember Test')
    run.hotkey(VK_F11)                       # remembered: types straight away
    assert run.result() == ['rem-user', 'rem-pass']
    assert run.state()['card'] == ''


def check_escape_and_lock(run: Run) -> None:
    run.open_target('Keytap Escape Test')
    run.hotkey(VK_F12)
    run.card_up('Picker')
    run.key(VK_ESCAPE)
    run.wait(lambda: run.state().get('card') == '', 5, 'the picker to close')
    assert not run.target[2].exists(), 'Escape still typed something'
    run.send('lock')
    run.wait(lambda: run.state().get('state') == 'locked', 5, 'Keytap to lock')
    assert run.state()['logins'] == 0


def check_compat_typing(run: Run) -> None:
    run.write_settings(compat=True)
    run.send('reload')
    run.open_target('Keytap Compat Test')
    run.hotkey(VK_F11)
    run.card_up('UnlockCard')
    run.type(run.password)
    run.key(VK_RETURN)
    got = run.result()
    assert got == ['compat-user', 'Abc!@#123 xyz'], got


def check_inline_username(run: Run) -> None:
    run.write_settings(compat=False)
    run.send('reload')
    run.open_target('Keytap Inline Test', 'tp')
    run.inline_up('username', 'Inline login')
    run.click_inline(0)
    got = run.result()
    assert got == ['inline-user', 'inline-pass'], got


def check_inline_password_box(run: Run) -> None:
    run.open_target('Keytap Inline Test', 'tp', click=1)
    run.inline_up('password', 'Inline login')
    run.click_inline(0)
    got = run.result()
    assert got == ['', 'inline-pass'], got        # the password only, in its own box


def check_hotkey_in_password_box(run: Run) -> None:
    run.open_target('Keytap Inline Test', 'tp', click=1)
    run.inline_up('password', 'Inline login')
    run.hotkey(VK_F11)
    got = run.result()
    assert got == ['', 'inline-pass'], got


def check_inline_escape(run: Run) -> None:
    run.open_target('Keytap Inline Test', 'tp')
    run.inline_up('username', 'Inline login')
    run.key(VK_ESCAPE)
    run.wait(lambda: not run.state()['inline']['visible'], 5, 'Esc to close the pop-up')
    time.sleep(0.5)
    assert not run.state()['inline']['visible'], 'the pop-up came back by itself'


def check_inline_unlock(run: Run) -> None:
    run.send('lock')
    run.wait(lambda: run.state().get('state') == 'locked', 5, 'Keytap to lock')
    run.open_target('Keytap Inline Test', 'tp')
    run.inline_up('username', 'Unlock Keytap')
    run.click_inline(0)
    run.card_up('UnlockCard')
    run.type(run.password)
    run.key(VK_RETURN)
    run.inline_up('username', 'Inline login')     # back in the box, now with the logins
    run.click_inline(0)
    got = run.result()
    assert got == ['inline-user', 'inline-pass'], got


INLINE_CHECKS = [check_unlock_then_type, check_inline_username, check_inline_password_box,
                 check_hotkey_in_password_box, check_inline_escape, check_inline_unlock]

CHECKS = [check_unlock_then_type, check_picker_and_unicode, check_reprompt_totp_and_own_sequence,
          check_remember, check_escape_and_lock, check_compat_typing,
          check_inline_username, check_inline_password_box, check_hotkey_in_password_box,
          check_inline_escape, check_inline_unlock]


def fullscreen_in_front() -> bool:
    hwnd = user32.GetForegroundWindow()
    rect = win32.window_rect(hwnd)
    info = MONITORINFO(ctypes.sizeof(MONITORINFO))
    if not rect or not user32.GetMonitorInfoW(user32.MonitorFromWindow(hwnd, 2), ctypes.byref(info)):
        return False
    m = info.rcMonitor
    front = win32.window_info(hwnd)
    return (rect[0] <= m.left and rect[1] <= m.top and rect[2] >= m.right and rect[3] >= m.bottom
            and not (front and front.is_shell))


def main() -> int:
    # Real screen pixels throughout. Unaware, Windows scales this process's
    # coordinates - differently per monitor when their scaling differs.
    ctypes.windll.user32.SetProcessDpiAwarenessContext(ctypes.c_void_p(-4))
    if '--now' not in sys.argv:
        print('waiting for the PC to be idle for 20 seconds, with no full-screen program in front…', flush=True)
        while win32.idle_seconds() < 20 or fullscreen_in_front():
            time.sleep(2)
    if fullscreen_in_front():
        front = win32.foreground_window()
        print(f'a full-screen program is in front ({front.exe if front else "?"}) - not starting')
        return 2
    QCoreApplication(sys.argv[:1])
    run = Run()
    failures = 0
    try:
        run.start()
        for check in (INLINE_CHECKS if '--inline' in sys.argv else CHECKS):
            started = time.monotonic()
            try:
                check(run)
                print(f'ok    {check.__name__} ({time.monotonic() - started:.1f}s)', flush=True)
            except AssertionError as error:
                failures += 1
                print(f'FAIL  {check.__name__}: {error}', flush=True)
    except Abort as error:
        print(f'STOPPED: {error}', flush=True)
        return 3
    finally:
        run.close_target()
        run.stop()
        log = (WORK / 'keytap.log').read_text(errors='replace').strip()
        if log:
            print('--- keytap log ---\n' + log)
        if run.password in log:
            print('FAIL  the test password appeared in Keytap’s log')
            failures += 1
    print('all passed' if not failures else f'{failures} failed')
    return 1 if failures else 0


if __name__ == '__main__':
    sys.exit(main())
