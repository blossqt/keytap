"""The Win32 calls Keytap needs, made through ctypes."""

from __future__ import annotations

import ctypes
import os
import subprocess
import sys
import winreg
from ctypes import wintypes
from dataclasses import dataclass
from pathlib import Path

user32 = ctypes.WinDLL('user32', use_last_error=True)
kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
advapi32 = ctypes.WinDLL('advapi32', use_last_error=True)
wtsapi32 = ctypes.WinDLL('wtsapi32', use_last_error=True)

HWND = wintypes.HWND
DWORD = wintypes.DWORD
WNDENUMPROC = ctypes.WINFUNCTYPE(wintypes.BOOL, HWND, wintypes.LPARAM)

user32.GetForegroundWindow.restype = HWND
user32.GetWindowTextLengthW.argtypes = [HWND]
user32.GetWindowTextLengthW.restype = ctypes.c_int
user32.GetWindowTextW.argtypes = [HWND, wintypes.LPWSTR, ctypes.c_int]
user32.GetWindowTextW.restype = ctypes.c_int
user32.GetClassNameW.argtypes = [HWND, wintypes.LPWSTR, ctypes.c_int]
user32.GetClassNameW.restype = ctypes.c_int
user32.GetWindowThreadProcessId.argtypes = [HWND, ctypes.POINTER(DWORD)]
user32.GetWindowThreadProcessId.restype = DWORD
user32.GetAncestor.argtypes = [HWND, wintypes.UINT]
user32.GetAncestor.restype = HWND
user32.EnumChildWindows.argtypes = [HWND, WNDENUMPROC, wintypes.LPARAM]
user32.EnumChildWindows.restype = wintypes.BOOL
user32.IsWindow.argtypes = [HWND]
user32.IsWindow.restype = wintypes.BOOL
user32.IsIconic.argtypes = [HWND]
user32.IsIconic.restype = wintypes.BOOL
user32.ShowWindow.argtypes = [HWND, ctypes.c_int]
user32.ShowWindow.restype = wintypes.BOOL
user32.SetForegroundWindow.argtypes = [HWND]
user32.SetForegroundWindow.restype = wintypes.BOOL
user32.BringWindowToTop.argtypes = [HWND]
user32.BringWindowToTop.restype = wintypes.BOOL
user32.AttachThreadInput.argtypes = [DWORD, DWORD, wintypes.BOOL]
user32.AttachThreadInput.restype = wintypes.BOOL
user32.GetWindowRect.argtypes = [HWND, ctypes.POINTER(wintypes.RECT)]
user32.GetWindowRect.restype = wintypes.BOOL
user32.GetAsyncKeyState.argtypes = [ctypes.c_int]
user32.GetAsyncKeyState.restype = ctypes.c_short
user32.GetKeyState.argtypes = [ctypes.c_int]
user32.GetKeyState.restype = ctypes.c_short
user32.RegisterHotKey.argtypes = [HWND, ctypes.c_int, wintypes.UINT, wintypes.UINT]
user32.RegisterHotKey.restype = wintypes.BOOL
user32.UnregisterHotKey.argtypes = [HWND, ctypes.c_int]
user32.UnregisterHotKey.restype = wintypes.BOOL
kernel32.GetCurrentThreadId.restype = DWORD
kernel32.GetCurrentProcess.restype = wintypes.HANDLE
kernel32.GetTickCount.restype = DWORD
kernel32.OpenProcess.argtypes = [DWORD, wintypes.BOOL, DWORD]
kernel32.OpenProcess.restype = wintypes.HANDLE
kernel32.QueryFullProcessImageNameW.argtypes = [wintypes.HANDLE, DWORD, wintypes.LPWSTR, ctypes.POINTER(DWORD)]
kernel32.QueryFullProcessImageNameW.restype = wintypes.BOOL
kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
kernel32.CloseHandle.restype = wintypes.BOOL
advapi32.OpenProcessToken.argtypes = [wintypes.HANDLE, DWORD, ctypes.POINTER(wintypes.HANDLE)]
advapi32.OpenProcessToken.restype = wintypes.BOOL
advapi32.GetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, DWORD, ctypes.POINTER(DWORD)]
advapi32.GetTokenInformation.restype = wintypes.BOOL
advapi32.GetSidSubAuthorityCount.argtypes = [ctypes.c_void_p]
advapi32.GetSidSubAuthorityCount.restype = ctypes.POINTER(ctypes.c_ubyte)
advapi32.GetSidSubAuthority.argtypes = [ctypes.c_void_p, DWORD]
advapi32.GetSidSubAuthority.restype = ctypes.POINTER(DWORD)
wtsapi32.WTSRegisterSessionNotification.argtypes = [HWND, DWORD]
wtsapi32.WTSRegisterSessionNotification.restype = wintypes.BOOL


class LASTINPUTINFO(ctypes.Structure):
    _fields_ = [('cbSize', wintypes.UINT), ('dwTime', DWORD)]


user32.GetLastInputInfo.argtypes = [ctypes.POINTER(LASTINPUTINFO)]
user32.GetLastInputInfo.restype = wintypes.BOOL

VK_SHIFT = 0x10
VK_CONTROL = 0x11
VK_MENU = 0x12      # Alt
VK_CAPITAL = 0x14
VK_LWIN = 0x5B
VK_RWIN = 0x5C
MODIFIER_KEYS = (VK_SHIFT, VK_CONTROL, VK_MENU, VK_LWIN, VK_RWIN)

WM_HOTKEY = 0x0312
WM_WTSSESSION_CHANGE = 0x02B1
WM_POWERBROADCAST = 0x0218
WTS_SESSION_LOCK = 0x7
PBT_APMSUSPEND = 0x4

CREATE_NO_WINDOW = 0x08000000
CREATE_NEW_CONSOLE = 0x00000010
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
TOKEN_QUERY = 0x0008
TOKEN_INTEGRITY_LEVEL = 25
GA_ROOT = 2
SW_RESTORE = 9
ERROR_ACCESS_DENIED = 5

# Windows that belong to the shell itself: there is nothing to type into.
SHELL_CLASSES = {'Progman', 'WorkerW', 'Shell_TrayWnd', 'Shell_SecondaryTrayWnd',
                 'NotifyIconOverflowWindow', 'TopLevelWindowForOverflowXamlIsland'}


def key_down(vk: int) -> bool:
    return bool(user32.GetAsyncKeyState(vk) & 0x8000)


def caps_lock_on() -> bool:
    return bool(user32.GetKeyState(VK_CAPITAL) & 1)


def idle_seconds() -> float:
    """How long since the last keyboard or mouse input anywhere on this PC."""
    info = LASTINPUTINFO(ctypes.sizeof(LASTINPUTINFO), 0)
    if not user32.GetLastInputInfo(ctypes.byref(info)):
        return 0.0
    return ((kernel32.GetTickCount() - info.dwTime) & 0xFFFFFFFF) / 1000.0


# --------------------------------------------------------------------------- windows


@dataclass(frozen=True)
class WindowInfo:
    hwnd: int
    title: str
    class_name: str
    pid: int
    exe_path: str

    @property
    def exe(self) -> str:
        """The program's file name, lower case: 'steam.exe'."""
        return Path(self.exe_path).name.lower() if self.exe_path else ''

    @property
    def is_shell(self) -> bool:
        return self.class_name in SHELL_CLASSES


def _text(getter, hwnd, length=512) -> str:
    buffer = ctypes.create_unicode_buffer(length)
    getter(hwnd, buffer, length)
    return buffer.value


def window_pid(hwnd) -> int:
    pid = DWORD()
    user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
    return pid.value


def window_thread(hwnd) -> int:
    return user32.GetWindowThreadProcessId(hwnd, None)


def process_path(pid: int) -> str:
    handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not handle:
        return ''
    try:
        size = DWORD(32768)
        buffer = ctypes.create_unicode_buffer(size.value)
        if kernel32.QueryFullProcessImageNameW(handle, 0, buffer, ctypes.byref(size)):
            return buffer.value
        return ''
    finally:
        kernel32.CloseHandle(handle)


def _hosted_app_pid(frame_hwnd, frame_pid: int) -> int:
    """The app inside a Store app's frame window, which ApplicationFrameHost owns."""
    found = []

    def visit(child, _):
        pid = window_pid(child)
        if pid and pid != frame_pid:
            found.append(pid)
            return False
        return True

    user32.EnumChildWindows(frame_hwnd, WNDENUMPROC(visit), 0)
    return found[0] if found else frame_pid


def window_info(hwnd) -> WindowInfo | None:
    if not hwnd or not user32.IsWindow(hwnd):
        return None
    root = user32.GetAncestor(hwnd, GA_ROOT) or hwnd
    pid = window_pid(root)
    path = process_path(pid)
    if Path(path).name.lower() == 'applicationframehost.exe':
        inner = _hosted_app_pid(root, pid)
        if inner != pid:
            pid, path = inner, process_path(inner) or path
    length = max(user32.GetWindowTextLengthW(root) + 1, 2)
    return WindowInfo(hwnd=int(root), title=_text(user32.GetWindowTextW, root, length),
                      class_name=_text(user32.GetClassNameW, root, 256), pid=pid, exe_path=path)


def foreground_window() -> WindowInfo | None:
    return window_info(user32.GetForegroundWindow())


def foreground_pid() -> int:
    hwnd = user32.GetForegroundWindow()
    return window_pid(hwnd) if hwnd else 0


def window_rect(hwnd) -> tuple[int, int, int, int] | None:
    rect = wintypes.RECT()
    if not user32.GetWindowRect(hwnd, ctypes.byref(rect)):
        return None
    return rect.left, rect.top, rect.right, rect.bottom


def set_foreground(hwnd) -> bool:
    """Bring a window to the front and give it the keyboard.

    Windows lets a process do this only while it has the foreground itself (or
    just received the user's input, as with a hotkey). If it refuses, joining
    the current foreground window's input queue for a moment usually works.
    """
    if not hwnd or not user32.IsWindow(hwnd):
        return False
    if user32.IsIconic(hwnd):
        user32.ShowWindow(hwnd, SW_RESTORE)
    if user32.SetForegroundWindow(hwnd) and user32.GetForegroundWindow() == hwnd:
        return True
    current = user32.GetForegroundWindow()
    theirs = window_thread(current) if current else 0
    mine = kernel32.GetCurrentThreadId()
    attached = bool(theirs and theirs != mine and user32.AttachThreadInput(mine, theirs, True))
    try:
        user32.BringWindowToTop(hwnd)
        user32.SetForegroundWindow(hwnd)
    finally:
        if attached:
            user32.AttachThreadInput(mine, theirs, False)
    return user32.GetForegroundWindow() == hwnd


# --------------------------------------------------------------------------- integrity

UNKNOWN_INTEGRITY = -1


def _token_integrity(token) -> int:
    size = DWORD()
    advapi32.GetTokenInformation(token, TOKEN_INTEGRITY_LEVEL, None, 0, ctypes.byref(size))
    buffer = ctypes.create_string_buffer(size.value or 64)
    if not advapi32.GetTokenInformation(token, TOKEN_INTEGRITY_LEVEL, buffer, size, ctypes.byref(size)):
        return UNKNOWN_INTEGRITY
    sid = ctypes.c_void_p.from_buffer(buffer).value   # TOKEN_MANDATORY_LABEL.Label.Sid
    count = advapi32.GetSidSubAuthorityCount(sid)[0]
    return int(advapi32.GetSidSubAuthority(sid, count - 1)[0])


def own_integrity() -> int:
    token = wintypes.HANDLE()
    if not advapi32.OpenProcessToken(kernel32.GetCurrentProcess(), TOKEN_QUERY, ctypes.byref(token)):
        return UNKNOWN_INTEGRITY
    try:
        return _token_integrity(token)
    finally:
        kernel32.CloseHandle(token)


def process_integrity(pid: int) -> int:
    """The process's integrity level (0x2000 medium, 0x3000 high = admin).

    A process run as administrator will not let an ordinary one read its
    token, so being refused is itself the answer: it runs above us.
    """
    handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not handle:
        return 0x3000 if ctypes.get_last_error() == ERROR_ACCESS_DENIED else UNKNOWN_INTEGRITY
    try:
        token = wintypes.HANDLE()
        if not advapi32.OpenProcessToken(handle, TOKEN_QUERY, ctypes.byref(token)):
            return 0x3000 if ctypes.get_last_error() == ERROR_ACCESS_DENIED else UNKNOWN_INTEGRITY
        try:
            return _token_integrity(token)
        finally:
            kernel32.CloseHandle(token)
    finally:
        kernel32.CloseHandle(handle)


def runs_above_us(pid: int) -> bool:
    """Whether Windows will drop keystrokes Keytap sends to this process.

    Windows keeps an ordinary program from typing into one running as
    administrator (UIPI), and it does so silently.
    """
    theirs, ours = process_integrity(pid), own_integrity()
    return theirs != UNKNOWN_INTEGRITY and ours != UNKNOWN_INTEGRITY and theirs > ours


# --------------------------------------------------------------------------- processes


def run_hidden(args: list, **kwargs) -> subprocess.CompletedProcess:
    """Run a command-line tool without a console window flashing up."""
    kwargs.setdefault('creationflags', CREATE_NO_WINDOW)
    return subprocess.run([str(a) for a in args], **kwargs)


def open_console(command_line: str, env: dict[str, str]) -> subprocess.Popen:
    """Run a command in a console window of its own, for the person to use."""
    return subprocess.Popen(command_line, env=env, creationflags=CREATE_NEW_CONSOLE)


# --------------------------------------------------------------------------- start with Windows

_RUN_KEY = r'Software\Microsoft\Windows\CurrentVersion\Run'
_RUN_NAME = 'Keytap'


def launch_command() -> str:
    """How Windows starts Keytap at sign-in: --startup, so it stays in the background."""
    if getattr(sys, 'frozen', False):
        return f'"{sys.executable}" --startup'
    pythonw = Path(sys.executable).with_name('pythonw.exe')
    main = Path(__file__).resolve().parents[1] / 'main.py'
    return f'"{pythonw}" "{main}" --startup'


def starts_with_windows() -> bool:
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _RUN_KEY) as key:
            winreg.QueryValueEx(key, _RUN_NAME)
            return True
    except OSError:
        return False


def refresh_start_with_windows() -> None:
    """Keep the sign-in entry pointing at this copy, as it starts now - an entry made by an
    older Keytap, without --startup, would open the vault window at every sign-in."""
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _RUN_KEY) as key:
            current, _ = winreg.QueryValueEx(key, _RUN_NAME)
    except OSError:
        return
    # Only this copy's own entry: one pointing at another copy of Keytap is left be.
    mine = f'"{sys.executable}"'.lower()
    if getattr(sys, 'frozen', False) and current.lower().startswith(mine) and current != launch_command():
        set_start_with_windows(True)


def set_start_with_windows(enabled: bool) -> None:
    with winreg.CreateKey(winreg.HKEY_CURRENT_USER, _RUN_KEY) as key:
        if enabled:
            winreg.SetValueEx(key, _RUN_NAME, 0, winreg.REG_SZ, launch_command())
        else:
            try:
                winreg.DeleteValue(key, _RUN_NAME)
            except FileNotFoundError:
                pass


def watch_session(hwnd) -> bool:
    """Have Windows tell this window when the session is locked."""
    return bool(wtsapi32.WTSRegisterSessionNotification(hwnd, 0))


def app_data() -> Path:
    return Path(os.environ.get('APPDATA', str(Path.home()))) / 'Keytap'
