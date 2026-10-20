"""Typing into another program, as if on the keyboard (SendInput).

Text normally goes in as Unicode characters, which every keyboard layout
types the same. Games, remote desktops and virtual machines often read the
keys themselves instead of the characters; for those, compatibility typing
presses the keys that make each character on the target's keyboard layout.
"""

from __future__ import annotations

import ctypes
import time
from ctypes import wintypes

from . import win32

user32 = win32.user32

INPUT_KEYBOARD = 1
KEYEVENTF_EXTENDEDKEY = 0x0001
KEYEVENTF_KEYUP = 0x0002
KEYEVENTF_UNICODE = 0x0004
KEYEVENTF_SCANCODE = 0x0008
MAPVK_VK_TO_VSC = 0
VK_CAPITAL = 0x14
_EXTENDED = {0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x2D, 0x2E, 0x5B, 0x5C, 0x6F, 0xA3, 0xA5}
_SHIFT_STATE_KEYS = ((1, win32.VK_SHIFT), (2, win32.VK_CONTROL), (4, win32.VK_MENU))
ULONG_PTR = ctypes.c_size_t


class KEYBDINPUT(ctypes.Structure):
    _fields_ = [('wVk', wintypes.WORD), ('wScan', wintypes.WORD), ('dwFlags', wintypes.DWORD),
                ('time', wintypes.DWORD), ('dwExtraInfo', ULONG_PTR)]


class MOUSEINPUT(ctypes.Structure):
    _fields_ = [('dx', wintypes.LONG), ('dy', wintypes.LONG), ('mouseData', wintypes.DWORD),
                ('dwFlags', wintypes.DWORD), ('time', wintypes.DWORD), ('dwExtraInfo', ULONG_PTR)]


class HARDWAREINPUT(ctypes.Structure):
    _fields_ = [('uMsg', wintypes.DWORD), ('wParamL', wintypes.WORD), ('wParamH', wintypes.WORD)]


class _INPUTUNION(ctypes.Union):
    _fields_ = [('ki', KEYBDINPUT), ('mi', MOUSEINPUT), ('hi', HARDWAREINPUT)]


class INPUT(ctypes.Structure):
    _anonymous_ = ('u',)
    _fields_ = [('type', wintypes.DWORD), ('u', _INPUTUNION)]


user32.SendInput.argtypes = [wintypes.UINT, ctypes.POINTER(INPUT), ctypes.c_int]
user32.SendInput.restype = wintypes.UINT
user32.MapVirtualKeyW.argtypes = [wintypes.UINT, wintypes.UINT]
user32.MapVirtualKeyW.restype = wintypes.UINT
user32.VkKeyScanExW.argtypes = [wintypes.WCHAR, wintypes.HKL]
user32.VkKeyScanExW.restype = ctypes.c_short
user32.GetKeyboardLayout.argtypes = [wintypes.DWORD]
user32.GetKeyboardLayout.restype = wintypes.HKL
user32.SendMessageTimeoutW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM,
                                       wintypes.UINT, wintypes.UINT, ctypes.POINTER(ULONG_PTR)]
user32.SendMessageTimeoutW.restype = wintypes.LPARAM
WM_NULL = 0x0000
SMTO_ABORTIFHUNG = 0x0002

DONE = 'done'
FOCUS_LOST = 'focus_lost'
KEYS_HELD = 'keys_held'
BLOCKED = 'blocked'


class _Keyboard:
    def __init__(self, layout, compat: bool, hwnd=None):
        self.layout = layout
        self.compat = compat
        self.hwnd = hwnd

    def caught_up(self) -> None:
        """Wait until the program has taken the last key from its queue.

        Windows hands each Unicode character over beside the keystroke rather
        than in it, and when a busy program lets several pile up, one can come
        out as the one before ("pass" typed as "-ass"). Two round trips
        through the program's message loop mean it has fetched what came first.
        """
        if not self.hwnd:
            return
        result = ULONG_PTR()
        for _ in range(2):
            user32.SendMessageTimeoutW(self.hwnd, WM_NULL, 0, 0, SMTO_ABORTIFHUNG, 250, ctypes.byref(result))

    @staticmethod
    def _send(events: list[INPUT]) -> bool:
        array = (INPUT * len(events))(*events)
        return user32.SendInput(len(events), array, ctypes.sizeof(INPUT)) == len(events)

    @staticmethod
    def _vk_event(vk: int, up: bool) -> INPUT:
        flags = (KEYEVENTF_KEYUP if up else 0) | (KEYEVENTF_EXTENDEDKEY if vk in _EXTENDED else 0)
        event = INPUT(type=INPUT_KEYBOARD)
        event.ki = KEYBDINPUT(vk, user32.MapVirtualKeyW(vk, MAPVK_VK_TO_VSC), flags, 0, 0)
        return event

    def press(self, vk: int, modifiers: tuple[int, ...] = ()) -> bool:
        events = [self._vk_event(m, False) for m in modifiers]
        events += [self._vk_event(vk, False), self._vk_event(vk, True)]
        events += [self._vk_event(m, True) for m in reversed(modifiers)]
        return self._send(events)

    def character(self, char: str) -> bool:
        if char == '\t':
            return self.press(0x09)
        if char in '\r\n':
            return self.press(0x0D)
        if self.compat and ord(char) < 0x10000:
            scan = user32.VkKeyScanExW(char, self.layout)
            if scan != -1:
                vk, state = scan & 0xFF, (scan >> 8) & 0xFF
                if not state & ~0x07:   # Hankaku and other odd shift states: use Unicode
                    modifiers = tuple(key for bit, key in _SHIFT_STATE_KEYS if state & bit)
                    return self.press(vk, modifiers)
        events = []
        units = char.encode('utf-16-le')
        for i in range(0, len(units), 2):
            unit = int.from_bytes(units[i:i + 2], 'little')
            for up in (False, True):
                event = INPUT(type=INPUT_KEYBOARD)
                event.ki = KEYBDINPUT(0, unit, KEYEVENTF_UNICODE | (KEYEVENTF_KEYUP if up else 0), 0, 0)
                events.append(event)
        return self._send(events)


def wait_for_keys_released(timeout: float = 3.0) -> bool:
    """Wait until Ctrl, Alt, Shift and Win are all up - the hotkey's own keys.

    Typing while they are still held would turn each character into a
    shortcut: Ctrl+W, Alt+F4 and worse.
    """
    deadline = time.monotonic() + timeout
    while any(win32.key_down(vk) for vk in win32.MODIFIER_KEYS):
        if time.monotonic() > deadline:
            return False
        time.sleep(0.02)
    return True


def type_steps(steps, target_pid: int, *, compat: bool = False, key_delay_ms: int = 10,
               settle_ms: int = 120) -> str:
    """Type steps (from sequence.compile) into the foreground window.

    Stops the moment the foreground window belongs to a different program
    than target_pid - the person clicked away, and the rest must not land
    somewhere else. Runs on a worker thread; it sleeps between keys.
    """
    time.sleep(settle_ms / 1000)
    if not wait_for_keys_released():
        return KEYS_HELD
    if win32.foreground_pid() != target_pid:
        return FOCUS_LOST
    if win32.runs_above_us(target_pid):
        return BLOCKED

    front = win32.user32.GetForegroundWindow()
    keyboard = _Keyboard(user32.GetKeyboardLayout(win32.window_thread(front)), compat, front)
    caps = compat and win32.caps_lock_on()
    if caps:
        keyboard.press(VK_CAPITAL)      # off while typing, so letters keep their case
    delay = key_delay_ms / 1000

    def still_there() -> bool:
        return win32.foreground_pid() == target_pid

    try:
        for kind, value in steps:
            if kind == 'delay':
                time.sleep(value / 1000)
                continue
            if kind == 'keydelay':
                delay = value / 1000
                continue
            if not still_there():
                return FOCUS_LOST
            if kind == 'key':
                keyboard.press(value)
                keyboard.caught_up()
                time.sleep(max(delay, 0.03))   # a new field needs a moment to take focus
            elif kind == 'chord':
                modifier, vk = value
                keyboard.press(vk, (modifier,))
                keyboard.caught_up()
                time.sleep(delay)
            elif kind == 'text':
                for char in value:
                    if not still_there():
                        return FOCUS_LOST
                    keyboard.character(char)
                    keyboard.caught_up()
                    if delay:
                        time.sleep(delay)
        return DONE
    finally:
        if caps:
            keyboard.press(VK_CAPITAL)
