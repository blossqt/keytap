"""A classic Windows login box (EDIT controls, one ES_PASSWORD), shown without taking the keyboard.

    python win32_target.py <report file> <seconds> <x> <y>

Prints {"hwnd": ...}, then writes what its boxes hold to the report file every 50 ms."""
import ctypes
import json
import sys
import time
from ctypes import wintypes

u, k = ctypes.windll.user32, ctypes.windll.kernel32
u.SetProcessDpiAwarenessContext(ctypes.c_void_p(-4))
WNDPROC = ctypes.WINFUNCTYPE(ctypes.c_ssize_t, wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM)
u.DefWindowProcW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
u.DefWindowProcW.restype = ctypes.c_ssize_t
submitted = []


def proc(h, msg, wp, lp):
    if msg == 0x0111 and (wp & 0xFFFF) == 3:      # WM_COMMAND from the Log in button
        submitted.append(1)
    return u.DefWindowProcW(h, msg, wp, lp)


wndproc = WNDPROC(proc)


class WNDCLASS(ctypes.Structure):
    _fields_ = [('style', wintypes.UINT), ('lpfnWndProc', WNDPROC), ('cbClsExtra', ctypes.c_int),
                ('cbWndExtra', ctypes.c_int), ('hInstance', wintypes.HINSTANCE), ('hIcon', wintypes.HICON),
                ('hCursor', wintypes.HANDLE), ('hbrBackground', wintypes.HBRUSH),
                ('lpszMenuName', wintypes.LPCWSTR), ('lpszClassName', wintypes.LPCWSTR)]


wc = WNDCLASS(0, wndproc, 0, 0, k.GetModuleHandleW(None), None, None, ctypes.c_void_p(6), None, 'KeytapFillTarget')
u.RegisterClassW(ctypes.byref(wc))
u.CreateWindowExW.restype = wintypes.HWND
u.CreateWindowExW.argtypes = [wintypes.DWORD, wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD, ctypes.c_int,
                              ctypes.c_int, ctypes.c_int, ctypes.c_int, wintypes.HWND, wintypes.HMENU,
                              wintypes.HINSTANCE, wintypes.LPVOID]
CHILD = 0x10000000 | 0x40000000 | 0x00010000    # WS_VISIBLE | WS_CHILD | WS_TABSTOP
x, y = int(sys.argv[3]), int(sys.argv[4])
top = u.CreateWindowExW(0, 'KeytapFillTarget', 'Win32 login', 0x00CF0000, x, y, 360, 230, None, None, None, None)
u.CreateWindowExW(0, 'STATIC', 'User name:', CHILD, 10, 10, 300, 20, top, None, None, None)
user = u.CreateWindowExW(0x200, 'EDIT', '', CHILD | 0x0080, 10, 32, 320, 26, top, 1, None, None)
u.CreateWindowExW(0, 'STATIC', 'Password:', CHILD, 10, 66, 300, 20, top, None, None, None)
pw = u.CreateWindowExW(0x200, 'EDIT', '', CHILD | 0x0080 | 0x0020, 10, 88, 320, 26, top, 2, None, None)
u.CreateWindowExW(0, 'BUTTON', 'Log in', CHILD | 0x0001, 10, 130, 100, 30, top, 3, None, None)
u.ShowWindow(top, 4)    # SW_SHOWNOACTIVATE
print(json.dumps({'hwnd': top}), flush=True)


def text(h):
    buf = ctypes.create_unicode_buffer(512)
    u.GetWindowTextW(h, buf, 512)
    return buf.value


end = time.monotonic() + float(sys.argv[2])
msg = wintypes.MSG()
u.SetTimer(None, 0, 50, None)       # as a real program waits: on its messages, with a timer to report
while time.monotonic() < end and u.GetMessageW(ctypes.byref(msg), None, 0, 0) > 0:
    if msg.message == 0x0113:       # WM_TIMER
        with open(sys.argv[1], 'w', encoding='utf-8') as f:
            f.write(json.dumps({'u': text(user), 'p': text(pw), 's': 'submitted' if submitted else ''}))
        continue
    u.TranslateMessage(ctypes.byref(msg))
    u.DispatchMessageW(ctypes.byref(msg))
u.DestroyWindow(top)
