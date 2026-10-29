r"""Filling real login windows box by box (filling.fill), in the kinds of program Keytap meets:
classic Windows boxes, Qt, WPF, and Chromium pages (Edge, as Electron, CEF and WebView2 apps
are) drawn as React draws them - Ubisoft Connect's shape, a Log in button greyed out until both
boxes hold something, a search box above, an email-first page, a password page.

    %LOCALAPPDATA%\KeytapBuild\venv\Scripts\python.exe tests\fill_test.py [case ...]

Each window comes up without the keyboard, in the main screen's lower right, for a few seconds;
pressing its Log in button through UI Automation may bring it to the front. Nothing is typed:
every box here takes its value set. Edge runs with a profile of its own in %TEMP%. Check the
window in front first: not over a game.

typed-password (a password box that empties itself unless typed into) and select-first (Ubisoft
Connect's: a box takes nothing until Enter opens it) take real keys, so they run only when named,
while nobody is using the PC.
"""

import ctypes
import json
import os
import subprocess
import sys
import tempfile
import time
from ctypes import wintypes
from pathlib import Path

HERE = Path(__file__).resolve().parent
TARGETS = HERE / 'fill_targets'
sys.path.insert(0, str(HERE.parent / 'app'))

from keytap import filling, focus, win32  # noqa: E402

USER, PASSWORD = 'tester@example.com', 'Pa$$w0rd-ü€'
EDGE = r'C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe'
X, Y = 1500, 760
user32 = ctypes.windll.user32
# case: (program, page, the box with the keyboard, what the program should end up with)
CASES = {
    'win32': ('win32', '', 'none', {'u': USER, 'p': PASSWORD, 's': 'submitted'}),
    'win32-from-password': ('win32', '', 'password', {'u': USER, 'p': PASSWORD, 's': 'submitted'}),
    'qt': ('qt', '', 'username', {'u': USER, 'p': PASSWORD, 's': 'submitted'}),
    'wpf': ('wpf', '', 'username', {'u': USER, 'p': PASSWORD, 's': 'submitted'}),
    'ubisoft': ('chromium', '', 'username', {'u': USER, 'p': PASSWORD, 's': 'submitted'}),
    'disabled-button': ('chromium', 'disabled', 'username', {'u': USER, 'p': PASSWORD, 's': 'submitted'}),
    'search-first': ('chromium', 'search-first', 'none', {'u': USER, 'p': PASSWORD, 'q': '', 's': 'submitted'}),
    'email-first': ('chromium', 'identifier', 'username', {'u': USER, 's': 'submitted'}),
    'password-page': ('chromium', 'password-step', 'password', {'u': USER, 'p': PASSWORD, 's': 'submitted'}),
    'typed-password': ('chromium', 'typed-password', 'none', {'u': USER, 'p': PASSWORD, 's': 'submitted'}),
    'select-first': ('chromium', 'select-first', 'none', {'u': USER, 'p': PASSWORD, 's': 'submitted'}),
}
TYPED = {'typed-password', 'select-first'}      # real keys (Enter, typing): run only when named


def _title(hwnd) -> str:
    buf = ctypes.create_unicode_buffer(512)
    user32.GetWindowTextW(hwnd, buf, 512)
    return buf.value


def _edge_window(deadline: float):
    ENUM = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
    while time.monotonic() < deadline:
        found = []
        user32.EnumWindows(ENUM(lambda h, _: (found.append(h) if _title(h).startswith('{"u"') else None) or True), 0)
        if found:
            return found[0]
        time.sleep(0.2)
    raise RuntimeError('Edge did not open the page')


def start(program: str, page: str, report: Path):
    venv_python = sys.executable
    if program == 'chromium':
        info = subprocess.STARTUPINFO()
        info.dwFlags, info.wShowWindow = 1, 4           # STARTF_USESHOWWINDOW, SW_SHOWNOACTIVATE
        profile = Path(tempfile.gettempdir()) / 'keytap-fill-edge'
        proc = subprocess.Popen([EDGE, f'--user-data-dir={profile}', '--no-first-run', '--no-default-browser-check',
                                 f'--window-position={X},{Y}', '--window-size=420,330',
                                 '--app=' + (TARGETS / 'login.html').as_uri() + '#' + page], startupinfo=info)
        return proc, _edge_window(time.monotonic() + 20)
    command = {'win32': [venv_python, str(TARGETS / 'win32.py')], 'qt': [venv_python, str(TARGETS / 'qt.py')],
               'wpf': ['powershell', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', str(TARGETS / 'wpf.ps1')]}
    proc = subprocess.Popen(command[program] + [str(report), '25', str(X), str(Y)], stdout=subprocess.PIPE, text=True)
    return proc, json.loads(proc.stdout.readline())['hwnd']


def has(program: str, hwnd, report: Path) -> dict:
    text = _title(hwnd) if program == 'chromium' else report.read_text(encoding='utf-8-sig')
    return json.loads(text)


def run(name: str, automation) -> bool:
    program, page, start_in, expected = CASES[name]
    report = Path(tempfile.gettempdir()) / f'keytap-fill-{program}.json'
    report.unlink(missing_ok=True)
    proc, hwnd = start(program, page, report)
    try:
        root = automation.ElementFromHandle(hwnd)
        edits, deadline = [], time.monotonic() + 10       # a page's boxes, once Chromium has built them
        while time.monotonic() < deadline and not any(e.CurrentIsPassword or 'mail' in e.CurrentName.lower()
                                                      for e in edits):
            found = root.FindAll(4, automation.CreatePropertyCondition(filling.UIA_CONTROL_TYPE, filling.UIA_EDIT))
            edits = [found.GetElement(i) for i in range(found.Length)]
            time.sleep(0.2)
        start_box = None
        if start_in != 'none':
            start_box = next(e for e in edits if bool(e.CurrentIsPassword) == (start_in == 'password')
                             and focus.is_login_name(e.CurrentName))
        began = time.perf_counter()
        result = filling.fill(automation, win32.window_info(hwnd), start_box, USER, PASSWORD, True, (False, 10),
                              focus.is_login_name)
        took = (time.perf_counter() - began) * 1000
        time.sleep(0.4)
        got = has(program, hwnd, report)
        got = {key: got.get(key) for key in expected}
        ok = result.outcome == 'filled' and got == expected and result.typed == (name in TYPED)
        print(f'{"PASS" if ok else "FAIL"}  {name:20} {took:5.0f} ms  {result.submitted or "not sent"}'
              + ('' if ok else f'\n      {result}\n      has {got}\n      not {expected}'))
        return ok
    finally:
        if program == 'chromium':
            user32.PostMessageW(hwnd, 0x0010, 0, 0)         # WM_CLOSE
            proc.wait(10)
        else:
            proc.terminate()


def through_keytap() -> bool:
    """The same, as the hotkey asks for it: through FieldWatcher's own UI Automation thread."""
    from PySide6.QtCore import QCoreApplication
    app = QCoreApplication.instance() or QCoreApplication([])
    report = Path(tempfile.gettempdir()) / 'keytap-fill-wpf.json'
    report.unlink(missing_ok=True)
    proc, hwnd = start('wpf', '', report)
    try:
        watcher = focus.FieldWatcher(lambda window: False)
        answers = []
        time.sleep(1)
        watcher.fill(win32.window_info(hwnd), USER, PASSWORD, True, (False, 10), answers.append)
        deadline = time.monotonic() + 20
        while not answers and time.monotonic() < deadline:
            app.processEvents()
            time.sleep(0.01)
        time.sleep(0.4)
        got = has('wpf', hwnd, report)
        ok = bool(answers) and answers[0] is not None and answers[0].outcome == 'filled' and \
            got == {'u': USER, 'p': PASSWORD, 's': 'submitted'}
        print(f'{"PASS" if ok else "FAIL"}  {"through-keytap":20} {answers}  has {got}')
        return ok
    finally:
        proc.terminate()


def main() -> int:
    automation, _ = focus._automation()
    names = sys.argv[1:] or [*(name for name in CASES if name not in TYPED), 'through-keytap']
    passed = sum(through_keytap() if name == 'through-keytap' else run(name, automation) for name in names)
    print(f'{passed} of {len(names)} passed')
    return 0 if passed == len(names) else 1


if __name__ == '__main__':
    sys.exit(main())
