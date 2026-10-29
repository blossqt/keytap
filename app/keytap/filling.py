"""Filling a login form in another program, box by box, through UI Automation.

The username goes into the username box and the password into the password box: each box is
found by what it is - Windows marks a password box as one, and the username box is the text box
just before it - and gets its value set directly (UI Automation's Value pattern). No key is
pressed and nothing goes on the clipboard, so a slow program can't drop or swap characters,
the keyboard layout doesn't matter, and the keyboard needn't be handed back to the box first.
That handing back is what failed in Ubisoft Connect ("could not put the keyboard back").

Then the form is sent: its sign-in button ("Log in", "Sign in", "Next" ...) is pressed through
UI Automation too, or else Enter is pressed in the last box filled.

A box that won't take a value is clicked into (UI Automation's focus) and typed into instead.
A program that shows UI Automation no boxes at all - a game drawing its own, a remote desktop -
gets the keystrokes it always got (fill() says 'nothing').

Classic Windows boxes, WPF, Qt and Chromium pages (Electron, CEF, WebView2 apps) all take a set
value: the program sees it as typed - a web page gets its input events, so React and the like
notice it. A page may still drop it: Ubisoft Connect's empties its password box again at once
(and says "Required" when sent). Chromium's and Qt's password boxes say a dot for each character
they hold, so there a box still empty didn't take it, and gets typed into.

Runs on FieldWatcher's UI Automation thread.
"""

from __future__ import annotations

import time
from dataclasses import dataclass

from . import typer, win32

UIA_INVOKE_PATTERN = 10000
UIA_VALUE_PATTERN = 10002
UIA_CONTROL_TYPE = 30003
UIA_IS_ENABLED = 30010
UIA_IS_OFFSCREEN = 30022
UIA_BUTTON, UIA_EDIT = 50000, 50004
TREE_SCOPE_DESCENDANTS = 4
VK_CONTROL, VK_RETURN = 0x11, 0x0D

DOTTED = ('Chrome', 'Qt')   # UI Automation frameworks whose password boxes say a dot a character
ANCESTORS = 6       # how far up from the box with the keyboard to look for the rest of its form
BUTTON_ANCESTORS = 3    # and further, for its sign-in button
NEAR = 4            # a password box this many of its heights below the username box is its own
# A text box with no password box after it that says it is for these is a sign-in's first step.
IDENTIFIER_WORDS = ('user', 'email', 'e-mail', 'phone', 'login', 'identifier', 'account', '账号', '邮箱', '手机')
# A form's sign-in button, by its whole name: "Can't log in?" and "Log in with Google" are not.
SUBMIT_NAMES = frozenset({
    'log in', 'login', 'log on', 'logon', 'sign in', 'signin', 'sign on', 'continue', 'next', 'submit',
    'ok', 'go', 'enter', 'connect', 'unlock', 'log in now', 'sign in now',
    '登录', '登入', '下一步', '继续', '确定', '登錄', '繼續', 'ログイン', '次へ', '로그인', '다음',
    'anmelden', 'weiter', 'connexion', 'se connecter', 'suivant', 'iniciar sesión', 'entrar', 'siguiente',
    'accedi', 'avanti', 'inloggen', 'volgende', 'войти', 'далее'})


@dataclass(frozen=True)
class Box:
    """A text box of the form, as pick() sees it."""
    password: bool
    words: str                          # its name and id, in lower case
    rect: tuple[int, int, int, int]     # left, top, right, bottom


@dataclass
class Filled:
    outcome: str                # 'filled'; 'nothing' (no box for it: type as before); 'failed'
    username: bool = False      # a username box was filled
    password: bool = False      # a password box was filled
    submitted: str = ''         # 'button', 'enter', or '' (not sent)
    typed: bool = False         # some box would not take its value and was typed into
    detail: str = ''


# --------------------------------------------------------------------------- choosing the boxes

def near(username: Box, password: Box) -> bool:
    """Whether a password box sits where a username box's own would: below it, or beside it."""
    ul, ut, ur, ub = username.rect
    pl, pt, pr, pb = password.rect
    height = max(1, pb - pt)
    if ut < pt and pt - ub <= NEAR * height and ul < pr and pl < ur:
        return True             # below, overlapping across
    middle = (pt + pb) / 2
    return ut <= middle <= ub and ur <= pl + height and pl - ur <= NEAR * height     # to its right


def pick(boxes: list[Box], start: int | None, login_name) -> tuple[int | None, int | None]:
    """Which of boxes (in the window's order) are the username box and the password box.

    start is the box with the keyboard, if one does: it is whichever it is, as the person chose
    it. login_name(words) says whether a text box can be a login box (not a search box, say)."""
    def before(index: int) -> int | None:
        """The text box just before a password box - not past another (a sign-up's confirm box)."""
        if index > 0 and not boxes[index - 1].password:
            i = index - 1
            return i if login_name(boxes[i].words) and near(boxes[i], boxes[index]) else None
        return None

    if start is not None and boxes[start].password:
        return before(start), start
    if start is not None:
        for i in range(start + 1, len(boxes)):
            if boxes[i].password:
                # The next password box is its own if it follows at once, or sits just below.
                return start, (i if i == start + 1 or near(boxes[start], boxes[i]) else None)
        return start, None
    first = next((i for i, box in enumerate(boxes) if box.password), None)
    return (before(first), first) if first is not None else (None, None)


def submit_name(name: str) -> bool:
    words = ' '.join(name.lower().replace('’', "'").split()).strip(' >→›»…')
    return words in SUBMIT_NAMES


# --------------------------------------------------------------------------- UI Automation

def _uia():
    from comtypes.gen import UIAutomationClient as uia
    return uia


def _items(automation, scope) -> list:
    """The text boxes and buttons under scope, in the window's order, as (element, is_box)."""
    kinds = automation.CreateOrCondition(automation.CreatePropertyCondition(UIA_CONTROL_TYPE, UIA_EDIT),
                                         automation.CreatePropertyCondition(UIA_CONTROL_TYPE, UIA_BUTTON))
    shown = automation.CreateAndCondition(kinds, automation.CreatePropertyCondition(UIA_IS_OFFSCREEN, False))
    found = scope.FindAll(TREE_SCOPE_DESCENDANTS, shown)
    items = []
    for i in range(found.Length if found else 0):
        element = found.GetElement(i)
        try:
            items.append((element, element.CurrentControlType == UIA_EDIT))
        except Exception:  # noqa: BLE001 - gone already
            pass
    return items


def _box(element) -> Box | None:
    try:
        if not element.CurrentIsEnabled:
            return None
        r = element.CurrentBoundingRectangle
        if r.right - r.left < 12 or r.bottom - r.top < 8:
            return None
        return Box(bool(element.CurrentIsPassword), f'{element.CurrentName} {element.CurrentAutomationId}'.lower(),
                   (r.left, r.top, r.right, r.bottom))
    except Exception:  # noqa: BLE001
        return None


def _index(automation, elements: list, element) -> int | None:
    for i, other in enumerate(elements):
        try:
            if automation.CompareElements(other, element):
                return i
        except Exception:  # noqa: BLE001
            pass
    return None


def within(automation, element, root, levels: int = 60) -> bool:
    """Whether element is in root's window - a box on a web page can belong to another process
    than its window (WebView2's), so its process doesn't say."""
    walker = automation.ControlViewWalker
    node = element
    for _ in range(levels):
        if not node:
            return False
        if automation.CompareElements(node, root):
            return True
        node = walker.GetParentElement(node)
    return False


def _scopes(automation, start, root, levels: int):
    """start's ancestors, nearest first, up to levels of them or the window."""
    walker = automation.ControlViewWalker
    node = start
    for _ in range(levels):
        node = walker.GetParentElement(node)
        if not node:
            return
        yield node
        if automation.CompareElements(node, root):
            return


def find_form(automation, root, start, login_name):
    """(items, boxes, username index, password index, scope): the form round start, the box with
    the keyboard (None: the window's first password box decides). Looks up from start a level at
    a time, and stops at the first that holds both boxes."""
    best = None
    for scope in ([root] if start is None else _scopes(automation, start, root, ANCESTORS)):
        items = _items(automation, scope)
        elements = [element for element, is_box in items if is_box]
        boxes = [_box(element) for element in elements]
        keep = [i for i, box in enumerate(boxes) if box is not None]
        elements, boxes = [elements[i] for i in keep], [boxes[i] for i in keep]
        at = _index(automation, elements, start) if start is not None else None
        if start is not None and at is None:
            continue
        name_at, password_at = pick(boxes, at, login_name)
        found = (items, elements, boxes, name_at, password_at, scope)
        if best is None or (name_at is not None) + (password_at is not None) > \
                (best[3] is not None) + (best[4] is not None):
            best = found
        if name_at is not None and password_at is not None:
            break
    return best


def _value_pattern(element):
    pattern = element.GetCurrentPattern(UIA_VALUE_PATTERN)
    return pattern.QueryInterface(_uia().IUIAutomationValuePattern) if pattern else None


def read_only(element) -> bool:
    """A box showing the username rather than asking for it (a password page's, say)."""
    try:
        pattern = _value_pattern(element)
        return bool(pattern is not None and pattern.CurrentIsReadOnly)
    except Exception:  # noqa: BLE001
        return False


def put(element, value: str, password: bool) -> bool:
    """Set a box's value, and see that it took."""
    try:
        pattern = _value_pattern(element)
        if pattern is None:
            return False
        pattern.SetValue(value)
    except Exception:  # noqa: BLE001 - no value to set here: it gets typed
        return False
    return holds(element, pattern, value, password)


def holds(element, pattern, value: str, password: bool, seconds: float = 0.6) -> bool:
    """Whether a box holds value, as it says within seconds (a web page's says so a moment
    later). A password box says a dot for each character it holds (Chromium's, Qt's), so an
    empty one there holds nothing; others say nothing at all (Windows' own) or won't be read
    (WPF's), and are taken at their word."""
    try:
        dotted = password and element.CurrentFrameworkId in DOTTED
    except Exception:  # noqa: BLE001
        dotted = False
    deadline = time.monotonic() + seconds
    while True:
        try:
            now = pattern.CurrentValue or ''
        except Exception:  # noqa: BLE001
            return password
        if now == value or password and (
                not now and not dotted or len(now) == len(value) and len(set(now)) == 1 and not now[0].isalnum()):
            return True
        if time.monotonic() > deadline:
            return False
        time.sleep(0.05)


def give_focus(automation, window, element, seconds: float = 0.8) -> bool:
    """The keyboard to this box, its window in front first. True once the box has it."""
    try:
        if win32.foreground_pid() != window.pid:
            win32.set_foreground(window.hwnd)
        if automation.CompareElements(automation.GetFocusedElement(), element):
            return True
        element.SetFocus()
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            if automation.CompareElements(automation.GetFocusedElement(), element):
                return True
            time.sleep(0.05)
    except Exception:  # noqa: BLE001 - the box, or its program, is gone
        pass
    return False


def key_in(automation, window, element, value: str, keys: tuple, password: bool) -> bool:
    """Type value into a box that wouldn't take it set, over whatever it held, and see that it
    holds it.

    A box that took nothing at all, set or typed, may be in a form driven like a game console's
    (Ubisoft Connect's: "↵ Select" along its foot): there a box opens for typing on Enter, and
    drops everything until then. So it gets Enter, and is set again - only where the box says
    what it holds, so Enter never sends a form whose box took the keys after all."""
    if not give_focus(automation, window, element):
        return False
    try:
        pattern = _value_pattern(element)
        before = pattern.CurrentValue or '' if pattern is not None else None
        telling = pattern is not None and (not password or element.CurrentFrameworkId in DOTTED)
    except Exception:  # noqa: BLE001
        pattern, before, telling = None, None, False
    if not _type_over(window, value, keys):
        return False
    if pattern is None:
        return True
    if _landed(element, pattern, value, password, before, seconds=0.4):
        return True
    try:
        untouched = telling and (pattern.CurrentValue or '') == before and \
            automation.CompareElements(automation.GetFocusedElement(), element)
    except Exception:  # noqa: BLE001
        untouched = False
    if not untouched or typer.type_steps([('key', VK_RETURN)], window.pid, settle_ms=0) != typer.DONE:
        return _landed(element, pattern, value, password, before, seconds=1.1)
    time.sleep(0.15)
    if put(element, value, password):
        return True
    return _type_over(window, value, keys) and _landed(element, pattern, value, password, before, seconds=1.5)


def _type_over(window, value: str, keys: tuple) -> bool:
    steps = [('chord', (VK_CONTROL, 0x41)), ('text', value)]       # Ctrl+A: over what is there
    return typer.type_steps(steps, window.pid, compat=keys[0], key_delay_ms=keys[1], settle_ms=0) == typer.DONE


def _landed(element, pattern, value: str, password: bool, before, seconds: float) -> bool:
    """Whether what was typed is in the box. A password box must say so (holds); a text box needs
    only to have changed, since it may shape what is typed (a phone number's)."""
    if password:
        return holds(element, pattern, value, password, seconds=seconds)
    deadline = time.monotonic() + seconds
    while True:
        try:
            now = pattern.CurrentValue or ''
        except Exception:  # noqa: BLE001
            return True
        if now and (now == value or now != before):
            return True
        if time.monotonic() > deadline:
            return False
        time.sleep(0.05)


def _invoke(element) -> bool:
    deadline = time.monotonic() + 0.6           # a form may enable its button once both boxes are filled
    while True:
        try:
            if element.CurrentIsEnabled:
                pattern = element.GetCurrentPattern(UIA_INVOKE_PATTERN)
                if not pattern:
                    return False
                pattern.QueryInterface(_uia().IUIAutomationInvokePattern).Invoke()
                return True
        except Exception:  # noqa: BLE001
            return False
        if time.monotonic() > deadline:
            return False
        time.sleep(0.05)


def _button_after(automation, items, last, scope, root):
    """The form's sign-in button: the first after its last box filled, by its name - in the
    form, else a few levels further out."""
    for level, items_here in enumerate(_wider(automation, items, scope, root)):
        elements = [element for element, _ in items_here]
        at = _index(automation, elements, last)
        if at is None:
            continue
        for element, is_box in items_here[at + 1:]:
            try:
                if not is_box and submit_name(element.CurrentName):
                    return element
            except Exception:  # noqa: BLE001
                pass
    return None


def _wider(automation, items, scope, root):
    yield items
    for outer in _scopes(automation, scope, root, BUTTON_ANCESTORS):
        yield _items(automation, outer)


def submit(automation, window, items, scope, root, last, keys) -> str:
    """Send the form: its sign-in button, else Enter in last (the last box filled)."""
    if not typer.wait_for_keys_released():
        return ''           # a press with Ctrl or Alt held would be a different one
    button = _button_after(automation, items, last, scope, root)
    if button is not None and _invoke(button):
        return 'button'
    if give_focus(automation, window, last) and \
            typer.type_steps([('key', VK_RETURN)], window.pid, settle_ms=0) == typer.DONE:
        return 'enter'
    return ''


def fill(automation, window, start, username: str | None, password: str | None, send: bool,
         keys: tuple, login_name) -> Filled:
    """Fill the login form in window: username (None: not asked for) into its username box,
    password into its password box, then send it if asked.

    start is the box that had the keyboard when the hotkey was pressed, if known. keys is
    (compatibility typing, delay between keys) for a box that has to be typed into."""
    root = automation.ElementFromHandle(window.hwnd)
    if start is not None:
        try:
            if start.CurrentControlType != UIA_EDIT or not within(automation, start, root):
                start = None
        except Exception:  # noqa: BLE001
            start = None
    form = find_form(automation, root, start, login_name)
    if form is None:
        return Filled('nothing')
    items, elements, boxes, name_at, password_at, scope = form
    if password is not None and password_at is None:
        if name_at is None or start is None:
            return Filled('nothing')
        # A text box and no password box: a sign-in that asks for the username first (Google's,
        # Microsoft's) - if the box says it is for one. Anything else gets typed as before.
        if not any(word in boxes[name_at].words for word in IDENTIFIER_WORDS):
            return Filled('nothing')
    if username is not None and password is None and name_at is None:
        return Filled('nothing')
    if password is not None and username is None and password_at is None:
        return Filled('nothing')
    done = Filled('filled')
    last = None
    for at, value, secret in ((name_at, username, False), (password_at, password, True)):
        if at is None or value is None:
            continue
        element = elements[at]
        if read_only(element):
            continue
        if put(element, value, secret):
            pass
        elif key_in(automation, window, element, value, keys, secret):
            done.typed = True
        else:
            done.outcome = 'failed'
            done.detail = 'password' if secret else 'username'
            return done
        if secret:
            done.password = True
        else:
            done.username = True
        last = element
    if last is None:
        return Filled('nothing')
    if send:
        done.submitted = submit(automation, window, items, scope, root, last, keys)
    return done
