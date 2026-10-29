r"""Filling a login form box by box (filling.py): which boxes are the username's and password's,
which button sends the form, what is set and what is typed, and how Keytap takes the outcome.

    %LOCALAPPDATA%\KeytapBuild\venv\Scripts\python.exe tests\test_filling.py

Nothing is shown and no program is filled: UI Automation is stood in for. fill_test.py fills
real windows of four kinds.
"""

import os
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / 'app'))

from PySide6.QtWidgets import QApplication  # noqa: E402

app = QApplication.instance() or QApplication([])

from keytap import filling, focus, sequence, typer, win32  # noqa: E402
from keytap.app import Controller  # noqa: E402
from keytap.filling import Box, Filled  # noqa: E402
from keytap.win32 import WindowInfo  # noqa: E402


def box(top, password=False, words='', left=100, width=300, height=40):
    return Box(password, words.lower(), (left, top, left + width, top + height))


class SequenceTests(unittest.TestCase):
    def test_plain_sequences_fill_boxes(self):
        self.assertEqual(sequence.boxes('{USERNAME}{TAB}{PASSWORD}{ENTER}'), (True, True, True))
        self.assertEqual(sequence.boxes('{username}{tab}{password}'), (True, True, False))
        self.assertEqual(sequence.boxes('{PASSWORD}{ENTER}'), (False, True, True))
        self.assertEqual(sequence.boxes('{USERNAME}{ENTER}'), (True, False, True))
        self.assertEqual(sequence.boxes('{PASSWORD}'), (False, True, False))

    def test_anything_more_is_typed(self):
        for typed in ('{USERNAME}{TAB}{TAB}{PASSWORD}{ENTER}', '{USERNAME}{TAB}{PASSWORD}{ENTER}{TOTP}',
                      'x{PASSWORD}', '{DELAY 200}{PASSWORD}', '{USERNAME} {TAB}{PASSWORD}', '{TOTP}', '', '{ENTER}'):
            self.assertIsNone(sequence.boxes(typed), typed)


class PickTests(unittest.TestCase):
    login = staticmethod(focus.is_login_name)

    def test_from_either_box(self):
        boxes = [box(100, words='Enter your email address'), box(160, True, 'Enter your password')]
        for start in (None, 0, 1):
            self.assertEqual(filling.pick(boxes, start, self.login), (0, 1), start)

    def test_a_search_box_above_is_left_alone(self):
        boxes = [box(10, words='Search'), box(100, words='Email'), box(160, True, 'Password')]
        self.assertEqual(filling.pick(boxes, None, self.login), (1, 2))
        just_password = [box(100, words='Search'), box(160, True, 'Password')]
        self.assertEqual(filling.pick(just_password, 1, self.login), (None, 1), 'not the search box')

    def test_beside_or_far(self):
        side = [box(100, words='User', left=0, width=200), box(100, True, 'Password', left=220, width=200)]
        self.assertEqual(filling.pick(side, None, self.login), (0, 1), 'on one row')
        far = [box(100, words='Email'), box(900, True, 'Password')]
        self.assertEqual(filling.pick(far, None, self.login), (None, 1), 'another form, further down')
        self.assertEqual(filling.pick(far, 0, self.login), (0, 1), 'the next box after it, though far')

    def test_sign_up_and_first_steps(self):
        sign_up = [box(100, words='Email'), box(160, True, 'Password'), box(220, True, 'Confirm password')]
        self.assertEqual(filling.pick(sign_up, 0, self.login), (0, 1))
        self.assertEqual(filling.pick(sign_up, 2, self.login), (None, 2), 'the box chosen is the one filled')
        self.assertEqual(filling.pick([box(100, words='Email or phone')], 0, self.login), (0, None))
        self.assertEqual(filling.pick([box(100, words='Notes')], None, self.login), (None, None))

    def test_the_sign_in_button_by_its_whole_name(self):
        for name in ('Log in', 'LOGIN', 'Sign in →', '登录', 'Next', ' Continue ', 'Sign  in'):
            self.assertTrue(filling.submit_name(name), name)
        for name in ("Can't log in?", 'Can’t log in?', 'Log in with Google', 'Or create an account',
                     'Forgot password?', '', 'Show password'):
            self.assertFalse(filling.submit_name(name), name)


class FillTests(unittest.TestCase):
    """filling.fill's choices, with the form and the program stood in for."""

    def setUp(self):
        self.window = WindowInfo(1, 'Ubisoft Connect', 'Chrome_WidgetWin_1', 10, r'C:\x\upc.exe')

        class Element:
            CurrentControlType = filling.UIA_EDIT
        self.name_box, self.password_box = Element(), Element()
        self.set, self.typed, self.sent = [], [], []
        self.takes = {self.name_box: True, self.password_box: True}
        self.types = True
        self.locked = set()
        patches = [
            mock.patch.object(filling, 'put', lambda e, v, secret: self.set.append(v) or self.takes[e]),
            mock.patch.object(filling, 'key_in', lambda a, w, e, v, k, secret: self.typed.append(v) or self.types),
            mock.patch.object(filling, 'read_only', lambda e: e in self.locked),
            mock.patch.object(filling, 'submit', lambda *a: self.sent.append(a[-2]) or 'button'),
            mock.patch.object(filling, 'within', lambda a, e, r: True),
        ]
        for patch in patches:
            patch.start()
            self.addCleanup(patch.stop)
        self.automation = SimpleNamespace(ElementFromHandle=lambda hwnd: 'root')

    def form(self, *found):
        """find_form gives found: (boxes, username index, password index)."""
        boxes, name_at, password_at = found
        elements = [self.name_box, self.password_box][:len(boxes)]
        return mock.patch.object(filling, 'find_form', lambda *a: ([], elements, boxes, name_at, password_at, 'scope'))

    def fill(self, username='me@example.com', password='hunter2', start=None):
        return filling.fill(self.automation, self.window, start, username, password, True, (False, 10),
                            focus.is_login_name)

    def test_each_box_set(self):
        with self.form([box(100, words='Email'), box(160, True)], 0, 1):
            result = self.fill()
        self.assertEqual((result.outcome, result.username, result.password, result.submitted, result.typed),
                         ('filled', True, True, 'button', False))
        self.assertEqual(self.set, ['me@example.com', 'hunter2'])
        self.assertEqual(self.typed, [])
        self.assertEqual(self.sent, [self.password_box], 'sent from the password box')

    def test_a_box_that_wont_take_it_is_typed_into(self):
        self.takes[self.password_box] = False
        with self.form([box(100, words='Email'), box(160, True)], 0, 1):
            result = self.fill()
        self.assertEqual((result.outcome, result.typed), ('filled', True))
        self.assertEqual(self.typed, ['hunter2'])

    def test_nor_typed_into(self):
        self.takes[self.password_box] = self.types = False
        with self.form([box(100, words='Email'), box(160, True)], 0, 1):
            result = self.fill()
        self.assertEqual((result.outcome, result.detail), ('failed', 'password'))
        self.assertEqual(self.sent, [], 'not sent half filled')

    def test_a_username_shown_not_asked_for(self):
        self.locked.add(self.name_box)
        with self.form([box(100, words='Email'), box(160, True)], 0, 1):
            result = self.fill()
        self.assertEqual((result.username, result.password), (False, True))
        self.assertEqual(self.set, ['hunter2'])

    def test_username_first_sign_ins(self):
        with self.form([box(100, words='Email or phone')], 0, None):
            result = self.fill(start=self.name_box)
        self.assertEqual((result.outcome, result.username, result.password), ('filled', True, False))
        self.assertEqual(self.set, ['me@example.com'], 'the password waits for its page')
        self.assertEqual(self.sent, [self.name_box])

    def test_typed_as_before_without_boxes_for_it(self):
        with self.form([box(100, words='Notes')], 0, None):
            self.assertEqual(self.fill(start=self.name_box).outcome, 'nothing', 'a text box that is no sign-in')
        with mock.patch.object(filling, 'find_form', lambda *a: None):
            self.assertEqual(self.fill().outcome, 'nothing', 'a game drawing its own boxes')
        with self.form([box(100, words='Email or phone')], 0, None):
            self.assertEqual(self.fill().outcome, 'nothing', 'no box had the keyboard')
        self.assertEqual(self.set, [])


class HoldsTests(unittest.TestCase):
    """Whether a box took what was set or typed into it, as it says."""

    @staticmethod
    def holds(framework, reads, value='hunter2', password=True):
        element = SimpleNamespace(CurrentFrameworkId=framework)

        class Pattern:
            @property
            def CurrentValue(self):  # noqa: N802 - UI Automation's name
                if isinstance(reads, Exception):
                    raise reads
                return reads
        return filling.holds(element, Pattern(), value, password, seconds=0.05)

    def test_a_web_pages_password_box_says_its_dots(self):
        self.assertTrue(self.holds('Chrome', '•' * 7))
        self.assertFalse(self.holds('Chrome', ''), "Ubisoft Connect's, emptied again by its page")
        self.assertFalse(self.holds('Chrome', '•' * 3), 'not all of it')
        self.assertFalse(self.holds('Qt', ''))

    def test_others_are_taken_at_their_word(self):
        self.assertTrue(self.holds('Win32', ''), "Windows' own reads empty, whatever it holds")
        self.assertTrue(self.holds('WPF', OSError('not to be read')))
        self.assertTrue(self.holds('XAML', ''))

    def test_a_text_box_says_what_it_holds(self):
        self.assertTrue(self.holds('Chrome', 'me@example.com', 'me@example.com', password=False))
        self.assertFalse(self.holds('Chrome', '', 'me@example.com', password=False))
        self.assertFalse(self.holds('Win32', 'someone@else.com', 'me@example.com', password=False))


class KeyInTests(unittest.TestCase):
    """Typing into a box that wouldn't take its value set - and a console-like form's box (Ubisoft
    Connect's), which takes nothing at all until Enter opens it."""

    def box(self, framework='Chrome', opens_on_enter=False, takes_keys=True, reads_empty=False):
        state = SimpleNamespace(value='', open=not opens_on_enter, pressed=[])

        class Pattern:
            @property
            def CurrentValue(self):  # noqa: N802 - UI Automation's name
                return '' if reads_empty else state.value

            def SetValue(self, value):  # noqa: N802
                if state.open:
                    state.value = value
        element = SimpleNamespace(CurrentFrameworkId=framework)

        def type_steps(steps, pid, **kwargs):
            for kind, value in steps:
                state.pressed.append(value if kind == 'key' else kind)
                if kind == 'key' and value == filling.VK_RETURN:
                    state.open = True
                elif kind == 'text' and state.open and takes_keys:
                    state.value = value
            return typer.DONE
        for name, stand_in in (('give_focus', lambda *a: True), ('_value_pattern', lambda e: Pattern())):
            patch = mock.patch.object(filling, name, stand_in)
            patch.start()
            self.addCleanup(patch.stop)
        patch = mock.patch.object(typer, 'type_steps', type_steps)
        patch.start()
        self.addCleanup(patch.stop)
        automation = SimpleNamespace(GetFocusedElement=lambda: element, CompareElements=lambda a, b: a is b)
        return automation, element, state

    def key_in(self, automation, element, value='hunter2', password=True):
        window = WindowInfo(1, 'Ubisoft Connect', 'Chrome_WidgetWin_1', 10, r'C:\x\upc.exe')
        return filling.key_in(automation, window, element, value, (False, 10), password)

    def test_typed_where_keys_are_taken(self):
        automation, element, state = self.box()
        self.assertTrue(self.key_in(automation, element))
        self.assertEqual(state.value, 'hunter2')
        self.assertNotIn(filling.VK_RETURN, state.pressed, 'no Enter: it would send the form')

    def test_a_console_like_box_is_opened_with_enter(self):
        for password in (True, False):
            automation, element, state = self.box(opens_on_enter=True)
            self.assertTrue(self.key_in(automation, element, password=password))
            self.assertEqual(state.value, 'hunter2')
            self.assertEqual(state.pressed.count(filling.VK_RETURN), 1)

    def test_never_enter_where_the_box_cant_say(self):
        automation, element, state = self.box('Win32', opens_on_enter=True, reads_empty=True)
        self.assertTrue(self.key_in(automation, element), "Windows' own password box: taken at its word")
        self.assertNotIn(filling.VK_RETURN, state.pressed)

    def test_a_box_that_takes_nothing(self):
        automation, element, state = self.box(opens_on_enter=True, takes_keys=False)
        state.open = False
        with mock.patch.object(filling, 'put', lambda *a: False):
            self.assertFalse(self.key_in(automation, element))
        self.assertEqual(state.pressed.count(filling.VK_RETURN), 1, 'Enter once, not again and again')


BORROWED = ('_use', '_fill', '_keys', '_typed', '_in_password_box', '_in_identifier_box')


class Lite(type('LiteBase', (), {name: vars(Controller)[name] for name in BORROWED})):
    """Keytap's controller, as far as using a login goes."""

    def __init__(self, outcome):
        self.outcome = outcome
        self.toasts = SimpleNamespace(shown=[], show=lambda title, text='', error=False, action=None:
                                      self.toasts.shown.append(title))
        self.settings = SimpleNamespace(sequence=sequence.DEFAULT, compat_typing=False, key_delay=10,
                                        hotkeys={'type': 'Ctrl+Alt+A'})
        self.fields = SimpleNamespace(fill=self._filled)
        self.field = None
        self.typing = False
        self._just_typed = None
        self.asked, self.keyed = [], []

    def _filled(self, window, username, password, send, keys, then):
        self.asked.append((username, password, send))
        then(self.outcome)

    def _type(self, steps, window, login, copy_code=False):
        self.keyed.append(steps)

    def _hide_inline(self):
        pass

    def copy(self, *args, **kwargs):
        pass


class ControllerTests(unittest.TestCase):
    def setUp(self):
        self.window = WindowInfo(1, 'Ubisoft Connect', 'Chrome_WidgetWin_1', 10, r'C:\x\upc.exe')
        self.login = SimpleNamespace(id='1', name='Ubisoft', username='me@example.com', password='hunter2', totp='',
                                     sequence='', reprompt=False)
        for name, value in (('set_foreground', lambda hwnd: True), ('runs_above_us', lambda pid: False)):
            patch = mock.patch.object(win32, name, value)
            patch.start()
            self.addCleanup(patch.stop)
        patch = mock.patch.object(win32.user32, 'IsWindow', lambda hwnd: True, create=True)
        patch.start()
        self.addCleanup(patch.stop)

    def test_filled_box_by_box(self):
        keytap = Lite(Filled('filled', True, True, 'button'))
        keytap._use(self.login, 'all', self.window)
        self.assertEqual(keytap.asked, [('me@example.com', 'hunter2', True)])
        self.assertEqual((keytap.keyed, keytap.toasts.shown, keytap.typing), ([], [], False))

    def test_typed_as_before_where_there_are_no_boxes(self):
        keytap = Lite(Filled('nothing'))
        keytap._use(self.login, 'all', self.window)
        self.assertEqual(len(keytap.keyed), 1, 'typed: {USERNAME}{TAB}{PASSWORD}{ENTER}')
        self.assertIn(('text', 'hunter2'), keytap.keyed[0])

    def test_said_when_it_could_not_fill_or_send(self):
        keytap = Lite(Filled('failed', detail='password'))
        keytap._use(self.login, 'all', self.window)
        self.assertEqual(keytap.toasts.shown, ['Nothing typed'])
        keytap = Lite(Filled('filled', True, True, ''))
        keytap._use(self.login, 'all', self.window)
        self.assertEqual(keytap.toasts.shown, ['Filled in'], 'Enter is left to the person')
        keytap = Lite(None)
        keytap._use(self.login, 'all', self.window)
        self.assertEqual((keytap.toasts.shown, keytap.typing), (['Nothing typed'], False), 'took too long')

    def test_one_box_only_and_own_sequences(self):
        keytap = Lite(Filled('filled', False, True))
        keytap._use(self.login, 'password', self.window)
        self.assertEqual(keytap.asked, [(None, 'hunter2', False)])
        keytap = Lite(Filled('filled', True, True, 'button'))
        keytap._use(SimpleNamespace(**{**vars(self.login), 'sequence': '{USERNAME}{TAB}{TAB}{PASSWORD}{ENTER}'}),
                    'all', self.window)
        self.assertEqual((keytap.asked, len(keytap.keyed)), ([], 1), 'its own sequence: typed')
        keytap = Lite(Filled('filled', True, True, 'button'))
        keytap._use(self.login, 'totp', self.window)
        self.assertEqual(keytap.asked, [], 'a code goes where the keyboard is')

    def test_username_first_page_remembered(self):
        keytap = Lite(Filled('filled', True, False, 'button'))
        keytap._use(self.login, 'all', self.window)
        self.assertIsNotNone(keytap._just_typed, 'its password page offers this login first')
        self.assertEqual(keytap._just_typed[2], '1')

    def test_administrator_programs(self):
        with mock.patch.object(win32, 'runs_above_us', lambda pid: True):
            keytap = Lite(Filled('filled', True, True, 'button'))
            keytap._use(self.login, 'all', self.window)
        self.assertEqual((keytap.asked, keytap.toasts.shown), ([], ['Windows will not let Keytap type there']))


if __name__ == '__main__':
    unittest.main(verbosity=2)
