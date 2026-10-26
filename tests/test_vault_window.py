r"""Keytap's vault window, offscreen, on a made-up vault.

    %LOCALAPPDATA%\KeytapBuild\venv\Scripts\python.exe tests\test_vault_window.py

Nothing is shown on screen and no real vault is read.
"""

import os
import sys
import unittest
from pathlib import Path

os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')
# Windows' own fonts: offscreen Qt otherwise has none, and draws every letter as a wide box.
os.environ.setdefault('QT_QPA_FONTDIR', str(Path(os.environ.get('WINDIR', r'C:\Windows')) / 'Fonts'))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'app'))

from PySide6.QtWidgets import QApplication, QLabel, QTextEdit  # noqa: E402

app = QApplication.instance() or QApplication([])

from keytap.ui.vault_window import DOTS, VaultWindow, sample_controller, spaced, web_vault  # noqa: E402
from keytap.vault import Login  # noqa: E402

SECRET = 'JBSWY3DPEHPK3PXP'
ANDROID = 'android://TaLviCw10Tcjk_stQJrL0-uOoXrTtEcKX9q5DFB329e7as4oeNxHU0QgqH9uZtNdK2Qx@com.instagram.android'
LOGINS = [
    Login('1', 'store.steampowered.com', 'viridaria', 'pw-one', uris=('https://store.steampowered.com',),
          favorite=True, folder_id='g'),
    Login('2', 'Steam Community', 'smurf', 'pw-two', uris=('https://steamcommunity.com',), folder_id='g'),
    Login('3', 'GitHub', 'blossqt', 'pw-three', totp=SECRET, folder_id='w', fields=(('PIN', '2468'),),
          hidden=frozenset({'PIN'}), notes='Work account.'),
    Login('4', 'Bank', 'me', 'pw-four', reprompt=True),
    Login('5', 'android.instagram.com', 'not_evan_', 'pw-five-' + 'x' * 60, uris=(
        ANDROID, 'https://www.instagram.com/accounts/login/?next=https%3A%2F%2Fwww.instagram.com%2Fdirect%2F')),
]


def texts(widget) -> str:
    return '\n'.join([label.text() for label in widget.findChildren(QLabel)] +
                     [text.text() for text in widget.findChildren(QTextEdit)])


class VaultWindowTest(unittest.TestCase):
    def setUp(self):
        self.controller = sample_controller(list(LOGINS), {'g': 'Games', 'w': 'Work'})
        self.copied = []
        self.confirmations = []
        self.controller.copy = lambda value, label: self.copied.append((label, value))
        self.controller.confirm = lambda login, then, near: self.confirmations.append((login.id, then))
        self.window = VaultWindow(self.controller)

    def tearDown(self):
        self.window.close()
        self.window.deleteLater()

    def names(self) -> list[str]:
        return [self.window.list.item(i).data(0x0100).name for i in range(self.window.list.count())]

    def select(self, name: str) -> None:
        self.window.list.setCurrentRow(self.names().index(name))

    def test_lists_sorted_with_filters_and_folders(self):
        self.assertEqual(self.names(), ['android.instagram.com', 'Bank', 'GitHub', 'Steam Community',
                                        'store.steampowered.com'])
        filters = [self.window.filters.item(i).text() for i in range(self.window.filters.count())]
        self.assertEqual(filters, ['All logins   5', 'Favourites   1', 'Verification codes   1', 'FOLDERS',
                                   'Games   2', 'Work   1', 'No folder   2'])
        self.window.filters.setCurrentRow(4)                 # Games
        self.assertEqual(self.names(), ['Steam Community', 'store.steampowered.com'])
        self.window.filters.setCurrentRow(1)                 # Favourites
        self.assertEqual(self.names(), ['store.steampowered.com'])

    def test_search_matches_name_username_and_website(self):
        self.window.search.setText('steam')
        self.assertEqual(self.names(), ['Steam Community', 'store.steampowered.com'])
        self.window.search.setText('blossqt')
        self.assertEqual(self.names(), ['GitHub'])
        self.window.search.setText('steamcommunity.com smurf')
        self.assertEqual(self.names(), ['Steam Community'])
        self.assertEqual(self.window.count.text(), '1 of 5 logins')

    def test_secrets_stay_hidden_until_shown(self):
        self.select('GitHub')
        shown = texts(self.window.details)
        self.assertIn('blossqt', shown)
        self.assertNotIn('pw-three', shown)
        self.assertNotIn('2468', shown, 'a hidden custom field is hidden too')
        self.assertIn(DOTS, shown)
        self.assertIn('Work account.', shown)
        masked = [text for text in self.window.details.widget().findChildren(QTextEdit) if text.text() == DOTS]
        reveal = masked[0].parentWidget().reveal         # the password's field comes first
        reveal.click()
        self.assertIn('pw-three', texts(self.window.details))
        # Copying goes through the controller, which keeps it out of the clipboard history.
        self.window._copy_part('password')
        self.assertEqual(self.copied[-1], ('password', 'pw-three'))

    def test_verification_code_counts_down(self):
        self.select('GitHub')
        code = self.window.details._code.value.text()
        self.assertRegex(code, r'^\d{3} \d{3}\s+·\s+\d{1,2}s$')

    def test_a_login_that_asks_for_the_password_shows_nothing_until_given(self):
        self.select('Bank')
        self.assertNotIn('pw-four', texts(self.window.details))
        self.assertNotIn('me', texts(self.window.details).split('\n'), 'not even the username')
        self.window._copy_part('password')
        self.assertEqual(self.copied, [], 'copying asks first')
        self.assertEqual(self.confirmations[-1][0], '4')
        self.confirmations[-1][1]()                         # the master password was right
        self.assertIn('me', texts(self.window.details).split('\n'))
        self.window._copy_part('password')
        self.assertEqual(self.copied[-1], ('password', 'pw-four'))
        # Opened again later: asked again.
        self.select('GitHub')
        self.select('Bank')
        self.assertNotIn('me', texts(self.window.details).split('\n'))

    def test_locking_clears_the_window(self):
        self.select('GitHub')
        self.controller.unlocked = False
        self.controller.logins = None
        self.controller.status.state = 'locked'
        self.window.refresh()
        self.assertIs(self.window.pages.currentWidget(), self.window.lock_page)
        self.assertEqual(self.window.list.count(), 0)
        self.assertEqual(self.window.filters.count(), 0, 'folder names and counts go too')
        everything = texts(self.window)
        for login in LOGINS:
            self.assertNotIn(login.username, everything.split('\n'))
            self.assertNotIn(login.password, everything)
        self.assertIn('Signed in as someone@example.com', everything)

    def test_long_values_wrap_instead_of_widening_the_window(self):
        self.window.resize(740, 520)                       # the smallest it goes
        self.window.show()                                 # offscreen: laid out as on screen
        try:
            self.select('android.instagram.com')
            self.window.details.widget().findChildren(QTextEdit)[2].parentWidget().reveal.click()   # the password
            for _ in range(10):        # the layout settles, as it does between frames on screen
                app.processEvents()
            page = self.window.details.widget()
            self.assertLessEqual(page.minimumSizeHint().width(), self.window.details.viewport().width(),
                                 'nothing in the login is wider than its pane')
            shown = texts(self.window.details)
            self.assertIn('com.instagram.android', shown.split('\n'), 'an Android app by its name')
            self.assertNotIn(ANDROID, shown.split('\n'))
            self.assertIn('pw-five-' + 'x' * 60, shown, 'the whole password, wrapped')
            for text in page.findChildren(QTextEdit):      # each row is as tall as its wrapped text
                self.assertGreaterEqual(text.parentWidget().height(), text.height())
                self.assertLessEqual(text.document().size().height(), text.height() + 1)
            self.assertLessEqual(self.window.sidebar.width() + self.window.middle.width(), 740 - 300)
            # Copying a selection by hand keeps it out of the clipboard history too.
            name = page.findChildren(QTextEdit)[0]
            name.selectAll()
            mime = name.createMimeDataFromSelection()
            self.assertEqual(mime.text(), 'android.instagram.com', 'without the places a line may break')
            self.assertIn('application/x-qt-windows-mime;value="CanIncludeInClipboardHistory"', mime.formats())
        finally:
            self.window.hide()

    def test_helpers(self):
        self.assertEqual(spaced('123456'), '123 456')
        self.assertEqual(spaced('ABCDE'), 'ABCDE')
        self.assertEqual(web_vault(''), 'https://vault.bitwarden.com')
        self.assertEqual(web_vault('https://vault.bitwarden.eu'), 'https://vault.bitwarden.eu')
        self.assertEqual(web_vault('https://bw.example.org/'), 'https://bw.example.org')


class RememberTests(unittest.TestCase):
    """The picker's 'Always use', for the login chosen or for any login on its website."""

    def pick(self, login_id: str, ticks: str, site_choice: bool = True) -> str:
        from PySide6.QtCore import Qt

        from keytap import matching
        from keytap.ui.picker import Picker
        picker = Picker(LOGINS, matching.find(matching_window(), LOGINS, {}), 'steam.exe',
                        'Always use this login in steam.exe', site_choice=site_choice)
        picker.list.setCurrentRow(next(i for i in range(picker.list.count())
                                       if picker.list.item(i).data(Qt.UserRole)[0].id == login_id))
        if 'login' in ticks:
            picker.remember.setChecked(True)
        if 'site' in ticks:
            self.assertTrue(picker.whole_site.isVisibleTo(picker), 'offered for a login with a website')
            picker.whole_site.setChecked(True)
        got = []
        picker.chosen.connect(lambda login, action, remember: got.append((login.id, remember)))
        picker._choose('all')
        return got[0]

    def test_remember_a_login_or_its_website(self):
        self.assertEqual(self.pick('1', ''), ('1', ''))
        self.assertEqual(self.pick('1', 'login'), ('1', 'login'))
        self.assertEqual(self.pick('1', 'site'), ('1', 'site'), 'ticking it ticks "Always use" too')
        self.assertEqual(self.pick('1', 'login site'), ('1', 'site'))
        self.assertEqual(self.pick('2', 'site'), ('2', 'site'))

    def test_not_offered_without_a_website_or_on_a_web_page(self):
        from keytap import matching
        from keytap.ui.picker import Picker
        picker = Picker(LOGINS, [], 'steam.exe', 'Always use this login in steam.exe', site_choice=True)
        picker.search.setText('Bank')                      # no website saved for it
        self.assertFalse(picker.whole_site.isVisibleTo(picker))
        picker = Picker(LOGINS, matching.find(matching_window(), LOGINS, {}), 'steampowered.com',
                        'Always use this login on steampowered.com', site_choice=False)
        self.assertFalse(picker.whole_site.isVisibleTo(picker))

    def test_settings_turn_a_remembered_login_into_its_website(self):
        from PySide6.QtCore import Qt
        from PySide6.QtWidgets import QListWidget, QListWidgetItem

        from keytap import matching
        from keytap.app import Controller
        from keytap.ui import dialogs

        class Owner:                        # the controller, as far as remembered programs go
            logins, unlocked = list(LOGINS), True
            link_target, login_site, login_name = Controller.link_target, Controller.login_site, Controller.login_name

        class Page:                         # the settings dialog's remembered programs, alone
            controller, _links = Owner(), QListWidget()
            _show_link, _links_to_sites = dialogs.SettingsDialog._show_link, dialogs.SettingsDialog._links_to_sites

        page = Page()
        page._links.setSelectionMode(QListWidget.ExtendedSelection)        # as in the dialog
        for key, value in {'steam.exe': '1', 'notepad.exe': '4'}.items():
            item = QListWidgetItem()
            item.setData(Qt.UserRole, (key, value))
            page._show_link(item)
            page._links.addItem(item)
            item.setSelected(True)
        told, information = [], dialogs.QMessageBox.information
        dialogs.QMessageBox.information = lambda *args: told.append(args[2])
        try:
            page._links_to_sites()
        finally:
            dialogs.QMessageBox.information = information
        items = [page._links.item(i) for i in range(page._links.count())]
        self.assertEqual(dict(item.data(Qt.UserRole) for item in items),
                         {'steam.exe': matching.SITE_LINK + 'steampowered.com', 'notepad.exe': '4'})
        self.assertEqual(items[0].text(), 'steam.exe  →  any login for steampowered.com')
        self.assertEqual(items[1].text(), 'notepad.exe  →  Bank')
        self.assertIn('no website', told[0], 'the Bank login has none')


def matching_window():
    from keytap.win32 import WindowInfo
    return WindowInfo(hwnd=1, title='Steam', class_name='X', pid=1, exe_path='C:\\Steam\\steam.exe')



class ToastTest(unittest.TestCase):
    def test_a_fifth_toast_doesnt_hang_keytap(self):
        # The oldest of five only starts fading; counted until it had faded, the stack went round
        # for ever, and Keytap hung (until 2026-10-26). Should that come back, the test is stopped.
        import faulthandler
        from unittest import mock
        from keytap.ui import suitetheme
        from keytap.ui.toast import ToastStack
        faulthandler.dump_traceback_later(20, exit=True)
        try:
            with mock.patch.object(suitetheme, 'motion_on', lambda: True):
                stack = ToastStack()
                for n in range(7):
                    stack.show(f'Toast {n}')
                self.assertEqual(stack.titles(), ['Toast 3', 'Toast 4', 'Toast 5', 'Toast 6'])
                for toast in list(stack._toasts):
                    toast.close_toast()
        finally:
            faulthandler.cancel_dump_traceback_later()


if __name__ == '__main__':
    unittest.main(verbosity=2)
