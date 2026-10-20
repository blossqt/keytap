r"""Keytap's vault window, offscreen, on a made-up vault.

    %LOCALAPPDATA%\KeytapBuild\venv\Scripts\python.exe tests\test_vault_window.py

Nothing is shown on screen and no real vault is read.
"""

import os
import sys
import unittest
from pathlib import Path

os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'app'))

from PySide6.QtWidgets import QApplication, QLabel  # noqa: E402

app = QApplication.instance() or QApplication([])

from keytap.ui.vault_window import DOTS, VaultWindow, sample_controller, spaced, web_vault  # noqa: E402
from keytap.vault import Login  # noqa: E402

SECRET = 'JBSWY3DPEHPK3PXP'
LOGINS = [
    Login('1', 'store.steampowered.com', 'viridaria', 'pw-one', uris=('https://store.steampowered.com',),
          favorite=True, folder_id='g'),
    Login('2', 'Steam Community', 'smurf', 'pw-two', uris=('https://steamcommunity.com',), folder_id='g'),
    Login('3', 'GitHub', 'blossqt', 'pw-three', totp=SECRET, folder_id='w', fields=(('PIN', '2468'),),
          hidden=frozenset({'PIN'}), notes='Work account.'),
    Login('4', 'Bank', 'me', 'pw-four', reprompt=True),
]


def texts(widget) -> str:
    return '\n'.join(label.text() for label in widget.findChildren(QLabel))


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
        self.assertEqual(self.names(), ['Bank', 'GitHub', 'Steam Community', 'store.steampowered.com'])
        filters = [self.window.filters.item(i).text() for i in range(self.window.filters.count())]
        self.assertEqual(filters, ['All logins   4', 'Favourites   1', 'Verification codes   1', 'FOLDERS',
                                   'Games   2', 'Work   1', 'No folder   1'])
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
        self.assertEqual(self.window.count.text(), '1 of 4 logins')

    def test_secrets_stay_hidden_until_shown(self):
        self.select('GitHub')
        shown = texts(self.window.details)
        self.assertIn('blossqt', shown)
        self.assertNotIn('pw-three', shown)
        self.assertNotIn('2468', shown, 'a hidden custom field is hidden too')
        self.assertIn(DOTS, shown)
        self.assertIn('Work account.', shown)
        masked = [label for label in self.window.details.widget().findChildren(QLabel) if label.text() == DOTS]
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

    def test_helpers(self):
        self.assertEqual(spaced('123456'), '123 456')
        self.assertEqual(spaced('ABCDE'), 'ABCDE')
        self.assertEqual(web_vault(''), 'https://vault.bitwarden.com')
        self.assertEqual(web_vault('https://vault.bitwarden.eu'), 'https://vault.bitwarden.eu')
        self.assertEqual(web_vault('https://bw.example.org/'), 'https://bw.example.org')


if __name__ == '__main__':
    unittest.main(verbosity=2)
