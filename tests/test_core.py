"""Keytap's logic, without the keyboard: codes, sequences, matching, the vault.

    %LOCALAPPDATA%\\KeytapBuild\\venv\\Scripts\\python.exe tests\\test_core.py

The vault tests run against tests/fake_bw.py, and - for the answers it gives
while signed out - the real bundled bw.exe, if bootstrap.ps1 has fetched it.
"""

import ctypes
import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / 'app'))

from keytap import hotkeys, matching, sequence, totp, typer, vault  # noqa: E402
from keytap.vault import Bitwarden, Login, NotSignedIn, VaultError  # noqa: E402
from keytap.win32 import WindowInfo  # noqa: E402

RFC_SHA1 = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'          # "12345678901234567890"


def item(id, name, username='', password='', uris=(), totp_key='', fields=(), reprompt=0, type=1,
         favorite=False):
    return {'object': 'item', 'id': id, 'organizationId': None, 'folderId': None, 'type': type,
            'reprompt': reprompt, 'name': name, 'notes': None, 'favorite': favorite,
            'fields': [{'name': n, 'value': v, 'type': t, 'linkedId': None} for n, v, t in fields],
            'login': {'uris': [{'match': None, 'uri': u} for u in uris], 'username': username or None,
                      'password': password or None, 'totp': totp_key or None, 'fido2Credentials': []}
            if type == 1 else None,
            'collectionIds': [], 'revisionDate': '2026-10-01T00:00:00.000Z',
            'creationDate': '2026-10-01T00:00:00.000Z', 'deletedDate': None}


def window(exe='steam.exe', title='Steam', path=None):
    return WindowInfo(hwnd=1, title=title, class_name='X', pid=1,
                      exe_path=path or (f'C:\\Program Files\\App\\{exe}' if exe else ''))


class TotpTests(unittest.TestCase):
    def test_rfc6238_vectors(self):
        uri = f'otpauth://totp/x?secret={RFC_SHA1}&digits=8'
        self.assertEqual(totp.code(uri, at=59), '94287082')
        self.assertEqual(totp.code(uri, at=1111111109), '07081804')
        self.assertEqual(totp.code(uri, at=20000000000), '65353130')
        sha256 = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA'
        self.assertEqual(totp.code(f'otpauth://totp/x?secret={sha256}&digits=8&algorithm=SHA256', at=59),
                         '46119246')

    def test_bare_secret_with_spaces_is_six_digits(self):
        self.assertEqual(totp.code('gezd gnbv gy3t qojq gezd gnbv gy3t qojq', at=59), '287082')

    def test_steam(self):
        code = totp.code('steam://' + RFC_SHA1, at=59)
        self.assertEqual(len(code), 5)
        self.assertTrue(set(code) <= set('23456789BCDFGHJKMNPQRTVWXY'))

    def test_bad_keys(self):
        for key in ('', 'not base32!', 'otpauth://totp/x?digits=6'):
            with self.assertRaises(totp.TotpError):
                totp.code(key)


class SequenceTests(unittest.TestCase):
    login = Login('1', 'Steam', 'gaben', 'p{a}ss', totp=RFC_SHA1, fields=(('PIN', '1234'),))

    def steps(self, text):
        return sequence.compile(text, self.login, lambda: '123456')

    def test_default(self):
        self.assertEqual(self.steps(sequence.DEFAULT),
                         [('text', 'gaben'), ('key', 0x09), ('text', 'p{a}ss'), ('key', 0x0D)])

    def test_braces_repeat_delay_and_fields(self):
        self.assertEqual(self.steps('{{}x{}}{TAB 2}{DELAY 250}{DELAY=40}{FIELD:pin}{SPACE}{TOTP}'),
                         [('text', '{x}'), ('key', 9), ('key', 9), ('delay', 250), ('keydelay', 40),
                          ('text', '1234 123456')])

    def test_clearfield(self):
        self.assertEqual(self.steps('{CLEARFIELD}'), [('key', 0x24), ('chord', (0x10, 0x23)), ('key', 0x2E)])

    def test_errors(self):
        for text in ('{NOPE}', '{TAB x}', '{DELAY 99999}', '{FIELD:missing}', 'a{b'):
            with self.assertRaises(sequence.SequenceError, msg=text):
                self.steps(text)
        self.assertTrue(sequence.check('{NOPE}'))
        self.assertEqual(sequence.check(sequence.DEFAULT), '')

    def test_no_totp(self):
        with self.assertRaises(sequence.SequenceError):
            sequence.compile('{TOTP}', Login('2', 'X', 'u', 'p'), lambda: '1')

    def test_from_password_box(self):
        self.assertEqual(sequence.from_password_box(sequence.DEFAULT), '{PASSWORD}{ENTER}')
        self.assertEqual(sequence.from_password_box('{USERNAME}{ENTER}{DELAY 900}{PASSWORD}{ENTER}'),
                         '{PASSWORD}{ENTER}')
        self.assertEqual(sequence.from_password_box('{PASSWORD}{TAB}{TOTP}'), '{PASSWORD}{TAB}{TOTP}')

    def test_for_login(self):
        self.assertEqual(sequence.for_login(Login('3', 'PIN only', '', 'p'), sequence.DEFAULT), '{PASSWORD}{ENTER}')
        own = Login('4', 'X', 'u', 'p', fields=(('AutoType', '{PASSWORD}{ENTER}'),))
        self.assertEqual(sequence.for_login(own, sequence.DEFAULT), '{PASSWORD}{ENTER}')


class MatchingTests(unittest.TestCase):
    def test_uris(self):
        w = window('steam.exe', 'Sign in to Steam', 'C:\\Games\\Steam\\steam.exe')
        self.assertTrue(matching.uri_matches('app://steam.exe', w))
        self.assertTrue(matching.uri_matches('APP://Steam', w))
        self.assertTrue(matching.uri_matches('app://C:/Games/Steam/steam.exe', w))
        self.assertTrue(matching.uri_matches('app://Steam\\steam.exe', w))
        self.assertTrue(matching.uri_matches('steam.exe', w))
        self.assertTrue(matching.uri_matches('title://sign in to', w))
        self.assertTrue(matching.uri_matches('title://Sign in*Steam', w))
        self.assertFalse(matching.uri_matches('title://Sign in*Epic', w))
        self.assertFalse(matching.uri_matches('app://C:/Other/steam.exe', w))
        self.assertFalse(matching.uri_matches('https://store.steampowered.com', w))

    def test_find_and_sure_choice(self):
        w = window('steam.exe', 'Steam')
        a = Login('a', 'Steam', 'me', 'x', uris=('app://steam.exe',))
        b = Login('b', 'Steam (alt)', 'alt', 'y')
        c = Login('c', 'Valve store', 'me', 'z', uris=('https://store.steampowered.com',))
        d = Login('d', 'Unrelated', 'me', 'w')
        found = matching.find(w, [d, c, b, a], {})
        self.assertEqual([(m.login.id, m.strength) for m in found], [('a', 'uri'), ('b', 'hint')])
        self.assertIs(matching.sure_choice(found), a)
        # A remembered choice wins over the URI.
        found = matching.find(w, [d, c, b, a], {'steam.exe': 'b'})
        self.assertIs(matching.sure_choice(found), b)
        # Two URI matches and nothing remembered: ask.
        e = Login('e', 'Steam 2', 'two', 'v', uris=('app://steam.exe',))
        self.assertIsNone(matching.sure_choice(matching.find(w, [a, e], {})))
        # Hints alone never type by themselves.
        self.assertIsNone(matching.sure_choice(matching.find(w, [b], {})))

    def test_same_site_as_the_remembered_login(self):
        # Steam's sign-in is steamwebhelper.exe; its logins are saved for its websites.
        w = window('steamwebhelper.exe', 'Sign in to Steam')
        mine = Login('v', 'store.steampowered.com', 'viridaria', 'x', uris=('https://store.steampowered.com',))
        alt = Login('o', 'store.steampowered.com', 'alt', 'y', uris=('https://store.steampowered.com/login',))
        community = Login('c', 'Steam Community', 'third', 'z', uris=('https://steamcommunity.com',))
        unrelated = Login('u', 'GitHub', 'me', 'q', uris=('https://github.com',))
        logins = [unrelated, community, alt, mine]
        found = matching.find(w, logins, {'steamwebhelper.exe': 'v'})
        self.assertEqual([(m.login.id, m.strength) for m in found], [('v', 'linked'), ('c', 'site'), ('o', 'site')])
        self.assertIs(matching.sure_choice(found), mine, 'the remembered one is still typed straight away')
        # Nothing remembered and no app:// URI: nothing to say which site, so no site matches.
        self.assertEqual(matching.find(w, logins, {}), [])

    def test_site_of(self):
        self.assertEqual(matching.site_of('https://store.steampowered.com/login'), 'steampowered.com')
        self.assertEqual(matching.site_of('steamcommunity.com'), 'steamcommunity.com')
        self.assertEqual(matching.site_of('https://login.example.co.uk/x'), 'example.co.uk')
        self.assertEqual(matching.site_of('http://192.168.1.1:8080'), '192.168.1.1')
        for not_a_site in ('app://steam.exe', 'steam.exe', 'title://Sign in.', 'androidapp://com.valvesoftware',
                           'localhost', ''):
            self.assertEqual(matching.site_of(not_a_site), '', not_a_site)

    def test_site_hint_in_browser(self):
        w = window('chrome.exe', 'Sign in to GitHub · GitHub - Google Chrome')
        g = Login('g', 'Work account', 'me', 'x', uris=('https://github.com/login',))
        self.assertEqual([m.strength for m in matching.find(w, [g], {})], ['hint'])

    def test_link_keys(self):
        self.assertEqual(matching.link_key(window('steam.exe', 'Steam')), 'steam.exe')
        self.assertEqual(matching.link_key(window('mstsc.exe', 'server1 - Remote Desktop Connection')),
                         'mstsc.exe|server1 - Remote Desktop Connection')
        self.assertEqual(matching.describe(window('steam.exe', 'Steam')), 'steam.exe')


class HotkeyTests(unittest.TestCase):
    def test_parse(self):
        self.assertEqual(hotkeys.parse('Ctrl+Alt+A'), (0x3, 0x41))
        self.assertEqual(hotkeys.normalize('alt+ctrl+shift+a'), 'Ctrl+Alt+Shift+A')
        self.assertEqual(hotkeys.normalize('F9'), 'F9')
        self.assertEqual(hotkeys.normalize('Meta+K'), 'Win+K')
        for bad in ('Shift+A', 'A', 'Ctrl+Nope', ''):
            with self.assertRaises(hotkeys.HotkeyError, msg=bad):
                hotkeys.parse(bad)


class TyperTests(unittest.TestCase):
    def test_input_struct_matches_windows(self):
        self.assertEqual(ctypes.sizeof(typer.INPUT), 40 if ctypes.sizeof(ctypes.c_void_p) == 8 else 28)


class FakeVaultTests(unittest.TestCase):
    password = 'correct horse battery staple'

    def setUp(self):
        self.folder = Path(tempfile.mkdtemp(prefix='keytap-test-'))
        self.state = self.folder / 'vault.json'
        self.state.write_text(json.dumps({
            'email': 'test@example.com', 'password': self.password, 'signed_in': False, 'items': [
                item('1', 'Steam', 'gaben', 'hl3', uris=['app://steam.exe'], totp_key=RFC_SHA1,
                     fields=[('autotype', '{USERNAME}{TAB}{PASSWORD}{ENTER}', 0), ('flag', 'true', 2)],
                     reprompt=1, favorite=True),
                item('2', 'A card', type=3),
                item('3', 'No username', password='pin'),
            ]}), encoding='utf-8')
        os.environ['KEYTAP_FAKE_VAULT'] = str(self.state)
        os.environ['KEYTAP_FAKE_DELAY'] = '0'
        self.vault = Bitwarden([sys.executable, str(HERE / 'fake_bw.py')], self.folder / 'bw')

    def tearDown(self):
        shutil.rmtree(self.folder, ignore_errors=True)

    def test_whole_journey(self):
        self.assertEqual(self.vault.status().state, 'unauthenticated')
        with self.assertRaises(NotSignedIn):
            self.vault.unlock(self.password)
        self.vault.set_server('https://vault.bitwarden.eu')
        self.assertEqual(self.vault.status().server, 'https://vault.bitwarden.eu')
        state = json.loads(self.state.read_text())
        state['signed_in'] = True
        self.state.write_text(json.dumps(state))
        with self.assertRaises(VaultError):
            self.vault.set_server('bitwarden.com')
        status = self.vault.status()
        self.assertEqual((status.state, status.email), ('locked', 'test@example.com'))

        with self.assertRaises(VaultError) as caught:
            self.vault.unlock('wrong')
        self.assertEqual(str(caught.exception), 'Invalid master password.')
        self.vault.unlock(self.password)
        self.assertEqual(self.vault.status().state, 'unlocked')
        logins = self.vault.logins()
        self.assertEqual([l.name for l in logins], ['Steam', 'No username'])
        steam = logins[0]
        self.assertEqual((steam.username, steam.password, steam.uris), ('gaben', 'hl3', ('app://steam.exe',)))
        self.assertTrue(steam.reprompt and steam.favorite)
        self.assertEqual(steam.sequence, '{USERNAME}{TAB}{PASSWORD}{ENTER}')
        self.assertEqual(steam.fields, (('autotype', '{USERNAME}{TAB}{PASSWORD}{ENTER}'),))
        self.assertNotIn('hl3', repr(steam))
        self.vault.sync()

        session = self.vault.take_session()
        self.vault.lock(session)
        self.assertEqual(self.vault.status().state, 'locked')
        with self.assertRaises(VaultError):
            self.vault.logins()
        log = (self.folder / 'vault.log').read_text()
        self.assertNotIn(self.password, log)      # never on a command line

    def test_console_command_lines(self):
        line, env = self.vault.sign_in_command()
        self.assertTrue(line.startswith('cmd.exe /d /c "title '))
        self.assertIn('fake_bw.py" login', line)
        self.assertEqual(env['BITWARDENCLI_APPDATA_DIR'], str(self.folder / 'bw'))
        self.assertNotIn('BW_SESSION', env)


@unittest.skipUnless(vault.find_cli() and 'KEYTAP_BW' not in os.environ, 'the real bw.exe is not here')
class RealCliTests(unittest.TestCase):
    """What the real bw says while signed out: enough to show Keytap reads it right."""

    def test_signed_out_answers(self):
        folder = Path(tempfile.mkdtemp(prefix='keytap-bw-'))
        try:
            real = Bitwarden(data=folder)
            self.assertRegex(real.version(), r'^\d{4}\.\d+\.\d+$')
            self.assertEqual(real.status().state, 'unauthenticated')
            with self.assertRaises(NotSignedIn):
                real.unlock('not a password')
            real.set_server('https://vault.bitwarden.eu')
            self.assertEqual(real.status().server, 'https://vault.bitwarden.eu')
        finally:
            shutil.rmtree(folder, ignore_errors=True)


if __name__ == '__main__':
    unittest.main(verbosity=2)
