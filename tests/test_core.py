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

from keytap import focus, hello, hotkeys, matching, sequence, totp, typer, vault  # noqa: E402
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
        # On a web page, by its website: the program could be showing any.
        claude, page = window('claude.exe', 'Claude'), 'https://www.instagram.com/accounts/login/?next=%2F'
        self.assertEqual(matching.link_key(claude, page), 'claude.exe|site:instagram.com')
        self.assertEqual(matching.describe(claude, page), 'instagram.com')
        self.assertEqual(matching.link_key(claude, 'http://localhost:3000/'), 'claude.exe', 'no website: the program')

    def test_web_page_in_a_program(self):
        # Claude's desktop app has a browser of its own, where Bitwarden's extension can't help.
        claude, page = window('claude.exe', 'Claude'), 'https://www.instagram.com/accounts/login/'
        one = Login('1', 'www.instagram.com', 'not_evan_', 'a', uris=('https://www.instagram.com/',))
        two = Login('2', 'Instagram', 'blossqt', 'b', uris=('instagram.com',))
        app = Login('3', 'com.instagram.android', 'not_evan_', 'c',
                    uris=('android://hash@com.instagram.android',))
        claude_login = Login('4', 'Claude', 'me', 'd', uris=('https://claude.ai',))
        other = Login('5', 'GitHub', 'blossqt', 'e', uris=('https://github.com',))
        logins = [other, claude_login, app, two, one]
        found = matching.find(claude, logins, {}, page)
        self.assertEqual([(m.login.id, m.strength) for m in found], [('2', 'page'), ('1', 'page'), ('3', 'hint')],
                         "the page's website, not the program's name")
        self.assertIsNone(matching.sure_choice(found), 'two accounts there: ask')
        self.assertIs(matching.sure_choice(matching.find(claude, [one, app, other], {}, page)), one,
                      'one login for the website: typed, as Bitwarden fills it in a browser')
        # Remembered for the website, not for every page in the program.
        links = {'claude.exe|site:instagram.com': '2'}
        self.assertIs(matching.sure_choice(matching.find(claude, logins, links, page)), two)
        github = matching.find(claude, logins, links, 'https://github.com/login')
        self.assertEqual([(m.login.id, m.strength) for m in github], [('5', 'page')])
        # Off the page - Claude's own chat box, say - the program goes by its name, as before.
        self.assertEqual([(m.login.id, m.strength) for m in matching.find(claude, logins, links)], [('4', 'hint')])
        # Steam's websites are one account.
        steam = Login('6', 'Steam', 'v', 'f', uris=('https://store.steampowered.com',))
        self.assertEqual([m.strength for m in matching.find(claude, [steam], {}, 'https://steamcommunity.com/login')],
                         ['page'])

    def test_match_detection_set_in_bitwarden(self):
        claude = window('claude.exe', 'Claude')

        def on(page, *logins):
            return sorted(m.login.id for m in matching.find(claude, list(logins), {}, page) if m.strength == 'page')
        base = Login('b', 'GitHub', 'me', 'x', uris=('https://github.com',))
        never = Login('n', 'GitHub old', 'old', 'x', uris=('https://github.com',), uri_match=(matching.NEVER,))
        host = Login('h', 'Gist', 'g', 'x', uris=('https://gist.github.com',), uri_match=(matching.HOST,))
        starts = Login('s', 'Enterprise', 'e', 'x', uris=('https://github.com/enterprises/acme',),
                       uri_match=(matching.STARTS_WITH,))
        exact = Login('e', 'Exact', 'x', 'x', uris=('https://github.com/login',), uri_match=(matching.EXACT,))
        regex = Login('r', 'Regex', 'r', 'x', uris=(r'^https://(www\.)?github\.com/log',), uri_match=(matching.REGEX,))
        everyone = (base, never, host, starts, exact, regex)
        self.assertEqual(on('https://github.com/login', *everyone), ['b', 'e', 'r'])
        self.assertEqual(on('https://gist.github.com/auth', *everyone), ['b', 'h'])
        self.assertEqual(on('https://github.com/enterprises/acme/sso', *everyone), ['b', 's'])
        self.assertEqual(on('https://github.com/login?return_to=x', *everyone), ['b', 'r'], 'exact is exact')
        broken = Login('x', 'Broken', 'x', 'x', uris=('([',), uri_match=(matching.REGEX,))
        self.assertEqual(on('https://github.com/', broken), [], 'a broken expression matches nothing')
        # Never also keeps a login out of "the same website" and the hints.
        w = window('steamwebhelper.exe', 'Sign in to Steam')
        mine = Login('v', 'store.steampowered.com', 'v', 'x', uris=('https://store.steampowered.com',))
        hidden = Login('o', 'Steam alt', 'o', 'y', uris=('https://store.steampowered.com',),
                       uri_match=(matching.NEVER,))
        found = matching.find(w, [mine, hidden], {'steamwebhelper.exe': 'v'})
        self.assertEqual([(m.login.id, m.strength) for m in found], [('v', 'linked')], 'not another account there')
        # From the vault: each address's setting, in step with the addresses.
        item = {'type': 1, 'id': 'i', 'name': 'n', 'login': {'uris': [
            {'uri': 'https://a.example.com', 'match': 1}, {'uri': 'https://b.example.com', 'match': None},
            {'uri': ''}, {'uri': 'app://x.exe', 'match': 5}]}}
        login = Login.from_item(item)
        self.assertEqual(login.uris, ('https://a.example.com', 'https://b.example.com', 'app://x.exe'))
        self.assertEqual(login.uri_match, (1, None, 5))

    def test_websites_that_share_one_account(self):
        claude = window('claude.exe', 'Claude')
        google = Login('g', 'Google', 'me', 'x', uris=('https://accounts.google.com',))
        riot = Login('r', 'Riot', 'me', 'x', uris=('https://auth.riotgames.com',))
        xbox = Login('m', 'Microsoft', 'me', 'x', uris=('https://login.live.com',))
        logins = [google, riot, xbox]
        for page, wanted in (('https://www.youtube.com/signin', 'g'), ('https://playvalorant.com/en-us/', 'r'),
                             ('https://www.xbox.com/en-US/auth/msa', 'm'), ('https://www.minecraft.net/login', 'm')):
            self.assertEqual([m.login.id for m in matching.find(claude, logins, {}, page) if m.strength == 'page'],
                             [wanted], page)
        # Only for base-domain matching, as in Bitwarden.
        exact = Login('e', 'Google', 'me', 'x', uris=('https://accounts.google.com',), uri_match=(matching.HOST,))
        self.assertEqual(matching.find(claude, [exact], {}, 'https://www.youtube.com/signin'), [])

    def test_pages_a_program_serves_itself(self):
        # Steam draws its own screens as web pages from steamloopback.host: the program decides, as before.
        w = window('steamwebhelper.exe', 'Sign in to Steam')
        mine = Login('v', 'store.steampowered.com', 'viridaria', 'x', uris=('https://store.steampowered.com',))
        for page in ('https://steamloopback.host/index.html', 'http://localhost:5173/login',
                     'https://127.0.0.1:52144/rso', 'http://192.168.1.20/', 'https://ui.app.localhost/'):
            self.assertEqual(matching.page_site(page), '', page)
            self.assertEqual(matching.link_key(w, page), 'steamwebhelper.exe', page)
            found = matching.find(w, [mine], {'steamwebhelper.exe': 'v'}, page)
            self.assertEqual([(m.login.id, m.strength) for m in found], [('v', 'linked')], page)
        self.assertEqual(matching.page_site('https://www.instagram.com/x'), 'instagram.com')
        self.assertEqual(matching.page_site('https://8.8.8.8/'), '8.8.8.8')

    def test_choice_remembered_for_the_program_before(self):
        # Remembered for discord.exe before Keytap knew Discord's page: still used on discord.com,
        discord = window('discord.exe', 'Discord')
        main = Login('d', 'Discord', 'main', 'x', uris=('https://discord.com',))
        alt = Login('a', 'Discord alt', 'alt', 'y', uris=('https://discord.com/login',))
        found = matching.find(discord, [alt, main], {'discord.exe': 'd'}, 'https://discord.com/login')
        self.assertIs(matching.sure_choice(found), main)
        # but never on another website the program shows.
        claude = window('claude.exe', 'Claude')
        insta = Login('i', 'Instagram', 'me', 'z', uris=('https://instagram.com',))
        github = Login('g', 'GitHub', 'me', 'q', uris=('https://github.com',))
        found = matching.find(claude, [insta, github], {'claude.exe': 'i'}, 'https://github.com/login')
        self.assertEqual([(m.login.id, m.strength) for m in found], [('g', 'page')])


class FocusTests(unittest.TestCase):
    def test_login_names(self):
        for name in ('Username or email address', 'Email address', 'Phone number, username, or email', 'Password',
                     'login_field', ''):
            self.assertTrue(focus.is_login_name(name), name)
        for name in ('Address and search bar', 'Search', 'Message #general', 'Filter', 'URL'):
            self.assertFalse(focus.is_login_name(name), name)

    def test_keyboard_handed_back_only_to_the_same_box(self):
        class Automation:                       # UI Automation, as far as handing back goes
            def __init__(self, focused, moves=True):
                self.focused, self.moves = focused, moves

            def GetFocusedElement(self):
                return self.focused

            def CompareElements(self, a, b):
                return a is b

        class Element:
            def __init__(self, automation=None):
                self.automation = automation

            def SetFocus(self):
                if self.automation.moves:
                    self.automation.focused = self

        page, box = object(), Element()
        claude, other = WindowInfo(1, 'Claude', 'Chrome_WidgetWin_1', 10, r'C:\x\claude.exe'), \
            WindowInfo(2, 'Other', 'X', 20, r'C:\x\other.exe')
        same = Automation(box)
        self.assertTrue(focus.FieldWatcher._give(same, claude, (1, box)), 'still in the box')
        back = Automation(page)
        box.automation = back
        self.assertTrue(focus.FieldWatcher._give(back, claude, (1, box)), 'put back in the box')
        self.assertIs(back.focused, box)
        stuck = Automation(page, moves=False)    # Claude's app: the keyboard stays on its own page
        box.automation = stuck
        self.assertFalse(focus.FieldWatcher._give(stuck, claude, (1, box)), 'not typed somewhere else')
        self.assertTrue(focus.FieldWatcher._give(stuck, other, (1, box)), 'nothing noted for that window')
        self.assertTrue(focus.FieldWatcher._give(stuck, claude, None), 'nothing noted at all: as before')


class HelloTests(unittest.TestCase):
    def test_sealed_so_only_the_same_signature_opens_it(self):
        sealed = hello.seal('a made-up master password', b'signature' * 32)
        self.assertNotIn(b'made-up', sealed)
        self.assertEqual(hello.unseal(sealed, b'signature' * 32), 'a made-up master password')
        with self.assertRaises(hello.HelloError):
            hello.unseal(sealed, b'another one' * 32)

    def test_on_and_off_with_a_stand_in_for_windows_hello(self):
        folder = Path(tempfile.mkdtemp())
        saved = {k: os.environ.get(k) for k in ('KEYTAP_DEV', 'KEYTAP_FAKE_HELLO', 'KEYTAP_HELLO_FILE')}
        os.environ.update(KEYTAP_DEV='1', KEYTAP_FAKE_HELLO='yes', KEYTAP_HELLO_FILE=str(folder / 'hello.json'))
        try:
            self.assertFalse(hello.is_on())
            hello.turn_on('a made-up master password')
            self.assertTrue(hello.is_on())
            self.assertNotIn('made-up', (folder / 'hello.json').read_text())
            self.assertEqual(hello.password(), 'a made-up master password')
            os.environ['KEYTAP_FAKE_HELLO'] = 'cancel'
            with self.assertRaises(hello.HelloCancelled):
                hello.password()
            hello.turn_off()
            self.assertFalse(hello.is_on())
            with self.assertRaises(hello.HelloError):
                hello.password()
        finally:
            for key, value in saved.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value
            shutil.rmtree(folder, ignore_errors=True)


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
