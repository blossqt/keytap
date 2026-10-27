r"""Everything in a vault besides typing logins: every kind of item, the trash and the archive,
folders, organizations, attachments, Send, the health report, export and import - against the
stand-in bw (fake_bw.py) - and the generator and SSH keys.

    %LOCALAPPDATA%\KeytapBuild\venv\Scripts\python.exe tests\test_items.py
"""

import base64
import json
import os
import re
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / 'app'))
sys.path.insert(0, str(HERE.parent / 'build'))

from keytap import generator, items, sshkey  # noqa: E402
from keytap.items import CARD, IDENTITY, LOGIN, NOTE, SSH_KEY, Item  # noqa: E402
from keytap.vault import Bitwarden, Login, VaultError  # noqa: E402

PASSWORD = 'correct horse battery staple'


def vault_state() -> dict:
    """A made-up vault with one of everything."""
    return {
        'email': 'test@example.com', 'password': PASSWORD, 'signed_in': True,
        'folders': [{'object': 'folder', 'id': 'f1', 'name': 'Games'}],
        'organizations': [{'object': 'organization', 'id': 'o1', 'name': 'Family'}],
        'collections': [{'object': 'collection', 'id': 'c1', 'organizationId': 'o1', 'name': 'Shared'},
                        {'object': 'collection', 'id': 'c2', 'organizationId': 'o1', 'name': 'Kids'}],
        'exposed': {'hunter2': 4141},
        'items': [
            {'id': 'l1', 'type': 1, 'name': 'Steam', 'folderId': 'f1', 'favorite': True, 'reprompt': 0,
             'fields': [{'name': 'PIN', 'value': '2468', 'type': 1}, {'name': 'Kid', 'value': 'true', 'type': 2},
                        {'name': 'Who', 'value': None, 'type': 3, 'linkedId': 100}],
             'login': {'username': 'gaben', 'password': 'hunter2', 'totp': None,
                       'uris': [{'uri': 'http://store.steampowered.com', 'match': None}]},
             'creationDate': '2026-01-02T03:04:05.000Z', 'revisionDate': '2026-02-03T04:05:06.000Z'},
            {'id': 'l2', 'type': 1, 'name': 'Old mail', 'reprompt': 0,
             'login': {'username': 'me', 'password': 'hunter2', 'uris': []}},
            {'id': 'k1', 'type': 3, 'name': 'Bank card', 'reprompt': 1,
             'card': {'cardholderName': 'A Person', 'number': '4111 1111 1111 1111', 'brand': 'Visa',
                      'expMonth': '7', 'expYear': '2031', 'code': '123'}},
            {'id': 'i1', 'type': 4, 'name': 'Me', 'reprompt': 0,
             'identity': {'title': 'Mx', 'firstName': 'Sam', 'lastName': 'Sample', 'email': 'sam@example.com',
                          'passportNumber': 'P1234567', 'address1': '1 Blossom Way', 'city': 'Leeds',
                          'postalCode': 'LS1 1AA', 'country': 'GB'}},
            {'id': 'n1', 'type': 2, 'name': 'Wi-Fi', 'notes': 'The router is upstairs.', 'secureNote': {'type': 0}},
            {'id': 's1', 'type': 5, 'name': 'Server', 'sshKey': {'privateKey': 'PRIVATE', 'publicKey':
                                                                 'ssh-ed25519 AAAA', 'keyFingerprint': 'SHA256:x'}},
            {'id': 't1', 'type': 1, 'name': 'Binned', 'deletedDate': '2026-10-01T00:00:00.000Z',
             'login': {'username': 'gone', 'password': 'pw'}},
            {'id': 'a1', 'type': 2, 'name': 'Put away', 'archivedDate': '2026-10-02T00:00:00.000Z',
             'secureNote': {'type': 0}},
        ]}


class FakeVault:
    """The stand-in bw, unlocked, in a folder of its own."""

    def __init__(self, state: dict | None = None):
        self.folder = Path(tempfile.mkdtemp(prefix='keytap-items-'))
        self.state_file = self.folder / 'vault.json'
        self.state_file.write_text(json.dumps(state or vault_state()), encoding='utf-8')
        os.environ['KEYTAP_FAKE_VAULT'] = str(self.state_file)
        os.environ['KEYTAP_FAKE_DELAY'] = '0'
        self.vault = Bitwarden([sys.executable, str(HERE / 'fake_bw.py')], self.folder / 'bw')
        self.vault.unlock(PASSWORD)

    @property
    def state(self) -> dict:
        return json.loads(self.state_file.read_text(encoding='utf-8'))

    def stored(self, item_id: str) -> dict:
        return next(i for i in self.state['items'] if i['id'] == item_id)

    def log(self) -> str:
        return (self.folder / 'vault.log').read_text(encoding='utf-8')

    def remove(self) -> None:
        shutil.rmtree(self.folder, ignore_errors=True)


class ItemTests(unittest.TestCase):
    def test_every_kind_reads_as_its_own(self):
        found = {item.id: item for item in items.of(vault_state()['items'])}
        self.assertEqual(found['l1'].subtitle, 'gaben')
        self.assertEqual(found['l1'].login.password, 'hunter2')
        self.assertEqual(found['k1'].subtitle, 'Visa, *1111')
        self.assertEqual(found['i1'].subtitle, 'Mx Sam Sample')
        self.assertEqual(found['s1'].subtitle, 'SHA256:x')
        self.assertEqual(found['n1'].subtitle, '')
        self.assertTrue(found['k1'].reprompt)
        self.assertTrue(found['t1'].deleted and found['t1'].login is not None, 'a binned login is still shown')
        self.assertIsNone(Login.from_item(found['t1'].raw), 'but never typed')
        self.assertTrue(found['l1'].matches(['steam', 'gaben']))
        self.assertTrue(found['l1'].matches(['store.steampowered']), 'by website too')
        self.assertFalse(found['l1'].matches(['bank']))

    def test_clone_and_blank(self):
        steam = Item(vault_state()['items'][0])
        clone = steam.clone()
        self.assertNotIn('id', clone)
        self.assertEqual(clone['name'], 'Steam - Clone')
        self.assertEqual(clone['login']['password'], 'hunter2')
        self.assertIn('id', steam.raw, 'the original as it was')
        for kind in items.KINDS:
            made = items.blank(kind, 'New')
            self.assertEqual((made['type'], made['name']), (kind, 'New'))
        self.assertEqual(items.blank(NOTE)['secureNote'], {'type': 0})
        self.assertIn('sshKey', items.blank(SSH_KEY))

    def test_card_brands(self):
        for number, brand in (('4111111111111111', 'Visa'), ('5500 0000 0000 0004', 'Mastercard'),
                              ('340000000000009', 'Amex'), ('6011000000000004', 'Discover'),
                              ('3530111333300000', 'JCB'), ('30000000000004', 'Diners Club'), ('', '')):
            self.assertEqual(items.brand_of(number), brand, number)
        self.assertEqual(items.last_four('4111 1111 1111 1234'), '1234')

    def test_from_a_login_windows_hello_kept(self):
        login = Login('1', 'Steam', 'gaben', 'pw', uris=('app://steam.exe',), uri_match=(None,),
                      fields=(('PIN', '1'),), hidden=frozenset({'PIN'}))
        item = Item.from_login(login)
        self.assertTrue(item.partial)
        self.assertIs(item.login, login)
        self.assertEqual(item.fields, [{'name': 'PIN', 'value': '1', 'type': items.HIDDEN}])


class GeneratorTests(unittest.TestCase):
    def test_passwords_keep_to_their_rules(self):
        for _ in range(200):
            made = generator.password({'length': 20, 'special': True, 'min_digits': 3, 'min_special': 2})
            self.assertEqual(len(made), 20)
            self.assertGreaterEqual(sum(ch.isdigit() for ch in made), 3)
            self.assertGreaterEqual(sum(ch in generator.SPECIAL for ch in made), 2)
            self.assertTrue(any(ch.isupper() for ch in made) and any(ch.islower() for ch in made))
        plain = generator.password({'length': 64, 'upper': False, 'digits': False, 'avoid_ambiguous': True})
        self.assertRegex(plain, r'^[a-km-z]{64}$', 'lowercase only, without l')
        self.assertEqual(len(generator.password({'length': 1})), 5, 'never shorter than Bitwarden allows')
        self.assertEqual(len({generator.password() for _ in range(50)}), 50)

    def test_passphrases_and_usernames(self):
        self.assertEqual(len(generator.words()), 7776, "EFF's long list, whole")
        made = generator.passphrase({'words': 5, 'separator': '_', 'capitalize': True, 'number': True})
        parts = made.split('_')
        self.assertEqual(len(parts), 5)
        self.assertTrue(all(part[0].isupper() for part in parts))
        self.assertEqual(sum(bool(re.search(r'\d$', part)) for part in parts), 1)
        self.assertRegex(generator.username({'username': 'plus', 'email': 'me@example.com'}),
                         r'^me\+[a-z0-9]{8}@example\.com$')
        self.assertRegex(generator.username({'username': 'catchall', 'domain': 'example.org'}),
                         r'^[a-z0-9]{8}@example\.org$')
        self.assertEqual(generator.username({'username': 'plus', 'email': 'not an address'}), '')
        self.assertIn(generator.username({'username': 'word'}), generator.words())
        self.assertEqual(generator.settled({'length': 'twelve', 'words': 99})['words'], 20, 'bad choices put right')


class SshKeyTests(unittest.TestCase):
    def test_a_new_key_is_openssh_as_ssh_keygen_reads_it(self):
        import ed25519
        seed = os.urandom(32)
        self.assertEqual(sshkey.public_key(seed), ed25519.public_key(seed))
        key = sshkey.new_key()
        self.assertTrue(key['privateKey'].startswith('-----BEGIN OPENSSH PRIVATE KEY-----\n'))
        body = base64.b64decode(''.join(key['privateKey'].strip().splitlines()[1:-1]))
        self.assertTrue(body.startswith(b'openssh-key-v1\0'))
        blob = base64.b64decode(key['publicKey'].split()[1])
        self.assertIn(blob, body, 'the public key, in the private one')
        self.assertTrue(key['publicKey'].startswith('ssh-ed25519 AAAAC3NzaC1lZDI1NTE5'))
        self.assertEqual(key['keyFingerprint'], sshkey.fingerprint(key['publicKey']))
        self.assertRegex(key['keyFingerprint'], r'^SHA256:[A-Za-z0-9+/]{43}$')
        self.assertNotEqual(sshkey.new_key()['privateKey'], key['privateKey'])

    @unittest.skipUnless(Path(r'C:\Windows\System32\OpenSSH\ssh-keygen.exe').is_file(), "no Windows ssh-keygen")
    def test_ssh_keygen_agrees(self):
        import subprocess
        folder = Path(tempfile.mkdtemp(prefix='keytap-ssh-'))
        try:
            key = sshkey.new_key()
            public = folder / 'key.pub'
            public.write_text(key['publicKey'] + '\n', encoding='ascii')
            out = subprocess.run([r'C:\Windows\System32\OpenSSH\ssh-keygen.exe', '-l', '-f', str(public)],
                                 capture_output=True, text=True, timeout=30)
            self.assertIn(key['keyFingerprint'], out.stdout)
        finally:
            shutil.rmtree(folder, ignore_errors=True)


class VaultTests(unittest.TestCase):
    def setUp(self):
        self.fake = FakeVault()
        self.vault = self.fake.vault

    def tearDown(self):
        self.fake.remove()

    def test_listing_in_use_trash_and_archive(self):
        self.assertEqual({i['id'] for i in self.vault.items()}, {'l1', 'l2', 'k1', 'i1', 'n1', 's1'})
        self.assertEqual([i['id'] for i in self.vault.items(trash=True)], ['t1'])
        self.assertEqual([i['id'] for i in self.vault.items(archived=True)], ['a1'])
        self.assertEqual([login.name for login in self.vault.logins()], ['Steam', 'Old mail'])
        self.assertEqual(self.vault.folders(), {'f1': 'Games'})
        self.assertEqual(self.vault.organizations()[0]['name'], 'Family')
        self.assertEqual(len(self.vault.collections()), 2)

    def test_making_changing_and_deleting(self):
        made = self.vault.save_item(dict(items.blank(LOGIN, 'GitHub'), login={
            'username': 'blossqt', 'password': 's3cret-new', 'uris': [{'uri': 'https://github.com', 'match': None}]}))
        self.assertEqual(self.fake.stored(made['id'])['login']['username'], 'blossqt')
        changed = Item(made).editable()
        changed['login']['password'] = 's3cret-newer'
        self.vault.save_item(changed, made['id'])
        stored = self.fake.stored(made['id'])
        self.assertEqual(stored['login']['password'], 's3cret-newer')
        self.assertEqual(stored['passwordHistory'][0]['password'], 's3cret-new', 'bw keeps the old one')

        self.vault.delete_item(made['id'])
        self.assertTrue(self.fake.stored(made['id']).get('deletedDate'))
        self.vault.restore_item(made['id'])
        self.assertFalse(self.fake.stored(made['id']).get('deletedDate'))
        self.vault.archive_item(made['id'])
        self.assertEqual([i['id'] for i in self.vault.items(archived=True)], ['a1', made['id']])
        self.vault.restore_item(made['id'])
        self.vault.delete_item(made['id'], forever=True)
        self.assertNotIn(made['id'], [i['id'] for i in self.fake.state['items']])
        log = self.fake.log()
        self.assertNotIn('s3cret', log, 'what is saved never goes on a command line')
        self.assertIn('delete item made-9 --permanent', log)

    def test_folders_and_organizations(self):
        folder = self.vault.save_folder('Work')
        self.assertEqual(self.vault.folders()[folder['id']], 'Work')
        self.vault.save_folder('Office', folder['id'])
        self.assertEqual(self.vault.folders()[folder['id']], 'Office')
        self.vault.delete_folder('f1')
        self.assertIsNone(self.fake.stored('l1')['folderId'], "what was in it stays, in no folder")
        self.vault.move_item('n1', 'o1', ['c1'])
        self.assertEqual((self.fake.stored('n1')['organizationId'], self.fake.stored('n1')['collectionIds']),
                         ('o1', ['c1']))
        self.vault.set_collections('n1', ['c1', 'c2'])
        self.assertEqual(self.fake.stored('n1')['collectionIds'], ['c1', 'c2'])

    def test_attachments(self):
        source = self.fake.folder / 'photo.jpg'
        source.write_bytes(b'\xff\xd8 a photo')
        item = self.vault.add_attachment('n1', str(source))
        attachment = Item(item).attachments[0]
        self.assertEqual(attachment['fileName'], 'photo.jpg')
        copy = self.fake.folder / 'copy.jpg'
        self.vault.save_attachment('n1', attachment['id'], str(copy))
        self.assertEqual(copy.read_bytes(), b'\xff\xd8 a photo')
        self.vault.delete_attachment('n1', attachment['id'])
        self.assertEqual(Item(self.vault.item('n1')).attachments, [])

    def test_send(self):
        made = self.vault.save_send({'object': 'send', 'name': 'Wi-Fi', 'type': 0, 'password': 'open-sesame',
                                     'text': {'text': 'the key', 'hidden': True}, 'deletionDate': '2099-01-01'})
        self.assertTrue(made['accessUrl'].startswith('https://send.bitwarden.com/#/'))
        self.assertTrue(made['passwordSet'])
        self.vault.save_send(dict(made, name='Wi-Fi at home'), made['id'])
        self.assertEqual([s['name'] for s in self.vault.sends()], ['Wi-Fi at home'])
        self.assertFalse(self.vault.remove_send_password(made['id'])['passwordSet'])
        self.vault.delete_send(made['id'])
        self.assertEqual(self.vault.sends(), [])
        self.assertNotIn('open-sesame', self.fake.log())
        with self.assertRaises(VaultError):
            self.vault.save_send({'type': 1, 'name': 'x', 'file': {'fileName': str(self.fake.folder / 'missing')}})

    def test_health_report(self):
        report = {entry['id']: entry for entry in self.vault.health()}
        self.assertEqual(report['l1']['reuseCount'], 2)
        self.assertTrue(report['l1']['exposed'])
        self.assertEqual(report['l1']['exposedCount'], 4141)
        self.assertNotIn('k1', report, 'logins only')
        self.assertFalse(any(e['exposed'] for e in self.vault.health(check_exposed=False)))

    def test_export_and_import(self):
        out = self.fake.folder / 'export.json'
        self.vault.export(str(out), 'encrypted_json')
        self.assertTrue(json.loads(out.read_text())['encrypted'])
        self.vault.export(str(out), 'json')
        self.assertEqual(self.vault.import_formats(), ['bitwardencsv', 'bitwardenjson', 'chromecsv', 'keepass2xml'])
        before = len(self.vault.items())
        said = self.vault.import_file('bitwardenjson', str(out))
        self.assertTrue(said.startswith('Imported'))
        self.assertEqual(len(self.vault.items()), before * 2)
        state = self.fake.state
        state['import_password'] = 'file-password'
        self.fake.state_file.write_text(json.dumps(state))
        with self.assertRaises(VaultError):
            self.vault.import_file('bitwardenjson', str(out), 'wrong')
        self.vault.import_file('bitwardenjson', str(out), 'file-password')
        self.assertNotIn('file-password', self.fake.log(), 'given through its environment')

    def test_locked_does_nothing(self):
        self.vault.take_session()
        for call in (lambda: self.vault.items(), lambda: self.vault.save_item({}), lambda: self.vault.sends(),
                     lambda: self.vault.delete_item('l1'), lambda: self.vault.health()):
            with self.assertRaises(VaultError):
                call()


if __name__ == '__main__':
    unittest.main(verbosity=2)
