r"""The vault window as an editor, offscreen, against the stand-in bw (fake_bw.py): every kind of
item shown, made and changed, the trash and the archive, folders, attachments, and the tools -
the generator, Send, vault health, export and import.

    %LOCALAPPDATA%\KeytapBuild\venv\Scripts\python.exe tests\test_editing.py

Nothing is shown on screen and no real vault is read. The controller is Keytap's own, as far as
the vault goes (its methods, borrowed), without hotkeys, the tray or Windows Hello.
"""

import json
import os
import sys
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')
os.environ.setdefault('QT_QPA_FONTDIR', str(Path(os.environ.get('WINDIR', r'C:\Windows')) / 'Fonts'))
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / 'app'))
sys.path.insert(0, str(HERE))

from PySide6.QtWidgets import QApplication, QLabel, QTextEdit  # noqa: E402

app = QApplication.instance() or QApplication([])

from keytap import items  # noqa: E402
from keytap.app import Controller  # noqa: E402
from keytap.items import CARD, LOGIN, SSH_KEY  # noqa: E402
from keytap.ui import tools  # noqa: E402
from keytap.ui import vault_window as vw  # noqa: E402
from keytap.ui.editor import ItemEditor  # noqa: E402
from keytap.ui.vault_window import DOTS, VaultWindow  # noqa: E402
from keytap.vault import Status  # noqa: E402
from test_items import FakeVault  # noqa: E402

BORROWED = ('unlocked', '_load_extras', '_take_items', '_changed', '_replace', '_vault_job', 'save_item',
            'delete_item', 'restore_item', 'archive_item', '_then_reread', 'move_item', 'set_collections',
            'add_attachment', 'save_attachment', 'delete_attachment', 'save_folder', 'delete_folder',
            'remember_generated', 'run_vault', 'reload', '_refresh_vault', '_sync_passkeys', '_keep_logins',
            'new_login_for')


class Toasts:
    def __init__(self):
        self.shown = []

    def show(self, title, text='', error=False, action=None):
        self.shown.append((title, text, error))

    def titles(self):
        return [title for title, _, _ in self.shown]


Lite = type('Lite', (), {name: vars(Controller)[name] for name in BORROWED})


def spin(until, seconds: float = 30) -> None:
    deadline = time.monotonic() + seconds
    while not until() and time.monotonic() < deadline:
        app.processEvents()
        time.sleep(0.005)
    app.processEvents()


def open_(widget) -> bool:
    """Still on screen - a closed editor is deleted."""
    import shiboken6
    return shiboken6.isValid(widget) and widget.isVisible()


def texts(widget) -> str:
    return '\n'.join([label.text() for label in widget.findChildren(QLabel)] +
                     [text.text() for text in widget.findChildren(QTextEdit)])


def filter_rows(filters) -> list[str]:
    """The sidebar's rows as they read: a name, and its count after it."""
    from keytap.ui.suitesettings import COUNT
    rows = []
    for i in range(filters.count()):
        item = filters.item(i)
        count = item.data(COUNT)
        rows.append(item.text() if count is None else f'{item.text()}   {count}')
    return rows


class EditingTests(unittest.TestCase):
    def setUp(self):
        self.fake = FakeVault()
        c = self.c = Lite()
        c.vault = self.fake.vault
        c.status = Status('unlocked', 'test@example.com', '')
        c.logins, c.items, c.trash, c.archive, c.can_archive = None, None, [], [], True
        c.folders, c.organizations, c.collections, c.generated = {}, {}, [], []
        c._generation, c._windows, c._logins_key, c.passkeys_on = 0, {}, None, False
        c.toasts = Toasts()
        c.copied = []
        c.copy = lambda value, label, quiet=False: c.copied.append((label, value))
        c.confirm = lambda item, then, near=None: then()          # the master password, given
        c.settings = SimpleNamespace(hotkeys={'type': 'Ctrl+Alt+A'}, generator={})
        c.hello_on = lambda: False
        for name in ('lock', 'sync', 'show_settings', 'show_sign_in', 'unlock_in', 'show_vault', 'show_generator',
                     'show_sends', 'show_health', 'show_export', 'show_import'):
            setattr(c, name, lambda *a, **k: None)
        c._take_items(items.of(c.vault.items()))
        c._load_extras()
        spin(lambda: c.collections)
        self.window = VaultWindow(c)
        c._windows['vault'] = self.window

    def tearDown(self):
        for editor in self.window.findChildren(ItemEditor):
            editor.discard()
        self.window.close()
        self.window.deleteLater()
        app.processEvents()
        self.fake.remove()

    # ------------------------------------------------------------------ helpers

    def names(self) -> list[str]:
        return [self.window.list.item(i).data(0x0100).name for i in range(self.window.list.count())]

    def select(self, name: str) -> None:
        self.window.list.setCurrentRow(self.names().index(name))

    def filter(self, label: str) -> None:
        rows = [self.window.filters.item(i).text().split('   ')[0] for i in range(self.window.filters.count())]
        self.window.filters.setCurrentRow(rows.index(label))

    def editor(self) -> ItemEditor:
        spin(lambda: self.window.findChildren(ItemEditor), 5)
        found = [e for e in self.window.findChildren(ItemEditor) if e.isVisible()]
        self.assertEqual(len(found), 1, 'one editor open')
        return found[0]

    def save(self, editor: ItemEditor) -> None:
        editor._save()
        spin(lambda: not open_(editor))
        self.assertFalse(open_(editor), editor.message.text() if open_(editor) else '')

    def stored(self, name: str) -> dict:
        return next(i for i in self.fake.state['items'] if i.get('name') == name)

    # ------------------------------------------------------------------ showing

    def test_every_kind_is_shown(self):
        filters = filter_rows(self.window.filters)
        for wanted in ('All items   6', 'Logins   2', 'Cards   1', 'Identities   1', 'Notes   1', 'SSH keys   1',
                       'Games   1', 'Collections', 'Shared   0', 'Archive   1', 'Trash   1'):
            self.assertIn(wanted, filters)
        self.select('Bank card')
        self.assertNotIn('A Person', texts(self.window.details), 'asks for the master password first')
        self.window.details.confirm.emit(self.window.details.item)
        shown = texts(self.window.details)
        self.assertIn('A Person', shown)
        self.assertIn('07 / 2031', shown)
        self.assertNotIn('4111', shown)
        self.assertNotIn('123', shown.split('\n'))
        self.assertIn(DOTS, shown)
        self.select('Me')
        shown = texts(self.window.details)
        self.assertIn('Mx Sam Sample', shown)
        self.assertIn('1 Blossom Way\nLeeds LS1 1AA\nGB', shown)
        self.assertNotIn('P1234567', shown, 'a passport number stays hidden')
        self.select('Server')
        self.assertIn('SHA256:x', texts(self.window.details))
        self.assertNotIn('PRIVATE', texts(self.window.details))
        self.select('Steam')
        shown = texts(self.window.details)
        self.assertIn('✓ Yes', shown)
        self.assertIn('Linked to Username', shown)
        self.assertNotIn('2468', shown)
        self.assertIn(f'Created: {items.when("2026-01-02T03:04:05.000Z")}', shown, "in this PC's time")
        self.filter('Trash')
        self.assertEqual(self.names(), ['Binned'])
        self.assertIn('In the trash', texts(self.window.details))
        self.filter('Archive')
        self.assertEqual(self.names(), ['Put away'])

    # ------------------------------------------------------------------ making and changing

    def test_a_new_login_through_the_editor(self):
        self.window.new_item(LOGIN, 'Example', ('https://example.com',))
        editor = self.editor()
        self.assertEqual(editor.name.text(), 'Example')
        editor.username.setText('someone')
        editor._new_password()
        password = editor.password.text()
        self.assertEqual(len(password), 14, "the generator's own default")
        self.assertEqual(self.c.generated[0][0], password, 'in its history')
        editor._add_field(items.HIDDEN)
        row = editor._rows(editor.field_rows)[-1]
        row.name.setText('Recovery code')
        row.value.set_text('ABCD-EFGH')
        self.save(editor)
        stored = self.stored('Example')
        self.assertEqual((stored['login']['username'], stored['login']['password']), ('someone', password))
        self.assertEqual(stored['login']['uris'], [{'match': None, 'uri': 'https://example.com'}])
        self.assertEqual(stored['fields'], [{'name': 'Recovery code', 'value': 'ABCD-EFGH', 'type': 1,
                                             'linkedId': None}])
        self.assertIn('Example', [login.name for login in self.c.logins], 'auto-type has it at once')
        self.assertEqual(self.window.details.item.name, 'Example', 'chosen once made')
        self.assertNotIn(password, self.fake.log())

    def test_editing_keeps_what_isnt_shown(self):
        self.select('Steam')
        self.window.act('edit', self.window.details.item)
        editor = self.editor()
        editor.password.set_text('a-new-password')
        self.save(editor)
        stored = self.stored('Steam')
        self.assertEqual(stored['login']['password'], 'a-new-password')
        self.assertEqual([f['name'] for f in stored['fields']], ['PIN', 'Kid', 'Who'])
        self.assertEqual(stored['fields'][2]['linkedId'], 100)
        self.assertEqual(stored['folderId'], 'f1')
        self.assertEqual(stored['creationDate'], '2026-01-02T03:04:05.000Z')
        self.assertIn('Show 1 earlier password', [b.text() for b in self.window.details.findChildren(vw.QPushButton)])

    def test_cards_identities_and_ssh_keys(self):
        self.window.new_item(CARD, 'Travel card')
        editor = self.editor()
        editor.card['number'].set_text('5500 0000 0000 0004')
        editor.card['number'].edit.editingFinished.emit()
        self.assertEqual(editor.card['brand'].currentData(), 'Mastercard', 'guessed from the number')
        editor.card['expMonth'].setCurrentIndex(editor.card['expMonth'].findData('9'))
        editor.card['expYear'].setText('20x9')
        editor._save()
        self.assertIn('expiry year', editor.message.text())
        editor.card['expYear'].setText('2029')
        self.save(editor)
        card = self.stored('Travel card')['card']
        self.assertEqual((card['brand'], card['expMonth'], card['expYear']), ('Mastercard', '9', '2029'))

        self.window.new_item(SSH_KEY, 'Laptop')
        editor = self.editor()
        self.assertIn('OPENSSH PRIVATE KEY', editor.private_key.toPlainText(), 'a new key comes with it')
        self.save(editor)
        key = self.stored('Laptop')['sshKey']
        from keytap import sshkey
        self.assertEqual(key['keyFingerprint'], sshkey.fingerprint(key['publicKey']))

        self.window.new_item(items.IDENTITY, '')
        editor = self.editor()
        editor._save()
        self.assertEqual(editor.message.text(), 'Give it a name.')
        editor.name.setText('Work me')
        editor.identity['title'].setCurrentIndex(editor.identity['title'].findData('Dr'))
        editor.identity['passportNumber'].set_text('X999')
        self.save(editor)
        self.assertEqual(self.stored('Work me')['identity']['passportNumber'], 'X999')
        self.assertEqual(self.stored('Work me')['identity']['title'], 'Dr')

    def test_trash_restore_and_forever(self):
        self.select('Wi-Fi')
        with mock.patch.object(VaultWindow, '_ask', lambda *a: True):
            self.window.act('delete', self.window.details.item)
            spin(lambda: 'Wi-Fi' not in self.names())
            self.assertTrue(self.stored('Wi-Fi').get('deletedDate'))
            self.filter('Trash')
            self.assertEqual(sorted(self.names()), ['Binned', 'Wi-Fi'])
            self.select('Wi-Fi')
            self.window.act('restore', self.window.details.item)
            spin(lambda: 'Wi-Fi' not in self.names())
            self.assertFalse(self.stored('Wi-Fi').get('deletedDate'))
            self.select('Binned')
            self.window.act('delete_forever', self.window.details.item)
            spin(lambda: not self.names())
            self.assertNotIn('Binned', [i['name'] for i in self.fake.state['items']])

    def test_favourite_archive_and_folders(self):
        self.select('Old mail')
        self.window.act('favorite', self.window.details.item)
        spin(lambda: self.window.details.item.favorite)          # once bw has it, and Keytap has heard
        self.assertTrue(self.stored('Old mail').get('favorite'))
        self.window.act('archive', self.window.details.item)
        spin(lambda: 'Old mail' not in self.names())
        self.assertNotIn('Old mail', [login.name for login in self.c.logins], 'nothing types an archived login')
        self.filter('Archive')
        self.assertEqual(sorted(self.names()), ['Old mail', 'Put away'])

        with mock.patch.object(vw.QInputDialog, 'getText', lambda *a, **k: ('Work', True)):
            self.window.new_folder()
        spin(lambda: 'Work' in self.c.folders.values())
        folder_id = next(key for key, name in self.c.folders.items() if name == 'Work')
        with mock.patch.object(vw.QInputDialog, 'getText', lambda *a, **k: ('Office', True)):
            self.window._rename_folder(folder_id, 'Work')
        spin(lambda: self.c.folders.get(folder_id) == 'Office')
        with mock.patch.object(VaultWindow, '_ask', lambda *a: True):
            self.window._delete_folder('f1', 'Games')
        spin(lambda: 'f1' not in self.c.folders)
        self.assertFalse(any(item.folder_id == 'f1' for item in self.c.items))

    def test_attachments_and_organizations(self):
        source = self.fake.folder / 'scan.pdf'
        source.write_bytes(b'%PDF scan')
        self.select('Wi-Fi')
        with mock.patch.object(vw.QFileDialog, 'getOpenFileName', lambda *a, **k: (str(source), '')):
            self.window.act('attach', self.window.details.item)
        spin(lambda: self.window.details.item.attachments)
        attachment = self.window.details.item.attachments[0]
        copy = self.fake.folder / 'out.pdf'
        with mock.patch.object(vw.QFileDialog, 'getSaveFileName', lambda *a, **k: (str(copy), '')):
            self.window.act('save_attachment', self.window.details.item, attachment)
        spin(copy.exists)
        self.assertEqual(copy.read_bytes(), b'%PDF scan')
        with mock.patch.object(VaultWindow, '_ask', lambda *a: True):
            self.window.act('delete_attachment', self.window.details.item, attachment)
        spin(lambda: not self.window.details.item.attachments)

        self.c.move_item(self.window.details.item, 'o1', ['c2'], None)
        spin(lambda: self.window.details.item.organization_id == 'o1')
        self.assertIn('Family', texts(self.window.details))
        self.filter('Kids')
        self.assertEqual(self.names(), ['Wi-Fi'])

    def test_locking_closes_the_editor(self):
        self.window.new_item(LOGIN, 'Half made')
        editor = self.editor()
        editor.password.set_text('typed-in')
        self.c.logins = self.c.items = None
        self.c.status = Status('locked', 'test@example.com', '')
        self.window.refresh()
        app.processEvents()
        self.assertFalse(open_(editor))
        self.assertNotIn('Half made', [i.get('name') for i in self.fake.state['items']])

    def test_a_new_login_from_the_picker(self):
        from keytap.ui.picker import Picker
        from keytap.win32 import WindowInfo
        picker = Picker(self.c.logins, [], 'steam.exe')
        asked = []
        picker.new_login.connect(lambda: asked.append(True))
        picker._new()
        self.assertEqual(asked, [True])
        self.c.new_login_for(WindowInfo(hwnd=1, title='Steam', class_name='X', pid=1,
                                        exe_path='C:\\Steam\\steamwebhelper.exe'))
        editor = self.editor()
        self.assertEqual(editor.name.text(), 'Steamwebhelper')
        self.assertEqual(editor._rows(editor.uris)[0].uri.text(), 'app://steamwebhelper.exe')
        editor.discard()
        self.c.new_login_for(None, 'https://accounts.example.com/signin')
        editor = self.editor()
        self.assertEqual(editor.name.text(), 'example.com')
        self.assertEqual(editor._rows(editor.uris)[0].uri.text(), 'https://example.com')

    # ------------------------------------------------------------------ the tools

    def test_generator(self):
        window = tools.GeneratorWindow(self.c)
        first = window.output.text()
        self.assertEqual(len(first), 14)
        window.kind.button(1).setChecked(True)            # passphrase
        self.assertEqual(len(window.output.text().split('-')), 6)
        self.assertEqual(self.c.settings.generator['kind'], 'passphrase', 'its choices kept')
        self.assertEqual(self.c.generated[-1][0], first)
        self.assertEqual(window.history.count(), len(self.c.generated))
        window._copy()
        self.assertEqual(self.c.copied[-1], ('passphrase', window.output.text()))
        window.close()

    def test_send(self):
        window = tools.SendsWindow(self.c)
        spin(lambda: 'Send' in window.state.text())
        window._new(0)
        window.name.setText('Door code')
        window.text.setPlainText('2468')
        window.password.set_text('knock-knock')
        window._save()
        spin(lambda: window.list.count() == 1)
        sent = self.fake.state['sends'][0]
        self.assertEqual((sent['name'], sent['text']['text'], sent['passwordSet']), ('Door code', '2468', True))
        self.assertEqual(self.c.copied[-1][0], 'link to the Send', 'its link, ready to paste')
        self.assertNotIn('knock-knock', self.fake.log())
        window.list.setCurrentRow(0)
        self.assertTrue(window.remove_password.isVisible() or not window.isVisible())
        window.close()

    def test_health(self):
        window = tools.HealthWindow(self.c)
        self.assertEqual(window.lists['unsecured'].count(), 1, "Steam's http:// website, at once")
        window.check()
        spin(lambda: 'checked' in window.state.text())
        self.assertEqual(window.lists['exposed'].count(), 2)
        self.assertEqual(window.lists['reused'].count(), 2)
        self.assertEqual(window.lists['weak'].count(), 2)
        self.assertIn('4141 times', window.lists['exposed'].item(0).text())
        window.close()

    def test_export_and_import(self):
        out = self.fake.folder / 'export.json'      # not vault.json: the stand-in's own
        export = tools.ExportDialog(self.c)
        export.choice.button(1).setChecked(True)
        self.assertIn('not encrypted', export.warning.text())
        with mock.patch.object(tools.QFileDialog, 'getSaveFileName', lambda *a, **k: (str(out), '')):
            export._export()
        spin(lambda: 'Exported' in export.message.text())
        self.assertTrue(out.exists())
        importing = tools.ImportDialog(self.c)
        spin(lambda: importing.go.isEnabled())
        self.assertEqual(importing.form_.currentData(), 'bitwardenjson')
        importing.file.setText(str(out))
        before = len(self.c.items)
        importing._import()
        spin(lambda: len(self.c.items or []) > before)
        self.assertEqual(len(self.c.items), before * 2)
        export.close()
        importing.close()


if __name__ == '__main__':
    unittest.main(verbosity=2)
