r"""Signing in with a passkey, from Windows' request to Keytap's answer, offscreen.

    %LOCALAPPDATA%\KeytapBuild\venv\Scripts\python.exe tests\test_signins.py

Windows' side is played here: its request comes in on a thread of its own, as
COM calls it, and its checks (that it signed the request, Windows Hello) are
stood in for. Keytap's controller is a stand-in too, which records the cards
it is asked for and answers them as a person would.
"""

import os
import sys
import threading
import time
import unittest
import uuid
from pathlib import Path
from types import SimpleNamespace

os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'app'))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from PySide6.QtCore import QTimer  # noqa: E402
from PySide6.QtWidgets import QApplication  # noqa: E402

app = QApplication.instance() or QApplication([])

from keytap import cbor, p256, provider, signins  # noqa: E402
from keytap.vault import Login  # noqa: E402
from test_passkeys import D, bitwarden_item, request_bytes  # noqa: E402


class Person:
    """The controller, as far as signing in goes, with someone answering its cards."""

    def __init__(self, logins, unlocked=True):
        self.logins = logins if unlocked else None
        self._vault = logins
        self.status = SimpleNamespace(state='unlocked' if unlocked else 'locked')
        self.card = None
        self.asked = []                      # what was asked of the person
        self.answers = {}                    # what they answer: 'unlock', 'confirm', 'choose' -> True/False/index
        self.toasts = SimpleNamespace(show=lambda title, text, **kw: self.asked.append(('toast', text)))

    @property
    def unlocked(self):
        return self.logins is not None

    def unlock_for(self, detail, hwnd, then, cancelled):
        self.asked.append(('unlock', detail))

        def answer():
            if self.answers.get('unlock', True):
                self.logins = self._vault
                self.status.state = 'unlocked'
                then()
            else:
                cancelled()
        QTimer.singleShot(10, answer)
        return SimpleNamespace(close=lambda: None)

    def confirm(self, login, then, hwnd, cancelled=None, detail=''):
        self.asked.append(('confirm', detail or login.name))
        QTimer.singleShot(10, then if self.answers.get('confirm', True) else cancelled)
        return SimpleNamespace(close=lambda: None)

    def show_card(self, card, hwnd):
        self.asked.append(('choose', card.list.count()))
        choice = self.answers.get('choose', 0)
        if choice is None:
            QTimer.singleShot(10, card.close)
        else:
            card.list.setCurrentRow(choice)
            QTimer.singleShot(10, card._choose)


def login(item_id, name, user, rp='github.com', reprompt=False):
    import base64
    key = p256.pkcs8_from_private_key(D)
    item = bitwarden_item(credentialId=str(uuid.uuid4()), userName=user, rpId=rp,
                          keyValue=base64.urlsafe_b64encode(key).decode().rstrip('='))
    item.update(id=item_id, name=name, reprompt=1 if reprompt else 0)
    return Login.from_item(item)


class SignInTests(unittest.TestCase):
    def setUp(self):
        self.hello = []
        self.windows_signed = True
        self.hello_answer = True
        self._patched = (provider.from_windows, provider.verify_user, provider.identity)
        provider.identity = lambda: 'Blossqt.Keytap_test'
        provider.from_windows = lambda data, signature: self.windows_signed

        def verify_user(hwnd, transaction, user, hint):
            self.hello.append(user)
            if isinstance(self.hello_answer, Exception):
                raise self.hello_answer
            return self.hello_answer
        provider.verify_user = verify_user

    def tearDown(self):
        provider.from_windows, provider.verify_user, provider.identity = self._patched

    def sign_in(self, person, data=None, cancel_after=None):
        """Windows' call, on a thread of its own; the UI thread runs meanwhile. (answer, refusal)."""
        handler = signins.PasskeySignIns(person)
        op = SimpleNamespace(hwnd=0, transaction=uuid.uuid4(), data=data or request_bytes(), signature=b'signed')
        result = {}

        def call():
            try:
                result['answer'] = handler.get_assertion(op)
            except provider.Refusal as refusal:
                result['refusal'] = refusal.hr
        thread = threading.Thread(target=call)
        thread.start()
        started = time.monotonic()
        while thread.is_alive() and time.monotonic() - started < 10:
            app.processEvents()
            if cancel_after is not None and time.monotonic() - started > cancel_after:
                handler.cancel(op.transaction)
                cancel_after = None
            time.sleep(0.005)
        thread.join(1)
        return result.get('answer'), result.get('refusal')

    def test_unlocked_one_passkey_windows_hello(self):
        person = Person([login('a', 'GitHub', 'blossqt')])
        answer, refusal = self.sign_in(person)
        self.assertIsNone(refusal)
        response = cbor.loads(answer)
        self.assertEqual(response[2][32] & 0x04, 0x04, 'verified')
        self.assertEqual(self.hello, ['blossqt'], 'Windows Hello checked it is you')
        self.assertEqual(person.asked, [])

    def test_locked_unlocking_is_the_check(self):
        person = Person([login('a', 'GitHub', 'blossqt')], unlocked=False)
        answer, refusal = self.sign_in(person)
        self.assertIsNone(refusal)
        self.assertEqual(person.asked, [('unlock', 'to sign in to github.com with a passkey')])
        self.assertEqual(self.hello, [], 'no second check right after unlocking')
        person = Person([login('a', 'GitHub', 'blossqt')], unlocked=False)
        person.answers['unlock'] = False
        self.assertEqual(self.sign_in(person)[1], provider.NTE_USER_CANCELLED)

    def test_several_accounts_choose_one(self):
        person = Person([login('a', 'GitHub', 'blossqt'), login('b', 'GitHub (work)', 'work-account')])
        person.answers['choose'] = 1
        answer, refusal = self.sign_in(person)
        self.assertIsNone(refusal)
        self.assertEqual(person.asked, [('choose', 2)])
        chosen = cbor.loads(answer)[1]['id']
        self.assertEqual(chosen, person.logins[1].passkeys[0].credential_id)
        person.answers['choose'] = None                  # closed the card
        self.assertEqual(self.sign_in(person)[1], provider.NTE_USER_CANCELLED)

    def test_login_that_asks_for_the_master_password(self):
        person = Person([login('a', 'Bank', 'me', reprompt=True)])
        answer, refusal = self.sign_in(person)
        self.assertIsNone(refusal)
        self.assertEqual(person.asked, [('confirm', 'Bank')])
        self.assertEqual(self.hello, [], 'the master password was the check')

    def test_no_passkey_for_the_site(self):
        person = Person([login('a', 'GitHub', 'blossqt')])
        answer, refusal = self.sign_in(person, request_bytes(rp='gitlab.com'))
        self.assertEqual(refusal, provider.NTE_NOT_FOUND)
        self.assertIn(('toast', 'No passkey for gitlab.com in your vault.'), person.asked)

    def test_windows_hello_cancelled_or_missing(self):
        person = Person([login('a', 'GitHub', 'blossqt')])
        self.hello_answer = False
        self.assertEqual(self.sign_in(person)[1], provider.NTE_USER_CANCELLED)
        # No Windows Hello on this PC: the master password instead.
        self.hello_answer = OSError(1, 'no Windows Hello')
        answer, refusal = self.sign_in(person)
        self.assertIsNone(refusal)
        self.assertEqual(person.asked[-1][0], 'confirm')

    def test_cancelled_by_windows_and_unsigned_requests(self):
        person = Person([login('a', 'GitHub', 'blossqt')], unlocked=False)
        person.unlock_for = lambda *a: (person.asked.append(('unlock', '')), SimpleNamespace(close=lambda: None))[1]
        self.assertEqual(self.sign_in(person, cancel_after=0.2)[1], provider.NTE_USER_CANCELLED)
        self.windows_signed = False
        self.assertEqual(self.sign_in(Person([login('a', 'GitHub', 'blossqt')]))[1], provider.E_ACCESSDENIED)


class RelayTests(unittest.TestCase):
    """The Keytap Windows starts relaying to the running Keytap, over a local socket."""

    def setUp(self):
        from PySide6.QtNetwork import QLocalServer
        self._patched = (provider.from_windows, provider.verify_user, provider.identity)
        provider.identity = lambda: 'Blossqt.Keytap_test'
        provider.from_windows = lambda data, signature: True
        provider.verify_user = lambda hwnd, transaction, user, hint: True
        self.person = Person([login('a', 'GitHub', 'blossqt')])
        self.handler = signins.PasskeySignIns(self.person)
        self.name = f'keytap-relay-test-{os.getpid()}'
        QLocalServer.removeServer(self.name)
        self.server = QLocalServer()
        self.server.newConnection.connect(self._connection)
        self.assertTrue(self.server.listen(self.name))

    def tearDown(self):
        provider.from_windows, provider.verify_user, provider.identity = self._patched
        self.server.close()

    def _connection(self):
        # As Controller._connection routes them.
        socket = self.server.nextPendingConnection()
        socket.waitForReadyRead(500)
        message = bytes(socket.readAll()).decode()
        if message.startswith('passkey '):
            self.handler.serve_relay(socket, message[len('passkey '):])
            return
        words = message.split()
        if words[0] == 'passkey-locked':
            socket.write(b'unlocked' if self.person.unlocked else b'locked')
        elif words[0] == 'passkey-cancel':
            self.handler.cancel(uuid.UUID(words[1]))
        socket.waitForBytesWritten(500)
        socket.disconnectFromServer()

    def through_relay(self, call, cancel_after=None):
        relay = signins.Relay(self.name)
        result = {}

        def run():
            try:
                result['value'] = call(relay)
            except provider.Refusal as refusal:
                result['refusal'] = refusal.hr
        thread = threading.Thread(target=run)
        thread.start()
        started = time.monotonic()
        while thread.is_alive() and time.monotonic() - started < 10:
            app.processEvents()
            if cancel_after is not None and time.monotonic() - started > cancel_after:
                threading.Thread(target=lambda: relay.cancel(self.op.transaction)).start()
                cancel_after = None
            time.sleep(0.005)
        thread.join(1)
        return result.get('value'), result.get('refusal')

    def test_relayed_sign_in(self):
        self.op = SimpleNamespace(hwnd=0, transaction=uuid.uuid4(), data=request_bytes(), signature=b'signed')
        answer, refusal = self.through_relay(lambda relay: relay.get_assertion(self.op))
        self.assertIsNone(refusal)
        response = cbor.loads(answer)
        self.assertEqual(response[1]['id'], self.person.logins[0].passkeys[0].credential_id)
        self.assertEqual(response[2][32] & 0x04, 0x04)
        self.assertEqual(self.through_relay(lambda relay: relay.unlocked())[0], True)

    def test_relayed_refusal_and_cancel(self):
        self.op = SimpleNamespace(hwnd=0, transaction=uuid.uuid4(), data=request_bytes(rp='gitlab.com'),
                                  signature=b'signed')
        self.assertEqual(self.through_relay(lambda relay: relay.get_assertion(self.op))[1], provider.NTE_NOT_FOUND)
        self.person.logins, self.person.status.state = None, 'locked'           # waits on an unlock
        self.person.unlock_for = lambda *a: SimpleNamespace(close=lambda: None)
        self.op = SimpleNamespace(hwnd=0, transaction=uuid.uuid4(), data=request_bytes(), signature=b'signed')
        self.assertEqual(self.through_relay(lambda relay: relay.get_assertion(self.op), cancel_after=0.3)[1],
                         provider.NTE_USER_CANCELLED)
        self.assertEqual(signins.Relay('keytap-nobody-here').unlocked(), False, 'no Keytap: locked, not stuck')


if __name__ == '__main__':
    unittest.main(verbosity=2)
