"""Answering Windows when a website or app asks Keytap for a passkey.

Windows calls on one of COM's threads and waits for the answer; Keytap's cards
and vault live on the UI thread. So each request becomes a job: the UI thread
unlocks Keytap if need be, finds the website's passkeys, lets you choose the
account when there are several, and asks for the master password for a login
that wants it again. Back on COM's thread, Windows Hello checks it is you -
unless you have just unlocked Keytap for this - and the passkey signs.

There is only ever one Keytap with the vault. Windows starts a Keytap of its
own for a passkey request (inside the package's container), and won't use one
started otherwise. With none running, that one becomes Keytap. With one
running, the one Windows started only relays (Relay, below): it passes each
call to the running Keytap over Keytap's local socket, and that Keytap -
which checks Windows signed the request, as for a call from COM - answers.
The relay quits once idle.
"""

from __future__ import annotations

import base64
import ctypes
import json
import threading
import time
import traceback
import uuid
from types import SimpleNamespace

from PySide6.QtCore import QObject, Signal

from . import passkeys, provider
from .provider import Refusal
from .ui.accounts import AccountCard

WAIT_SECONDS = 300          # as long as Windows' own passkey window waits
RELAY_IDLE_SECONDS = 120    # a relay with nothing to pass on quits after this long
PIPE_PREFIX = '\\\\.\\pipe\\'   # where Qt's QLocalServer listens on Windows
_NO_CREATING = ("Keytap signs in with the passkeys in your vault but does not save new ones. Save this one with "
                "Bitwarden's browser extension or app, or choose another place in Windows' passkey window.")


class _Job:
    def __init__(self, op: provider.Operation, request: passkeys.Request):
        self.op, self.request = op, request
        self.passkey = None
        self.verified = False
        self.refusal: Refusal | None = None
        self.cancelled = False
        self.card = None
        self._done = threading.Event()

    @property
    def site(self) -> str:
        return self.request.rp_id

    def finish(self, passkey, verified: bool) -> None:
        self.passkey, self.verified = passkey, verified
        self._done.set()

    def refuse(self, hr: int, message: str = '') -> None:
        if self.refusal is None:
            self.refusal = Refusal(hr, message)
        self._done.set()

    def wait(self) -> bool:
        return self._done.wait(WAIT_SECONDS)

    def again(self) -> None:
        self._done.clear()


class PasskeySignIns(QObject):
    """provider.Server's handler. Its methods named for COM run on COM's threads."""

    _to_ui = Signal(object, str, str)        # job (or None), what, message
    _replied = Signal(object, bytes)          # a relay's socket, and the answer for it

    def __init__(self, controller):
        super().__init__()
        self.controller = controller
        self._job: _Job | None = None
        self._one_at_a_time = threading.Lock()
        self._relays: set = set()             # relays' sockets waiting for their answers
        self._to_ui.connect(self._on_ui)
        self._replied.connect(self._reply)

    # ------------------------------------------------------------------ calls passed on by a relay

    def serve_relay(self, socket, payload: str) -> None:
        """UI thread: a request the Keytap Windows started has passed on. Answered on a thread of
        its own, as a call from COM is, then written back."""
        try:
            fields = json.loads(payload)
            op = SimpleNamespace(hwnd=int(fields['hwnd']), transaction=uuid.UUID(fields['transaction']),
                                 data=base64.b64decode(fields['data']),
                                 signature=base64.b64decode(fields['signature']))
        except (ValueError, KeyError, TypeError):
            self._reply(socket, json.dumps({'hr': 0x80070057}).encode())        # E_INVALIDARG
            return
        self._relays.add(socket)

        def work():
            try:
                reply = {'answer': base64.b64encode(self.get_assertion(op)).decode('ascii')}
            except Refusal as refusal:
                reply = {'hr': refusal.hr}
            except Exception:  # noqa: BLE001 - the relay must get an answer
                traceback.print_exc()
                reply = {'hr': provider.E_FAIL}
            self._replied.emit(socket, json.dumps(reply).encode())
        threading.Thread(target=work, name='keytap-passkey', daemon=True).start()

    def _reply(self, socket, data: bytes) -> None:
        self._relays.discard(socket)
        try:
            socket.write(data)
            socket.waitForBytesWritten(2000)
            socket.disconnectFromServer()
            socket.deleteLater()
        except RuntimeError:                  # the relay went away first
            pass

    def creating_refused(self) -> None:
        self._to_ui.emit(None, 'toast', _NO_CREATING)

    # ------------------------------------------------------------------ COM's threads

    def unlocked(self) -> bool:
        return self.controller.unlocked

    def cancel(self, transaction) -> None:
        job = self._job
        if job is not None and job.op.transaction == transaction:
            job.cancelled = True
            job.refuse(provider.NTE_USER_CANCELLED)
            self._to_ui.emit(job, 'cancelled', '')

    def make_credential(self, op) -> bytes:
        self.creating_refused()
        raise Refusal(provider.NTE_NOT_SUPPORTED)

    def get_assertion(self, op) -> bytes:
        if not provider.identity():
            # Only the Keytap.exe in the folder set up for passkeys can check Windows signed this.
            self._to_ui.emit(None, 'toast', 'This copy of Keytap is not the one set up for passkeys. Set it up in '
                                             'Settings > Passkeys, or start the one that is.')
            raise Refusal(provider.E_ACCESSDENIED, 'no package identity to check the request with')
        if not provider.from_windows(op.data, op.signature):
            print('passkeys: a request not signed by Windows - refused', flush=True)
            raise Refusal(provider.E_ACCESSDENIED, 'a passkey request Windows did not sign')
        try:
            request = passkeys.Request.parse(op.data)
        except passkeys.PasskeyError as error:
            self._to_ui.emit(None, 'toast', str(error))
            raise Refusal(provider.NTE_NOT_FOUND) from error
        if not self._one_at_a_time.acquire(blocking=False):
            raise Refusal(provider.ERROR_BUSY_HR)
        try:
            job = self._job = _Job(op, request)
            self._to_ui.emit(job, 'start', '')
            if not job.wait():
                job.refuse(provider.NTE_USER_CANCELLED)
                self._to_ui.emit(job, 'cancelled', '')
            if job.refusal is not None:
                raise job.refusal
            if not job.verified and not self._windows_hello(job):
                raise job.refusal or Refusal(provider.NTE_USER_CANCELLED)
            try:
                return passkeys.answer(job.passkey, request, verified=True)
            except passkeys.PasskeyError as error:
                self._to_ui.emit(None, 'toast', str(error))
                raise Refusal(provider.NTE_NOT_SUPPORTED) from error
        finally:
            self._job = None
            self._one_at_a_time.release()

    def _windows_hello(self, job: _Job) -> bool:
        try:
            return provider.verify_user(job.op.hwnd, job.op.transaction, job.passkey.who,
                                        f'Sign in to {job.site} with your passkey from Keytap')
        except OSError:
            traceback.print_exc()
        # Windows Hello can't (not set up, say): the master password instead.
        job.again()
        self._to_ui.emit(job, 'password', '')
        if not job.wait():
            return False
        return job.refusal is None and job.verified

    # ------------------------------------------------------------------ the UI thread

    def _on_ui(self, job, what: str, message: str) -> None:
        try:
            if what == 'toast':
                self.controller.toasts.show('Passkeys', message, error=True)
            elif what == 'start':
                self._start(job)
            elif what == 'password':
                self._password(job)
            elif what == 'cancelled' and job.card is not None:
                try:
                    job.card.close()
                except RuntimeError:            # closed already
                    pass
        except Exception:  # noqa: BLE001 - never leave Windows waiting on a broken step
            traceback.print_exc()
            if job is not None:
                job.refuse(provider.E_FAIL)

    def _start(self, job: _Job) -> None:
        c = self.controller
        if c.status.state not in ('locked', 'unlocked'):
            c.toasts.show('Passkeys', 'Sign Keytap in to Bitwarden first.', error=True)
            job.refuse(provider.NTE_NOT_FOUND)
        elif c.card is not None:
            c.card.bring_back()
            c.toasts.show('Passkeys', 'Finish with the Keytap card on screen, then try the passkey again.')
            job.refuse(provider.ERROR_BUSY_HR)
        elif not c.unlocked:
            job.card = c.unlock_for(f'to sign in to {job.site} with a passkey', job.op.hwnd,
                                    lambda: self._choose(job, just_unlocked=True),
                                    lambda: job.refuse(provider.NTE_USER_CANCELLED))
        else:
            self._choose(job, just_unlocked=False)

    def _choose(self, job: _Job, just_unlocked: bool) -> None:
        if job.cancelled:
            return
        c = self.controller
        found = passkeys.candidates([key for login in c.logins or [] for key in login.passkeys], job.request)
        if not found:
            c.toasts.show('Passkeys', f'No passkey for {job.site} in your vault.', error=True)
            job.refuse(provider.NTE_NOT_FOUND)
            return
        if len(found) == 1:
            self._chosen(job, found[0], just_unlocked)
            return
        names = {login.id: login.name for login in c.logins or []}
        card = AccountCard(job.site, found, names)
        card.chosen.connect(lambda key: self._chosen(job, key, just_unlocked))
        card.closed.connect(lambda: None if card.succeeded else job.refuse(provider.NTE_USER_CANCELLED))
        job.card = card
        c.show_card(card, job.op.hwnd)

    def _chosen(self, job: _Job, key, just_unlocked: bool) -> None:
        if job.cancelled:
            return
        c = self.controller
        login = next((login for login in c.logins or [] if login.id == key.login_id), None)
        if login is not None and login.reprompt:
            # As in Bitwarden: a login that asks for the master password asks for it here too.
            job.card = c.confirm(login, lambda: job.finish(key, True), job.op.hwnd,
                                 cancelled=lambda: job.refuse(provider.NTE_USER_CANCELLED))
            return
        job.finish(key, just_unlocked)

    def _password(self, job: _Job) -> None:
        c = self.controller
        login = next((login for login in c.logins or [] if login.id == job.passkey.login_id), None)
        job.card = c.confirm(login, lambda: job.finish(job.passkey, True), job.op.hwnd,
                             cancelled=lambda: job.refuse(provider.NTE_USER_CANCELLED),
                             detail=f'Your master password, to sign in to {job.site}')


def _whole_json(data: bytes) -> bool:
    try:
        json.loads(data)
        return True
    except ValueError:
        return False


class Relay:
    """provider.Server's handler in the Keytap Windows starts for a passkey while another Keytap
    runs: each call goes on to that Keytap, which has the vault, over its local socket."""

    def __init__(self, server_name: str):
        self._name = server_name
        self._busy = 0
        self._last = time.monotonic()

    def idle_seconds(self) -> float:
        return 0.0 if self._busy else time.monotonic() - self._last

    def _call(self, message: str, json_reply: bool = False) -> str | None:
        """Send one message to the running Keytap and read its answer. Through the named pipe its
        QLocalServer listens on rather than a QLocalSocket, which sends nothing from a thread Qt
        doesn't run - and COM calls in on threads of its own."""
        self._busy += 1
        try:
            pipe = None
            for _ in range(50):
                try:
                    pipe = open(PIPE_PREFIX + self._name, 'r+b', buffering=0)  # noqa: SIM115
                    break
                except FileNotFoundError:
                    return None                     # no Keytap running
                except OSError:
                    time.sleep(0.1)                 # busy with another caller
            if pipe is None:
                return None
            with pipe:
                pipe.write(message.encode('utf-8'))
                data = b''
                while True:                         # until the answer is whole, or Keytap hangs up
                    try:
                        chunk = pipe.read(65536)
                    except OSError:
                        break
                    if not chunk:
                        break
                    data += chunk
                    if not json_reply or _whole_json(data):
                        break
            return data.decode('utf-8', 'replace')
        finally:
            self._busy -= 1
            self._last = time.monotonic()

    def get_assertion(self, op) -> bytes:
        # Windows let this process come to the front; pass that on, for the running Keytap's cards.
        ctypes.windll.user32.AllowSetForegroundWindow(-1)        # ASFW_ANY
        payload = json.dumps({'hwnd': op.hwnd, 'transaction': str(op.transaction),
                              'data': base64.b64encode(op.data).decode('ascii'),
                              'signature': base64.b64encode(op.signature).decode('ascii')})
        reply = self._call(f'passkey {payload}', json_reply=True)
        if not reply:
            raise Refusal(provider.E_FAIL, 'the running Keytap did not answer')
        try:
            answer = json.loads(reply)
        except ValueError as error:
            raise Refusal(provider.E_FAIL, 'the running Keytap answered nonsense') from error
        if 'answer' in answer:
            return base64.b64decode(answer['answer'])
        raise Refusal(int(answer.get('hr', provider.E_FAIL)))

    def make_credential(self, op) -> bytes:
        self._call('passkey-make')
        raise Refusal(provider.NTE_NOT_SUPPORTED)

    def cancel(self, transaction) -> None:
        self._call(f'passkey-cancel {transaction}')

    def unlocked(self) -> bool:
        return (self._call('passkey-locked') or '').strip() == 'unlocked'
