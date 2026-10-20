"""Running slow work (every bw call takes a second or more) off the UI thread."""

from __future__ import annotations

import threading
import traceback
from collections.abc import Callable

from PySide6.QtCore import QObject, Signal

from .sequence import SequenceError
from .totp import TotpError
from .vault import VaultError

# Failures with a message fit to show; anything else is a bug worth a traceback in the log.
_EXPECTED = (VaultError, SequenceError, TotpError, OSError)


class _Relay(QObject):
    finished = Signal(object)

    def __init__(self):
        super().__init__()
        self.finished.connect(self._deliver)

    @staticmethod
    def _deliver(payload) -> None:
        done, result, error = payload
        if done is not None:
            done(result, error)


_relay: _Relay | None = None


def run(work: Callable[[], object], done: Callable[[object, Exception | None], None] | None = None) -> None:
    """Run work() on a thread of its own; done(result, error) then runs on the UI thread.

    The first call must come from the UI thread, which the relay then lives on.
    """
    global _relay
    if _relay is None:
        _relay = _Relay()
    relay = _relay

    def thread() -> None:
        try:
            result, error = work(), None
        except Exception as caught:  # noqa: BLE001 - handed to done()
            if not isinstance(caught, _EXPECTED):
                traceback.print_exc()
            result, error = None, caught
        relay.finished.emit((done, result, error))

    threading.Thread(target=thread, daemon=True).start()
