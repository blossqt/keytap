"""What Keytap remembers, kept in the registry under HKCU\\Software\\Keytap.

Nothing secret is kept here: only preferences, and which login was chosen for
which program (by the login's id).
"""

from __future__ import annotations

import json
import os

from PySide6.QtCore import QSettings

from .sequence import DEFAULT as DEFAULT_SEQUENCE

DEFAULT_HOTKEYS = {'type': 'Ctrl+Alt+A', 'pick': 'Ctrl+Alt+Shift+A'}
IDLE_CHOICES = (5, 15, 30, 60, 240, 0)     # minutes; 0 for never


class Settings:
    def __init__(self):
        # Tests point this at a file so they leave the real settings alone.
        path = os.environ.get('KEYTAP_SETTINGS')
        self._store = QSettings(path, QSettings.IniFormat) if path else QSettings('Keytap', 'Keytap')

    def _get(self, key: str, default, kind=str):
        value = self._store.value(key, default)
        if kind is bool:
            return value if isinstance(value, bool) else str(value).lower() in ('true', '1')
        try:
            return kind(value)
        except (TypeError, ValueError):
            return default

    @property
    def hotkeys(self) -> dict[str, str]:
        return {action: self._get(f'hotkeys/{action}', default) for action, default in DEFAULT_HOTKEYS.items()}

    @hotkeys.setter
    def hotkeys(self, hotkeys: dict[str, str]) -> None:
        for action in DEFAULT_HOTKEYS:
            self._store.setValue(f'hotkeys/{action}', hotkeys.get(action, ''))

    @property
    def sequence(self) -> str:
        return self._get('typing/sequence', DEFAULT_SEQUENCE) or DEFAULT_SEQUENCE

    @sequence.setter
    def sequence(self, value: str) -> None:
        self._store.setValue('typing/sequence', value.strip() or DEFAULT_SEQUENCE)

    @property
    def compat_typing(self) -> bool:
        return self._get('typing/compat', False, bool)

    @compat_typing.setter
    def compat_typing(self, value: bool) -> None:
        self._store.setValue('typing/compat', bool(value))

    @property
    def key_delay(self) -> int:
        return max(0, min(500, self._get('typing/key_delay', 10, int)))

    @key_delay.setter
    def key_delay(self, value: int) -> None:
        self._store.setValue('typing/key_delay', int(value))

    @property
    def lock_with_windows(self) -> bool:
        return self._get('lock/with_windows', True, bool)

    @lock_with_windows.setter
    def lock_with_windows(self, value: bool) -> None:
        self._store.setValue('lock/with_windows', bool(value))

    @property
    def idle_minutes(self) -> int:
        value = self._get('lock/idle_minutes', 30, int)
        return value if value in IDLE_CHOICES else 30

    @idle_minutes.setter
    def idle_minutes(self, value: int) -> None:
        self._store.setValue('lock/idle_minutes', int(value))

    @property
    def links(self) -> dict[str, str]:
        """{program or program|title: login id}, from the picker's "Always use"."""
        try:
            links = json.loads(self._get('links/json', '{}') or '{}')
        except json.JSONDecodeError:
            return {}
        return {str(k): str(v) for k, v in links.items()} if isinstance(links, dict) else {}

    @links.setter
    def links(self, links: dict[str, str]) -> None:
        self._store.setValue('links/json', json.dumps(links, ensure_ascii=False))

    @property
    def inline(self) -> bool:
        """Whether the list of logins pops up under login boxes."""
        return self._get('inline/enabled', True, bool)

    @inline.setter
    def inline(self, value: bool) -> None:
        self._store.setValue('inline/enabled', bool(value))

    @property
    def inline_muted(self) -> list[str]:
        """Programs ('steam.exe') the pop-up stays out of."""
        try:
            muted = json.loads(self._get('inline/muted', '[]') or '[]')
        except json.JSONDecodeError:
            return []
        return sorted({str(m).lower() for m in muted}) if isinstance(muted, list) else []

    @inline_muted.setter
    def inline_muted(self, programs: list[str]) -> None:
        self._store.setValue('inline/muted', json.dumps(sorted({p.lower() for p in programs})))

    @property
    def tray_shown(self) -> bool:
        """In the tray (Hanami's icon, or Keytap's own), or out of it altogether."""
        return self._get('tray/shown', True, bool)

    @tray_shown.setter
    def tray_shown(self, value: bool) -> None:
        self._store.setValue('tray/shown', bool(value))

    @property
    def welcomed(self) -> bool:
        return self._get('welcomed', False, bool)

    @welcomed.setter
    def welcomed(self, value: bool) -> None:
        self._store.setValue('welcomed', bool(value))

    def sync(self) -> None:
        self._store.sync()
