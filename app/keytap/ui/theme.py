"""Colours for Keytap's own painted cards, following Windows' light or dark mode.

They are the suite's, from suitetheme.py - the shared file Hanami keeps in
step across the suite's apps - plus the one Keytap adds below.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from PySide6.QtGui import QColor

from . import suitetheme
from .suitetheme import *  # noqa: F401,F403 - the suite's look, used as theme.<name>
from .suitetheme import is_dark


BACKDROP = str(Path(__file__).with_name('backdrop.jpg'))     # AJ's blossom, on Unsplash, faint behind the windows


@dataclass(frozen=True)
class Colors(suitetheme.Colors):
    hover: QColor       # a row of a list under the pointer: grey, as the pink means chosen


def colors() -> Colors:
    """Kept for each mode and glass, as suitetheme's are: copy one before changing it."""
    key = (is_dark(), suitetheme.glass_on())
    kept = _kept.get(key)
    if kept is None:
        if key[1]:
            hover = QColor(255, 255, 255, 24) if key[0] else QColor(0, 0, 0, 14)
        else:
            hover = QColor('#2c2d35') if key[0] else QColor('#f1f2f6')
        kept = _kept[key] = Colors(**vars(suitetheme.colors()), hover=hover)
    return kept


_kept: dict = {}
