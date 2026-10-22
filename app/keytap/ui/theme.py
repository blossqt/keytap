"""Colours for Keytap's own painted cards, following Windows' light or dark mode.

They are the suite's, from suitetheme.py - the shared file Hanami keeps in
step across the suite's apps - plus the one Keytap adds below.
"""

from __future__ import annotations

from dataclasses import dataclass

from PySide6.QtGui import QColor

from . import suitetheme
from .suitetheme import *  # noqa: F401,F403 - the suite's look, used as theme.<name>
from .suitetheme import is_dark


@dataclass(frozen=True)
class Colors(suitetheme.Colors):
    hover: QColor       # a row of a list under the pointer: grey, as the pink means chosen


def colors() -> Colors:
    hover = QColor('#2c2d35') if is_dark() else QColor('#f1f2f6')
    return Colors(**vars(suitetheme.colors()), hover=hover)
