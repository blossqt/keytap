"""The app icon, and the few small line glyphs Keytap's cards use."""

from __future__ import annotations

from PySide6.QtCore import QRectF, Qt
from PySide6.QtGui import QColor, QIcon, QPainter, QPixmap

from . import suiteicons

_SHAPES = suiteicons.SHAPES      # the suite's one set of line icons


def glyph(name: str, color: QColor | str, size: int = 20, width: float = suiteicons.STROKE) -> QPixmap:
    """One of the suite's line icons as a pixmap, sharp on high-DPI screens."""
    return suiteicons.pixmap(name, color, size, width)


def clear_cache() -> None:
    suiteicons.clear_cache()


# The icon follows the suite's shared shape, so it sits beside Homework Hub's,
# Grabbit's, Dropshift's and Hanami's as one of a set: a tile in blossom pink
# filling the
# whole square, corners rounded to 42/192 of its width, and one mark in deep
# rose on it - white would vanish on the pale pink.
#
# The colours are constants on purpose: make_icon.py bakes this icon into the
# exe at build time, and a colour taken from the palette there would be
# whatever accent Windows happened to have that day.
APP_ICON_COLOR = '#ffd1dc'
APP_ICON_MARK = '#c2255c'
APP_ICON_CORNER = 42 / 192

# The mark is a key lying on its side, bow on the left, two teeth hanging
# from the end of its shaft. In units of a 64-wide tile: the bow's centre
# (cx, cy), outer and inner radius (r, hole), the shaft's thickness t and
# right end x1, and each tooth as (left, right, bottom). Small icons get their
# own numbers, so the shaft and teeth sit on whole pixels and the hole in the
# bow stays open.
_MARK_LARGE = dict(cx=23.5, cy=32, r=10, hole=4.5, t=7, x1=51,
                   teeth=((39.5, 44, 42), (46.5, 51, 40)))
_MARK_MEDIUM = dict(cx=23.333, cy=32, r=10, hole=4, t=8, x1=50.667,      # 24px: whole 3/8 px
                    teeth=((37.333, 42.667, 42.667), (45.333, 50.667, 40)))
_MARK_SMALL = dict(cx=24, cy=32, r=10, hole=4, t=8, x1=52,                # 16-20px
                   teeth=((40, 44, 44), (48, 52, 40)))


def _mark(size: int) -> dict:
    if size <= 20:
        return _MARK_SMALL
    if size <= 24:
        return _MARK_MEDIUM
    return _MARK_LARGE


def render_app_icon(size: int) -> QPixmap:
    """The app icon at one size, drawn for that size rather than scaled."""
    pixmap = QPixmap(size, size)
    pixmap.fill(Qt.transparent)
    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.Antialiasing)
    painter.scale(size / 64.0, size / 64.0)
    painter.setPen(Qt.NoPen)
    painter.setBrush(QColor(APP_ICON_COLOR))
    corner = 64 * APP_ICON_CORNER
    painter.drawRoundedRect(QRectF(0, 0, 64, 64), corner, corner)

    k = _mark(size)
    cx, cy, r, t = k['cx'], k['cy'], k['r'], k['t']
    painter.setBrush(QColor(APP_ICON_MARK))
    painter.drawEllipse(QRectF(cx - r, cy - r, 2 * r, 2 * r))
    painter.drawRoundedRect(QRectF(cx, cy - t / 2, k['x1'] - cx, t), 1.2, 1.2)
    for left, right, bottom in k['teeth']:
        painter.drawRoundedRect(QRectF(left, cy, right - left, bottom - cy), 1.0, 1.0)
    # The hole in the bow, punched by painting the tile's own pink back in
    # (a path subtraction would leave it faceted at large sizes).
    painter.setBrush(QColor(APP_ICON_COLOR))
    hole = k['hole']
    painter.drawEllipse(QRectF(cx - hole, cy - hole, 2 * hole, 2 * hole))
    painter.end()
    return pixmap


def app_icon_svg() -> str:
    """The same drawing as SVG, for Windows' passkey window, which takes its providers' logos so."""
    k = _MARK_LARGE
    cx, cy, r, t = k['cx'], k['cy'], k['r'], k['t']
    corner = 64 * APP_ICON_CORNER
    shapes = [f'<rect width="64" height="64" rx="{corner:.2f}" fill="{APP_ICON_COLOR}"/>',
              f'<circle cx="{cx}" cy="{cy}" r="{r}" fill="{APP_ICON_MARK}"/>',
              f'<rect x="{cx}" y="{cy - t / 2}" width="{k["x1"] - cx}" height="{t}" rx="1.2" fill="{APP_ICON_MARK}"/>']
    shapes += [f'<rect x="{left}" y="{cy}" width="{right - left}" height="{bottom - cy}" rx="1" fill="{APP_ICON_MARK}"/>'
               for left, right, bottom in k['teeth']]
    shapes.append(f'<circle cx="{cx}" cy="{cy}" r="{k["hole"]}" fill="{APP_ICON_COLOR}"/>')
    return ('<svg xmlns="http://www.w3.org/2000/svg" version="1.1" width="64" height="64" viewBox="0 0 64 64">'
            + ''.join(shapes) + '</svg>')


ICON_SIZES = (16, 20, 24, 32, 40, 48, 64, 128, 256)


def app_icon() -> QIcon:
    """The window, tray and card icon - and the one in the exe."""
    result = QIcon()
    for size in ICON_SIZES:
        result.addPixmap(render_app_icon(size))
    return result
