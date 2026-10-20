"""The app icon, and the few small line glyphs Keytap's cards use."""

from __future__ import annotations

from PySide6.QtCore import QByteArray, QRectF, Qt
from PySide6.QtGui import QColor, QIcon, QPainter, QPixmap
from PySide6.QtSvg import QSvgRenderer
from PySide6.QtWidgets import QApplication

# 24x24 stroke drawings. '{c}' is filled in with the requested colour.
_STROKE = ('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" '
           'stroke="{c}" stroke-width="{w}" stroke-linecap="round" stroke-linejoin="round">{body}</svg>')

_SHAPES = {
    'close_x': '<path d="M6 6l12 12M18 6 6 18"/>',
    'lock': '<rect x="5" y="10.5" width="14" height="10" rx="2"/><path d="M8 10.5V7.5a4 4 0 0 1 8 0v3"/>',
    'search': '<circle cx="10.5" cy="10.5" r="6"/><path d="M15 15l5 5"/>',
    'star': '<path d="M12 4l2.4 5 5.4.6-4 3.7 1.1 5.3L12 16l-4.9 2.6 1.1-5.3-4-3.7 5.4-.6z" fill="{c}"/>',
    'key': '<circle cx="8" cy="12" r="3.5"/><path d="M11.5 12H20M17 12v3M20 12v2.5"/>',
}

_cache: dict = {}


def glyph(name: str, color: QColor | str, size: int = 20, width: float = 1.8) -> QPixmap:
    """One of the drawings above as a pixmap, sharp on high-DPI screens."""
    color = QColor(color)
    hex_color, alpha = color.name(), color.alphaF()
    ratio = QApplication.primaryScreen().devicePixelRatio() if QApplication.primaryScreen() else 1.0
    key = (name, hex_color, alpha, size, width, ratio)
    cached = _cache.get(key)
    if cached is not None:
        return cached
    body = _SHAPES[name].replace('{c}', hex_color)
    svg = _STROKE.format(c=hex_color, w=width, body=f'<g opacity="{alpha:.3f}">{body}</g>')
    renderer = QSvgRenderer(QByteArray(svg.encode('utf-8')))
    pixmap = QPixmap(round(size * ratio), round(size * ratio))
    pixmap.setDevicePixelRatio(ratio)
    pixmap.fill(Qt.transparent)
    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.Antialiasing)
    renderer.render(painter, QRectF(0, 0, size, size))
    painter.end()
    _cache[key] = pixmap
    return pixmap


def clear_cache() -> None:
    _cache.clear()


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


ICON_SIZES = (16, 20, 24, 32, 40, 48, 64, 128, 256)


def app_icon() -> QIcon:
    """The window, tray and card icon - and the one in the exe."""
    result = QIcon()
    for size in ICON_SIZES:
        result.addPixmap(render_app_icon(size))
    return result
