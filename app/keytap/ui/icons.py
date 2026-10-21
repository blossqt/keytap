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
    'copy': '<rect x="9" y="9" width="11" height="11" rx="2"/><path d="M5 15V6a2 2 0 0 1 2-2h8"/>',
    'eye': '<path d="M2.5 12S6 5.5 12 5.5 21.5 12 21.5 12 18 18.5 12 18.5 2.5 12 2.5 12z"/>'
           '<circle cx="12" cy="12" r="3"/>',
    'eye_off': '<path d="M2.5 12S6 5.5 12 5.5 21.5 12 21.5 12 18 18.5 12 18.5 2.5 12 2.5 12z"/>'
               '<circle cx="12" cy="12" r="3"/><path d="M4 4l16 16"/>',
    'refresh': '<path d="M19.5 10.5A7.5 7.5 0 0 0 6 7.2L4.5 9M4.5 4.5V9H9"/>'
               '<path d="M4.5 13.5A7.5 7.5 0 0 0 18 16.8l1.5-1.8M19.5 19.5V15H15"/>',
    'sliders': '<path d="M4 7h9M18 7h2M4 17h3M12 17h8"/><circle cx="15.5" cy="7" r="2.3"/>'
               '<circle cx="9.5" cy="17" r="2.3"/>',
    'external': '<path d="M14 4h6v6M20 4l-8.5 8.5"/>'
                '<path d="M18.5 14v4a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V7.5a2 2 0 0 1 2-2h4"/>',
    'folder': '<path d="M3.5 7.5a2 2 0 0 1 2-2h4l2 2.5h7a2 2 0 0 1 2 2v7.5a2 2 0 0 1-2 2h-13a2 2 0 0 1-2-2z"/>',
    'grid': '<rect x="4" y="4" width="7" height="7" rx="1.5"/><rect x="13" y="4" width="7" height="7" rx="1.5"/>'
            '<rect x="4" y="13" width="7" height="7" rx="1.5"/><rect x="13" y="13" width="7" height="7" rx="1.5"/>',
    'clock': '<circle cx="12" cy="12" r="8"/><path d="M12 8v4l2.5 2.5"/>',
    'star_line': '<path d="M12 4l2.4 5 5.4.6-4 3.7 1.1 5.3L12 16l-4.9 2.6 1.1-5.3-4-3.7 5.4-.6z"/>',
    'globe': '<circle cx="12" cy="12" r="8.5"/><path d="M3.5 12h17M12 3.5c2.4 2.6 3.6 5.4 3.6 8.5s-1.2 5.9-3.6 '
             '8.5c-2.4-2.6-3.6-5.4-3.6-8.5s1.2-5.9 3.6-8.5z"/>',
    'window': '<rect x="3.5" y="5" width="17" height="14" rx="2"/><path d="M3.5 9h17"/>',
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
