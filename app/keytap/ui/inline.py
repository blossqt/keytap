"""The little list that pops up under a login box, as Bitwarden's does in a browser.

It never takes the keyboard: the cursor stays in the box, so clicking a login
types straight into it. Esc, clicking elsewhere or leaving the box hides it.
"""

from __future__ import annotations

from PySide6.QtCore import QRect, QRectF, Qt, Signal
from PySide6.QtGui import QColor, QFont, QFontMetrics, QGuiApplication, QPainter
from PySide6.QtWidgets import QWidget

from ..matching import JUST, LINKED, PAGE, URI
from . import icons, theme
from .card import to_logical, to_physical

SHADOW = 0 if theme.glass_on() else 12       # on glass, Windows draws the shadow
HEADER = 30
ROW = 42
FOOTER = 28
MIN_WIDTH, MAX_WIDTH = 290, 380
MAX_LOGINS = 6
_TAGS = {JUST: 'Just used', LINKED: 'Always', URI: 'Matches', PAGE: 'Matches'}


class InlineMenu(QWidget):
    chosen = Signal(object)     # a Login
    search = Signal()
    unlock = Signal()
    mute = Signal()
    dismiss = Signal()

    def __init__(self):
        super().__init__(None, Qt.FramelessWindowHint | Qt.Tool | Qt.WindowStaysOnTopHint
                         | Qt.WindowDoesNotAcceptFocus | Qt.NoDropShadowWindowHint)
        self.setAttribute(Qt.WA_TranslucentBackground)
        self.setAttribute(Qt.WA_ShowWithoutActivating)
        theme.frost(self)
        self.setMouseTracking(True)
        self.field = None
        self.program = ''
        self._rows: list[tuple[str, object, str, str, str]] = []    # (kind, login, title, detail, tag)
        self._hover: object = None

    # ------------------------------------------------------------------ showing

    def present(self, field, matches, place: str, program: str) -> None:
        """matches: [(login, strength)] to offer, or None while the vault is locked. place is
        what the box is in - the program, or the website of the page it is on; program is what
        "Don't pop up in" mutes."""
        self.field, self.program = field, program
        if matches is None:
            self._rows = [('unlock', None, 'Unlock Keytap', 'to fill this from your vault', '')]
        else:
            self._rows = [('login', login, login.name, login.username or 'no username', _TAGS.get(strength, ''))
                          for login, strength in matches[:MAX_LOGINS]]
            more = len(matches) - MAX_LOGINS
            detail = (f'and {more} more for {place}' if more > 0 else
                      '' if matches else f'nothing saved for {place} yet')
            self._rows.append(('search', None, 'Search your vault…' if matches else 'Choose a login…',
                               detail, ''))
        self._hover = None

        left, top, right, bottom = field.rect
        box = QRect(to_logical(left, top), to_logical(right, bottom))
        width = max(MIN_WIDTH, min(MAX_WIDTH, box.width())) + 2 * SHADOW
        height = HEADER + ROW * len(self._rows) + FOOTER + 2 * SHADOW
        self.resize(width, height)
        screen = QGuiApplication.screenAt(box.center()) or QGuiApplication.primaryScreen()
        area = screen.availableGeometry()
        x = box.left() - SHADOW
        y = box.bottom() + 4 - SHADOW
        if y + height - SHADOW > area.bottom():            # no room below: above the box
            y = box.top() - 4 - height + SHADOW
        x = max(area.left() - SHADOW, min(x, area.right() - width + SHADOW))
        y = max(area.top() - SHADOW, min(y, area.bottom() - height + SHADOW))
        self.move(x, y)
        self.update()
        self.show()
        self.raise_()

    def describe(self) -> dict:
        return {'visible': self.isVisible(), 'kind': self.field.kind if self.field else '',
                'page': self.field.page if self.field else '',
                'rows': [title for _, _, title, _, _ in self._rows]}

    def row_point(self, index: int) -> tuple[int, int]:
        """The middle of a row, in physical screen pixels (for tests)."""
        rect = self._row_rect(index)
        return to_physical(self.mapToGlobal(rect.center().toPoint()))

    # ------------------------------------------------------------------ layout

    @property
    def _card(self) -> QRectF:
        return QRectF(self.rect()).adjusted(SHADOW, SHADOW, -SHADOW, -SHADOW)

    def _row_rect(self, index: int) -> QRectF:
        card = self._card
        return QRectF(card.left() + 6, card.top() + HEADER + index * ROW, card.width() - 12, ROW)

    def _close_rect(self) -> QRectF:
        card = self._card
        return QRectF(card.right() - 28, card.top() + 5, 22, 22)

    def _mute_rect(self) -> QRectF:
        card = self._card
        return QRectF(card.left() + 12, card.bottom() - FOOTER + 2, card.width() - 24, FOOTER - 6)

    def _hit(self, pos) -> object:
        if self._close_rect().contains(pos):
            return 'close'
        if self._mute_rect().contains(pos):
            return 'mute'
        for index in range(len(self._rows)):
            if self._row_rect(index).contains(pos):
                return index
        return None

    # ------------------------------------------------------------------ mouse

    def mouseMoveEvent(self, event):
        hover = self._hit(event.position())
        if hover != self._hover:
            self._hover = hover
            self.setCursor(Qt.PointingHandCursor if hover is not None else Qt.ArrowCursor)
            self.update()

    def leaveEvent(self, event):
        self._hover = None
        self.update()

    def mouseReleaseEvent(self, event):
        if event.button() != Qt.LeftButton:
            return
        hit = self._hit(event.position())
        if hit == 'close':
            self.dismiss.emit()
        elif hit == 'mute':
            self.mute.emit()
        elif isinstance(hit, int):
            kind, login, *_ = self._rows[hit]
            if kind == 'login':
                self.chosen.emit(login)
            elif kind == 'search':
                self.search.emit()
            else:
                self.unlock.emit()

    # ------------------------------------------------------------------ painting

    def paintEvent(self, event):
        c = theme.colors()
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        card = self._card
        if theme.glass_on():
            theme.paint_glass(p, card)
        else:
            theme.paint_shadow(p, card, 10, SHADOW - 2, c.shadow)
            p.setPen(c.border)
            p.setBrush(c.card)
            p.drawRoundedRect(card.adjusted(0.5, 0.5, -0.5, -0.5), 10, 10)

        p.drawPixmap(int(card.left() + 12), int(card.top() + 8), icons.render_app_icon(16))
        p.setFont(theme.font(8.5, QFont.DemiBold))
        p.setPen(c.dim)
        what = 'password' if self.field and self.field.kind == 'password' else 'login'
        p.drawText(QRectF(card.left() + 34, card.top() + 4, card.width() - 70, 24), Qt.AlignVCenter,
                   f'Keytap  ·  fill this {what}')
        p.drawPixmap(self._close_rect().adjusted(4, 4, -4, -4).toRect(),
                     icons.glyph('close_x', c.text if self._hover == 'close' else c.dim, 14, 2))

        for index, (kind, login, title, detail, tag) in enumerate(self._rows):
            rect = self._row_rect(index)
            hovered = self._hover == index
            if hovered:
                p.setPen(Qt.NoPen)
                p.setBrush(c.selected)
                p.drawRoundedRect(rect, 8, 8)
            text, dim = (c.selected_text, c.selected_text) if hovered else (c.text, c.dim)
            left, right = rect.left() + 10, rect.right() - 10
            if kind != 'login':
                p.drawPixmap(int(left), int(rect.center().y() - 8),
                             icons.glyph('lock' if kind == 'unlock' else 'search', text, 16, 1.8))
                left += 26
            if tag:
                p.setFont(theme.font(7.5, QFont.DemiBold))
                width = QFontMetrics(p.font()).horizontalAdvance(tag) + 12
                chip = QRectF(right - width, rect.center().y() - 9, width, 18)
                p.setPen(Qt.NoPen)
                p.setBrush(c.chip if not hovered else QColor(255, 255, 255, 50))
                p.drawRoundedRect(chip, 9, 9)
                p.setPen(text)
                p.drawText(chip, Qt.AlignCenter, tag)
                right = chip.left() - 6
            width = int(max(20, right - left))
            p.setFont(theme.font(9.5, QFont.DemiBold))
            p.setPen(text)
            p.drawText(QRectF(left, rect.top() + (4 if detail else 0), width, 18 if detail else ROW),
                       Qt.AlignVCenter, QFontMetrics(p.font()).elidedText(title, Qt.ElideRight, width))
            if detail:
                p.setFont(theme.font(8.25))
                p.setPen(dim)
                p.drawText(QRectF(left, rect.top() + 21, width, 16), Qt.AlignVCenter,
                           QFontMetrics(p.font()).elidedText(detail, Qt.ElideRight, width))

        p.setFont(theme.font(8))
        p.setPen(c.text if self._hover == 'mute' else c.dim)
        p.drawText(self._mute_rect(), Qt.AlignVCenter, f"Don't pop up in {self.program}")
        p.end()
