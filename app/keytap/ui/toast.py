"""Small cards in the corner of the screen saying what just happened."""

from __future__ import annotations

from collections.abc import Callable

from PySide6.QtCore import QRectF, Qt, QTimer, Signal
from PySide6.QtGui import QFont, QFontMetrics, QGuiApplication, QPainter
from PySide6.QtWidgets import QWidget

from . import icons, theme

SHADOW = 0 if theme.glass_on() else 14       # on glass, Windows draws the shadow
WIDTH = 340
HEIGHT = 74
SPACING = 8
LINGER = 5000       # ms a toast stays up (not counting while hovered)


class Toast(QWidget):
    closed = Signal(object)

    def __init__(self, title: str, detail: str = '', error: bool = False,
                 action: tuple[str, Callable[[], None]] | None = None):
        super().__init__(None, Qt.FramelessWindowHint | Qt.Tool | Qt.WindowStaysOnTopHint
                         | Qt.WindowDoesNotAcceptFocus | Qt.NoDropShadowWindowHint)
        self.setAttribute(Qt.WA_TranslucentBackground)
        self.setAttribute(Qt.WA_ShowWithoutActivating)
        theme.frost(self)
        self.setMouseTracking(True)
        self.resize(WIDTH + 2 * SHADOW, HEIGHT + 2 * SHADOW)
        self.title, self.detail, self.error, self.action = title, detail, error, action
        self._hover = ''
        self._timer = QTimer(self)
        self._timer.setSingleShot(True)
        self._timer.timeout.connect(self.close_toast)
        self._timer.start(LINGER * (2 if error or action else 1))

    @property
    def _card(self) -> QRectF:
        return QRectF(SHADOW, SHADOW, WIDTH, HEIGHT)

    @property
    def _close_rect(self) -> QRectF:
        return QRectF(self._card.right() - 30, self._card.top() + 8, 22, 22)

    @property
    def _action_rect(self) -> QRectF:
        return QRectF(self._card.right() - 128, self._card.bottom() - 30, 116, 22)

    def close_toast(self) -> None:
        self.hide()
        self.closed.emit(self)
        self.deleteLater()

    def enterEvent(self, event):
        self._timer.stop()

    def leaveEvent(self, event):
        self._hover = ''
        self.update()
        self._timer.start(LINGER // 2)

    def mouseMoveEvent(self, event):
        pos = event.position()
        hover = 'close' if self._close_rect.contains(pos) else (
            'action' if self.action and self._action_rect.contains(pos) else '')
        if hover != self._hover:
            self._hover = hover
            self.setCursor(Qt.PointingHandCursor if hover else Qt.ArrowCursor)
            self.update()

    def mouseReleaseEvent(self, event):
        pos = event.position()
        if self.action and self._action_rect.contains(pos):
            self.action[1]()
        self.close_toast()

    def paintEvent(self, event):
        c = theme.colors()
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        card = self._card
        if theme.glass_on():
            theme.paint_glass(p, card)
        else:
            theme.paint_shadow(p, card, 12, SHADOW - 2, c.shadow)
            p.setPen(c.border)
            p.setBrush(c.card)
            p.drawRoundedRect(card.adjusted(0.5, 0.5, -0.5, -0.5), 12, 12)

        p.drawPixmap(int(card.left() + 14), int(card.top() + 14), icons.render_app_icon(20))
        left, width = card.left() + 44, card.width() - 44 - 40
        p.setFont(theme.font(9.5, QFont.DemiBold))
        p.setPen(c.error if self.error else c.text)
        metrics = QFontMetrics(p.font())
        p.drawText(QRectF(left, card.top() + 10, width, 22), Qt.AlignVCenter,
                   metrics.elidedText(self.title, Qt.ElideRight, int(width)))
        p.setFont(theme.font(8.5))
        p.setPen(c.dim)
        metrics = QFontMetrics(p.font())
        detail_w = width + 30 if not self.action else width - 96
        p.drawText(QRectF(left, card.top() + 32, detail_w, 34), Qt.AlignTop | Qt.TextWordWrap,
                   self.detail if metrics.horizontalAdvance(self.detail) < detail_w * 2 - 20
                   else metrics.elidedText(self.detail, Qt.ElideRight, int(detail_w * 2 - 20)))

        if self.action:
            p.setPen(Qt.NoPen)
            p.setBrush(c.selected if self._hover == 'action' else c.chip)
            p.drawRoundedRect(self._action_rect, 7, 7)
            p.setFont(theme.font(8.5, QFont.DemiBold))
            p.setPen(c.selected_text if self._hover == 'action' else c.text)
            p.drawText(self._action_rect, Qt.AlignCenter, self.action[0])

        p.drawPixmap(self._close_rect.adjusted(4, 4, -4, -4).toRect(),
                     icons.glyph('close_x', c.text if self._hover == 'close' else c.dim, 14, 2))
        p.end()


class ToastStack:
    """Keeps toasts stacked upwards from the bottom-right corner."""

    def __init__(self):
        self._toasts: list[Toast] = []

    def show(self, title: str, detail: str = '', error: bool = False,
             action: tuple[str, Callable[[], None]] | None = None) -> Toast:
        toast = Toast(title, detail, error, action)
        toast.closed.connect(self._closed)
        self._toasts.append(toast)
        while len(self._toasts) > 4:
            self._toasts[0].close_toast()
        self._reflow()
        toast.show()
        return toast

    def _closed(self, toast: Toast) -> None:
        if toast in self._toasts:
            self._toasts.remove(toast)
        self._reflow()

    def _reflow(self) -> None:
        area = QGuiApplication.primaryScreen().availableGeometry()
        bottom = area.bottom() + SHADOW - 8
        for toast in reversed(self._toasts):
            toast.move(area.right() - toast.width() + SHADOW - 8, bottom - toast.height())
            bottom -= toast.height() - 2 * SHADOW + SPACING

    def titles(self) -> list[str]:
        return [toast.title for toast in self._toasts]
