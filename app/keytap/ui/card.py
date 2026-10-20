"""The frameless card the picker and the unlock prompt are built on."""

from __future__ import annotations

from PySide6.QtCore import QPoint, QRect, QRectF, Qt, Signal
from PySide6.QtGui import QFont, QGuiApplication, QPainter
from PySide6.QtWidgets import QHBoxLayout, QLabel, QVBoxLayout, QWidget

from .. import win32
from . import icons, theme

SHADOW = 16
RADIUS = 12
PAD = 16


def to_logical(x: int, y: int) -> QPoint:
    """A point in Windows' physical pixels as Qt's logical ones.

    Qt keeps each screen's top-left corner where Windows has it and scales
    only from there, so the screen that holds the point does the conversion.
    """
    for screen in QGuiApplication.screens():
        geometry, ratio = screen.geometry(), screen.devicePixelRatio()
        native = QRect(geometry.topLeft(), geometry.size() * ratio)
        if native.contains(x, y):
            return geometry.topLeft() + QPoint(round((x - geometry.x()) / ratio),
                                               round((y - geometry.y()) / ratio))
    return QPoint(x, y)


def to_physical(point: QPoint) -> tuple[int, int]:
    """A point in Qt's logical pixels as Windows' physical ones (to_logical, reversed)."""
    screen = QGuiApplication.screenAt(point) or QGuiApplication.primaryScreen()
    geometry, ratio = screen.geometry(), screen.devicePixelRatio()
    return (geometry.x() + round((point.x() - geometry.x()) * ratio),
            geometry.y() + round((point.y() - geometry.y()) * ratio))


class Card(QWidget):
    """A rounded card with a soft shadow, in front of everything, taking the keyboard."""
    closed = Signal()

    def __init__(self, width: int):
        super().__init__(None, Qt.FramelessWindowHint | Qt.Tool | Qt.WindowStaysOnTopHint
                         | Qt.NoDropShadowWindowHint)
        self.setAttribute(Qt.WA_TranslucentBackground)
        self.setAttribute(Qt.WA_DeleteOnClose)
        self.setWindowIcon(icons.app_icon())
        self.setFixedWidth(width + 2 * SHADOW)
        self.setStyleSheet(theme.card_style())
        self.body = QVBoxLayout(self)
        self.body.setContentsMargins(SHADOW + PAD, SHADOW + PAD - 2, SHADOW + PAD, SHADOW + PAD)
        self.body.setSpacing(10)
        self._drag: QPoint | None = None

    def header(self, title: str, detail: str = '') -> QLabel:
        row = QHBoxLayout()
        row.setSpacing(10)
        logo = QLabel()
        logo.setPixmap(icons.app_icon().pixmap(28, 28))
        row.addWidget(logo, 0, Qt.AlignTop)
        text = QVBoxLayout()
        text.setSpacing(0)
        heading = QLabel(title)
        heading.setFont(theme.font(11, QFont.DemiBold))
        text.addWidget(heading)
        sub = QLabel(detail)
        sub.setProperty('role', 'dim')
        sub.setFont(theme.font(8.75))
        sub.setVisible(bool(detail))
        text.addWidget(sub)
        row.addLayout(text, 1)
        self.body.addLayout(row)
        return sub

    def present(self, near_hwnd: int | None = None) -> None:
        """Show the card over the given window (else mid-screen) and give it the keyboard."""
        self.adjustSize()
        screen = QGuiApplication.primaryScreen()
        anchor = None
        rect = win32.window_rect(near_hwnd) if near_hwnd else None
        if rect:
            top_left, bottom_right = to_logical(rect[0], rect[1]), to_logical(rect[2], rect[3])
            anchor = QRect(top_left, bottom_right)
            screen = QGuiApplication.screenAt(anchor.center()) or screen
        area = screen.availableGeometry()
        if anchor is None or anchor.width() < 50 or not area.intersects(anchor):
            anchor = area
        x = anchor.center().x() - self.width() // 2
        y = anchor.top() + max(40, (anchor.height() - self.height()) // 3)
        x = max(area.left() - SHADOW, min(x, area.right() - self.width() + SHADOW))
        y = max(area.top() - SHADOW, min(y, area.bottom() - self.height() + SHADOW))
        self.move(x, y)
        self.show()
        self.raise_()
        self.activateWindow()
        win32.set_foreground(int(self.winId()))

    def bring_back(self) -> None:
        self.raise_()
        self.activateWindow()
        win32.set_foreground(int(self.winId()))

    # ------------------------------------------------------------------ painting and moving

    def paintEvent(self, event):
        c = theme.colors()
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        card = QRectF(self.rect()).adjusted(SHADOW, SHADOW, -SHADOW, -SHADOW)
        theme.paint_shadow(painter, card, RADIUS, SHADOW - 2, c.shadow)
        painter.setPen(c.border)
        painter.setBrush(c.card)
        painter.drawRoundedRect(card.adjusted(0.5, 0.5, -0.5, -0.5), RADIUS, RADIUS)
        painter.end()

    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton:
            self._drag = event.globalPosition().toPoint() - self.frameGeometry().topLeft()

    def mouseMoveEvent(self, event):
        if self._drag is not None and event.buttons() & Qt.LeftButton:
            self.move(event.globalPosition().toPoint() - self._drag)

    def mouseReleaseEvent(self, event):
        self._drag = None

    def keyPressEvent(self, event):
        if event.key() == Qt.Key_Escape:
            self.close()
            return
        super().keyPressEvent(event)

    def closeEvent(self, event):
        self.closed.emit()
        super().closeEvent(event)
