"""
widgets/avatar.py
Circular avatar placeholder (initials on a Nord frost gradient) with an
optional online dot. Repaints on theme change.
"""

from PySide6.QtWidgets import QWidget
from PySide6.QtCore import Qt, QRectF, QPointF
from PySide6.QtGui import QPainter, QLinearGradient, QColor, QBrush, QPen, QFont

try:
    from core.theme import theme, UI_FONT_FAMILY
except ImportError:  # tolerate an older core/theme.py left over from a previous copy
    from core.theme import theme
    UI_FONT_FAMILY = "Segoe UI"


def _initials(name: str) -> str:
    name = (name or "").strip()
    if not name:
        return "?"
    parts = [p for p in name.replace(".", " ").replace("_", " ").split() if p]
    if len(parts) >= 2:
        return (parts[0][0] + parts[1][0]).upper()
    return name[:2].upper()


class Avatar(QWidget):
    def __init__(self, name: str = "", size: int = 36, online: bool = False, parent=None):
        super().__init__(parent)
        self._name = name
        self._size = size
        self._online = online
        self.setFixedSize(size, size)
        theme.changed.connect(self.update)

    def set_name(self, name: str):
        self._name = name
        self.update()

    def paintEvent(self, event):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing, True)
        rect = QRectF(0, 0, self._size, self._size)

        grad = QLinearGradient(0, 0, self._size, self._size)
        grad.setColorAt(0.0, QColor(theme.c("ACCENT")))
        grad.setColorAt(1.0, QColor(theme.c("ACCENT_2")))
        p.setPen(Qt.NoPen)
        p.setBrush(QBrush(grad))
        p.drawEllipse(rect)

        p.setPen(QPen(QColor(theme.c("ON_ACCENT"))))
        f = QFont(UI_FONT_FAMILY, int(self._size * 0.34))
        f.setBold(True)
        p.setFont(f)
        p.drawText(rect, Qt.AlignCenter, _initials(self._name))

        if self._online:
            d = max(8, int(self._size * 0.26))
            cx = self._size - d * 0.7
            cy = self._size - d * 0.7
            p.setPen(Qt.NoPen)
            p.setBrush(QBrush(QColor(theme.c("CARD_BG"))))
            p.drawEllipse(QPointF(cx, cy), d * 0.62, d * 0.62)
            p.setBrush(QBrush(QColor(theme.c("SUCCESS"))))
            p.drawEllipse(QPointF(cx, cy), d * 0.42, d * 0.42)

        p.end()
