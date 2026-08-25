"""
widgets/sparkline.py
A compact trend line rendered with QPainter, used as the small trend
indicator on status cards. Keeps a rolling window of recent values.
"""

import collections

from PySide6.QtWidgets import QWidget, QSizePolicy
from PySide6.QtCore import Qt, QPointF
from PySide6.QtGui import QPainter, QPen, QColor, QBrush, QPainterPath, QLinearGradient

from core.theme import theme


class Sparkline(QWidget):
    def __init__(self, points=24, height=30, color_role="ACCENT", parent=None):
        super().__init__(parent)
        self._data = collections.deque(maxlen=points)
        self._role = color_role
        self.setMinimumHeight(height)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        theme.changed.connect(self.update)

    def set_color_role(self, role):
        self._role = role
        self.update()

    def add(self, value):
        if value is None:
            return
        try:
            self._data.append(float(value))
        except (TypeError, ValueError):
            return
        self.update()

    def clear(self):
        self._data.clear()
        self.update()

    def paintEvent(self, event):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing, True)
        w = self.width()
        h = self.height()
        color = QColor(theme.c(self._role))

        if len(self._data) < 2:
            pen = QPen(QColor(theme.c("BORDER")), 2)
            p.setPen(pen)
            p.drawLine(2, h - 4, w - 2, h - 4)
            p.end()
            return

        vals = list(self._data)
        lo, hi = min(vals), max(vals)
        span = (hi - lo) or 1.0
        n = len(vals)
        pad = 3
        usable_w = max(1, w - 2 * pad)
        usable_h = max(1, h - 2 * pad)

        pts = []
        for i, v in enumerate(vals):
            x = pad + (i / (n - 1)) * usable_w
            y = pad + (1 - (v - lo) / span) * usable_h
            pts.append(QPointF(x, y))

        # Fill under the line
        fill = QPainterPath()
        fill.moveTo(pts[0].x(), h - pad)
        for pt in pts:
            fill.lineTo(pt)
        fill.lineTo(pts[-1].x(), h - pad)
        fill.closeSubpath()
        grad = QLinearGradient(0, 0, 0, h)
        c0 = QColor(color); c0.setAlpha(70)
        c1 = QColor(color); c1.setAlpha(0)
        grad.setColorAt(0.0, c0)
        grad.setColorAt(1.0, c1)
        p.setPen(Qt.NoPen)
        p.setBrush(QBrush(grad))
        p.drawPath(fill)

        # Line
        pen = QPen(color, 2)
        pen.setJoinStyle(Qt.RoundJoin)
        pen.setCapStyle(Qt.RoundCap)
        p.setPen(pen)
        path = QPainterPath(pts[0])
        for pt in pts[1:]:
            path.lineTo(pt)
        p.drawPath(path)
        p.end()
