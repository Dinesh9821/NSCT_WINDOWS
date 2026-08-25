"""
widgets/stat_card.py
Reusable status card for the landing dashboard.

Displays: icon + title, current value, a status-colored dot, a small
trend/progress indicator (progress bar or sparkline), and a "last updated"
timestamp. Re-themes on Dark/Light toggle.
"""

import datetime

from PySide6.QtWidgets import (
    QFrame, QVBoxLayout, QHBoxLayout, QLabel, QSizePolicy, QProgressBar
)
from PySide6.QtCore import Qt

from core.theme import theme, apply_soft_shadow
from core import iconkit
from widgets.sparkline import Sparkline

_STATUS_KEYS = {
    "success": "SUCCESS", "warning": "WARNING", "error": "ERROR",
    "info": "ACCENT", "neutral": "TEXT_SECONDARY",
}


class StatCard(QFrame):
    def __init__(self, title: str, icon_name: str, indicator: str = "bar", parent=None):
        super().__init__(parent)
        self.setProperty("cls", "statcard")
        apply_soft_shadow(self, radius=12, offset=(0, 3))
        self.setMinimumWidth(196)
        self.setFixedHeight(126)
        self.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Fixed)

        self._indicator = indicator
        self._status = "neutral"
        self._pct = None

        root = QVBoxLayout(self)
        root.setContentsMargins(16, 14, 16, 12)
        root.setSpacing(6)

        # Header: icon + title + status dot
        head = QHBoxLayout()
        head.setSpacing(8)
        self.lbl_icon = QLabel()
        iconkit.label(self.lbl_icon, icon_name, role="ACCENT", size=26)
        self.lbl_title = QLabel(title.upper())
        self.lbl_title.setProperty("role", "cardtitle")
        self.lbl_title.setWordWrap(True)
        self.dot = QLabel("\u25CF")
        head.addWidget(self.lbl_icon)
        head.addWidget(self.lbl_title, 1)
        head.addWidget(self.dot)
        root.addLayout(head)

        # Value
        self.lbl_value = QLabel("—")
        self.lbl_value.setProperty("role", "value")
        self.lbl_value.setWordWrap(True)
        root.addWidget(self.lbl_value)

        root.addStretch()

        # Indicator
        if indicator == "bar":
            self.bar = QProgressBar()
            self.bar.setProperty("cls", "thin")
            self.bar.setTextVisible(False)
            self.bar.setFixedHeight(8)
            self.bar.setRange(0, 100)
            self.bar.setValue(0)
            root.addWidget(self.bar)
            self.spark = None
        elif indicator == "spark":
            self.spark = Sparkline(points=24, height=28, color_role="ACCENT")
            root.addWidget(self.spark)
            self.bar = None
        else:
            self.bar = None
            self.spark = None

        # Timestamp
        self.lbl_time = QLabel("")
        self.lbl_time.setProperty("role", "secondary")
        self.lbl_time.setStyleSheet("font-size: 10px;")
        root.addWidget(self.lbl_time)

        theme.changed.connect(self._reapply)
        self._reapply()

    def _status_color(self):
        return theme.c(_STATUS_KEYS.get(self._status, "TEXT_SECONDARY"))

    def _reapply(self):
        col = self._status_color()
        self.dot.setStyleSheet(f"color: {col}; font-size: 11px;")
        if self.bar is not None and self._pct is not None:
            self.bar.setStyleSheet(
                f"QProgressBar {{ background-color: {theme.c('ELEVATED')};"
                f" border: none; border-radius: 4px; }}"
                f"QProgressBar::chunk {{ background-color: {col}; border-radius: 4px; }}")
        if self.spark is not None:
            role = _STATUS_KEYS.get(self._status, "ACCENT")
            self.spark.set_color_role(role if role != "TEXT_SECONDARY" else "ACCENT")

    def set_value(self, value, status="neutral", pct=None, stamp=True):
        self._status = status if status in _STATUS_KEYS else "neutral"
        self.lbl_value.setText(str(value))
        if self.bar is not None:
            if pct is not None:
                self._pct = max(0, min(100, int(round(pct))))
                self.bar.setValue(self._pct)
            else:
                self.bar.setValue(0)
        if stamp:
            self.lbl_time.setText("Updated " + datetime.datetime.now().strftime("%H:%M:%S"))
        self._reapply()

    def add_point(self, value):
        if self.spark is not None:
            self.spark.add(value)
