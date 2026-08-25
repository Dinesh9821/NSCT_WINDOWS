"""
widgets/header.py
Top bar: sidebar toggle, breadcrumb, search, live clock, host chip, user chip.
The Dark/Light toggle now lives in the sidebar. A resizeEvent hides
lower-priority widgets on narrow widths so nothing ever overlaps.
"""

import socket
from PySide6.QtWidgets import (
    QFrame, QHBoxLayout, QLabel, QPushButton, QSizePolicy, QWidget, QLineEdit
)
from PySide6.QtCore import Qt, QTimer, QDateTime, Signal

from core.theme import theme
from core import iconkit
from widgets.avatar import Avatar
from backend.diagnostics import get_ad_username, get_local_ip


class Header(QFrame):
    toggle_sidebar_signal = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("HeaderFrame")
        self.setFixedHeight(66)

        self.layout = QHBoxLayout(self)
        self.layout.setContentsMargins(16, 0, 16, 0)
        self.layout.setSpacing(12)

        self._setup_left()
        spacer = QWidget()
        spacer.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
        self.layout.addWidget(spacer)
        self._setup_right()
        self._start_clock()

    def _setup_left(self):
        self.btn_toggle = QPushButton()
        self.btn_toggle.setProperty("cls", "iconbtn")
        self.btn_toggle.setFixedSize(36, 36)
        self.btn_toggle.setCursor(Qt.PointingHandCursor)
        iconkit.button(self.btn_toggle, "fa5s.bars", role="TEXT_PRIMARY", size=18)
        self.btn_toggle.clicked.connect(self.toggle_sidebar_signal.emit)
        self.layout.addWidget(self.btn_toggle)

        self.crumb = QLabel("Smart Health Check Tool")
        self.crumb.setProperty("role", "title")
        self.crumb.setSizePolicy(QSizePolicy.Maximum, QSizePolicy.Preferred)
        self.layout.addWidget(self.crumb)

        self.search = QLineEdit()
        self.search.setObjectName("Search")
        self.search.setPlaceholderText("Search anything here…")
        self.search.setFixedHeight(38)
        self.search.setMinimumWidth(160)
        self.search.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.search.setMaximumWidth(360)
        self.layout.addSpacing(4)
        self.layout.addWidget(self.search)

    def _setup_right(self):
        self.lbl_clock = QLabel()
        self.lbl_clock.setProperty("role", "mono")
        self.layout.addWidget(self.lbl_clock)

        hostname = socket.gethostname()
        self.host_chip = QLabel(f"  {hostname} · {get_local_ip()}  ")
        self.host_chip.setProperty("cls", "chip")
        self.host_chip.setAlignment(Qt.AlignCenter)
        self.host_chip.setFixedHeight(34)
        self.layout.addWidget(self.host_chip)

        username = get_ad_username()
        chip = QFrame()
        chip.setProperty("cls", "chip")
        chip.setFixedHeight(42)
        row = QHBoxLayout(chip)
        row.setContentsMargins(5, 4, 12, 4)
        row.setSpacing(9)
        row.addWidget(Avatar(username, size=30, online=True))
        name = QLabel(username)
        name.setStyleSheet("border: none; font-weight: 700;")
        row.addWidget(name)
        self.layout.addWidget(chip)

    def resizeEvent(self, event):
        super().resizeEvent(event)
        w = self.width()
        # Hide lower-priority items first as the header narrows.
        self.search.setVisible(w > 820)
        self.host_chip.setVisible(w > 700)
        self.lbl_clock.setVisible(w > 560)
        self.crumb.setVisible(w > 430)

    def _start_clock(self):
        self.timer = QTimer(self)
        self.timer.timeout.connect(self._update_clock)
        self.timer.start(1000)
        self._update_clock()

    def _update_clock(self):
        self.lbl_clock.setText(QDateTime.currentDateTime().toString("ddd dd MMM  HH:mm:ss"))
