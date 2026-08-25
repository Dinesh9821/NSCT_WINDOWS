"""
pages/settings.py
Application configuration, connection details, and system information.
UI restyled to Nord; adds an Appearance card with a Dark/Light toggle.
_open_logs logic is unchanged.
"""

import os
import socket
import subprocess
import sys

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame, QPushButton, QScrollArea
)
from PySide6.QtCore import Qt

from core.theme import theme, apply_soft_shadow
from core import iconkit
from core.constants import (
    APP_NAME, APP_VERSION, VENDOR, LLM_API_URL, USERNAME, log_dir,
    VERIFY_API_URL, VERIFY_API_TIMEOUT, PACKET_CAPTURE_TIMEOUT, capture_dir,
    PCAP_RETENTION,
)
from backend.diagnostics import get_ad_username, get_local_ip, uptime_short


class SettingsPage(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.workers = None

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)

        content = QWidget()
        self.layout = QVBoxLayout(content)
        self.layout.setContentsMargins(24, 22, 24, 22)
        self.layout.setSpacing(18)

        self._build_header()
        self._build_appearance_card()
        self._build_card("Application", [
            ("Name", APP_NAME), ("Version", APP_VERSION), ("Vendor", VENDOR),
        ])
        self._build_card("Connection", [
            ("LLM Endpoint", LLM_API_URL),
            ("Auth User", USERNAME),
            ("Auth Secret", "•" * 8),
        ])
        self._build_card("Packet capture & verification", [
            ("Verification API", VERIFY_API_URL or "(not configured)"),
            ("API timeout", "{} s".format(VERIFY_API_TIMEOUT)),
            ("Capture timeout", "{} s".format(PACKET_CAPTURE_TIMEOUT)),
            ("Capture folder", capture_dir()),
            ("PCAP retention", "{} files".format(PCAP_RETENTION)),
        ])
        self._build_card("System", [
            ("Hostname", socket.gethostname()),
            ("Signed-in User", get_ad_username()),
            ("Local IP", get_local_ip()),
            ("Uptime", uptime_short()),
            ("Platform", sys.platform),
        ])
        self._build_log_row()
        self.layout.addStretch()

        scroll.setWidget(content)
        outer.addWidget(scroll)

    def _build_header(self):
        title = QLabel("Settings")
        title.setProperty("role", "title")
        title.setStyleSheet("font-size: 24px; font-weight: 800;")
        sub = QLabel("Application configuration and environment details.")
        sub.setProperty("role", "subtitle")
        self.layout.addWidget(title)
        self.layout.addWidget(sub)

    def _build_appearance_card(self):
        card = QFrame()
        card.setProperty("cls", "card")
        apply_soft_shadow(card, radius=14, offset=(0, 4))
        box = QVBoxLayout(card)
        box.setContentsMargins(22, 18, 22, 18)
        box.setSpacing(10)

        lbl = QLabel("APPEARANCE")
        lbl.setStyleSheet(f"color: {theme.c('ACCENT')}; font-size: 12px; font-weight: bold; border: none;")
        box.addWidget(lbl)

        row = QHBoxLayout()
        k = QLabel("Theme")
        k.setProperty("role", "secondary")
        self.lbl_mode = QLabel(theme.mode.capitalize())
        self.lbl_mode.setStyleSheet("font-weight: 600; border: none;")
        self.btn_toggle = QPushButton("  Toggle Dark / Light")
        self.btn_toggle.setProperty("cls", "ghost")
        self.btn_toggle.setCursor(Qt.PointingHandCursor)
        iconkit.button(self.btn_toggle, "fa5s.adjust", role="ACCENT", size=14)
        self.btn_toggle.clicked.connect(theme.toggle)
        row.addWidget(k)
        row.addStretch()
        row.addWidget(self.lbl_mode)
        row.addSpacing(12)
        row.addWidget(self.btn_toggle)
        box.addLayout(row)

        theme.changed.connect(lambda: self.lbl_mode.setText(theme.mode.capitalize()))
        self.layout.addWidget(card)

    def _build_card(self, heading, rows):
        card = QFrame()
        card.setProperty("cls", "card")
        apply_soft_shadow(card, radius=14, offset=(0, 4))
        box = QVBoxLayout(card)
        box.setContentsMargins(22, 18, 22, 18)
        box.setSpacing(10)

        lbl = QLabel(heading.upper())
        lbl.setStyleSheet(f"color: {theme.c('ACCENT')}; font-size: 12px; font-weight: bold; border: none;")
        box.addWidget(lbl)

        for key, value in rows:
            row = QHBoxLayout()
            k = QLabel(key)
            k.setProperty("role", "secondary")
            v = QLabel(str(value))
            v.setStyleSheet("font-weight: 600; border: none;")
            v.setWordWrap(True)
            v.setTextInteractionFlags(Qt.TextSelectableByMouse)
            row.addWidget(k)
            row.addStretch()
            row.addWidget(v)
            box.addLayout(row)

        self.layout.addWidget(card)

    def _build_log_row(self):
        row = QHBoxLayout()
        row.addStretch()
        btn = QPushButton("  Open Log Folder")
        btn.setProperty("cls", "ghost")
        btn.setCursor(Qt.PointingHandCursor)
        iconkit.button(btn, "fa5s.folder-open", role="TEXT_PRIMARY", size=14)
        btn.clicked.connect(self._open_logs)
        row.addWidget(btn)
        self.layout.addLayout(row)

    def _open_logs(self):
        path = log_dir()
        try:
            if sys.platform.startswith("win"):
                os.startfile(path)  # noqa
            elif sys.platform == "darwin":
                subprocess.Popen(["open", path])
            else:
                subprocess.Popen(["xdg-open", path])
        except Exception:
            pass
