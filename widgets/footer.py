"""
widgets/footer.py
Minimal footer: application version, support, copyright — plus a live
activity progress indicator driven by the global busy signals.
"""

from PySide6.QtWidgets import QFrame, QHBoxLayout, QLabel, QProgressBar
from PySide6.QtCore import Qt

from core.theme import theme
from core.constants import VENDOR, APP_VERSION, APP_NAME, SUPPORT_EMAIL, APP_ARCHITECT
from core.signals import app_signals


class Footer(QFrame):
    SUPPORT = SUPPORT_EMAIL

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("FooterFrame")
        self.setFixedHeight(40)
        self._busy = 0

        layout = QHBoxLayout(self)
        layout.setContentsMargins(18, 0, 18, 0)
        layout.setSpacing(16)

        ver = QLabel(f"{APP_NAME}  {APP_VERSION}")
        ver.setProperty("role", "secondary")
        ver.setStyleSheet("font-size: 11px;")
        layout.addWidget(ver)

        sep1 = QLabel("·")
        sep1.setProperty("role", "secondary")
        layout.addWidget(sep1)

        support = QLabel(f"Support: {self.SUPPORT}")
        support.setProperty("role", "secondary")
        support.setStyleSheet("font-size: 11px;")
        layout.addWidget(support)

        sep2 = QLabel("·")
        sep2.setProperty("role", "secondary")
        layout.addWidget(sep2)

        architect = QLabel(f"App Architect: {APP_ARCHITECT}")
        architect.setProperty("role", "secondary")
        architect.setStyleSheet("font-size: 11px;")
        layout.addWidget(architect)

        layout.addStretch()

        self.progress = QProgressBar()
        self.progress.setObjectName("FooterBar")
        self.progress.setFixedSize(220, 8)
        self.progress.setTextVisible(False)
        self.progress.setRange(0, 1)
        self.progress.setValue(1)
        layout.addWidget(self.progress)

        self.dot = QLabel("\u25CF")
        self._set_dot("SUCCESS")
        layout.addWidget(self.dot)

        self.lbl_status = QLabel("Ready")
        self.lbl_status.setProperty("role", "secondary")
        self.lbl_status.setStyleSheet("font-size: 12px;")
        layout.addWidget(self.lbl_status)

        copyright_lbl = QLabel(f"  © 2026 {VENDOR}")
        copyright_lbl.setProperty("role", "secondary")
        copyright_lbl.setStyleSheet("font-size: 11px;")
        layout.addWidget(copyright_lbl)

        app_signals.busy_started.connect(self._on_busy)
        app_signals.busy_finished.connect(self._on_done)
        theme.changed.connect(lambda: self._set_dot("WARNING" if self._busy else "SUCCESS"))

    def _set_dot(self, role):
        self.dot.setStyleSheet(f"color: {theme.c(role)}; font-size: 12px;")

    def _on_busy(self, text):
        self._busy += 1
        self.lbl_status.setText(text or "Working…")
        self._set_dot("WARNING")
        self.progress.setRange(0, 0)

    def _on_done(self):
        self._busy = max(0, self._busy - 1)
        if self._busy == 0:
            self.progress.setRange(0, 1)
            self.progress.setValue(1)
            self._set_dot("SUCCESS")
            self.lbl_status.setText("Ready")
