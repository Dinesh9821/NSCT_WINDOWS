"""
widgets/sidebar.py
Collapsible Nord navigation: brand, pill-highlighted nav, a Dark/Light theme
toggle (above the user chip), and a user chip with avatar.
"""

import qtawesome as qta
from PySide6.QtWidgets import (
    QFrame, QVBoxLayout, QHBoxLayout, QPushButton, QSizePolicy, QWidget,
    QButtonGroup, QLabel
)
from PySide6.QtCore import QPropertyAnimation, QEasingCurve, Qt, Signal, QSize

from core.theme import theme
from core import iconkit
from core.constants import DEFAULT_ANIMATION_DURATION, APP_NAME
from widgets.avatar import Avatar
from backend.diagnostics import get_ad_username


NAV_ITEMS = [
    ("dashboard", "fa5s.th-large",           "Dashboard"),
    ("tools",     "fa5s.satellite-dish",     "Network Tools"),
    ("topology",  "fa5s.project-diagram",    "Live Topology"),
    ("health",    "fa5s.laptop-medical",     "System Health"),
    ("repair",    "fa5s.tools",              "Repair Center"),
    ("systests",  "fa5s.tachometer-alt",     "System Tests"),
    ("assistant", "fa5s.robot",              "AI Assistant"),
    ("servertest","fa5s.server",             "Server Test"),
    ("reports",   "fa5s.file-alt",           "Reports"),
    ("settings",  "fa5s.cog",                "Settings"),
]


class Sidebar(QFrame):
    page_selected = Signal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("SidebarFrame")

        self.expanded_width = 236
        self.collapsed_width = 74
        self.is_expanded = True
        self._buttons = {}
        self._collapsibles = []

        self.setMinimumWidth(self.expanded_width)
        self.setMaximumWidth(self.expanded_width)

        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(14, 18, 14, 16)
        self.layout.setSpacing(6)

        self._build_brand()
        self.layout.addSpacing(8)

        self.btn_group = QButtonGroup(self)
        self.btn_group.setExclusive(True)
        self._setup_navigation()

        spacer = QWidget()
        spacer.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self.layout.addWidget(spacer)

        self._build_theme_toggle()
        self._build_user_chip()

        self.animation = QPropertyAnimation(self, b"maximumWidth")
        self.animation.setDuration(DEFAULT_ANIMATION_DURATION)
        self.animation.setEasingCurve(QEasingCurve.InOutQuart)
        self.animation.valueChanged.connect(lambda w: self.setMinimumWidth(int(w)))

        theme.changed.connect(self._restyle_nav_icons)
        theme.changed.connect(self._update_theme_button)

    def _build_brand(self):
        row = QHBoxLayout()
        row.setContentsMargins(6, 0, 6, 0)
        row.setSpacing(10)
        logo = QLabel()
        iconkit.label(logo, "fa5s.wifi", role="ACCENT", size=24)
        row.addWidget(logo)
        name = QLabel(APP_NAME)
        name.setStyleSheet("font-size: 16px; font-weight: 800;")
        row.addWidget(name)
        row.addStretch()
        wrap = QWidget()
        wrap.setLayout(row)
        self.layout.addWidget(wrap)
        self._collapsibles.append(name)

    def _setup_navigation(self):
        for i, (page_id, icon_name, label_text) in enumerate(NAV_ITEMS):
            btn = QPushButton(f"   {label_text}")
            btn.setObjectName("NavButton")
            btn.setCheckable(True)
            btn.setFixedHeight(46)
            btn.setCursor(Qt.PointingHandCursor)
            btn.setProperty("label_text", label_text)
            iconkit.button(btn, icon_name, role="TEXT_SECONDARY", size=24)
            btn.clicked.connect(lambda checked, pid=page_id: self.page_selected.emit(pid))
            self.btn_group.addButton(btn, i)
            self.layout.addWidget(btn)
            self._buttons[page_id] = btn
            if i == 0:
                btn.setChecked(True)
        self._restyle_nav_icons()

    def _build_theme_toggle(self):
        self.btn_theme = QPushButton()
        self.btn_theme.setObjectName("ThemeToggle")
        self.btn_theme.setFixedHeight(42)
        self.btn_theme.setCursor(Qt.PointingHandCursor)
        self.btn_theme.clicked.connect(theme.toggle)
        self.layout.addWidget(self.btn_theme)
        self._update_theme_button()

    def _update_theme_button(self):
        dark = theme.mode == "dark"
        glyph = "fa5s.moon" if dark else "fa5s.sun"
        self.btn_theme.setIcon(qta.icon(glyph, color=theme.c("ACCENT")))
        self.btn_theme.setIconSize(QSize(16, 16))
        self.btn_theme.setText(("  Dark Mode" if dark else "  Light Mode")
                               if self.is_expanded else "")
        self.btn_theme.setToolTip("Switch to Light theme" if dark else "Switch to Dark theme")

    def _build_user_chip(self):
        chip = QFrame()
        chip.setProperty("cls", "chip")
        row = QHBoxLayout(chip)
        row.setContentsMargins(8, 7, 10, 7)
        row.setSpacing(10)
        username = get_ad_username()
        row.addWidget(Avatar(username, size=34))
        self.user_name = QLabel(username)
        self.user_name.setStyleSheet("border: none; font-weight: 700;")
        row.addWidget(self.user_name, 1)
        chevron = QLabel()
        iconkit.label(chevron, "fa5s.chevron-right", role="TEXT_SECONDARY", size=11)
        row.addWidget(chevron)
        self.layout.addSpacing(4)
        self.layout.addWidget(chip)
        self._collapsibles.append(self.user_name)
        self._collapsibles.append(chevron)

    def _restyle_nav_icons(self):
        for pid, btn in self._buttons.items():
            iconkit.set_role(btn, "ON_ACCENT" if btn.isChecked() else "TEXT_SECONDARY")

    # --- public API --------------------------------------------------------
    def select_page(self, page_id: str):
        btn = self._buttons.get(page_id)
        if btn:
            btn.setChecked(True)
            self._restyle_nav_icons()

    def toggle_state(self):
        self.is_expanded = not self.is_expanded
        target = self.expanded_width if self.is_expanded else self.collapsed_width
        for btn in self.btn_group.buttons():
            label = btn.property("label_text") or ""
            btn.setText(f"   {label}" if self.is_expanded else "")
            btn.setToolTip("" if self.is_expanded else label)
        for w in self._collapsibles:
            w.setVisible(self.is_expanded)
        self._update_theme_button()
        self.animation.stop()
        self.animation.setStartValue(self.width())
        self.animation.setEndValue(target)
        self.animation.start()
