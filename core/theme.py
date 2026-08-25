"""
core/theme.py
Nord theming engine with a working Dark / Light toggle.

Palettes follow the official Nord spec:
    Polar Night : nord0-3   (dark surfaces)
    Snow Storm  : nord4-6   (light surfaces)
    Frost       : nord7-10  (primary accents)
    Aurora      : nord11-15 (state colors)

`theme` is a singleton. Widgets that paint with QPainter read live values via
`theme.c(key)` and repaint on `theme.changed`. Everything else is styled by the
global stylesheet returned by `theme.qss()`, which is re-applied on toggle.
"""

from PySide6.QtCore import QObject, Signal
from PySide6.QtGui import QColor
from PySide6.QtWidgets import QGraphicsDropShadowEffect
import sys


# --- platform-native fonts --------------------------------------------------
if sys.platform.startswith("win"):
    UI_FONTS = '"Segoe UI Variable Text", "Segoe UI", "Inter", sans-serif'
    MONO_FONTS = '"Cascadia Mono", "Consolas", monospace'
    UI_FONT_FAMILY = "Segoe UI"
    MONO_FONT_FAMILY = "Consolas"
elif sys.platform == "darwin":
    UI_FONTS = '"SF Pro Text", "Helvetica Neue", "Segoe UI", sans-serif'
    MONO_FONTS = '"Menlo", "SF Mono", "Consolas", monospace'
    UI_FONT_FAMILY = "Helvetica Neue"
    MONO_FONT_FAMILY = "Menlo"
else:
    UI_FONTS = '"Inter", "DejaVu Sans", sans-serif'
    MONO_FONTS = '"DejaVu Sans Mono", monospace'
    UI_FONT_FAMILY = "DejaVu Sans"
    MONO_FONT_FAMILY = "DejaVu Sans Mono"


# --- raw Nord palette -------------------------------------------------------
NORD = {
    "n0": "#2E3440", "n1": "#3B4252", "n2": "#434C5E", "n3": "#4C566A",
    "n4": "#D8DEE9", "n5": "#E5E9F0", "n6": "#ECEFF4",
    "n7": "#8FBCBB", "n8": "#88C0D0", "n9": "#81A1C1", "n10": "#5E81AC",
    "n11": "#BF616A", "n12": "#D08770", "n13": "#EBCB8B", "n14": "#A3BE8C", "n15": "#B48EAD",
}

_DARK = {
    "BACKGROUND":     NORD["n0"],     # Polar Night
    "BG_GRAD_END":    NORD["n0"],     # no gradient - flat Nord surface
    "CARD_BG":        NORD["n1"],
    "ELEVATED":       NORD["n2"],
    "BORDER":         "#39414F",
    "TEXT_PRIMARY":   NORD["n6"],
    "TEXT_SECONDARY": "#AEB6C4",
    "ACCENT":         NORD["n8"],      # frost cyan
    "ACCENT_ALT":     NORD["n7"],
    "ACCENT_2":       NORD["n15"],     # aurora purple
    "ON_ACCENT":      NORD["n0"],      # dark text on light frost
    "SUCCESS":        NORD["n14"],
    "WARNING":        NORD["n13"],
    "ERROR":          NORD["n11"],
    "INFO":           NORD["n9"],
    "HOVER_BG":       NORD["n2"],
    "BUBBLE_USER":    "#3B4657",
    "BUBBLE_AI":      NORD["n2"],
    "SHADOW":         120,
}

_LIGHT = {
    "BACKGROUND":     NORD["n6"],
    "BG_GRAD_END":    NORD["n6"],
    "CARD_BG":        "#FFFFFF",
    "ELEVATED":       NORD["n5"],
    "BORDER":         NORD["n4"],
    "TEXT_PRIMARY":   NORD["n0"],
    "TEXT_SECONDARY": NORD["n3"],
    "ACCENT":         NORD["n10"],     # deeper frost reads better on light
    "ACCENT_ALT":     NORD["n9"],
    "ACCENT_2":       NORD["n15"],
    "ON_ACCENT":      NORD["n6"],
    "SUCCESS":        "#6E8B54",
    "WARNING":        "#B58900",
    "ERROR":          NORD["n11"],
    "INFO":           NORD["n10"],
    "HOVER_BG":       NORD["n5"],
    "BUBBLE_USER":    "#E3EAF3",
    "BUBBLE_AI":      NORD["n5"],
    "SHADOW":         40,
}

# Backwards-compat: some code references PURPLE_ACCENT.
for _p in (_DARK, _LIGHT):
    _p["PURPLE_ACCENT"] = _p["ACCENT_2"]


_QSS_TEMPLATE = """
* {{ outline: none; }}
QWidget {{
    background: transparent;
    color: {TEXT_PRIMARY};
    font-family: {UI_FONTS};
    font-size: 13px;
}}
QMainWindow {{
    background-color: {BACKGROUND};
}}
#MainContentWrapper, QStackedWidget, QStackedWidget > QWidget {{
    background: transparent;
}}
QScrollArea {{ background: transparent; border: none; }}
QToolTip {{
    background-color: {ELEVATED}; color: {TEXT_PRIMARY};
    border: 1px solid {BORDER}; border-radius: 8px; padding: 6px 8px;
}}

/* Cards & panels */
QFrame[cls="card"] {{
    background-color: {CARD_BG}; border: 1px solid {BORDER}; border-radius: 16px;
}}
QFrame[cls="statcard"] {{
    background-color: {CARD_BG}; border: 1px solid {BORDER}; border-radius: 16px;
}}
#SidebarFrame {{ background-color: {CARD_BG}; border: 1px solid {BORDER}; border-radius: 20px; }}
#HeaderFrame  {{ background-color: {CARD_BG}; border: 1px solid {BORDER}; border-radius: 16px; }}
#FooterFrame  {{ background-color: {CARD_BG}; border: 1px solid {BORDER}; border-radius: 14px; }}

/* Text roles */
QLabel[role="title"]     {{ color: {TEXT_PRIMARY}; font-size: 20px; font-weight: 800; letter-spacing: 0.5px; }}
QLabel[role="subtitle"]  {{ color: {TEXT_SECONDARY}; font-size: 13px; }}
QLabel[role="secondary"] {{ color: {TEXT_SECONDARY}; }}
QLabel[role="cardtitle"] {{ color: {TEXT_SECONDARY}; font-size: 11px; font-weight: bold; letter-spacing: 0.8px; }}
QLabel[role="value"]     {{ color: {TEXT_PRIMARY}; font-size: 22px; font-weight: 800; letter-spacing: 0.5px; }}
QLabel[role="mono"]      {{ color: {TEXT_SECONDARY}; font-family: {MONO_FONTS}; }}

/* Navigation */
QPushButton#NavButton {{
    text-align: left; padding-left: 14px; border: none; border-radius: 12px;
    background-color: transparent; color: {TEXT_SECONDARY}; font-weight: 600; font-size: 14px;
}}
QPushButton#NavButton:hover {{ background-color: {HOVER_BG}; color: {TEXT_PRIMARY}; }}
QPushButton#NavButton:checked {{ background-color: {ACCENT}; color: {ON_ACCENT}; font-weight: 700; }}

/* Buttons */
QPushButton[cls="primary"] {{
    background-color: {ACCENT}; color: {ON_ACCENT}; border: none; border-radius: 12px;
    padding: 10px 18px; font-weight: 700; font-size: 13px;
}}
QPushButton[cls="primary"]:hover {{ background-color: {ACCENT_ALT}; }}
QPushButton[cls="primary"]:disabled {{ background-color: {BORDER}; color: {TEXT_SECONDARY}; }}

QPushButton[cls="ghost"] {{
    background-color: {CARD_BG}; color: {TEXT_PRIMARY}; border: 1px solid {BORDER};
    border-radius: 12px; padding: 10px 16px; font-weight: 600; font-size: 13px;
}}
QPushButton[cls="ghost"]:hover {{ background-color: {HOVER_BG}; border: 1px solid {ACCENT}; }}
QPushButton[cls="ghost"]:disabled {{ color: {TEXT_SECONDARY}; }}

QPushButton[cls="iconbtn"] {{ background-color: transparent; border: none; border-radius: 10px; }}
QPushButton[cls="iconbtn"]:hover {{ background-color: {HOVER_BG}; }}

/* Sidebar Dark/Light toggle */
QPushButton#ThemeToggle {{
    text-align: left; padding-left: 12px; border: 1px solid {BORDER}; border-radius: 12px;
    background-color: {ELEVATED}; color: {TEXT_PRIMARY}; font-weight: 600; font-size: 13px;
}}
QPushButton#ThemeToggle:hover {{ border: 1px solid {ACCENT}; background-color: {HOVER_BG}; }}

/* Inputs */
QLineEdit[cls="input"] {{
    background-color: {ELEVATED}; border: 1px solid {BORDER}; border-radius: 12px;
    padding: 0 14px; color: {TEXT_PRIMARY}; selection-background-color: {ACCENT};
}}
QLineEdit[cls="input"]:focus {{ border: 1px solid {ACCENT}; }}
QLineEdit#Search {{
    background-color: {ELEVATED}; border: 1px solid {BORDER}; border-radius: 18px;
    padding: 0 16px; color: {TEXT_PRIMARY};
}}
QLineEdit#Search:focus {{ border: 1px solid {ACCENT}; }}

/* Console / bubbles */
QTextEdit#Console {{ background: transparent; border: none; color: {TEXT_PRIMARY};
    selection-background-color: {ACCENT}; }}
QFrame[cls="bubbleUser"] {{ background-color: {BUBBLE_USER}; border: 1px solid {ACCENT}; border-radius: 14px; }}
QFrame[cls="bubbleAI"]   {{ background-color: {BUBBLE_AI};   border: 1px solid {BORDER}; border-radius: 14px; }}
QTextBrowser[cls="bubble"] {{ background: transparent; border: none; color: {TEXT_PRIMARY}; font-size: 13px; }}

/* Chips */
QFrame[cls="chip"], QLabel[cls="chip"] {{
    background-color: {ELEVATED}; border: 1px solid {BORDER}; border-radius: 16px; color: {TEXT_SECONDARY};
}}

/* Thin progress bars used in stat cards */
QProgressBar[cls="thin"] {{ background-color: {ELEVATED}; border: none; border-radius: 4px; }}
QProgressBar[cls="thin"]::chunk {{ background-color: {ACCENT}; border-radius: 4px; }}

/* Footer progress */
QProgressBar#FooterBar {{ background-color: {ELEVATED}; border: 1px solid {BORDER}; border-radius: 4px; }}
QProgressBar#FooterBar::chunk {{ background-color: {ACCENT}; border-radius: 4px; }}

/* Scrollbars */
QScrollBar:vertical {{ background: transparent; width: 10px; margin: 2px; border-radius: 5px; }}
QScrollBar::handle:vertical {{ background: {BORDER}; border-radius: 5px; min-height: 30px; }}
QScrollBar::handle:vertical:hover {{ background: {ACCENT}; }}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0; }}
QScrollBar:horizontal {{ background: transparent; height: 10px; margin: 2px; border-radius: 5px; }}
QScrollBar::handle:horizontal {{ background: {BORDER}; border-radius: 5px; min-width: 30px; }}
QScrollBar::handle:horizontal:hover {{ background: {ACCENT}; }}
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{ width: 0; }}
"""


class Theme(QObject):
    changed = Signal()

    def __init__(self):
        super().__init__()
        self._mode = "dark"

    @property
    def mode(self):
        return self._mode

    def palette(self):
        return _DARK if self._mode == "dark" else _LIGHT

    def c(self, key):
        return self.palette()[key]

    def set_mode(self, mode):
        mode = "light" if mode == "light" else "dark"
        if mode != self._mode:
            self._mode = mode
            self.changed.emit()

    def toggle(self):
        self.set_mode("light" if self._mode == "dark" else "dark")

    def qss(self):
        return _QSS_TEMPLATE.format(UI_FONTS=UI_FONTS, MONO_FONTS=MONO_FONTS, **self.palette())


theme = Theme()


def apply_soft_shadow(widget, radius=20, offset=(0, 6), opacity=None):
    shadow = QGraphicsDropShadowEffect(widget)
    shadow.setBlurRadius(radius)
    shadow.setXOffset(offset[0])
    shadow.setYOffset(offset[1])
    op = theme.c("SHADOW") if opacity is None else opacity
    shadow.setColor(QColor(0, 0, 0, op))
    widget.setGraphicsEffect(shadow)
    return shadow
