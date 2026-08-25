"""
widgets/card.py
Reusable rounded, shadowed card frame — returns (frame, layout).
"""

from PySide6.QtWidgets import QFrame, QVBoxLayout, QLabel

from core.theme import apply_soft_shadow


def make_card(title=None, margins=(18, 16, 18, 16), spacing=12):
    frame = QFrame()
    frame.setProperty("cls", "card")
    apply_soft_shadow(frame, radius=16, offset=(0, 5))
    lay = QVBoxLayout(frame)
    lay.setContentsMargins(*margins)
    lay.setSpacing(spacing)
    if title:
        t = QLabel(title)
        t.setStyleSheet("font-size: 15px; font-weight: 700;")
        lay.addWidget(t)
    return frame, lay
