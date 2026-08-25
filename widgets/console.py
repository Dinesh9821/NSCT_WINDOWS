"""
widgets/console.py
A rich-text, themed console output widget. Styled via the global stylesheet;
status colors for inserted text are read live from the theme.
"""

from PySide6.QtWidgets import QTextEdit, QVBoxLayout, QFrame
from PySide6.QtGui import QFont, QTextCursor

try:
    from core.theme import theme, apply_soft_shadow, MONO_FONT_FAMILY
except ImportError:  # tolerate an older core/theme.py left over from a previous copy
    from core.theme import theme, apply_soft_shadow
    MONO_FONT_FAMILY = "Consolas"


class ConsoleWidget(QFrame):
    def __init__(self, parent=None, min_height=160, font_family=None):
        super().__init__(parent)
        self.setProperty("cls", "card")
        apply_soft_shadow(self, radius=14, offset=(0, 3))
        self.setMinimumHeight(min_height)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)

        self.text_edit = QTextEdit()
        self.text_edit.setObjectName("Console")
        self.text_edit.setReadOnly(True)
        self.text_edit.setFrameShape(QFrame.NoFrame)
        self.text_edit.setFont(QFont(font_family or MONO_FONT_FAMILY, 11))
        layout.addWidget(self.text_edit)

    def set_text(self, content: str, color_hex: str = None):
        self.text_edit.clear()
        self.append_text(content, color_hex)

    def append_text(self, content: str, color_hex: str = None):
        color_hex = color_hex or theme.c("TEXT_PRIMARY")
        safe = (content or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        safe = safe.replace("\n", "<br>")
        html = f"<span style='color: {color_hex};'>{safe}</span><br>"
        self.text_edit.moveCursor(QTextCursor.End)
        self.text_edit.insertHtml(html)
        self.text_edit.moveCursor(QTextCursor.End)
        self.text_edit.ensureCursorVisible()
