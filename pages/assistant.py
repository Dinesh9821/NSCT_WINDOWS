"""
pages/assistant.py
AI Assistant — dedicated conversation page.

Scrollable message bubbles with an always-visible rounded input, Send, and
Load PDF. All chat handler names and logic are unchanged (moved here intact).
"""

import requests
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame, QScrollArea,
    QLineEdit, QPushButton, QFileDialog, QTextBrowser, QSizePolicy
)
from PySide6.QtCore import Qt, QTimer

from core.theme import theme
from core import iconkit
from core.workers import WorkerManager
from core.constants import LLM_API_URL_DC, USERNAME, PASSWORD

from backend.chatbot import send_to_llm
from backend.diagnostics import (
    get_ad_username, check_internet, check_ip_type, check_default_gateway,
    check_dns_servers, check_dhcp_status, check_zscaler, get_public_ip
)

# Local network-command routing before hitting the LLM (unchanged logic).
_ROUTES = [
    (("internet",), check_internet),
    (("ip address", "my ip"), check_ip_type),
    (("gateway",), check_default_gateway),
    (("dns",), check_dns_servers),
    (("dhcp",), check_dhcp_status),
    (("zscaler",), check_zscaler),
    (("public ip",), get_public_ip),
]


def _route_or_llm(message: str) -> str:
    low = message.lower()
    for keywords, fn in _ROUTES:
        if any(k in low for k in keywords):
            return fn()
    return send_to_llm(message, get_response_only=True)


class ChatBubble(QFrame):
    def __init__(self, text: str, is_user: bool = False, parent=None):
        super().__init__(parent)
        self.setProperty("cls", "bubbleUser" if is_user else "bubbleAI")

        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 10, 14, 10)
        layout.setSpacing(4)

        sender = get_ad_username() if is_user else "Assistant"
        color = theme.c("ACCENT") if is_user else theme.c("ACCENT_2")
        lbl = QLabel(sender)
        lbl.setStyleSheet(
            f"color: {color}; font-weight: bold; font-size: 11px; border: none; background: transparent;")
        lbl.setAlignment(Qt.AlignRight if is_user else Qt.AlignLeft)
        layout.addWidget(lbl)

        self.content = QTextBrowser()
        self.content.setProperty("cls", "bubble")
        self.content.setOpenExternalLinks(True)
        self.content.setMarkdown(text)
        self.content.document().setTextWidth(680)
        doc_h = self.content.document().size().height()
        self.content.setFixedHeight(int(doc_h) + 12)
        self.content.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        layout.addWidget(self.content)


class ChatbotPage(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.workers = WorkerManager()
        self._typing = None

        root = QVBoxLayout(self)
        root.setContentsMargins(24, 22, 24, 22)
        root.setSpacing(14)

        # Header
        title_row = QHBoxLayout()
        icon = QLabel()
        iconkit.label(icon, "fa5s.robot", role="ACCENT", size=20)
        title = QLabel("AI Assistant")
        title.setProperty("role", "title")
        title.setStyleSheet("font-size: 24px; font-weight: 800;")
        title_row.addWidget(icon)
        title_row.addSpacing(8)
        title_row.addWidget(title)
        title_row.addStretch()
        root.addLayout(title_row)

        sub = QLabel("Ask about your network, or load a PDF to chat with documentation.")
        sub.setProperty("role", "subtitle")
        root.addWidget(sub)

        # Conversation card (scrollable)
        card = QFrame()
        card.setProperty("cls", "card")
        card_lay = QVBoxLayout(card)
        card_lay.setContentsMargins(12, 12, 12, 12)
        self.scroll_area = QScrollArea()
        self.scroll_area.setWidgetResizable(True)
        self.scroll_area.setFrameShape(QFrame.NoFrame)
        self.chat_container = QWidget()
        self.chat_layout = QVBoxLayout(self.chat_container)
        self.chat_layout.setAlignment(Qt.AlignTop)
        self.chat_layout.setSpacing(12)
        self.chat_layout.setContentsMargins(4, 4, 4, 4)
        self.scroll_area.setWidget(self.chat_container)
        card_lay.addWidget(self.scroll_area)
        root.addWidget(card, 1)

        # Input row (always visible, never scrolls away)
        input_row = QHBoxLayout()
        input_row.setSpacing(10)
        self.txt_input = QLineEdit()
        self.txt_input.setProperty("cls", "input")
        self.txt_input.setPlaceholderText("Type your message here…")
        self.txt_input.setFixedHeight(48)
        self.txt_input.returnPressed.connect(self._send_message)
        input_row.addWidget(self.txt_input, 1)

        self.btn_send = QPushButton("  Send")
        self.btn_send.setProperty("cls", "primary")
        self.btn_send.setFixedHeight(48)
        self.btn_send.setCursor(Qt.PointingHandCursor)
        iconkit.button(self.btn_send, "fa5s.paper-plane", role="ON_ACCENT", size=14)
        self.btn_send.clicked.connect(self._send_message)
        input_row.addWidget(self.btn_send)

        self.btn_pdf = QPushButton("  Load PDF")
        self.btn_pdf.setProperty("cls", "ghost")
        self.btn_pdf.setFixedHeight(48)
        self.btn_pdf.setCursor(Qt.PointingHandCursor)
        iconkit.button(self.btn_pdf, "fa5s.file-pdf", role="TEXT_PRIMARY", size=14)
        self.btn_pdf.clicked.connect(self._load_pdf)
        input_row.addWidget(self.btn_pdf)
        root.addLayout(input_row)

        self._add_message(
            "Hello! 👋 Ask me about your internet, DNS, DHCP, gateway, Zscaler — "
            "or anything network-related.", is_user=False)

    # --- chat handlers (unchanged logic) ----------------------------------
    def _add_message(self, text: str, is_user: bool) -> QWidget:
        row = QWidget()
        hl = QHBoxLayout(row)
        hl.setContentsMargins(0, 0, 0, 0)
        bubble = ChatBubble(text, is_user)
        if is_user:
            hl.addStretch()
            hl.addWidget(bubble, 3)
        else:
            hl.addWidget(bubble, 3)
            hl.addStretch()
        self.chat_layout.addWidget(row)
        QTimer.singleShot(80, lambda: self.scroll_area.verticalScrollBar().setValue(
            self.scroll_area.verticalScrollBar().maximum()))
        return row

    def _send_message(self):
        msg = self.txt_input.text().strip()
        if not msg:
            return
        self.txt_input.clear()
        self._add_message(msg, is_user=True)
        self._typing = self._add_message("_Thinking…_", is_user=False)

        def done(reply):
            if self._typing is not None:
                self._typing.deleteLater()
                self._typing = None
            self._add_message(reply, is_user=False)

        self.workers.run(_route_or_llm, msg, on_finished=done,
                         on_error=lambda err: done(f"**Error:** {err}"),
                         busy_text="Assistant is thinking…")

    def _load_pdf(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select PDF", "", "PDF Files (*.pdf)")
        if not file_path:
            return

        def work():
            try:
                response = requests.post(
                    f"{LLM_API_URL_DC}/load_pdf", json={"pdf_path": file_path},
                    auth=(USERNAME, PASSWORD), timeout=120)
                if response.status_code == 200:
                    return "📄 PDF loaded successfully — you can now chat with it."
                return f"⚠️ API Error: {response.text}"
            except Exception as e:
                return f"⚠️ Network Error: {e}"

        self.workers.run(work, on_finished=lambda res: self._add_message(res, is_user=False),
                         busy_text="Loading PDF…")
