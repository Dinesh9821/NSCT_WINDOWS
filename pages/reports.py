"""
pages/reports.py
Consolidated diagnostics report (checks + raw command outputs), exportable
to a text file. UI restyled to Nord; generation logic is unchanged.
"""

import datetime
import socket

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QFileDialog
)
from PySide6.QtCore import Qt

from widgets.console import ConsoleWidget
from core.theme import theme
from core import iconkit
from core.workers import WorkerManager
from core.constants import APP_NAME, APP_VERSION, VENDOR
from backend.diagnostics import (
    get_ad_username, get_local_ip, check_system_restart, run_command,
    check_ip_type, check_internet, check_default_gateway, check_dns_servers,
    check_dhcp_status, check_zscaler, get_ip_location, get_public_ip,
    network_quality, REPORT_COMMANDS
)

SUMMARY_CHECKS = [
    ("LAN / WiFi", check_ip_type),
    ("Internet", check_internet),
    ("Default Gateway", check_default_gateway),
    ("DNS Servers", check_dns_servers),
    ("DHCP Status", check_dhcp_status),
    ("Zscaler", check_zscaler),
    ("IP Location", get_ip_location),
    ("Public IP", get_public_ip),
]


class ReportsPage(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.workers = WorkerManager()
        self._report_text = ""

        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(24, 22, 24, 22)
        self.layout.setSpacing(16)

        self._build_header()
        self.console = ConsoleWidget(self, min_height=200)
        self.console.set_text(
            "Press 'Generate Report' to run a full diagnostic sweep, including "
            "ipconfig /all, routing table, ARP cache, DNS, and connectivity tests.",
            theme.c("TEXT_SECONDARY"))
        self.layout.addWidget(self.console, 1)

    def _build_header(self):
        header = QHBoxLayout()
        titles = QVBoxLayout()
        titles.setSpacing(2)
        title = QLabel("Diagnostic Reports")
        title.setProperty("role", "title")
        title.setStyleSheet("font-size: 24px; font-weight: 800;")
        sub = QLabel("Full system + network sweep, exportable for support tickets.")
        sub.setProperty("role", "subtitle")
        titles.addWidget(title)
        titles.addWidget(sub)
        header.addLayout(titles)
        header.addStretch()

        self.btn_generate = QPushButton("  Generate Report")
        self.btn_generate.setProperty("cls", "primary")
        self.btn_generate.setCursor(Qt.PointingHandCursor)
        iconkit.button(self.btn_generate, "fa5s.play", role="ON_ACCENT", size=13)
        self.btn_generate.clicked.connect(self._generate)
        header.addWidget(self.btn_generate)

        self.btn_save = QPushButton("  Save Report")
        self.btn_save.setProperty("cls", "ghost")
        self.btn_save.setCursor(Qt.PointingHandCursor)
        iconkit.button(self.btn_save, "fa5s.download", role="TEXT_PRIMARY", size=13)
        self.btn_save.setEnabled(False)
        self.btn_save.clicked.connect(self._save)
        header.addWidget(self.btn_save)

        self.btn_pdf = QPushButton("  Export PDF")
        self.btn_pdf.setProperty("cls", "ghost")
        self.btn_pdf.setCursor(Qt.PointingHandCursor)
        iconkit.button(self.btn_pdf, "fa5s.file-pdf", role="TEXT_PRIMARY", size=13)
        self.btn_pdf.setEnabled(False)
        self.btn_pdf.clicked.connect(self._export_pdf)
        header.addWidget(self.btn_pdf)

        self.layout.addLayout(header)

    # --- generation (unchanged logic) -------------------------------------
    def _generate(self):
        self.btn_generate.setEnabled(False)
        self.btn_save.setEnabled(False)
        self.btn_pdf.setEnabled(False)
        self.console.set_text("Generating full diagnostic report…\n"
                              "(collecting command outputs — this may take a moment)\n\n",
                              theme.c("ACCENT"))
        self.workers.run(self._collect, on_finished=self._done,
                         on_error=lambda err: self._done(f"Error generating report: {err}"),
                         busy_text="Generating report…")

    def _collect(self):
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        q = network_quality()
        lines = [
            "=" * 68,
            f"{APP_NAME} {APP_VERSION} — Diagnostic Report",
            f"Vendor : {VENDOR}",
            f"Date   : {now}",
            f"Host   : {socket.gethostname()}    User: {get_ad_username()}    "
            f"Local IP: {get_local_ip()}",
            "=" * 68,
            "",
            "-" * 68,
            "SECTION 1 — SYSTEM & CONNECTION SUMMARY",
            "-" * 68,
            f"[System Uptime]\n{check_system_restart()}",
            "",
            f"[Network Quality]\n"
            f"Latency (avg): {q.get('latency_ms')} ms   "
            f"Min/Max: {q.get('min_ms')}/{q.get('max_ms')} ms   "
            f"Jitter: {q.get('jitter_ms')} ms   "
            f"Packet Loss: {q.get('loss_pct')}%",
            "",
        ]
        for label, fn in SUMMARY_CHECKS:
            try:
                result = fn()
            except Exception as e:
                result = f"Error: {e}"
            lines.append(f"[{label}]\n{result}\n")

        lines += ["", "-" * 68,
                  "SECTION 2 — RAW COMMAND OUTPUTS",
                  "-" * 68, ""]
        for label, command in REPORT_COMMANDS:
            lines.append(f"$ {label}")
            lines.append("." * 68)
            try:
                output = run_command(command, timeout=90)
            except Exception as e:
                output = f"Error: {e}"
            lines.append(output)
            lines.append("")

        lines.append("=" * 68)
        lines.append("END OF REPORT")
        lines.append("=" * 68)
        return "\n".join(lines)

    def _done(self, text):
        self._report_text = text
        self.console.set_text(text, theme.c("TEXT_PRIMARY"))
        self.btn_generate.setEnabled(True)
        ready = bool(text) and not text.startswith("Error")
        self.btn_save.setEnabled(ready)
        self.btn_pdf.setEnabled(ready)

    def _save(self):
        default = f"network_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        path, _ = QFileDialog.getSaveFileName(self, "Save Report", default, "Text Files (*.txt)")
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(self._report_text)
            self.console.append_text(f"\n✔ Report saved to: {path}", theme.c("SUCCESS"))
        except Exception as e:
            self.console.append_text(f"\n✘ Save failed: {e}", theme.c("ERROR"))

    def _export_pdf(self):
        if not self._report_text or self._report_text.startswith("Error"):
            return
        default = f"network_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        path, _ = QFileDialog.getSaveFileName(self, "Export PDF", default, "PDF Files (*.pdf)")
        if not path:
            return
        meta = [
            f"{APP_NAME}  {APP_VERSION}",
            f"Vendor: {VENDOR}",
            f"Host: {socket.gethostname()}",
            f"Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        ]
        try:
            from backend.report_export import text_report_to_pdf
            text_report_to_pdf(self._report_text, path, "Network Diagnostic Report", meta)
            self.console.append_text(f"\n✔ PDF exported to: {path}", theme.c("SUCCESS"))
        except ImportError:
            self.console.append_text(
                "\n✘ PDF export needs the 'fpdf2' package (pip install fpdf2).",
                theme.c("ERROR"))
        except Exception as e:
            self.console.append_text(f"\n✘ PDF export failed: {e}", theme.c("ERROR"))
