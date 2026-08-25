"""
pages/server_test.py

Server Test - answers three questions for any host/port:

    1. Is the server reachable?          (DNS + ICMP ping + TCP handshake)
    2. Is the port actually open?        (Python socket connect + `nc` / PowerShell)
    3. Is a firewall blocking it?        (open vs refused vs filtered, plus the
                                          local firewall state)

The open/refused/filtered distinction is the useful part:
    open      -> handshake completed; nothing is blocking you.
    refused   -> host answered with RST: the host is UP and reachable, but no
                 service is listening. This is NOT a firewall block.
    filtered  -> no answer at all before timeout: a firewall/ACL is most likely
                 silently dropping the packets.

macOS-first (nc, lsof, socketfilterfw, pfctl) with Windows equivalents
(Test-NetConnection, netstat, netsh advfirewall).

Self-contained page: it only reuses run_command / IS_WINDOWS / IS_MAC from the
backend and does not modify any backend logic.
"""

import os
import sys
import subprocess

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGridLayout, QLabel, QLineEdit, QPushButton,
    QFrame, QComboBox, QScrollArea, QTableWidget, QTableWidgetItem, QHeaderView,
    QAbstractItemView,
)
from PySide6.QtCore import Qt
from PySide6.QtGui import QColor

from core.theme import theme, apply_soft_shadow
from core import iconkit
from core.workers import WorkerManager
from widgets.console import ConsoleWidget
from backend.diagnostics import run_command, IS_WINDOWS, IS_MAC, get_local_ip
from backend.server_checks import (
    verdict_for, local_firewall_status, local_listening_ports,
)
from core.constants import capture_dir


def _run_verified(host, ports_text, proto, timeout):
    """Background entry: capture + diagnose + analyze + Verification API."""
    from backend.network_verify import run_verified_server_test
    return run_verified_server_test(host, ports_text, proto=proto, timeout=timeout)

# =========================================================================== #
#  Page
# =========================================================================== #
class ServerTestPage(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.workers = WorkerManager()

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        content = QWidget()
        self.body = QVBoxLayout(content)
        self.body.setContentsMargins(24, 22, 24, 22)
        self.body.setSpacing(14)

        title = QLabel("Server Test")
        title.setProperty("role", "title")
        title.setStyleSheet("font-size: 24px; font-weight: 800;")
        sub = QLabel("Check whether a server is reachable, whether a port is open, "
                     "and whether a firewall is blocking it. Each run captures live "
                     "packets as Wireshark-compatible evidence and sends them for verification.")
        sub.setProperty("role", "subtitle")
        sub.setWordWrap(True)
        self.body.addWidget(title)
        self.body.addWidget(sub)

        self._build_inputs()
        self._build_summary()
        self._build_results()
        self._build_console()
        self.body.addStretch()

        scroll.setWidget(content)
        outer.addWidget(scroll)

        theme.changed.connect(self._on_theme)

    # ----------------------------------------------------------- building
    def _card(self, title_text):
        frame = QFrame()
        frame.setProperty("cls", "card")
        apply_soft_shadow(frame, radius=16, offset=(0, 5))
        lay = QVBoxLayout(frame)
        lay.setContentsMargins(18, 16, 18, 16)
        lay.setSpacing(12)
        if title_text:
            cap = QLabel(title_text)
            cap.setProperty("role", "cardtitle")
            lay.addWidget(cap)
        return frame, lay

    def _build_inputs(self):
        frame, lay = self._card("TARGET")
        grid = QGridLayout()
        grid.setHorizontalSpacing(12)
        grid.setVerticalSpacing(8)

        lbl_host = QLabel("Host / IP")
        lbl_host.setProperty("role", "secondary")
        self.txt_host = QLineEdit("google.com")
        self.txt_host.setProperty("cls", "input")
        self.txt_host.setFixedHeight(42)
        self.txt_host.setPlaceholderText("hostname or IP (e.g. 192.168.1.10 or api.example.com)")
        self.txt_host.returnPressed.connect(self._run)

        lbl_port = QLabel("Port(s)")
        lbl_port.setProperty("role", "secondary")
        self.txt_ports = QLineEdit("443, 80")
        self.txt_ports.setProperty("cls", "input")
        self.txt_ports.setFixedHeight(42)
        self.txt_ports.setPlaceholderText("443  |  80,443,22  |  8080-8090")
        self.txt_ports.returnPressed.connect(self._run)

        lbl_proto = QLabel("Protocol")
        lbl_proto.setProperty("role", "secondary")
        self.cmb_proto = QComboBox()
        self.cmb_proto.addItems(["TCP", "UDP", "ICMP"])
        self.cmb_proto.setFixedHeight(42)
        self.cmb_proto.setStyleSheet(self._combo_style())

        lbl_to = QLabel("Timeout")
        lbl_to.setProperty("role", "secondary")
        self.cmb_timeout = QComboBox()
        self.cmb_timeout.addItems(["2 s", "3 s", "5 s", "10 s"])
        self.cmb_timeout.setCurrentIndex(1)
        self.cmb_timeout.setFixedHeight(42)
        self.cmb_timeout.setStyleSheet(self._combo_style())

        grid.addWidget(lbl_host, 0, 0)
        grid.addWidget(lbl_port, 0, 1)
        grid.addWidget(lbl_proto, 0, 2)
        grid.addWidget(lbl_to, 0, 3)
        grid.addWidget(self.txt_host, 1, 0)
        grid.addWidget(self.txt_ports, 1, 1)
        grid.addWidget(self.cmb_proto, 1, 2)
        grid.addWidget(self.cmb_timeout, 1, 3)
        grid.setColumnStretch(0, 3)
        grid.setColumnStretch(1, 2)
        lay.addLayout(grid)

        self.lbl_source = QLabel("Source: {}".format(get_local_ip()))
        self.lbl_source.setProperty("role", "secondary")
        lay.addWidget(self.lbl_source)

        row = QHBoxLayout()
        row.setSpacing(10)
        self.btn_run = QPushButton("  Run Server Test")
        self.btn_run.setProperty("cls", "primary")
        self.btn_run.setFixedHeight(44)
        self.btn_run.setCursor(Qt.PointingHandCursor)
        iconkit.button(self.btn_run, "fa5s.server", role="ON_ACCENT", size=14)
        self.btn_run.clicked.connect(self._run)
        row.addWidget(self.btn_run)

        self.btn_fw = QPushButton("  Local Firewall & Listening Ports")
        self.btn_fw.setProperty("cls", "ghost")
        self.btn_fw.setFixedHeight(44)
        self.btn_fw.setCursor(Qt.PointingHandCursor)
        iconkit.button(self.btn_fw, "fa5s.shield-alt", role="ACCENT", size=14)
        self.btn_fw.clicked.connect(self._run_firewall)
        row.addWidget(self.btn_fw)
        self.btn_caps = QPushButton("  Open Captures")
        self.btn_caps.setProperty("cls", "ghost")
        self.btn_caps.setFixedHeight(44)
        self.btn_caps.setCursor(Qt.PointingHandCursor)
        iconkit.button(self.btn_caps, "fa5s.folder-open", role="ACCENT", size=14)
        self.btn_caps.clicked.connect(self._open_captures)
        row.addWidget(self.btn_caps)
        self.btn_admin = QPushButton("  Restart as Administrator")
        self.btn_admin.setProperty("cls", "ghost")
        self.btn_admin.setFixedHeight(44)
        self.btn_admin.setCursor(Qt.PointingHandCursor)
        iconkit.button(self.btn_admin, "fa5s.lock", role="ACCENT", size=14)
        self.btn_admin.clicked.connect(self._restart_admin)
        row.addWidget(self.btn_admin)
        row.addStretch()
        lay.addLayout(row)

        self.body.addWidget(frame)
        self._refresh_admin_hint()

    def _build_summary(self):
        frame, lay = self._card("VERDICT")
        self.lbl_verdict = QLabel("Run a test to see whether the server and port are reachable.")
        self.lbl_verdict.setWordWrap(True)
        self.lbl_verdict.setStyleSheet("font-size: 15px; font-weight: 700;")
        self.lbl_detail = QLabel("")
        self.lbl_detail.setProperty("role", "secondary")
        self.lbl_detail.setWordWrap(True)
        lay.addWidget(self.lbl_verdict)
        lay.addWidget(self.lbl_detail)
        self.body.addWidget(frame)

    def _build_results(self):
        frame, lay = self._card("PORT RESULTS")
        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(["Port", "State", "Time", "What it means"])
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setAlternatingRowColors(True)
        self.table.setShowGrid(False)
        self.table.setMinimumHeight(140)
        hh = self.table.horizontalHeader()
        hh.setStretchLastSection(True)
        hh.setSectionResizeMode(3, QHeaderView.Stretch)
        self._style_table()
        lay.addWidget(self.table)
        self.body.addWidget(frame)

    def _build_console(self):
        frame, lay = self._card("COMMAND OUTPUT")
        self.console = ConsoleWidget(self, min_height=220)
        self.console.set_text(
            "Raw output from ping, {} and the firewall commands appears here."
            .format("Test-NetConnection" if IS_WINDOWS else "nc"),
            theme.c("TEXT_SECONDARY"))
        lay.addWidget(self.console)
        self.body.addWidget(frame)

    # ----------------------------------------------------------- styling
    def _combo_style(self):
        return ("QComboBox {{ background-color: {elev}; color: {fg};"
                " border: 1px solid {bd}; border-radius: 10px; padding: 6px 12px; }}"
                "QComboBox:hover {{ border: 1px solid {acc}; }}"
                "QComboBox QAbstractItemView {{ background-color: {card}; color: {fg};"
                " selection-background-color: {acc}; selection-color: {on};"
                " border: 1px solid {bd}; outline: none; }}"
                ).format(elev=theme.c("ELEVATED"), fg=theme.c("TEXT_PRIMARY"),
                         bd=theme.c("BORDER"), acc=theme.c("ACCENT"),
                         card=theme.c("CARD_BG"), on=theme.c("ON_ACCENT"))

    def _style_table(self):
        self.table.setStyleSheet(
            "QTableWidget {{ background-color: {card}; alternate-background-color: {elev};"
            " color: {fg}; border: 1px solid {bd}; border-radius: 12px;"
            " gridline-color: {bd}; }}"
            "QTableWidget::item {{ padding: 6px 8px; border: none; }}"
            "QTableWidget::item:selected {{ background-color: {acc}; color: {on}; }}"
            "QHeaderView::section {{ background-color: {elev}; color: {sec};"
            " padding: 7px; border: none; font-weight: bold; }}"
            .format(card=theme.c("CARD_BG"), elev=theme.c("ELEVATED"),
                    fg=theme.c("TEXT_PRIMARY"), bd=theme.c("BORDER"),
                    acc=theme.c("ACCENT"), on=theme.c("ON_ACCENT"),
                    sec=theme.c("TEXT_SECONDARY")))

    def _on_theme(self):
        self.cmb_proto.setStyleSheet(self._combo_style())
        self.cmb_timeout.setStyleSheet(self._combo_style())
        self._style_table()

    # ----------------------------------------------------------- handlers
    def _timeout_value(self):
        try:
            return float(self.cmb_timeout.currentText().split()[0])
        except Exception:
            return 3.0

    def _run(self):
        host = self.txt_host.text().strip()
        if not host:
            self.lbl_verdict.setText("Enter a hostname or IP first.")
            return
        self.btn_run.setEnabled(False)
        self.lbl_verdict.setText("Testing {}\u2026".format(host))
        self.lbl_detail.setText("")
        self.console.set_text("Running checks against {}\u2026".format(host), theme.c("ACCENT"))
        self.workers.run(
            _run_verified, host, self.txt_ports.text(),
            self.cmb_proto.currentText(), self._timeout_value(),
            on_finished=self._done,
            on_error=lambda e: self._failed(str(e)),
            busy_text="Testing {}\u2026".format(host))

    def _failed(self, message):
        self.btn_run.setEnabled(True)
        self.lbl_verdict.setText("Test failed")
        self.lbl_verdict.setStyleSheet(
            "font-size: 15px; font-weight: 700; color: {};".format(theme.c("ERROR")))
        self.lbl_detail.setText(message)

    def _done(self, res):
        self.btn_run.setEnabled(True)
        res = res or {}
        if res.get("error"):
            self._failed(res["error"])
            return

        dns = res.get("dns") or {}
        ping = res.get("ping") or {}
        ports = res.get("ports") or []

        # ---- port table ----
        self.table.setRowCount(len(ports))
        for r, p in enumerate(ports):
            text, key = verdict_for(p["state"])
            cells = [str(p["port"]), p["state"].upper(),
                     "{} ms".format(p["ms"]) if p.get("ms") is not None else "\u2014",
                     p.get("detail", "")]
            for c, v in enumerate(cells):
                item = QTableWidgetItem(v)
                if c == 1:
                    item.setForeground(QColor(theme.c(key)))
                self.table.setItem(r, c, item)

        # ---- verdict ----
        open_ports = [p["port"] for p in ports if p["state"] == "open"]
        filtered = [p["port"] for p in ports if p["state"] == "filtered"]
        closed = [p["port"] for p in ports if p["state"] == "closed"]

        if not dns.get("ok"):
            headline, key = "Hostname could not be resolved", "ERROR"
            detail = "DNS lookup failed: {}. Check the name or your DNS settings.".format(
                dns.get("error"))
        elif (res.get("protocol") or res.get("proto") or "").upper() == "ICMP":
            if ping.get("reachable"):
                headline, key = "Host replied to ICMP echo", "SUCCESS"
                detail = "Echo requests were sent and at least one reply was received."
            else:
                headline, key = "No ICMP echo reply", "ERROR"
                detail = ("The ping completed without a reply. Many servers block ICMP, "
                          "so this is not conclusive by itself — see packet evidence below.")
        elif open_ports:
            headline, key = "Server is reachable and port {} is OPEN".format(
                ", ".join(str(p) for p in open_ports)), "SUCCESS"
            if (res.get("protocol") or res.get("proto") or "").upper() == "UDP":
                detail = "A UDP response was received, so the path is not silently dropping this port."
            else:
                detail = "A TCP handshake completed, so nothing on the path is blocking it."
        elif filtered:
            headline, key = "Port {} appears BLOCKED by a firewall".format(
                ", ".join(str(p) for p in filtered)), "ERROR"
            detail = ("No reply at all before the timeout - packets are being dropped "
                      "silently, which is how firewalls/ACLs usually behave. "
                      "A closed port would actively refuse instead.")
        elif closed:
            headline, key = "Host is UP, but nothing is listening on port {}".format(
                ", ".join(str(p) for p in closed)), "WARNING"
            detail = ("The host actively refused the connection, so it is reachable and "
                      "NOT firewalled - the service is simply not running on that port.")
        else:
            headline, key = "Could not determine port state", "TEXT_SECONDARY"
            detail = "; ".join(p.get("detail", "") for p in ports)

        bits = ["Resolved: {}".format(dns.get("ip") or "-")]
        if ping.get("reachable"):
            bits.append("ping OK{}".format(
                " ({} ms avg)".format(ping["avg_ms"]) if ping.get("avg_ms") is not None else ""))
        else:
            bits.append("no ICMP reply (many servers block ping - not conclusive)")
        if ping.get("loss_pct") is not None:
            bits.append("{}% loss".format(ping["loss_pct"]))
        if res.get("local"):
            bits.append("target is this machine")

        ver = res.get("verification") or {}
        if ver.get("result") == "PASS":
            key = "SUCCESS"
        elif ver.get("result") == "FAIL":
            key = "ERROR"
        elif ver.get("result") == "WARNING":
            key = "WARNING"
        cap = res.get("capture") or {}
        analysis = res.get("packet_analysis") or {}
        if res.get("test_id"):
            bits.append("id {}".format(res["test_id"]))
        if cap:
            bits.append("pcap {} pkt".format(cap.get("packet_count", 0)))
        if ver.get("result"):
            bits.append("verified {}".format(ver["result"]))

        self.lbl_verdict.setText(headline)
        self.lbl_verdict.setStyleSheet(
            "font-size: 15px; font-weight: 700; color: {};".format(theme.c(key)))
        extra = []
        if ver:
            extra.append("API Verification: {} — {}".format(
                ver.get("result") or "—", ver.get("reason") or ""))
            if ver.get("api_error"):
                extra.append(ver["api_error"])
        tcp = analysis.get("tcp") or {}
        if (res.get("protocol") or res.get("proto") or "").upper() == "TCP" and tcp:
            extra.append("TCP  SYN={}  SYN/ACK={}  ACK={}  RST={}  Retransmissions={}".format(
                tcp.get("syn"), tcp.get("syn_ack"), tcp.get("ack"),
                tcp.get("rst"), tcp.get("retransmissions")))
        icmp = analysis.get("icmp") or {}
        if (res.get("protocol") or res.get("proto") or "").upper() == "ICMP" and icmp:
            extra.append("ICMP  Request={}  Reply={}  Loss={}%".format(
                icmp.get("echo_request"), icmp.get("echo_reply"), icmp.get("packet_loss_pct")))
        if cap.get("filename"):
            extra.append("Capture: {} ({})".format(
                cap.get("filename"),
                "Wireshark compatible" if cap.get("wireshark_compatible") else "invalid"))
        if cap.get("error"):
            extra.append(cap["error"])
        self.lbl_detail.setText(
            detail + "\n" + "  \u00b7  ".join(bits)
            + (("\n" + "\n".join(extra)) if extra else ""))

        # ---- raw output ----
        blocks = []
        try:
            from backend.network_verify import format_evidence_report
            blocks.append(format_evidence_report(res))
            blocks.append("")
        except Exception:
            pass
        for caption, text in res.get("raw", []):
            blocks.append("=" * 66)
            blocks.append(caption)
            blocks.append("=" * 66)
            blocks.append(text or "(no output)")
            blocks.append("")
        self.console.set_text("\n".join(blocks) or "(no output)", theme.c("TEXT_PRIMARY"))

    def _run_firewall(self):
        self.btn_fw.setEnabled(False)
        self.console.set_text("Reading local firewall state\u2026", theme.c("ACCENT"))
        self.workers.run(self._collect_firewall,
                         on_finished=self._firewall_done,
                         on_error=lambda e: self._firewall_done(
                             {"summary": "Failed: {}".format(e), "blocks": []}),
                         busy_text="Checking local firewall\u2026")

    @staticmethod
    def _collect_firewall():
        fw = local_firewall_status()
        lcmd, lraw = local_listening_ports()
        blocks = [("Firewall state  -  {}".format(fw["cmd"]), fw["raw"]),
                  ("Listening ports  -  {}".format(lcmd), lraw)]
        if IS_MAC:
            blocks.append(("Packet filter  -  sudo pfctl -s info",
                           run_command("pfctl -s info 2>&1", timeout=15)))
        return {"summary": fw["summary"], "blocks": blocks}

    def _firewall_done(self, data):
        self.btn_fw.setEnabled(True)
        data = data or {}
        self.lbl_verdict.setText(data.get("summary", ""))
        self.lbl_verdict.setStyleSheet("font-size: 15px; font-weight: 700; color: {};".format(
            theme.c("TEXT_PRIMARY")))
        self.lbl_detail.setText(
            "pfctl needs sudo, so its section may show a permission error - that is expected "
            "when running unelevated." if IS_MAC else "")
        out = []
        for caption, text in data.get("blocks", []):
            out.append("=" * 66)
            out.append(caption)
            out.append("=" * 66)
            out.append(text or "(no output)")
            out.append("")
        self.console.set_text("\n".join(out) or "(no output)", theme.c("TEXT_PRIMARY"))

    def _open_captures(self):
        path = capture_dir()
        try:
            if sys.platform.startswith("win"):
                os.startfile(path)  # noqa
            elif sys.platform == "darwin":
                subprocess.Popen(["open", path])
            else:
                subprocess.Popen(["xdg-open", path])
        except Exception:
            self.lbl_detail.setText("Capture folder: {}".format(path))

    def _refresh_admin_hint(self):
        from backend.windows_elevate import is_admin, is_windows
        if not is_windows():
            self.btn_admin.setVisible(False)
            return
        elevated = is_admin()
        self.btn_admin.setVisible(not elevated)
        if elevated:
            self.lbl_source.setText("Source: {}  ·  Administrator (pktmon / SIO_RCVALL)".format(get_local_ip()))
        else:
            self.lbl_source.setText(
                "Source: {}  ·  Not elevated — capture needs Administrator".format(get_local_ip())
            )

    def _restart_admin(self):
        from backend.windows_elevate import relaunch_as_admin
        ok, err = relaunch_as_admin()
        if ok:
            from PySide6.QtWidgets import QApplication
            QApplication.quit()
            return
        self.lbl_detail.setText(err or "Could not restart as Administrator.")
