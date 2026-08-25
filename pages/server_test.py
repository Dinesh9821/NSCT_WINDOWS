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

import re
import time
import socket

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGridLayout, QLabel, QLineEdit, QPushButton,
    QFrame, QComboBox, QScrollArea, QTableWidget, QTableWidgetItem, QHeaderView,
    QAbstractItemView, QSizePolicy
)
from PySide6.QtCore import Qt
from PySide6.QtGui import QColor

from core.theme import theme, apply_soft_shadow
from core import iconkit
from core.workers import WorkerManager
from widgets.console import ConsoleWidget
from backend.diagnostics import run_command, IS_WINDOWS, IS_MAC


# =========================================================================== #
#  Checks (pure logic - safe to unit test)
# =========================================================================== #
MAX_PORTS = 64


def parse_ports(text):
    """
    '80, 443, 8080-8082' -> [80, 443, 8080, 8081, 8082]
    Ignores junk, de-duplicates, preserves order, caps at MAX_PORTS.
    """
    ports = []
    for chunk in re.split(r"[,\s]+", (text or "").strip()):
        if not chunk:
            continue
        m = re.match(r"^(\d{1,5})-(\d{1,5})$", chunk)
        if m:
            lo, hi = int(m.group(1)), int(m.group(2))
            if lo > hi:
                lo, hi = hi, lo
            for p in range(lo, min(hi, 65535) + 1):
                if 0 < p < 65536 and p not in ports:
                    ports.append(p)
                if len(ports) >= MAX_PORTS:
                    return ports
            continue
        if chunk.isdigit():
            p = int(chunk)
            if 0 < p < 65536 and p not in ports:
                ports.append(p)
            if len(ports) >= MAX_PORTS:
                return ports
    return ports


def resolve_host(host):
    """DNS resolution -> {'ok', 'ip', 'error'}."""
    try:
        ip = socket.gethostbyname(host)
        return {"ok": True, "ip": ip, "error": None}
    except Exception as e:
        return {"ok": False, "ip": None, "error": str(e)}


def tcp_port_check(host, port, timeout=3.0):
    """
    Returns {'port', 'state', 'ms', 'detail'} where state is one of
    open / closed / filtered / error.
    """
    t0 = time.perf_counter()
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.close()
        return {"port": port, "state": "open", "ms": round((time.perf_counter() - t0) * 1000),
                "detail": "TCP handshake succeeded"}
    except socket.timeout:
        return {"port": port, "state": "filtered", "ms": round(timeout * 1000),
                "detail": "No response before timeout (silently dropped)"}
    except ConnectionRefusedError:
        return {"port": port, "state": "closed", "ms": round((time.perf_counter() - t0) * 1000),
                "detail": "Connection refused (host up, nothing listening)"}
    except socket.gaierror as e:
        return {"port": port, "state": "error", "ms": None,
                "detail": "DNS resolution failed: {}".format(e)}
    except OSError as e:
        # EHOSTUNREACH / ENETUNREACH / EACCES ...
        return {"port": port, "state": "error", "ms": None, "detail": str(e)}


def verdict_for(state):
    """Human verdict + palette key for a port state."""
    return {
        "open": ("OPEN - reachable, not blocked", "SUCCESS"),
        "closed": ("CLOSED - host reachable, no service listening (not a firewall block)", "WARNING"),
        "filtered": ("FILTERED - no reply; a firewall is most likely blocking this port", "ERROR"),
        "error": ("ERROR - could not test", "TEXT_SECONDARY"),
    }.get(state, ("UNKNOWN", "TEXT_SECONDARY"))


def cli_port_check(host, port, proto="TCP", timeout=3):
    """The 'via cmd' proof: netcat on macOS/Linux, Test-NetConnection on Windows."""
    if IS_WINDOWS:
        cmd = ('powershell -NoProfile -Command "Test-NetConnection -ComputerName {h} '
               '-Port {p} -InformationLevel Detailed"').format(h=host, p=port)
        return cmd, run_command(cmd, timeout=timeout + 12)
    flag = "-zvu" if proto.upper() == "UDP" else "-zv"
    cmd = "nc {f} -w {t} {h} {p}".format(f=flag, t=timeout, h=host, p=port)
    return cmd, run_command(cmd + " 2>&1", timeout=timeout + 8)


def ping_check(host, count=4):
    """ICMP reachability -> {'reachable', 'loss_pct', 'avg_ms', 'cmd', 'raw'}."""
    cmd = ("ping -n {c} {h}" if IS_WINDOWS else "ping -c {c} {h}").format(c=count, h=host)
    raw = run_command(cmd, timeout=count * 3 + 8)
    low = raw.lower()
    if IS_WINDOWS:
        recv = re.search(r"received\s*=\s*(\d+)", low)
        loss = re.search(r"\((\d+)%\s*loss\)", raw)
        avg = re.search(r"average\s*=\s*(\d+)\s*ms", low)
        reachable = bool(recv and int(recv.group(1)) > 0)
        return {"reachable": reachable,
                "loss_pct": int(loss.group(1)) if loss else None,
                "avg_ms": int(avg.group(1)) if avg else None, "cmd": cmd, "raw": raw}
    recv = re.search(r"(\d+)\s+packets received", low)
    loss = re.search(r"([\d.]+)%\s*packet loss", raw)
    avg = re.search(r"=\s*[\d.]+/([\d.]+)/", raw)
    reachable = bool(recv and int(recv.group(1)) > 0)
    return {"reachable": reachable,
            "loss_pct": int(round(float(loss.group(1)))) if loss else None,
            "avg_ms": round(float(avg.group(1))) if avg else None, "cmd": cmd, "raw": raw}


def local_firewall_status():
    """Local firewall state -> {'enabled', 'summary', 'cmd', 'raw'}."""
    if IS_WINDOWS:
        cmd = "netsh advfirewall show allprofiles state"
        raw = run_command(cmd, timeout=20)
        enabled = "ON" in raw.upper()
        return {"enabled": enabled,
                "summary": "Windows Firewall is ON for one or more profiles." if enabled
                           else "Windows Firewall appears OFF.",
                "cmd": cmd, "raw": raw}
    if IS_MAC:
        fw = "/usr/libexec/ApplicationFirewall/socketfilterfw"
        cmd = "{fw} --getglobalstate; {fw} --getblockall; {fw} --getstealthmode".format(fw=fw)
        raw = run_command(cmd + " 2>&1", timeout=20)
        enabled = ("state = 1" in raw.lower()) or ("enabled" in raw.lower()
                                                   and "disabled" not in raw.lower())
        summary = ("macOS Application Firewall is ENABLED." if enabled
                   else "macOS Application Firewall is disabled "
                        "(outbound connections are not filtered by it).")
        return {"enabled": enabled, "summary": summary, "cmd": cmd, "raw": raw}
    return {"enabled": None, "summary": "Firewall state unavailable on this platform.",
            "cmd": "", "raw": ""}


def local_listening_ports():
    """What is listening on THIS machine (useful when testing your own server)."""
    if IS_WINDOWS:
        cmd = "netstat -ano | findstr LISTENING"
        return cmd, run_command(cmd, timeout=25)
    cmd = "lsof -nP -iTCP -sTCP:LISTEN"
    raw = run_command(cmd + " 2>/dev/null", timeout=25)
    if not raw or raw == "No output available.":
        cmd = "netstat -an -p tcp | grep LISTEN"
        raw = run_command(cmd, timeout=25)
    return cmd, raw


def is_local_target(host, resolved_ip):
    """True when the target is this machine (loopback / a local address)."""
    candidates = {host, resolved_ip or ""}
    if candidates & {"localhost", "127.0.0.1", "::1", "0.0.0.0"}:
        return True
    try:
        local = socket.gethostbyname(socket.gethostname())
        return resolved_ip == local
    except Exception:
        return False


def run_server_test(host, ports_text, proto="TCP", timeout=3.0):
    """Worker payload: DNS -> ping -> per-port TCP -> CLI proof for the first port."""
    host = (host or "").strip()
    result = {"host": host, "dns": None, "ping": None, "ports": [],
              "raw": [], "local": False, "proto": proto}
    if not host:
        result["error"] = "Enter a hostname or IP."
        return result

    dns = resolve_host(host)
    result["dns"] = dns

    ping = ping_check(host)
    result["ping"] = ping
    result["raw"].append(("Reachability  -  {}".format(ping["cmd"]), ping["raw"]))

    ports = parse_ports(ports_text)
    if not ports:
        result["error"] = "Enter at least one valid port (e.g. 443 or 80,443,8080-8082)."
        return result

    for port in ports:
        result["ports"].append(tcp_port_check(host, port, timeout=timeout))

    # CLI proof for the first port so the user sees the actual command output
    cmd, raw = cli_port_check(host, ports[0], proto=proto, timeout=int(timeout))
    result["raw"].append(("Port check  -  {}".format(cmd), raw))

    result["local"] = is_local_target(host, dns.get("ip"))
    if result["local"]:
        lcmd, lraw = local_listening_ports()
        result["raw"].append(("Local listening ports  -  {}".format(lcmd), lraw))
    return result


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
                     "and whether a firewall is blocking it.")
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
        self.cmb_proto.addItems(["TCP", "UDP"])
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
        row.addStretch()
        lay.addLayout(row)

        self.body.addWidget(frame)

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
            run_server_test, host, self.txt_ports.text(),
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
        elif open_ports:
            headline, key = "Server is reachable and port {} is OPEN".format(
                ", ".join(str(p) for p in open_ports)), "SUCCESS"
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

        self.lbl_verdict.setText(headline)
        self.lbl_verdict.setStyleSheet(
            "font-size: 15px; font-weight: 700; color: {};".format(theme.c(key)))
        self.lbl_detail.setText(detail + "\n" + "  \u00b7  ".join(bits))

        # ---- raw output ----
        blocks = []
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
