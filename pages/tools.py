"""
pages/tools.py
Network Tools & AI Analysis + Diagnostics.

Everything sits inside a scroll area with fixed console heights, so Command
Output, AI Analysis, and the Results console never overlap at any window size.
All tool and diagnostic handler names and logic are unchanged.
"""

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QLineEdit,
    QScrollArea, QFrame, QGridLayout, QSizePolicy
)
from PySide6.QtCore import Qt

from widgets.console import ConsoleWidget
from core.theme import theme
from core import iconkit
from core.workers import WorkerManager
from backend.diagnostics import (
    run_ping, run_traceroute, run_command,
    check_ip_type, check_internet, check_default_gateway, check_dns_servers,
    check_dhcp_status, check_zscaler, get_ip_location, get_public_ip
)
from backend.chatbot import send_to_llm


class ToolsPage(QWidget):
    DIAG_TESTS = [
        ("fa5s.wifi", "LAN / WiFi", check_ip_type),
        ("fa5s.globe", "Internet", check_internet),
        ("fa5s.route", "Gateway", check_default_gateway),
        ("fa5s.server", "DNS Servers", check_dns_servers),
        ("fa5s.sitemap", "DHCP Status", check_dhcp_status),
        ("fa5s.shield-alt", "Zscaler", check_zscaler),
        ("fa5s.map-marker-alt", "IP Location", get_ip_location),
        ("fa5s.network-wired", "Public IP", get_public_ip),
    ]

    def __init__(self, parent=None):
        super().__init__(parent)
        self.workers = WorkerManager()
        self._fn_by_title = {}
        self._diag_queue = []

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)

        content = QWidget()
        self.layout = QVBoxLayout(content)
        self.layout.setContentsMargins(24, 22, 24, 22)
        self.layout.setSpacing(16)

        self._build_header()
        self._build_inputs()
        self._build_consoles()
        self._build_diagnostics()
        self.layout.addStretch()

        scroll.setWidget(content)
        outer.addWidget(scroll)

    # --- header ------------------------------------------------------------
    def _build_header(self):
        title = QLabel("Network Tools & AI Analysis")
        title.setProperty("role", "title")
        title.setStyleSheet("font-size: 24px; font-weight: 800;")
        sub = QLabel("Execute diagnostics and instantly analyze behavior with the built-in assistant.")
        sub.setProperty("role", "subtitle")
        self.layout.addWidget(title)
        self.layout.addWidget(sub)
        self.layout.addSpacing(4)

    # --- ping / traceroute / execute --------------------------------------
    def _build_inputs(self):
        form = QHBoxLayout()
        form.setSpacing(16)

        ip_box = QVBoxLayout()
        ip_box.setSpacing(6)
        ip_lbl = QLabel("TARGET IP OR HOSTNAME")
        ip_lbl.setProperty("role", "cardtitle")
        self.txt_ip = QLineEdit("8.8.8.8")
        self.txt_ip.setProperty("cls", "input")
        self.txt_ip.setFixedHeight(46)
        ip_box.addWidget(ip_lbl)
        ip_box.addWidget(self.txt_ip)
        form.addLayout(ip_box, 1)

        cmd_box = QVBoxLayout()
        cmd_box.setSpacing(6)
        cmd_lbl = QLabel("CUSTOM SHELL COMMAND")
        cmd_lbl.setProperty("role", "cardtitle")
        self.txt_cmd = QLineEdit("ping -n 4 8.8.8.8")
        self.txt_cmd.setProperty("cls", "input")
        self.txt_cmd.setFixedHeight(46)
        cmd_box.addWidget(cmd_lbl)
        cmd_box.addWidget(self.txt_cmd)
        form.addLayout(cmd_box, 1)
        self.layout.addLayout(form)

        btns = QHBoxLayout()
        btns.setSpacing(12)
        btn_ping = self._action_btn("  Ping", "fa5s.bolt", primary=True)
        btn_ping.clicked.connect(self._do_ping)
        btn_trace = self._action_btn("  Traceroute", "fa5s.route")
        btn_trace.clicked.connect(self._do_trace)
        btn_exec = self._action_btn("  Execute", "fa5s.terminal")
        btn_exec.clicked.connect(self._do_exec)
        btns.addWidget(btn_ping)
        btns.addWidget(btn_trace)
        btns.addWidget(btn_exec)
        btns.addStretch()
        self.layout.addLayout(btns)

    def _action_btn(self, text, icon, primary=False):
        btn = QPushButton(text)
        btn.setProperty("cls", "primary" if primary else "ghost")
        btn.setFixedHeight(44)
        btn.setMinimumWidth(130)
        btn.setCursor(Qt.PointingHandCursor)
        iconkit.button(btn, icon, role="ON_ACCENT" if primary else "TEXT_PRIMARY", size=14)
        return btn

    def _build_consoles(self):
        lbl_out = QLabel("COMMAND OUTPUT")
        lbl_out.setProperty("role", "cardtitle")
        self.layout.addWidget(lbl_out)
        self.console_out = ConsoleWidget(self, min_height=190)
        self.console_out.setFixedHeight(190)
        self.layout.addWidget(self.console_out)

        self.layout.addSpacing(4)

        lbl_ai = QLabel("AI ANALYSIS")
        lbl_ai.setProperty("role", "cardtitle")
        self.layout.addWidget(lbl_ai)
        self.console_ai = ConsoleWidget(self, min_height=150)
        self.console_ai.setFixedHeight(150)
        self.layout.addWidget(self.console_ai)

    # --- diagnostics (moved here from the dashboard) ----------------------
    def _build_diagnostics(self):
        self.layout.addSpacing(8)
        div = QFrame()
        div.setFixedHeight(1)
        div.setStyleSheet(f"background-color: {theme.c('BORDER')}; border: none;")
        self.layout.addWidget(div)
        self.layout.addSpacing(4)

        head = QHBoxLayout()
        t = QLabel("Diagnostics")
        t.setProperty("role", "title")
        t.setStyleSheet("font-size: 18px; font-weight: 800;")
        head.addWidget(t)
        head.addStretch()
        self.btn_run_all = QPushButton("  Run All")
        self.btn_run_all.setProperty("cls", "primary")
        self.btn_run_all.setFixedHeight(42)
        self.btn_run_all.setCursor(Qt.PointingHandCursor)
        iconkit.button(self.btn_run_all, "fa5s.play", role="ON_ACCENT", size=13)
        self.btn_run_all.clicked.connect(self._run_all)
        head.addWidget(self.btn_run_all)
        self.layout.addLayout(head)

        grid = QGridLayout()
        grid.setHorizontalSpacing(12)
        grid.setVerticalSpacing(12)
        cols = 4
        for c in range(cols):
            grid.setColumnStretch(c, 1)
        for i, (icon, label_text, fn) in enumerate(self.DIAG_TESTS):
            self._fn_by_title[label_text] = fn
            btn = QPushButton("  " + label_text)
            btn.setProperty("cls", "ghost")
            btn.setCursor(Qt.PointingHandCursor)
            btn.setMinimumHeight(42)
            btn.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
            iconkit.button(btn, icon, role="ACCENT", size=20)
            btn.clicked.connect(lambda checked, tt=label_text: self._run_single(tt))
            grid.addWidget(btn, i // cols, i % cols)
        self.layout.addLayout(grid)

        lbl_res = QLabel("RESULTS")
        lbl_res.setProperty("role", "cardtitle")
        self.layout.addWidget(lbl_res)
        self.console_diag = ConsoleWidget(self, min_height=190)
        self.console_diag.setFixedHeight(190)
        self.console_diag.set_text("Run a diagnostic to see results here.", theme.c("TEXT_SECONDARY"))
        self.layout.addWidget(self.console_diag)

    # --- tool pipeline (unchanged logic) ----------------------------------
    def _execute_pipeline(self, target_fn, target_args, ai_prompt_template, title):
        self.console_out.set_text(f"Running {title}...", theme.c("TEXT_SECONDARY"))
        self.console_ai.set_text("Awaiting output generation...", theme.c("TEXT_SECONDARY"))

        def finish_shell(result_text):
            self.console_out.set_text(result_text, theme.c("SUCCESS"))
            self.console_ai.set_text("Analyzing payload with the assistant...", theme.c("ACCENT"))
            prompt = ai_prompt_template.format(out=result_text)
            self.workers.run(
                send_to_llm, prompt, get_response_only=True,
                on_finished=lambda res: self.console_ai.set_text(res, theme.c("ACCENT_2")),
                on_error=lambda err: self.console_ai.set_text(err, theme.c("ERROR")),
                busy_text="Analyzing with AI…")

        self.workers.run(
            target_fn, *target_args,
            on_finished=finish_shell,
            on_error=lambda err: self.console_out.set_text(err, theme.c("ERROR")),
            busy_text=title)

    def _do_ping(self):
        target = self.txt_ip.text().strip()
        prompt = "As a Network administrator analyze this ping output. Is there a network issue?\n{out}"
        self._execute_pipeline(run_ping, [target], prompt, f"Ping {target}")

    def _do_trace(self):
        target = self.txt_ip.text().strip()
        prompt = "Give me a one-liner analysis of this traceroute output:\n{out}"
        self._execute_pipeline(run_traceroute, [target], prompt, f"Traceroute {target}")

    def _do_exec(self):
        cmd = self.txt_cmd.text().strip()
        prompt = "Analyze this command output and tell me in max 3 lines what it means:\n{out}"
        self._execute_pipeline(run_command, [cmd], prompt, f"Command: {cmd}")

    # --- diagnostics handlers (unchanged logic) ---------------------------
    def _run_single(self, title: str):
        fn = self._fn_by_title.get(title)
        if not fn:
            return
        self.console_diag.set_text(f"Running {title}...", theme.c("TEXT_SECONDARY"))
        self.workers.run(
            fn,
            on_finished=lambda res, t=title: self.console_diag.set_text(f"[{t}]\n{res}", theme.c("SUCCESS")),
            on_error=lambda err: self.console_diag.set_text(f"Error: {err}", theme.c("ERROR")),
            busy_text=f"Running {title}…")

    def _run_all(self):
        self.console_diag.set_text("Initiating full diagnostic sweep...\n\n", theme.c("ACCENT"))
        self.btn_run_all.setEnabled(False)
        self._diag_queue = list(self.DIAG_TESTS)
        self._run_next()

    def _run_next(self):
        if not self._diag_queue:
            self.console_diag.append_text("\n✔ All checks completed.", theme.c("SUCCESS"))
            self.btn_run_all.setEnabled(True)
            return
        icon, label_text, fn = self._diag_queue.pop(0)
        self.console_diag.append_text(f"▸ {label_text}", theme.c("ACCENT"))
        self.workers.run(
            fn,
            on_finished=lambda res, l=label_text: self._on_step_done(l, res),
            on_error=lambda err, l=label_text: self._on_step_done(l, f"Error: {err}"),
            busy_text=f"Running {label_text}…")

    def _on_step_done(self, label_text, result):
        self.console_diag.append_text(f"{result}\n", theme.c("TEXT_PRIMARY"))
        self._run_next()
