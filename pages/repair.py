"""
pages/repair.py

Network Repair Center — one-click fixes for common laptop/desktop network
problems, plus a download speed test and a DNS-resolver benchmark.

Additive page; matches the Nord theme; all actions run on the WorkerManager.
Repair fixes that change system state ask for confirmation and flag when
Administrator rights are required.
"""

import sys

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGridLayout, QLabel, QPushButton, QFrame,
    QScrollArea, QMessageBox, QSizePolicy
)
from PySide6.QtCore import Qt

from core.theme import theme, apply_soft_shadow
from core import iconkit
from core.workers import WorkerManager
from widgets.console import ConsoleWidget
from backend.repair import REPAIR_ACTIONS, run_repair, speed_test, dns_benchmark

IS_WINDOWS = sys.platform.startswith("win")

_ICONS = {
    "flush_dns": "fa5s.broom", "renew_ip": "fa5s.sync", "clear_arp": "fa5s.eraser",
    "reset_winsock": "fa5s.plug", "reset_tcpip": "fa5s.network-wired",
    "restart_adapters": "fa5s.redo", "reset_firewall": "fa5s.shield-alt",
    "reset_wu": "fa5s.cloud-download-alt",
}


class RepairPage(QWidget):
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
        self.body.setSpacing(16)

        title = QLabel("Network Repair Center")
        title.setProperty("role", "title")
        title.setStyleSheet("font-size: 24px; font-weight: 800;")
        sub = QLabel("One-click fixes for common connectivity problems, plus performance tests.")
        sub.setProperty("role", "subtitle")
        self.body.addWidget(title)
        self.body.addWidget(sub)

        if IS_WINDOWS:
            note = QLabel("Some fixes need Administrator rights — relaunch as administrator if prompted.")
        else:
            note = QLabel("Repair actions are tuned for Windows; on macOS the closest equivalents "
                          "run where possible (some need sudo).")
        note.setProperty("role", "secondary")
        note.setWordWrap(True)
        self.body.addWidget(note)

        self._build_fix_grid()
        self._build_perf_section()
        self._build_console()
        self.body.addStretch()

        scroll.setWidget(content)
        outer.addWidget(scroll)

    def _card(self, title_text):
        frame = QFrame()
        frame.setProperty("cls", "card")
        apply_soft_shadow(frame, radius=16, offset=(0, 5))
        lay = QVBoxLayout(frame)
        lay.setContentsMargins(18, 16, 18, 16)
        lay.setSpacing(12)
        t = QLabel(title_text)
        t.setStyleSheet("font-size: 15px; font-weight: 700;")
        lay.addWidget(t)
        return frame, lay

    def _build_fix_grid(self):
        frame, lay = self._card("Quick Fixes")
        grid = QGridLayout()
        grid.setHorizontalSpacing(12)
        grid.setVerticalSpacing(12)
        cols = 2
        for c in range(cols):
            grid.setColumnStretch(c, 1)

        for i, action in enumerate(REPAIR_ACTIONS):
            btn = QPushButton("  " + action["label"] + ("   (admin)" if action["admin"] else ""))
            btn.setProperty("cls", "ghost")
            btn.setCursor(Qt.PointingHandCursor)
            btn.setMinimumHeight(48)
            btn.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
            btn.setToolTip(action["description"])
            iconkit.button(btn, _ICONS.get(action["key"], "fa5s.wrench"), role="ACCENT", size=15)
            btn.clicked.connect(lambda checked, a=action: self._run_fix(a))
            grid.addWidget(btn, i // cols, i % cols)
        lay.addLayout(grid)
        self.body.addWidget(frame)

    def _build_perf_section(self):
        frame, lay = self._card("Connectivity Performance")
        row = QHBoxLayout()
        row.setSpacing(12)

        self.btn_speed = QPushButton("  Run Speed Test")
        self.btn_speed.setProperty("cls", "primary")
        self.btn_speed.setFixedHeight(44)
        self.btn_speed.setCursor(Qt.PointingHandCursor)
        iconkit.button(self.btn_speed, "fa5s.gauge-high" if False else "fa5s.tachometer-alt",
                       role="ON_ACCENT", size=14)
        self.btn_speed.clicked.connect(self._run_speed)
        row.addWidget(self.btn_speed)

        self.btn_dns = QPushButton("  DNS Benchmark")
        self.btn_dns.setProperty("cls", "ghost")
        self.btn_dns.setFixedHeight(44)
        self.btn_dns.setCursor(Qt.PointingHandCursor)
        iconkit.button(self.btn_dns, "fa5s.stopwatch", role="ACCENT", size=14)
        self.btn_dns.clicked.connect(self._run_dns)
        row.addWidget(self.btn_dns)
        row.addStretch()
        lay.addLayout(row)

        self.perf_label = QLabel("Run a test to measure download throughput or find your fastest DNS.")
        self.perf_label.setProperty("role", "secondary")
        self.perf_label.setWordWrap(True)
        lay.addWidget(self.perf_label)
        self.body.addWidget(frame)

    def _build_console(self):
        frame, lay = self._card("Output")
        self.console = ConsoleWidget(self, min_height=200)
        self.console.set_text("Results from fixes and tests appear here.", theme.c("TEXT_SECONDARY"))
        lay.addWidget(self.console)
        self.body.addWidget(frame)

    # --- handlers ----------------------------------------------------------
    def _run_fix(self, action):
        if action["admin"] or action["key"] in ("reset_winsock", "reset_tcpip", "reset_wu"):
            ok = QMessageBox.question(
                self, "Confirm repair",
                f"{action['label']}\n\n{action['description']}\n\nProceed?",
                QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
            if ok != QMessageBox.Yes:
                return
        self.console.set_text(f"Running: {action['label']}…", theme.c("ACCENT"))
        self.workers.run(
            run_repair, action["key"],
            on_finished=lambda out, a=action: self.console.set_text(
                f"[{a['label']}]\n{out}", theme.c("TEXT_PRIMARY")),
            on_error=lambda err: self.console.set_text(f"Error: {err}", theme.c("ERROR")),
            busy_text=f"Running {action['label']}…")

    def _run_speed(self):
        self.btn_speed.setEnabled(False)
        self.perf_label.setText("Measuring download speed… (this takes a few seconds)")
        self.console.set_text("Running speed test…", theme.c("ACCENT"))
        self.workers.run(speed_test, on_finished=self._speed_done,
                         on_error=lambda e: self._speed_done({"error": str(e)}),
                         busy_text="Running speed test…")

    def _speed_done(self, res):
        self.btn_speed.setEnabled(True)
        if res.get("error"):
            self.perf_label.setText("Speed test failed — check your internet connection.")
            self.console.set_text(f"Speed test error: {res['error']}", theme.c("ERROR"))
            return
        msg = (f"Download: {res['down_mbps']} Mbps   ·   Latency: {res['latency_ms']} ms   "
               f"·   {res['bytes'] // (1024*1024)} MB in {res['seconds']} s")
        self.perf_label.setText(msg)
        self.console.set_text(msg, theme.c("SUCCESS"))

    def _run_dns(self):
        self.btn_dns.setEnabled(False)
        self.perf_label.setText("Benchmarking DNS resolvers…")
        self.console.set_text("Benchmarking DNS resolvers…", theme.c("ACCENT"))
        self.workers.run(dns_benchmark, on_finished=self._dns_done,
                         on_error=lambda e: self._dns_done(None),
                         busy_text="Benchmarking DNS…")

    def _dns_done(self, results):
        self.btn_dns.setEnabled(True)
        if not results:
            self.console.set_text("DNS benchmark failed.", theme.c("ERROR"))
            return
        lines = ["DNS resolver benchmark (lower is better):", ""]
        best = None
        for r in results:
            tag = "  ← fastest" if r.get("recommended") else ""
            ms = f"{r['avg_ms']} ms" if r["avg_ms"] is not None else "unreachable"
            lines.append(f"  {r['name']:<12} {r['ip']:<16} {ms}{tag}")
            if r.get("recommended"):
                best = r
        self.console.set_text("\n".join(lines), theme.c("TEXT_PRIMARY"))
        if best:
            self.perf_label.setText(f"Fastest DNS for you: {best['name']} ({best['ip']}) "
                                    f"at {best['avg_ms']} ms average.")
