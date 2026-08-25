"""
pages/dashboard.py
Landing Dashboard — live status overview.

Contains the responsive row of status cards plus a System Information card.
Diagnostics and the AI Assistant now live on their own pages. Metrics refresh
on background workers so the UI never freezes. Everything is inside a scroll
area so cards never overlap or clip at any window size.
"""

import socket

import psutil
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QScrollArea, QFrame, QSizePolicy
)
from PySide6.QtCore import Qt, QTimer

from core.workers import WorkerManager
from widgets.stat_card import StatCard
from widgets.flow_layout import FlowLayout
from widgets.card import make_card
from backend.diagnostics import (
    get_ad_username, get_local_ip, check_system_restart, network_summary,
    check_internet, network_quality, public_ip
)
from backend.system_health import wifi_signal
from backend.system_score import health_score


class DashboardPage(QWidget):
    REFRESH_MS = 20000
    SYS_MS = 2000

    def __init__(self, parent=None):
        super().__init__(parent)
        self.workers = WorkerManager()
        self._internet_ok = None
        self._quality = {}
        self._sys_labels = {}

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)

        content = QWidget()
        self.body = QVBoxLayout(content)
        self.body.setContentsMargins(24, 22, 24, 22)
        self.body.setSpacing(18)

        self._build_status_row()
        self._build_sysinfo_card()
        self.body.addStretch()

        scroll.setWidget(content)
        outer.addWidget(scroll)

        self._refresh_live_data()
        self._refresh_system()
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._refresh_live_data)
        self._timer.start(self.REFRESH_MS)
        self._sys_timer = QTimer(self)
        self._sys_timer.timeout.connect(self._refresh_system)
        self._sys_timer.start(self.SYS_MS)

    # ---------------------------------------------------- status cards row
    def _build_status_row(self):
        holder = QWidget()
        sp = holder.sizePolicy()
        sp.setHeightForWidth(True)
        sp.setVerticalPolicy(QSizePolicy.MinimumExpanding)
        holder.setSizePolicy(sp)
        flow = FlowLayout(holder, margin=0, hspacing=16, vspacing=16)

        self.card_internet = StatCard("Internet Health", "fa5s.globe", indicator="bar")
        self.card_score = StatCard("Network Score", "fa5s.shield-alt", indicator="bar")
        self.card_latency = StatCard("Latency", "fa5s.tachometer-alt", indicator="spark")
        self.card_loss = StatCard("Packet Loss", "fa5s.exclamation-triangle", indicator="bar")
        self.card_jitter = StatCard("Jitter", "fa5s.wave-square", indicator="spark")
        self.card_cpu = StatCard("CPU Utilization", "fa5s.microchip", indicator="bar")
        self.card_mem = StatCard("Memory Utilization", "fa5s.memory", indicator="bar")
        self.card_pubip = StatCard("Public IP", "fa5s.network-wired", indicator="none")
        self.card_wifi = StatCard("WiFi Signal", "fa5s.wifi", indicator="bar")
        self.card_syshealth = StatCard("System Health", "fa5s.heartbeat", indicator="bar")

        for c in (self.card_internet, self.card_score, self.card_latency, self.card_loss,
                  self.card_jitter, self.card_cpu, self.card_mem, self.card_pubip,
                  self.card_wifi, self.card_syshealth):
            flow.addWidget(c)
        self.body.addWidget(holder)

        # WiFi recommendation banner (updates from the WiFi analyzer)
        self.wifi_reco = QLabel("")
        self.wifi_reco.setProperty("role", "secondary")
        self.wifi_reco.setWordWrap(True)
        self.wifi_reco.setStyleSheet("font-size: 12px;")
        self.body.addWidget(self.wifi_reco)

    def _build_sysinfo_card(self):
        frame, lay = make_card("System Information")
        grid_holder = QWidget()
        grid = QHBoxLayout(grid_holder)
        grid.setContentsMargins(0, 0, 0, 0)
        grid.setSpacing(28)

        col_a = QVBoxLayout()
        col_b = QVBoxLayout()
        col_a.setSpacing(10)
        col_b.setSpacing(10)

        rows = ["Hostname", "Logged-in User", "IP Address",
                "Gateway", "Last Reboot", "Network Status"]
        for i, key in enumerate(rows):
            r = QHBoxLayout()
            k = QLabel(key)
            k.setProperty("role", "secondary")
            v = QLabel("…")
            v.setStyleSheet("font-weight: 600;")
            v.setWordWrap(True)
            v.setTextInteractionFlags(Qt.TextSelectableByMouse)
            v.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
            r.addWidget(k)
            r.addStretch()
            r.addWidget(v)
            (col_a if i < 3 else col_b).addLayout(r)
            self._sys_labels[key] = v

        grid.addLayout(col_a, 1)
        grid.addLayout(col_b, 1)
        lay.addWidget(grid_holder)

        self._sys_labels["Hostname"].setText(socket.gethostname())
        self._sys_labels["Logged-in User"].setText(get_ad_username())
        self.body.addWidget(frame)

    # ---------------------------------------------------- live metrics
    def _refresh_live_data(self):
        self.workers.run(check_internet, on_finished=self._apply_internet,
                         busy_text="Checking internet…")
        self.workers.run(network_quality, on_finished=self._apply_quality,
                         busy_text="Measuring latency…")
        self.workers.run(network_summary, on_finished=self._apply_summary,
                         busy_text="Reading adapter…")
        self.workers.run(public_ip, on_finished=self._apply_public,
                         busy_text="Resolving public IP…")
        self.workers.run(check_system_restart, on_finished=self._apply_reboot)
        self.workers.run(wifi_signal, on_finished=self._apply_wifi,
                         busy_text="Checking WiFi signal…")
        self.workers.run(health_score, on_finished=self._apply_syshealth,
                         busy_text="Scoring system health…")

    def _refresh_system(self):
        try:
            cpu = psutil.cpu_percent(interval=None)
            mem = psutil.virtual_memory().percent
        except Exception:
            return
        self.card_cpu.set_value(f"{cpu:.0f}%",
                                "success" if cpu < 70 else ("warning" if cpu < 90 else "error"),
                                pct=cpu)
        self.card_cpu.add_point(cpu)
        self.card_mem.set_value(f"{mem:.0f}%",
                                "success" if mem < 70 else ("warning" if mem < 90 else "error"),
                                pct=mem)
        self.card_mem.add_point(mem)

    def _apply_internet(self, result):
        self._internet_ok = "working fine" in (result or "").lower()
        self.card_internet.set_value("Online" if self._internet_ok else "Offline",
                                     "success" if self._internet_ok else "error",
                                     pct=100 if self._internet_ok else 0)
        if "Network Status" in self._sys_labels:
            self._sys_labels["Network Status"].setText("Online" if self._internet_ok else "Offline")
        self._update_score()

    def _apply_quality(self, q):
        self._quality = q or {}
        latency = q.get("latency_ms")
        loss = q.get("loss_pct")
        jitter = q.get("jitter_ms")

        self.card_latency.set_value(f"{latency} ms" if latency is not None else "—",
                                    "success" if (latency or 999) < 60 else "warning")
        self.card_latency.add_point(latency)

        loss_status = "success" if (loss or 0) == 0 else ("warning" if (loss or 0) < 20 else "error")
        self.card_loss.set_value(f"{loss}%" if loss is not None else "—", loss_status, pct=loss or 0)

        self.card_jitter.set_value(f"{jitter} ms" if jitter is not None else "—",
                                   "success" if (jitter or 0) < 15 else "warning")
        self.card_jitter.add_point(jitter)
        self._update_score()

    def _apply_summary(self, summary):
        summary = summary or {}
        if "IP Address" in self._sys_labels:
            self._sys_labels["IP Address"].setText(summary.get("local_ip", get_local_ip()))
        if "Gateway" in self._sys_labels:
            self._sys_labels["Gateway"].setText(summary.get("gateway", "—"))

    def _apply_public(self, ip):
        self.card_pubip.set_value(ip or "Unavailable",
                                  "success" if ip and ip != "Unavailable" else "warning")

    def _apply_wifi(self, w):
        w = w or {}
        pct = w.get("signal_pct")
        status = w.get("status", "neutral")
        self.card_wifi.set_value(f"{pct}%" if pct is not None else "—", status,
                                 pct=pct if pct is not None else 0)
        ssid = w.get("ssid", "—")
        reco = w.get("recommendation", "")
        self.card_wifi.setToolTip(reco)
        self.wifi_reco.setText(f"WiFi ({ssid}): {reco}" if reco else "")

    def _apply_syshealth(self, h):
        h = h or {}
        score = h.get("score")
        status = h.get("status", "warning")
        self.card_syshealth.set_value(
            f"{score} / 100" if score is not None else "—", status,
            pct=score if score is not None else 0)
        grade = h.get("grade", "")
        issues = h.get("issues", [])
        tip = grade
        if issues:
            tip += " — " + ", ".join(i["label"] for i in issues[:4])
        self.card_syshealth.setToolTip(tip)

    def _apply_reboot(self, text):
        if "Last Reboot" in self._sys_labels:
            line = (text or "").splitlines()[0] if text else "—"
            self._sys_labels["Last Reboot"].setText(line.replace("Last Reboot Time: ", ""))

    def _update_score(self):
        score = 100.0
        if self._internet_ok is False:
            score -= 60
        loss = self._quality.get("loss_pct")
        latency = self._quality.get("latency_ms")
        if loss:
            score -= min(loss, 100) * 0.5
        if latency:
            score -= max(0, latency - 40) * 0.25
        score = max(0, min(100, round(score)))
        status = "success" if score >= 80 else ("warning" if score >= 50 else "error")
        self.card_score.set_value(f"{score} / 100", status, pct=score)
