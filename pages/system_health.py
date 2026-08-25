"""
pages/system_health.py

Troubleshooting workspace with three sections (segmented switcher):
  • Application Health — running apps, CPU/memory/disk hogs, installed software,
    startup programs, crash history.
  • Service Health — critical services with status/startup + restart.
  • Event Logs — channel/level querying plus quick filters
    (Disk Errors, BSOD, Driver Failures, Kernel Errors).

Additive page; matches the existing Nord theme. Tables are styled inline against
the theme so no shared stylesheet is modified. All data collection runs on the
WorkerManager so the UI never freezes.
"""

import sys

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QFrame, QStackedWidget,
    QComboBox, QTableWidget, QTableWidgetItem, QHeaderView, QAbstractItemView,
    QSizePolicy, QButtonGroup
)
from PySide6.QtCore import Qt, QTimer

from core.theme import theme
from core import iconkit
from core.workers import WorkerManager
from widgets.console import ConsoleWidget
from backend.system_health import (
    process_snapshot, high_cpu_processes, memory_hogs, disk_intensive_processes,
    running_applications, installed_software, startup_programs, crash_history,
    critical_services, restart_service,
    event_logs, event_filter, EVENT_CHANNELS, EVENT_LEVELS, QUICK_FILTERS,
    active_connections, listening_ports, disk_health, battery_health, problem_devices,
)

IS_WINDOWS = sys.platform.startswith("win")


def _mb(n):
    try:
        return f"{n / (1024 * 1024):.0f} MB"
    except Exception:
        return "—"


def _combo_style():
    return (f"QComboBox {{ background-color: {theme.c('ELEVATED')}; color: {theme.c('TEXT_PRIMARY')};"
            f" border: 1px solid {theme.c('BORDER')}; border-radius: 10px; padding: 6px 12px; }}"
            f"QComboBox:hover {{ border: 1px solid {theme.c('ACCENT')}; }}"
            f"QComboBox QAbstractItemView {{ background-color: {theme.c('CARD_BG')};"
            f" color: {theme.c('TEXT_PRIMARY')}; selection-background-color: {theme.c('ACCENT')};"
            f" border: 1px solid {theme.c('BORDER')}; outline: none; }}")


def _table(headers):
    t = QTableWidget(0, len(headers))
    t.setHorizontalHeaderLabels(headers)
    t.verticalHeader().setVisible(False)
    t.setEditTriggers(QAbstractItemView.NoEditTriggers)
    t.setSelectionBehavior(QAbstractItemView.SelectRows)
    t.setSelectionMode(QAbstractItemView.SingleSelection)
    t.setAlternatingRowColors(True)
    t.setShowGrid(False)
    t.horizontalHeader().setStretchLastSection(True)
    t.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
    _style_table(t)
    return t


def _style_table(t):
    t.setStyleSheet(
        f"QTableWidget {{ background-color: {theme.c('CARD_BG')}; alternate-background-color: "
        f"{theme.c('ELEVATED')}; color: {theme.c('TEXT_PRIMARY')}; border: 1px solid "
        f"{theme.c('BORDER')}; border-radius: 12px; gridline-color: {theme.c('BORDER')}; }}"
        f"QTableWidget::item {{ padding: 6px 8px; border: none; }}"
        f"QTableWidget::item:selected {{ background-color: {theme.c('ACCENT')}; "
        f"color: {theme.c('ON_ACCENT')}; }}"
        f"QHeaderView::section {{ background-color: {theme.c('ELEVATED')}; color: "
        f"{theme.c('TEXT_SECONDARY')}; padding: 8px; border: none; font-weight: bold; }}")


def theme_color(key):
    from PySide6.QtGui import QColor
    return QColor(theme.c(key))


class _Section(QFrame):
    """A titled card wrapper with a content layout."""
    def __init__(self, title, parent=None):
        super().__init__(parent)
        self.setProperty("cls", "card")
        self.box = QVBoxLayout(self)
        self.box.setContentsMargins(16, 14, 16, 16)
        self.box.setSpacing(12)
        if title:
            t = QLabel(title)
            t.setStyleSheet("font-size: 15px; font-weight: 700;")
            self.box.addWidget(t)


# --------------------------------------------------------------------------- #
#  Application Health
# --------------------------------------------------------------------------- #
class _AppHealthTab(QWidget):
    VIEWS = ["High CPU", "Memory Hogs", "Disk Intensive", "Running Applications",
             "Startup Programs", "Installed Software", "Crash History"]

    def __init__(self, workers, parent=None):
        super().__init__(parent)
        self.workers = workers
        self._snapshot = None

        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(12)

        section = _Section("Application Health")
        controls = QHBoxLayout()
        controls.setSpacing(10)
        lbl = QLabel("View:")
        lbl.setProperty("role", "secondary")
        self.combo = QComboBox()
        self.combo.addItems(self.VIEWS)
        self.combo.setStyleSheet(_combo_style())
        self.combo.currentTextChanged.connect(self._load)
        self.btn_refresh = QPushButton("  Refresh")
        self.btn_refresh.setProperty("cls", "ghost")
        self.btn_refresh.setCursor(Qt.PointingHandCursor)
        iconkit.button(self.btn_refresh, "fa5s.sync", role="ACCENT", size=13)
        self.btn_refresh.clicked.connect(lambda: self._load(self.combo.currentText(), force=True))
        controls.addWidget(lbl)
        controls.addWidget(self.combo, 1)
        controls.addWidget(self.btn_refresh)
        section.box.addLayout(controls)

        self.table = _table(["Name", "PID", "CPU %", "Mem %"])
        section.box.addWidget(self.table, 1)
        lay.addWidget(section)

        self._load("High CPU")

    def _set_headers(self, headers, stretch_first=True):
        self.table.clear()
        self.table.setColumnCount(len(headers))
        self.table.setHorizontalHeaderLabels(headers)
        self.table.horizontalHeader().setStretchLastSection(True)

    def _load(self, view, force=False):
        self.btn_refresh.setEnabled(False)
        proc_views = ("High CPU", "Memory Hogs", "Disk Intensive", "Running Applications")
        if view in proc_views:
            if self._snapshot is not None and not force:
                self._render_proc(view, self._snapshot)
                self.btn_refresh.setEnabled(True)
            else:
                self.workers.run(process_snapshot, on_finished=lambda rows, v=view: self._proc_done(v, rows),
                                 on_error=lambda e: self._proc_done(view, []),
                                 busy_text="Sampling processes…")
        elif view == "Installed Software":
            self._set_headers(["Name", "Version"])
            self.workers.run(installed_software, on_finished=self._sw_done,
                             on_error=lambda e: self._sw_done([]), busy_text="Reading installed software…")
        elif view == "Startup Programs":
            self._set_headers(["Name", "Command", "Location"])
            self.workers.run(startup_programs, on_finished=self._startup_done,
                             on_error=lambda e: self._startup_done([]), busy_text="Reading startup items…")
        elif view == "Crash History":
            self._set_headers(["Time", "Application", "Detail"])
            self.workers.run(crash_history, on_finished=self._crash_done,
                             on_error=lambda e: self._crash_done([]), busy_text="Reading crash history…")

    def _proc_done(self, view, rows):
        self._snapshot = rows
        self._render_proc(view, rows)
        self.btn_refresh.setEnabled(True)

    def _render_proc(self, view, rows):
        if view == "Disk Intensive":
            self._set_headers(["Name", "PID", "Read", "Write"])
            data = disk_intensive_processes(rows)
            self.table.setRowCount(len(data))
            for r, p in enumerate(data):
                self._row(r, [p["name"], p["pid"], _mb(p["read_bytes"]), _mb(p["write_bytes"])])
        elif view == "Memory Hogs":
            self._set_headers(["Name", "PID", "Mem %", "RSS"])
            data = memory_hogs(rows)
            self.table.setRowCount(len(data))
            for r, p in enumerate(data):
                self._row(r, [p["name"], p["pid"], f'{p["mem"]}%', _mb(p["rss"])],
                          warn_col=2, warn=p["mem"] > 20)
        else:  # High CPU / Running Applications
            self._set_headers(["Name", "PID", "CPU %", "Mem %"])
            data = high_cpu_processes(rows) if view == "High CPU" else running_applications(rows)
            self.table.setRowCount(len(data))
            for r, p in enumerate(data):
                self._row(r, [p["name"], p["pid"], f'{p["cpu"]}%', f'{p["mem"]}%'],
                          warn_col=2, warn=p["cpu"] > 25)

    def _sw_done(self, rows):
        self.table.setRowCount(len(rows))
        for r, s in enumerate(rows):
            self._row(r, [s["name"], s["version"]])
        self.btn_refresh.setEnabled(True)

    def _startup_done(self, rows):
        self.table.setRowCount(len(rows))
        for r, s in enumerate(rows):
            self._row(r, [s["name"], s.get("command", ""), s.get("location", "")])
        self.btn_refresh.setEnabled(True)

    def _crash_done(self, rows):
        self.table.setRowCount(len(rows))
        for r, s in enumerate(rows):
            self._row(r, [s["time"], s["app"], s["detail"]])
        self.btn_refresh.setEnabled(True)

    def _row(self, r, values, warn_col=None, warn=False):
        for c, v in enumerate(values):
            item = QTableWidgetItem(str(v))
            if warn_col == c and warn:
                item.setForeground(theme_color("WARNING"))
            self.table.setItem(r, c, item)


# --------------------------------------------------------------------------- #
#  Service Health
# --------------------------------------------------------------------------- #
class _ServiceTab(QWidget):
    def __init__(self, workers, parent=None):
        super().__init__(parent)
        self.workers = workers

        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(12)

        section = _Section("Critical Services")
        controls = QHBoxLayout()
        note = QLabel("Windows services and startup type." if IS_WINDOWS
                      else "Windows-style services aren't present on macOS — showing "
                           "the nearest launchd equivalents.")
        note.setProperty("role", "secondary")
        note.setWordWrap(True)
        controls.addWidget(note, 1)

        self.btn_restart = QPushButton("  Restart Selected")
        self.btn_restart.setProperty("cls", "primary")
        self.btn_restart.setCursor(Qt.PointingHandCursor)
        iconkit.button(self.btn_restart, "fa5s.redo", role="ON_ACCENT", size=13)
        self.btn_restart.clicked.connect(self._restart)
        controls.addWidget(self.btn_restart)

        self.btn_refresh = QPushButton("  Refresh")
        self.btn_refresh.setProperty("cls", "ghost")
        self.btn_refresh.setCursor(Qt.PointingHandCursor)
        iconkit.button(self.btn_refresh, "fa5s.sync", role="ACCENT", size=13)
        self.btn_refresh.clicked.connect(self._load)
        controls.addWidget(self.btn_refresh)
        section.box.addLayout(controls)

        self.table = _table(["Service", "Status", "Startup Type"])
        section.box.addWidget(self.table, 1)
        self.status = QLabel("")
        self.status.setProperty("role", "secondary")
        self.status.setWordWrap(True)
        section.box.addWidget(self.status)
        lay.addWidget(section)

        self._rows = []
        self._load()

    def _load(self):
        self.btn_refresh.setEnabled(False)
        self.workers.run(critical_services, on_finished=self._done,
                         on_error=lambda e: self._done([]), busy_text="Querying services…")

    def _done(self, rows):
        self._rows = rows
        self.table.setRowCount(len(rows))
        for r, s in enumerate(rows):
            name = QTableWidgetItem(s["name"])
            st = QTableWidgetItem(s["status"])
            color = ("SUCCESS" if s["status"] == "Running"
                     else "ERROR" if s["status"] == "Stopped"
                     else "TEXT_SECONDARY")
            st.setForeground(theme_color(color))
            startup = QTableWidgetItem(s["startup"])
            self.table.setItem(r, 0, name)
            self.table.setItem(r, 1, st)
            self.table.setItem(r, 2, startup)
        self.btn_refresh.setEnabled(True)

    def _restart(self):
        row = self.table.currentRow()
        if row < 0 or row >= len(self._rows):
            self.status.setText("Select a service row first.")
            return
        key = self._rows[row]["key"]
        name = self._rows[row]["name"]
        self.status.setText(f"Restarting {name}…")
        self.workers.run(restart_service, key,
                         on_finished=lambda msg: (self.status.setText(msg), self._load()),
                         on_error=lambda e: self.status.setText(str(e)),
                         busy_text=f"Restarting {name}…")


# --------------------------------------------------------------------------- #
#  Event Logs
# --------------------------------------------------------------------------- #
class _EventTab(QWidget):
    def __init__(self, workers, parent=None):
        super().__init__(parent)
        self.workers = workers

        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(12)

        section = _Section("Event Log Analysis")
        if not IS_WINDOWS:
            note = QLabel("On macOS these map to the unified log (log show); "
                          "Windows channels/levels shown for parity.")
            note.setProperty("role", "secondary")
            note.setWordWrap(True)
            section.box.addWidget(note)

        controls = QHBoxLayout()
        controls.setSpacing(10)
        self.cmb_channel = QComboBox()
        self.cmb_channel.addItems(EVENT_CHANNELS)
        self.cmb_channel.setStyleSheet(_combo_style())
        self.cmb_level = QComboBox()
        self.cmb_level.addItems(EVENT_LEVELS)
        self.cmb_level.setStyleSheet(_combo_style())
        self.btn_collect = QPushButton("  Collect")
        self.btn_collect.setProperty("cls", "primary")
        self.btn_collect.setCursor(Qt.PointingHandCursor)
        iconkit.button(self.btn_collect, "fa5s.clipboard-list", role="ON_ACCENT", size=13)
        self.btn_collect.clicked.connect(self._collect)

        for w, lbl in ((self.cmb_channel, "Channel"), (self.cmb_level, "Level")):
            col = QVBoxLayout()
            col.setSpacing(4)
            cap = QLabel(lbl.upper())
            cap.setProperty("role", "cardtitle")
            col.addWidget(cap)
            col.addWidget(w)
            controls.addLayout(col)
        controls.addStretch()
        controls.addWidget(self.btn_collect)
        section.box.addLayout(controls)

        quick = QHBoxLayout()
        quick.setSpacing(8)
        ql = QLabel("Quick filters:")
        ql.setProperty("role", "secondary")
        quick.addWidget(ql)
        for name in QUICK_FILTERS:
            b = QPushButton(name)
            b.setProperty("cls", "ghost")
            b.setCursor(Qt.PointingHandCursor)
            b.clicked.connect(lambda checked, n=name: self._quick(n))
            quick.addWidget(b)
        quick.addStretch()
        section.box.addLayout(quick)

        self.console = ConsoleWidget(self, min_height=260)
        self.console.set_text("Choose a channel/level and click Collect, or use a quick filter.",
                              theme.c("TEXT_SECONDARY"))
        section.box.addWidget(self.console, 1)
        lay.addWidget(section)

    def _collect(self):
        ch = self.cmb_channel.currentText()
        lvl = self.cmb_level.currentText()
        self.console.set_text(f"Collecting {lvl} events from {ch}…", theme.c("ACCENT"))
        self.workers.run(event_logs, ch, lvl, 50,
                         on_finished=lambda txt: self.console.set_text(txt or "No events found.",
                                                                       theme.c("TEXT_PRIMARY")),
                         on_error=lambda e: self.console.set_text(str(e), theme.c("ERROR")),
                         busy_text="Collecting events…")

    def _quick(self, name):
        self.console.set_text(f"Analyzing: {name}…", theme.c("ACCENT"))
        self.workers.run(event_filter, name, 50,
                         on_finished=lambda txt: self.console.set_text(txt or "No matching events.",
                                                                       theme.c("TEXT_PRIMARY")),
                         on_error=lambda e: self.console.set_text(str(e), theme.c("ERROR")),
                         busy_text=f"Analyzing {name}…")


# --------------------------------------------------------------------------- #
#  Connections & Hardware
# --------------------------------------------------------------------------- #
class _HardwareTab(QWidget):
    VIEWS = ["Active Connections", "Listening Ports", "Disks & Storage",
             "Battery", "Problem Devices"]

    def __init__(self, workers, parent=None):
        super().__init__(parent)
        self.workers = workers

        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(12)

        section = _Section("Connections & Hardware")
        controls = QHBoxLayout()
        controls.setSpacing(10)
        lbl = QLabel("View:")
        lbl.setProperty("role", "secondary")
        self.combo = QComboBox()
        self.combo.addItems(self.VIEWS)
        self.combo.setStyleSheet(_combo_style())
        self.combo.currentTextChanged.connect(self._load)
        self.btn_refresh = QPushButton("  Refresh")
        self.btn_refresh.setProperty("cls", "ghost")
        self.btn_refresh.setCursor(Qt.PointingHandCursor)
        iconkit.button(self.btn_refresh, "fa5s.sync", role="ACCENT", size=13)
        self.btn_refresh.clicked.connect(lambda: self._load(self.combo.currentText()))
        controls.addWidget(lbl)
        controls.addWidget(self.combo, 1)
        controls.addWidget(self.btn_refresh)
        section.box.addLayout(controls)

        self.table = _table(["Process", "Protocol", "Local", "Remote", "Status"])
        section.box.addWidget(self.table, 1)
        self.note = QLabel("")
        self.note.setProperty("role", "secondary")
        self.note.setWordWrap(True)
        section.box.addWidget(self.note)
        lay.addWidget(section)

        self._load("Active Connections")

    def _headers(self, headers):
        self.table.clear()
        self.table.setColumnCount(len(headers))
        self.table.setHorizontalHeaderLabels(headers)
        self.table.horizontalHeader().setStretchLastSection(True)

    def _load(self, view):
        self.btn_refresh.setEnabled(False)
        self.note.setText("")
        if view in ("Active Connections", "Listening Ports"):
            fn = active_connections if view == "Active Connections" else listening_ports
            self.workers.run(fn, on_finished=self._conns_done,
                             on_error=lambda e: self._conns_done([]), busy_text="Reading sockets…")
        elif view == "Disks & Storage":
            self.workers.run(disk_health, on_finished=self._disk_done,
                             on_error=lambda e: self._disk_done({}), busy_text="Reading disks…")
        elif view == "Battery":
            self.workers.run(battery_health, on_finished=self._battery_done,
                             on_error=lambda e: self._battery_done({}), busy_text="Reading battery…")
        elif view == "Problem Devices":
            self.workers.run(problem_devices, on_finished=self._devices_done,
                             on_error=lambda e: self._devices_done([]), busy_text="Scanning devices…")

    def _row(self, r, values, color_col=None, color_key=None):
        for c, v in enumerate(values):
            item = QTableWidgetItem(str(v))
            if color_col == c and color_key:
                item.setForeground(theme_color(color_key))
            self.table.setItem(r, c, item)

    def _conns_done(self, rows):
        self._headers(["Process", "Protocol", "Local", "Remote", "Status"])
        self.table.setRowCount(len(rows))
        for r, c in enumerate(rows):
            key = "SUCCESS" if c["status"] == "LISTEN" else ("ACCENT" if c["status"] == "ESTABLISHED" else None)
            self._row(r, [c["process"], c["proto"], c["laddr"], c["raddr"], c["status"]],
                      color_col=4, color_key=key)
        self.btn_refresh.setEnabled(True)

    def _disk_done(self, data):
        self._headers(["Volume", "Type", "Used %", "Free", "Total"])
        vols = (data or {}).get("volumes", [])
        self.table.setRowCount(len(vols))
        for r, v in enumerate(vols):
            key = "ERROR" if v["percent"] >= 90 else ("WARNING" if v["percent"] >= 75 else "SUCCESS")
            self._row(r, [f'{v["device"]}  {v["mount"]}', v["fstype"], f'{v["percent"]}%',
                          _mb(v["free"]), _mb(v["total"])], color_col=2, color_key=key)
        drives = (data or {}).get("drives", [])
        if drives:
            self.note.setText("Physical drives: " + " · ".join(
                f'{d["model"]} [{d["status"]}]' for d in drives if d.get("model")))
        self.btn_refresh.setEnabled(True)

    def _battery_done(self, b):
        self._headers(["Metric", "Value"])
        b = b or {}
        if not b.get("present"):
            self.table.setRowCount(1)
            self._row(0, ["Battery", "No battery detected (desktop or unsupported)"])
            self.btn_refresh.setEnabled(True)
            return
        rows = [("Charge", f'{b["percent"]}%'),
                ("Power", "Plugged in / charging" if b["plugged"] else "On battery"),
                ("Time remaining", b["remaining"])]
        self.table.setRowCount(len(rows))
        for r, (k, v) in enumerate(rows):
            key = None
            if k == "Charge":
                key = "ERROR" if b["percent"] < 20 else ("WARNING" if b["percent"] < 40 else "SUCCESS")
            self._row(r, [k, v], color_col=1, color_key=key)
        self.btn_refresh.setEnabled(True)

    def _devices_done(self, rows):
        self._headers(["Device", "Class", "Status"])
        if not rows:
            self.table.setRowCount(1)
            self._row(0, ["No problem devices found 🎉" if IS_WINDOWS
                          else "Not available on macOS", "", ""])
            self.btn_refresh.setEnabled(True)
            return
        self.table.setRowCount(len(rows))
        for r, d in enumerate(rows):
            self._row(r, [d["name"], d.get("class", ""), d.get("status", "")],
                      color_col=2, color_key="ERROR")
        self.btn_refresh.setEnabled(True)


# --------------------------------------------------------------------------- #
#  Page shell with segmented switcher
# --------------------------------------------------------------------------- #
class SystemHealthPage(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.workers = WorkerManager()

        root = QVBoxLayout(self)
        root.setContentsMargins(24, 22, 24, 22)
        root.setSpacing(14)

        title = QLabel("System Health")
        title.setProperty("role", "title")
        title.setStyleSheet("font-size: 24px; font-weight: 800;")
        sub = QLabel("Diagnose application, service, and event-log issues on this machine.")
        sub.setProperty("role", "subtitle")
        root.addWidget(title)
        root.addWidget(sub)

        # Segmented switcher
        seg = QHBoxLayout()
        seg.setSpacing(8)
        self.group = QButtonGroup(self)
        self.group.setExclusive(True)
        self.stack = QStackedWidget()
        for i, (label, icon) in enumerate([
                ("Application Health", "fa5s.th-list"),
                ("Service Health", "fa5s.cogs"),
                ("Event Logs", "fa5s.clipboard-list"),
                ("Connections & Hardware", "fa5s.microchip")]):
            b = QPushButton("  " + label)
            b.setCheckable(True)
            b.setCursor(Qt.PointingHandCursor)
            b.setFixedHeight(40)
            b.setStyleSheet(self._seg_style())
            iconkit.button(b, icon, role="TEXT_SECONDARY", size=14)
            b.clicked.connect(lambda checked, idx=i: self.stack.setCurrentIndex(idx))
            self.group.addButton(b, i)
            seg.addWidget(b)
            if i == 0:
                b.setChecked(True)
        seg.addStretch()
        root.addLayout(seg)

        self.stack.addWidget(_AppHealthTab(self.workers))
        self.stack.addWidget(_ServiceTab(self.workers))
        self.stack.addWidget(_EventTab(self.workers))
        self.stack.addWidget(_HardwareTab(self.workers))
        root.addWidget(self.stack, 1)

    def _seg_style(self):
        return (f"QPushButton {{ background-color: {theme.c('CARD_BG')}; color: "
                f"{theme.c('TEXT_SECONDARY')}; border: 1px solid {theme.c('BORDER')}; "
                f"border-radius: 12px; padding: 8px 16px; font-weight: 600; }}"
                f"QPushButton:hover {{ border: 1px solid {theme.c('ACCENT')}; }}"
                f"QPushButton:checked {{ background-color: {theme.c('ACCENT')}; "
                f"color: {theme.c('ON_ACCENT')}; border: none; }}")
