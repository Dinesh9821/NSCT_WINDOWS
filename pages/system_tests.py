"""
pages/system_tests.py

System Tests - the endpoint counterpart to Network Tools.

  * Run a full system health scan -> a 0-100 score (like Network Score) with a
    grade, plus every check's status, value and an actionable suggestion.
  * Cleanup Advisor -> measures reclaimable space in temp/cache/Recycle Bin and
    shows the exact command to reclaim it (measure-only; nothing is deleted here).

Additive page. Reuses the WorkerManager so the UI never blocks. Does not modify
any backend logic.
"""

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QFrame, QScrollArea,
    QTableWidget, QTableWidgetItem, QHeaderView, QAbstractItemView, QProgressBar,
    QSizePolicy, QMessageBox
)
from PySide6.QtCore import Qt
from PySide6.QtGui import QColor

from core.theme import theme, apply_soft_shadow
from core import iconkit
from core.workers import WorkerManager
from widgets.console import ConsoleWidget
from backend.system_score import (
    run_all_checks, health_score, cleanup_scan, run_cleanup, run_cleanup_all,
)

_STATUS = {"ok": "SUCCESS", "warn": "WARNING", "crit": "ERROR"}


class SystemTestsPage(QWidget):
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

        title = QLabel("System Tests")
        title.setProperty("role", "title")
        title.setStyleSheet("font-size: 24px; font-weight: 800;")
        sub = QLabel("Run endpoint health checks, get a system score with suggestions, "
                     "and see how much disk space is safe to reclaim.")
        sub.setProperty("role", "subtitle")
        sub.setWordWrap(True)
        self.body.addWidget(title)
        self.body.addWidget(sub)

        self._build_score_card()
        self._build_checks_card()
        self._build_cleanup_card()
        self.body.addStretch()

        scroll.setWidget(content)
        outer.addWidget(scroll)
        theme.changed.connect(self._on_theme)

    # ------------------------------------------------------------- builders
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

    def _build_score_card(self):
        frame, lay = self._card("SYSTEM HEALTH SCORE")
        row = QHBoxLayout()
        row.setSpacing(20)

        # big score number
        col = QVBoxLayout()
        self.lbl_score = QLabel("--")
        self.lbl_score.setStyleSheet("font-size: 46px; font-weight: 800;")
        self.lbl_grade = QLabel("Run a scan to score this machine")
        self.lbl_grade.setProperty("role", "secondary")
        col.addWidget(self.lbl_score)
        col.addWidget(self.lbl_grade)
        row.addLayout(col)

        # progress + summary
        mid = QVBoxLayout()
        mid.setSpacing(8)
        self.bar = QProgressBar()
        self.bar.setRange(0, 100)
        self.bar.setValue(0)
        self.bar.setTextVisible(False)
        self.bar.setFixedHeight(10)
        self._style_bar("ACCENT")
        self.lbl_summary = QLabel("")
        self.lbl_summary.setProperty("role", "secondary")
        self.lbl_summary.setWordWrap(True)
        mid.addWidget(self.bar)
        mid.addWidget(self.lbl_summary)
        mid.addStretch()
        row.addLayout(mid, 1)
        lay.addLayout(row)

        btns = QHBoxLayout()
        self.btn_scan = QPushButton("  Run Health Scan")
        self.btn_scan.setProperty("cls", "primary")
        self.btn_scan.setFixedHeight(44)
        self.btn_scan.setCursor(Qt.PointingHandCursor)
        iconkit.button(self.btn_scan, "fa5s.heartbeat", role="ON_ACCENT", size=14)
        self.btn_scan.clicked.connect(self._run_scan)
        btns.addWidget(self.btn_scan)
        btns.addStretch()
        lay.addLayout(btns)
        self.body.addWidget(frame)

    def _build_checks_card(self):
        frame, lay = self._card("HEALTH CHECKS & SUGGESTIONS")
        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(["Check", "Status", "Value", "Suggestion"])
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setAlternatingRowColors(True)
        self.table.setShowGrid(False)
        self.table.setWordWrap(True)
        self.table.setMinimumHeight(230)
        hh = self.table.horizontalHeader()
        hh.setStretchLastSection(True)
        hh.setSectionResizeMode(3, QHeaderView.Stretch)
        self._style_table()
        lay.addWidget(self.table)
        self.body.addWidget(frame)

    def _build_cleanup_card(self):
        frame, lay = self._card("CLEANUP ADVISOR")
        info = QLabel("Scans temp folders, caches and the Recycle Bin and reports how much "
                      "is safe to reclaim. Use the Clear buttons to free space - you'll be "
                      "asked to confirm before anything is deleted.")
        info.setProperty("role", "secondary")
        info.setWordWrap(True)
        lay.addWidget(info)

        row = QHBoxLayout()
        self.btn_clean = QPushButton("  Scan Reclaimable Space")
        self.btn_clean.setProperty("cls", "ghost")
        self.btn_clean.setFixedHeight(42)
        self.btn_clean.setCursor(Qt.PointingHandCursor)
        iconkit.button(self.btn_clean, "fa5s.broom", role="ACCENT", size=14)
        self.btn_clean.clicked.connect(self._run_cleanup)
        row.addWidget(self.btn_clean)

        self.btn_clean_all = QPushButton("  Clear All")
        self.btn_clean_all.setProperty("cls", "primary")
        self.btn_clean_all.setFixedHeight(42)
        self.btn_clean_all.setCursor(Qt.PointingHandCursor)
        self.btn_clean_all.setEnabled(False)
        iconkit.button(self.btn_clean_all, "fa5s.trash-alt", role="ON_ACCENT", size=14)
        self.btn_clean_all.clicked.connect(self._clear_all)
        row.addWidget(self.btn_clean_all)

        self.lbl_reclaim = QLabel("")
        self.lbl_reclaim.setStyleSheet("font-size: 16px; font-weight: 800;")
        row.addWidget(self.lbl_reclaim)
        row.addStretch()
        lay.addLayout(row)

        self.clean_table = QTableWidget(0, 4)
        self.clean_table.setHorizontalHeaderLabels(["Location", "Size", "Path", "Action"])
        self.clean_table.verticalHeader().setVisible(False)
        self.clean_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.clean_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.clean_table.setAlternatingRowColors(True)
        self.clean_table.setShowGrid(False)
        self.clean_table.setMinimumHeight(150)
        chh = self.clean_table.horizontalHeader()
        chh.setStretchLastSection(False)
        chh.setSectionResizeMode(2, QHeaderView.Stretch)
        self.clean_table.setColumnWidth(3, 110)
        lay.addWidget(self.clean_table)

        self.clean_console = ConsoleWidget(self, min_height=110)
        self.clean_console.set_text("Run a scan to see what's safe to reclaim.",
                                    theme.c("TEXT_SECONDARY"))
        lay.addWidget(self.clean_console)
        self.body.addWidget(frame)
        self._style_clean_table()
        self._clean_items = []

    # ------------------------------------------------------------- styling
    def _style_bar(self, key):
        self.bar.setStyleSheet(
            "QProgressBar {{ background-color: {elev}; border: none; border-radius: 5px; }}"
            "QProgressBar::chunk {{ background-color: {c}; border-radius: 5px; }}"
            .format(elev=theme.c("ELEVATED"), c=theme.c(key)))

    def _table_qss(self):
        return (
            "QTableWidget {{ background-color: {card}; alternate-background-color: {elev};"
            " color: {fg}; border: 1px solid {bd}; border-radius: 12px; gridline-color: {bd}; }}"
            "QTableWidget::item {{ padding: 7px 9px; border: none; }}"
            "QTableWidget::item:selected {{ background-color: {acc}; color: {on}; }}"
            "QHeaderView::section {{ background-color: {elev}; color: {sec};"
            " padding: 7px; border: none; font-weight: bold; }}"
            .format(card=theme.c("CARD_BG"), elev=theme.c("ELEVATED"), fg=theme.c("TEXT_PRIMARY"),
                    bd=theme.c("BORDER"), acc=theme.c("ACCENT"), on=theme.c("ON_ACCENT"),
                    sec=theme.c("TEXT_SECONDARY")))

    def _style_table(self):
        self.table.setStyleSheet(self._table_qss())

    def _style_clean_table(self):
        self.clean_table.setStyleSheet(self._table_qss())

    def _on_theme(self):
        self._style_table()
        self._style_clean_table()

    # ------------------------------------------------------------- scan
    def _run_scan(self):
        self.btn_scan.setEnabled(False)
        self.lbl_grade.setText("Scanning\u2026")
        self.lbl_summary.setText("Checking disk, temp, memory, CPU, uptime, updates and startup\u2026")
        self.workers.run(self._collect_health, on_finished=self._scan_done,
                         on_error=lambda e: self._scan_error(str(e)),
                         busy_text="Running system health scan\u2026")

    @staticmethod
    def _collect_health():
        checks = run_all_checks()
        return health_score(checks)

    def _scan_error(self, msg):
        self.btn_scan.setEnabled(True)
        self.lbl_grade.setText("Scan failed")
        self.lbl_summary.setText(msg)

    def _scan_done(self, h):
        self.btn_scan.setEnabled(True)
        h = h or {}
        score = h.get("score", 0)
        status = h.get("status", "warning")
        self.lbl_score.setText(str(score))
        self.lbl_score.setStyleSheet(
            "font-size: 46px; font-weight: 800; color: {};".format(theme.c(status)))
        self.lbl_grade.setText("{}  \u00b7  {} / 100".format(h.get("grade", "-"), score))
        self.bar.setValue(int(score))
        self._style_bar(status)

        issues = h.get("issues", [])
        if issues:
            self.lbl_summary.setText(
                "{} item(s) need attention: {}".format(
                    len(issues), ", ".join(i["label"] for i in issues)))
        else:
            self.lbl_summary.setText("All checks passed - this machine is in good shape.")

        checks = h.get("checks", [])
        self.table.setRowCount(len(checks))
        for r, c in enumerate(checks):
            key = _STATUS.get(c["status"], "TEXT_SECONDARY")
            cells = [c["label"], c["status"].upper(), c["value"],
                     c["suggestion"] or c["detail"]]
            for col, v in enumerate(cells):
                item = QTableWidgetItem(str(v))
                if col == 1:
                    item.setForeground(QColor(theme.c(key)))
                self.table.setItem(r, col, item)
        self.table.resizeRowsToContents()

    # ------------------------------------------------------------- cleanup
    def _run_cleanup(self):
        self.btn_clean.setEnabled(False)
        self.lbl_reclaim.setText("Scanning\u2026")
        self.clean_console.set_text("Measuring temp folders, caches and Recycle Bin\u2026",
                                    theme.c("ACCENT"))
        self.workers.run(cleanup_scan, on_finished=self._cleanup_done,
                         on_error=lambda e: self._cleanup_error(str(e)),
                         busy_text="Scanning reclaimable space\u2026")

    def _cleanup_error(self, msg):
        self.btn_clean.setEnabled(True)
        self.lbl_reclaim.setText("")
        self.clean_console.set_text("Cleanup scan failed: {}".format(msg), theme.c("ERROR"))

    def _cleanup_done(self, scan):
        self.btn_clean.setEnabled(True)
        scan = scan or {}
        items = scan.get("items", [])
        self._clean_items = items
        self.lbl_reclaim.setText("{} reclaimable".format(scan.get("total_human", "0 B")))
        self.lbl_reclaim.setStyleSheet(
            "font-size: 16px; font-weight: 800; color: {};".format(theme.c("ACCENT")))
        self.btn_clean_all.setEnabled(any(it.get("bytes") for it in items))

        self.clean_table.setRowCount(len(items))
        for r, it in enumerate(items):
            cells = [it["label"] + ("  (partial)" if it.get("capped") else ""),
                     it["human"], it["path"]]
            for col, v in enumerate(cells):
                item = QTableWidgetItem(str(v))
                if col == 1:
                    item.setForeground(QColor(theme.c("ACCENT")))
                self.clean_table.setItem(r, col, item)

            # --- Action column: a Clear button per location ---
            btn = QPushButton("Clear")
            btn.setCursor(Qt.PointingHandCursor)
            btn.setFixedHeight(30)
            btn.setStyleSheet(self._clear_btn_style(bool(it.get("bytes"))))
            btn.setEnabled(bool(it.get("bytes")))
            # bind this row's location so the click knows what to clear
            btn.clicked.connect(
                lambda _checked=False, label=it["label"], path=it["path"],
                       human=it["human"]: self._clear_one(label, path, human))
            self.clean_table.setCellWidget(r, 3, btn)

        note = scan.get("note", "")
        self.clean_console.set_text(
            (note + "\n\nClick Clear on any row to free that location, or Clear All to "
                    "reclaim everything. You'll be asked to confirm first.")
            if items else "Nothing to reclaim - the machine is already clean.",
            theme.c("TEXT_PRIMARY"))

    def _clear_btn_style(self, enabled):
        if not enabled:
            return ("QPushButton {{ background: {elev}; color: {sec}; border: none;"
                    " border-radius: 8px; font-size: 12px; }}").format(
                        elev=theme.c("ELEVATED"), sec=theme.c("TEXT_SECONDARY"))
        return ("QPushButton {{ background: {err}; color: #FFFFFF; border: none;"
                " border-radius: 8px; font-weight: 700; font-size: 12px; }}"
                "QPushButton:hover {{ background: {acc}; color: {on}; }}").format(
                    err=theme.c("ERROR"), acc=theme.c("ACCENT"), on=theme.c("ON_ACCENT"))

    # ------------------------------------------------------------- clear (with confirm)
    def _confirm(self, title, text):
        box = QMessageBox(self)
        box.setIcon(QMessageBox.Warning)
        box.setWindowTitle(title)
        box.setText(text)
        box.setStandardButtons(QMessageBox.Yes | QMessageBox.No)
        box.setDefaultButton(QMessageBox.No)
        return box.exec() == QMessageBox.Yes

    def _clear_one(self, label, path, human):
        if not self._confirm(
                "Are you sure to delete?",
                "This will permanently delete the contents of:\n\n"
                "{}  ({})\n{}\n\nThis frees disk space and is safe, but cannot be undone. "
                "Continue?".format(label, human, path)):
            return
        self.btn_clean_all.setEnabled(False)
        self.clean_console.set_text("Clearing {}\u2026".format(label), theme.c("ACCENT"))
        self.workers.run(run_cleanup, path,
                         on_finished=lambda res, l=label: self._clear_done(l, res),
                         on_error=lambda e: self._clear_error(str(e)),
                         busy_text="Clearing {}\u2026".format(label))

    def _clear_all(self):
        paths = [it["path"] for it in self._clean_items if it.get("bytes")]
        if not paths:
            return
        total = sum(it.get("bytes", 0) for it in self._clean_items if it.get("bytes"))
        from backend.system_score import _human  # local import to format the prompt
        if not self._confirm(
                "Are you sure to delete?",
                "This will permanently delete the contents of {} location(s), "
                "freeing about {}.\n\nThis is safe but cannot be undone. Continue?"
                .format(len(paths), _human(total))):
            return
        self.btn_clean_all.setEnabled(False)
        self.clean_console.set_text("Clearing all locations\u2026", theme.c("ACCENT"))
        self.workers.run(run_cleanup_all, paths,
                         on_finished=lambda res: self._clear_done("all locations", res),
                         on_error=lambda e: self._clear_error(str(e)),
                         busy_text="Clearing all reclaimable space\u2026")

    def _clear_error(self, msg):
        self.btn_clean_all.setEnabled(True)
        self.clean_console.set_text("Cleanup failed: {}".format(msg), theme.c("ERROR"))

    def _clear_done(self, label, res):
        res = res or {}
        if res.get("error") and not res.get("removed"):
            self.clean_console.set_text(
                "Could not clear {}: {}".format(label, res["error"]), theme.c("ERROR"))
        else:
            skipped = res.get("skipped", 0)
            msg = "Cleared {} - freed {} ({} items removed{}).".format(
                label, res.get("freed_human", "0 B"), res.get("removed", 0),
                ", {} in use/skipped".format(skipped) if skipped else "")
            self.clean_console.set_text(msg, theme.c("SUCCESS"))
        # rescan so the table reflects the freed space
        self.workers.run(cleanup_scan, on_finished=self._cleanup_done,
                         on_error=lambda e: None, busy_text="Rechecking\u2026")
