"""
app.py
Root QMainWindow: sidebar + header + stacked pages + footer.
Nav scope: Dashboard (operations), Network Tools, Reports, Settings.
"""

import logging

from PySide6.QtWidgets import (
    QMainWindow, QWidget, QHBoxLayout, QVBoxLayout, QStackedWidget
)

from widgets.header import Header
from widgets.sidebar import Sidebar
from widgets.footer import Footer
from core.constants import APP_NAME
from core.telemetry import telemetry

log = logging.getLogger("NetworkAI.App")


class NetworkAIApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(APP_NAME)
        self.setMinimumSize(1024, 680)

        central = QWidget()
        self.setCentralWidget(central)

        root = QHBoxLayout(central)
        root.setContentsMargins(14, 14, 14, 14)
        root.setSpacing(14)

        self.sidebar = Sidebar()
        root.addWidget(self.sidebar)

        right = QWidget()
        right.setObjectName("MainContentWrapper")
        right_layout = QVBoxLayout(right)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(14)

        self.header = Header()
        right_layout.addWidget(self.header)

        self.page_stack = QStackedWidget()
        right_layout.addWidget(self.page_stack, 1)

        self.footer = Footer()
        right_layout.addWidget(self.footer)

        root.addWidget(right, 1)

        self.header.toggle_sidebar_signal.connect(self.sidebar.toggle_state)
        self.sidebar.page_selected.connect(self._navigate_to)

        self._initialize_pages()

    def _initialize_pages(self):
        from pages.dashboard import DashboardPage
        from pages.tools import ToolsPage
        from pages.topology import TopologyPage
        from pages.system_health import SystemHealthPage
        from pages.repair import RepairPage
        from pages.system_tests import SystemTestsPage
        from pages.server_test import ServerTestPage
        from pages.assistant import ChatbotPage
        from pages.reports import ReportsPage
        from pages.settings import SettingsPage

        self.pages = {
            "dashboard": DashboardPage(),
            "tools":     ToolsPage(),
            "topology":  TopologyPage(),
            "health":    SystemHealthPage(),
            "repair":    RepairPage(),
            "systests":  SystemTestsPage(),
            "servertest": ServerTestPage(),
            "assistant": ChatbotPage(),
            "reports":   ReportsPage(),
            "settings":  SettingsPage(),
        }
        for page_widget in self.pages.values():
            self.page_stack.addWidget(page_widget)

        self._navigate_to("dashboard")

    def _navigate_to(self, page_id: str):
        page = self.pages.get(page_id)
        if page is not None:
            self.page_stack.setCurrentWidget(page)
            self.sidebar.select_page(page_id)
            telemetry.track_page(page_id)

    def closeEvent(self, event):
        for page in getattr(self, "pages", {}).values():
            mgr = getattr(page, "workers", None)
            if mgr is not None:
                try:
                    mgr.stop_all()
                except Exception:
                    log.exception("worker cleanup failed")
        telemetry.shutdown()
        super().closeEvent(event)
