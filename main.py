
"""
main.py
Application bootstrapper: logging, DPI, Nord theme wiring, centering, event loop.
"""

import os
import sys
import logging

from PySide6.QtWidgets import QApplication
from PySide6.QtGui import QGuiApplication, QCursor
from PySide6.QtCore import Qt

from core.constants import log_dir
from core.theme import theme
from core.telemetry import telemetry


def _configure_logging():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler(os.path.join(log_dir(), "app.log"), encoding="utf-8"),
        ],
    )


def center_window(window):
    """Size to a comfortable fraction of the active screen and center it."""
    screen = QGuiApplication.screenAt(QCursor.pos()) or QGuiApplication.primaryScreen()
    avail = screen.availableGeometry()
    w = min(int(avail.width() * 0.86), 1600)
    h = min(int(avail.height() * 0.88), 1000)
    w = max(min(w, avail.width()), min(1024, avail.width()))
    h = max(min(h, avail.height()), min(680, avail.height()))
    window.resize(w, h)
    frame = window.frameGeometry()
    frame.moveCenter(avail.center())
    window.move(frame.topLeft())


def main():
    _configure_logging()

    QApplication.setHighDpiScaleFactorRoundingPolicy(
        Qt.HighDpiScaleFactorRoundingPolicy.PassThrough)
    # Required by QtWebEngine (used for the pyvis Live Topology view).
    # Must be set before the QApplication is constructed.
    QApplication.setAttribute(Qt.ApplicationAttribute.AA_ShareOpenGLContexts, True)

    app = QApplication(sys.argv)
    app.setStyle("Fusion")

    telemetry.start()   # usage analytics (no-op if disabled/unreachable)

    # Apply Nord theme, and re-apply the whole stylesheet whenever it toggles.
    app.setStyleSheet(theme.qss())
    theme.changed.connect(lambda: app.setStyleSheet(theme.qss()))

    try:
        from app import NetworkAIApp
        window = NetworkAIApp()
    except Exception:
        import traceback
        tb = traceback.format_exc()
        logging.getLogger("NetworkAI").error("Startup failed:\n%s", tb)
        try:
            from PySide6.QtWidgets import QMessageBox
            QMessageBox.critical(
                None, "Device and Network Tool — Startup Error",
                "The application failed to start.\n\nRoot cause:\n\n" + tb[-1600:]
                + "\n\nTip: if you extracted over an old copy, delete all __pycache__ "
                  "folders (or extract fresh into an empty folder) and try again.")
        except Exception:
            print(tb)
        sys.exit(1)

    center_window(window)
    window.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
