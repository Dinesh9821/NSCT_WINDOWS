"""
core/signals.py
A tiny application-wide signal bus so any worker can drive the footer
progress bar without pages needing to know about each other.
"""

from PySide6.QtCore import QObject, Signal


class AppSignals(QObject):
    busy_started = Signal(str)   # emits a short status label
    busy_finished = Signal()


# Single shared instance imported everywhere.
app_signals = AppSignals()
