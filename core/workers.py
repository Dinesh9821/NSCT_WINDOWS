"""
core/workers.py
Thread-safe concurrency execution engine.
Prevents GUI freezing during blocking I/O and subprocess calls,
and reports activity to the global footer progress bar.
"""

import time
import logging
import traceback

from PySide6.QtCore import QThread, Signal, QObject

from core.signals import app_signals
from core.telemetry import telemetry

log = logging.getLogger("NetworkAI.Worker")


class WorkerSignals(QObject):
    finished = Signal(object)
    error = Signal(str)
    progress = Signal(str)


class TaskWorker(QThread):
    """Generic QThread worker for executing arbitrary backend functions."""

    def __init__(self, fn, *args, **kwargs):
        super().__init__()
        self.fn = fn
        self.args = args
        self.kwargs = kwargs
        self.signals = WorkerSignals()
        self.is_running = True

    def run(self):
        try:
            result = self.fn(*self.args, **self.kwargs)
            if self.is_running:
                self.signals.finished.emit(result)
        except Exception as e:
            log.exception("Worker task failed: %s", getattr(self.fn, "__name__", self.fn))
            if self.is_running:
                self.signals.error.emit(f"System Error: {e}\n{traceback.format_exc()}")

    def stop(self):
        self.is_running = False
        self.quit()
        self.wait(2000)


class WorkerManager:
    """
    Keeps strong references to workers, cleans them up when finished,
    and drives the global footer progress bar via app_signals.
    """

    def __init__(self):
        self._workers = []

    def run(self, fn, *args, on_finished=None, on_error=None, busy_text=None, **kwargs):
        worker = TaskWorker(fn, *args, **kwargs)

        # --- usage analytics: every task in the app flows through here ---
        task_name = getattr(fn, "__name__", str(fn))
        started = time.perf_counter()

        def _track(status):
            try:
                telemetry.track_task(
                    task_name, status=status,
                    duration_ms=int((time.perf_counter() - started) * 1000))
            except Exception:
                pass

        if on_finished:
            worker.signals.finished.connect(on_finished)
        if on_error:
            worker.signals.error.connect(on_error)
        worker.signals.finished.connect(lambda *_: _track("ok"))
        worker.signals.error.connect(lambda *_: _track("error"))

        app_signals.busy_started.emit(busy_text or "Working…")
        worker.finished.connect(lambda w=worker: self._on_done(w))
        self._workers.append(worker)
        worker.start()
        return worker

    def _on_done(self, worker):
        app_signals.busy_finished.emit()
        try:
            self._workers.remove(worker)
        except ValueError:
            pass

    def stop_all(self):
        for worker in list(self._workers):
            worker.stop()
        self._workers.clear()
