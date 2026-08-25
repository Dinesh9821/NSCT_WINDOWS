"""
core/telemetry.py

Fire-and-forget usage telemetry for the Device and Network Tool desktop app.

Design rules (in priority order):
  1. NEVER block the UI            - everything happens on a daemon thread.
  2. NEVER crash the app           - every failure path is swallowed and logged.
  3. NEVER lose data when offline  - unsent events spool to disk and are
                                     re-sent on the next launch.
  4. Respect privacy               - can be disabled entirely, or hashed so the
                                     server only ever sees an opaque user id.

Nothing about the app's behaviour changes when the analytics server is down or
TELEMETRY_ENABLED is False.
"""

import os
import json
import time
import queue
import socket
import getpass
import hashlib
import logging
import platform
import threading
import datetime
import uuid

import requests

from core.constants import (
    APP_VERSION, log_dir,
    ANALYTICS_URL, ANALYTICS_KEY, TELEMETRY_ENABLED, TELEMETRY_ANONYMIZE,
)

log = logging.getLogger("NetworkAI.Telemetry")

_FLUSH_SECONDS = 15         # send at least this often
_BATCH_SIZE = 25            # ...or as soon as this many events are queued
_MAX_SPOOL = 5000           # cap the offline spool file
_HTTP_TIMEOUT = 6


def _utc():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class Telemetry:
    def __init__(self):
        self.enabled = bool(TELEMETRY_ENABLED and ANALYTICS_URL)
        self.session_id = uuid.uuid4().hex[:16]
        self._q = queue.Queue(maxsize=2000)
        self._thread = None
        self._stop = threading.Event()
        self._spool = os.path.join(log_dir(), "telemetry_spool.jsonl")

        try:
            raw_user = getpass.getuser() or "unknown"
        except Exception:
            raw_user = os.environ.get("USERNAME") or os.environ.get("USER") or "unknown"
        if "\\" in raw_user:
            raw_user = raw_user.split("\\")[-1]

        if TELEMETRY_ANONYMIZE:
            self.user_id = hashlib.sha256(raw_user.encode("utf-8")).hexdigest()[:16]
            self.user_name = self.user_id
        else:
            self.user_id = raw_user
            self.user_name = raw_user

        try:
            self.host = socket.gethostname()
        except Exception:
            self.host = "unknown"
        self.os_name = platform.system().lower()

    # ------------------------------------------------------------------ api
    def start(self):
        """Start the sender thread and emit session_start. Safe to call twice."""
        if not self.enabled or self._thread is not None:
            return
        self._thread = threading.Thread(target=self._run, name="telemetry",
                                        daemon=True)
        self._thread.start()
        self.track("session_start")

    def track(self, event_type, name=None, status="ok", duration_ms=None, **props):
        """Queue one event. Returns immediately; never raises."""
        if not self.enabled:
            return
        try:
            self._q.put_nowait({
                "ts": _utc(),
                "session_id": self.session_id,
                "user_id": self.user_id,
                "user_name": self.user_name,
                "host": self.host,
                "os": self.os_name,
                "app_version": APP_VERSION,
                "event_type": event_type,
                "name": name,
                "status": status,
                "duration_ms": duration_ms,
                "props": props or None,
            })
        except queue.Full:
            pass
        except Exception:
            log.debug("telemetry enqueue failed", exc_info=True)

    def track_task(self, name, status="ok", duration_ms=None, **props):
        self.track("task", name=name, status=status, duration_ms=duration_ms, **props)

    def track_page(self, name):
        self.track("page_view", name=name)

    def track_error(self, name, message=""):
        self.track("error", name=name, status="error", message=str(message)[:300])

    def shutdown(self, timeout=3.0):
        """Emit session_end, flush what we can, spool the rest. Never blocks long."""
        if not self.enabled:
            return
        try:
            self.track("session_end")
            self._stop.set()
            if self._thread is not None:
                self._thread.join(timeout=timeout)
            self._drain_to_spool()
        except Exception:
            log.debug("telemetry shutdown issue", exc_info=True)

    # --------------------------------------------------------------- worker
    def _run(self):
        self._resend_spool()
        batch = []
        last = time.time()
        while not self._stop.is_set():
            try:
                batch.append(self._q.get(timeout=1.0))
            except queue.Empty:
                pass
            except Exception:
                pass
            due = (time.time() - last) >= _FLUSH_SECONDS
            if batch and (len(batch) >= _BATCH_SIZE or due):
                if not self._post(batch):
                    self._spool_events(batch)
                batch = []
                last = time.time()
        # final flush on shutdown
        while True:
            try:
                batch.append(self._q.get_nowait())
            except Exception:
                break
        if batch and not self._post(batch):
            self._spool_events(batch)

    def _post(self, events):
        if not events:
            return True
        try:
            r = requests.post(ANALYTICS_URL, json={"events": events},
                              headers={"X-API-Key": ANALYTICS_KEY,
                                       "Content-Type": "application/json"},
                              timeout=_HTTP_TIMEOUT)
            if 200 <= r.status_code < 300:
                return True
            log.debug("telemetry rejected: HTTP %s", r.status_code)
            return False
        except Exception:
            return False   # offline / server down -> caller spools

    # --------------------------------------------------------------- spool
    def _spool_events(self, events):
        try:
            with open(self._spool, "a", encoding="utf-8") as f:
                for e in events:
                    f.write(json.dumps(e, ensure_ascii=False) + "\n")
            self._trim_spool()
        except Exception:
            log.debug("telemetry spool write failed", exc_info=True)

    def _drain_to_spool(self):
        pending = []
        while True:
            try:
                pending.append(self._q.get_nowait())
            except Exception:
                break
        if pending:
            self._spool_events(pending)

    def _trim_spool(self):
        try:
            if not os.path.exists(self._spool):
                return
            with open(self._spool, "r", encoding="utf-8") as f:
                lines = f.readlines()
            if len(lines) > _MAX_SPOOL:
                with open(self._spool, "w", encoding="utf-8") as f:
                    f.writelines(lines[-_MAX_SPOOL:])
        except Exception:
            pass

    def _resend_spool(self):
        """On startup, try to deliver anything captured while offline."""
        try:
            if not os.path.exists(self._spool):
                return
            with open(self._spool, "r", encoding="utf-8") as f:
                events = []
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        events.append(json.loads(line))
                    except Exception:
                        continue
            if not events:
                os.remove(self._spool)
                return
            ok = True
            for i in range(0, len(events), 100):
                if not self._post(events[i:i + 100]):
                    ok = False
                    break
            if ok:
                os.remove(self._spool)
                log.info("telemetry: re-sent %d spooled events", len(events))
        except Exception:
            log.debug("telemetry spool resend failed", exc_info=True)


# Module-level singleton used across the app.
telemetry = Telemetry()
