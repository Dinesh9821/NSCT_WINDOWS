"""Relaunch this process with Administrator rights (Windows UAC).

Packet capture on Windows (pktmon / SIO_RCVALL) requires elevation.
This uses ShellExecuteW with the runas verb — no third-party helper.
"""
from __future__ import annotations

import os
import sys


def is_windows() -> bool:
    return os.name == "nt"


def is_admin() -> bool:
    if not is_windows():
        return False
    try:
        import ctypes

        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def relaunch_as_admin() -> tuple[bool, str]:
    """Start a new elevated copy of this app. Caller should quit on success."""
    if not is_windows():
        return False, "Elevation is only used on Windows."
    if is_admin():
        return False, "Already running as Administrator."
    try:
        import ctypes
    except Exception as exc:
        return False, str(exc)

    exe = sys.executable
    if getattr(sys, "frozen", False):
        params = " ".join(_quote(a) for a in sys.argv[1:])
    else:
        script = os.path.abspath(sys.argv[0] if sys.argv else "main.py")
        params = " ".join([_quote(script)] + [_quote(a) for a in sys.argv[1:]])

    rc = ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, params, None, 1)
    # ShellExecuteW returns > 32 on success.
    if rc <= 32:
        return False, "UAC elevation was cancelled or failed (code %s)." % rc
    return True, ""


def _quote(value: str) -> str:
    if not value:
        return '""'
    if any(ch in value for ch in ' \t"'):
        return '"' + value.replace('"', '\\"') + '"'
    return value
