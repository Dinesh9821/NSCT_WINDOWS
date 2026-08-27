"""Platform elevation helpers used by Server Test.

Windows: UAC ShellExecuteW runas.
macOS: osascript with administrator privileges.
"""
from __future__ import annotations

import os
import sys


def is_windows() -> bool:
    return os.name == "nt" or sys.platform.startswith("win")


def is_macos() -> bool:
    return sys.platform == "darwin"


def is_admin() -> bool:
    if is_windows():
        from backend.windows_elevate import is_admin as win_admin
        return win_admin()
    if is_macos():
        from backend.macos_elevate import is_admin as mac_admin
        return mac_admin()
    try:
        return os.geteuid() == 0
    except Exception:
        return False


def relaunch_as_admin() -> tuple[bool, str]:
    if is_windows():
        from backend.windows_elevate import relaunch_as_admin as win_relaunch
        return win_relaunch()
    if is_macos():
        from backend.macos_elevate import relaunch_as_admin as mac_relaunch
        return mac_relaunch()
    return False, "Restart as Administrator is only used on Windows and macOS."


def capture_backend_hint() -> str:
    if is_windows():
        return "pktmon / SIO_RCVALL"
    if is_macos():
        return "BPF / tcpdump"
    return "AF_PACKET / tcpdump"
