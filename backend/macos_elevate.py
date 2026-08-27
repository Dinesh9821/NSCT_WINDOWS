"""Relaunch this process with administrator privileges on macOS (UAC equivalent).

Packet capture uses /dev/bpf* and inbox /usr/sbin/tcpdump, which need root.
Uses osascript ``with administrator privileges`` — no third-party helper.
"""
from __future__ import annotations

import os
import shlex
import subprocess
import sys


def is_macos() -> bool:
    return sys.platform == "darwin"


def is_admin() -> bool:
    if not is_macos():
        return False
    try:
        return os.geteuid() == 0
    except Exception:
        return False


def relaunch_as_admin() -> tuple[bool, str]:
    """Start a new elevated copy. Caller should quit on success."""
    if not is_macos():
        return False, "macOS elevation is only used on Darwin."
    if is_admin():
        return False, "Already running as administrator (root)."
    cmd = _launch_shell_command()
    if not cmd:
        return False, "Could not build an elevated launch command."
    script = 'do shell script %s with administrator privileges' % _as_quote(cmd)
    try:
        proc = subprocess.run(
            ["osascript", "-e", script],
            capture_output=True,
            text=True,
            timeout=180,
        )
    except FileNotFoundError:
        return False, "osascript not found."
    except subprocess.TimeoutExpired:
        return False, "Administrator prompt timed out."
    except OSError as exc:
        return False, str(exc)
    if proc.returncode != 0:
        err = (proc.stderr or proc.stdout or "cancelled").strip()[:300]
        return False, "Elevation was cancelled or failed: %s" % err
    return True, ""


def _launch_shell_command() -> str:
    if getattr(sys, "frozen", False):
        exe = sys.executable
        marker = "/Contents/MacOS/"
        if marker in exe:
            app = exe.split(marker)[0]
            return "open -na %s" % shlex.quote(app)
        return "nohup %s >/dev/null 2>&1 &" % shlex.quote(exe)
    root = os.path.abspath(os.path.join(os.path.dirname(sys.argv[0] or "main.py"), "."))
    if os.path.isfile(os.path.join(os.getcwd(), "main.py")):
        root = os.getcwd()
    script = os.path.abspath(sys.argv[0] if sys.argv else os.path.join(root, "main.py"))
    py = sys.executable
    return (
        "cd {root} && export PYTHONPATH={root} && nohup {py} {script} "
        ">/tmp/nsct-macos.log 2>&1 &"
    ).format(
        root=shlex.quote(root),
        py=shlex.quote(py),
        script=shlex.quote(script),
    )


def _as_quote(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'
