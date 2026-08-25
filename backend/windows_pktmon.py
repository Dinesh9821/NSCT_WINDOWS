"""Windows inbox PktMon.sys capture — no third-party install.

Requires Administrator. Uses Microsoft's pktmon.exe (Windows 10 2004+).
Converts ETL to pcapng with ``pktmon etl2pcap`` (official converter).
"""
from __future__ import annotations

import os
import shutil
import subprocess
import time
from pathlib import Path
from typing import Optional


def is_windows_admin() -> bool:
    if os.name != "nt":
        return False
    try:
        import ctypes

        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _run(cmd, timeout: int, text: bool = True):
    kwargs = {}
    try:
        from backend.diagnostics import _no_window_kwargs
        kwargs.update(_no_window_kwargs())
    except Exception:
        pass
    try:
        return subprocess.run(cmd, capture_output=True, text=text, timeout=timeout, **kwargs)
    except subprocess.TimeoutExpired as exc:
        class _R:
            returncode = 124
            stdout = ""
            stderr = "timeout"
        r = _R()
        r.stdout = "" if text else b""
        r.stderr = "timeout" if text else b"timeout"
        return r
    path = shutil.which("pktmon")
    if path:
        return path
    for candidate in (
        os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "pktmon.exe"),
        r"C:\Windows\System32\pktmon.exe",
    ):
        if os.path.isfile(candidate):
            return candidate
    return None


def _valid_ipv4(host: str) -> bool:
    parts = (host or "").split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False


def build_filter_args(host: str, port: int, protocol: str) -> Optional[list[str]]:
    """Single AND filter. pktmon rejects combining IP + protocol + port incorrectly."""
    proto = (protocol or "").upper()
    if proto not in ("TCP", "UDP", "ICMP"):
        return None
    if not _valid_ipv4(host):
        return None
    if proto == "ICMP":
        return ["-i", host, "-t", "ICMP"]
    if port and int(port) > 0:
        return ["-i", host, "-p", str(int(port)), "-t", proto]
    return ["-i", host, "-t", proto]


def etl2pcap_commands(pktmon: str, etl: Path, pcapng: Path) -> list[list[str]]:
    """Official converter first; older aliases as fallbacks."""
    etl_s, out_s = str(etl), str(pcapng)
    return [
        [pktmon, "etl2pcap", etl_s, "--out", out_s],
        [pktmon, "pcapng", etl_s, "--out", out_s],
        [pktmon, "pcapng", etl_s, "-o", out_s],
    ]


def convert_etl_to_pcapng(pktmon: str, etl: Path, pcapng: Path, timeout: int = 120) -> tuple[bool, str]:
    """Use official ``pktmon etl2pcap <etl> --out <pcapng>`` (Win10 2004+)."""
    last_err = "etl2pcap produced empty or missing pcapng"
    for cmd in etl2pcap_commands(pktmon, etl, pcapng):
        try:
            r = _run(cmd, timeout=timeout)
        except subprocess.TimeoutExpired:
            last_err = "pktmon etl2pcap timed out"
            continue
        except OSError as exc:
            last_err = str(exc)
            continue
        if r.returncode != 0:
            last_err = f"etl2pcap failed ({r.returncode}): {(r.stderr or r.stdout or '').strip()[:400]}"
            continue
        if pcapng.is_file() and pcapng.stat().st_size >= 16:
            return True, ""
        last_err = "etl2pcap produced empty or missing pcapng"
    return False, last_err


class WindowsPktmonCapture:
    def __init__(self, target_path: Path, host: str, port: int, protocol: str) -> None:
        self.target_path = Path(target_path)
        self.host = host
        self.port = int(port or 0)
        self.protocol = protocol
        self._pktmon: Optional[str] = None
        self._etl: Optional[Path] = None
        self._started = False
        self._error = ""

    def start(self) -> tuple[bool, str]:
        if not is_windows_admin():
            return False, (
                "pktmon requires Administrator. Right-click the app → Run as administrator."
            )
        self._pktmon = find_pktmon()
        if not self._pktmon:
            return False, "pktmon.exe not found (needs Windows 10 2004+ / Windows 11)"

        self.target_path.parent.mkdir(parents=True, exist_ok=True)
        self._etl = self.target_path.with_suffix(".etl")
        try:
            if self._etl.exists():
                self._etl.unlink()
        except OSError:
            pass

        self._stop_silent()
        _run([self._pktmon, "filter", "remove"], timeout=15)
        filt = build_filter_args(self.host, self.port, self.protocol)
        if filt:
            fr = _run([self._pktmon, "filter", "add", *filt], timeout=15)
            if fr.returncode != 0:
                _run([self._pktmon, "filter", "remove"], timeout=10)
                err = (fr.stderr or fr.stdout or "").strip()[:300]
                return False, f"pktmon filter add failed: {err}"

        # --pkt-size 0 = full frames. --file-name writes ETL for later etl2pcap.
        start_attempts: list[list[str]] = [
            [
                self._pktmon,
                "start",
                "--capture",
                "--pkt-size",
                "0",
                "--file-name",
                str(self._etl),
            ],
            [
                self._pktmon,
                "start",
                "-c",
                "-f",
                str(self._etl),
            ],
        ]
        last_err = ""
        for cmd in start_attempts:
            r = _run(cmd, timeout=20)
            if r.returncode == 0:
                self._started = True
                time.sleep(0.15)
                return True, ""
            last_err = (r.stderr or r.stdout or "").strip()[:400]
            if "access is denied" in last_err.lower() or r.returncode == 5:
                return False, "pktmon start failed: Access is denied (Administrator required)"
        return False, f"pktmon start failed: {last_err}"

    def _stop_silent(self) -> None:
        if not self._pktmon:
            return
        try:
            _run([self._pktmon, "stop"], timeout=20)
        except Exception:
            pass

    def stop_and_convert(self) -> tuple[int, str]:
        if not self._pktmon:
            return 0, "pktmon not started"
        if not self._started:
            return 0, self._error or "pktmon not started"
        time.sleep(0.25)
        self._stop_silent()
        try:
            _run([self._pktmon, "filter", "remove"], timeout=15)
        except Exception:
            pass

        etl = self._etl
        if etl is None or not etl.is_file():
            return 0, "pktmon produced no ETL file"
        ok, err = convert_etl_to_pcapng(self._pktmon, etl, self.target_path)
        try:
            etl.unlink(missing_ok=True)
        except OSError:
            pass
        if not ok:
            return 0, err
        size = self.target_path.stat().st_size
        return max(size, 1), ""
