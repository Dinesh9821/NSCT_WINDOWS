"""
backend/repair.py

Powerful one-click network repair toolkit plus connectivity performance tests.
Windows-first (the repair actions are Windows netsh/ipconfig fixes); the
speed test and DNS benchmark are cross-platform.

REPAIR_ACTIONS is a list of dicts consumed by the Repair Center UI:
    {key, label, description, admin, run()}
"""

import re
import time
import socket
import logging

import requests

from backend.diagnostics import run_command, IS_WINDOWS
from core.constants import HTTP_TIMEOUT

log = logging.getLogger("NetworkAI.Repair")


# --------------------------------------------------------------------------- #
#  Repair actions
# --------------------------------------------------------------------------- #
def _flush_dns():
    if IS_WINDOWS:
        return run_command("ipconfig /flushdns")
    return run_command("dscacheutil -flushcache; sudo killall -HUP mDNSResponder 2>/dev/null")


def _renew_ip():
    if IS_WINDOWS:
        rel = run_command("ipconfig /release", timeout=40)
        ren = run_command("ipconfig /renew", timeout=60)
        return f"{rel}\n\n{ren}"
    return run_command("sudo ipconfig set en0 DHCP 2>/dev/null || ipconfig set en0 DHCP")


def _reset_winsock():
    if IS_WINDOWS:
        return run_command("netsh winsock reset")
    return "Winsock reset is Windows-only. (No macOS equivalent.)"


def _reset_tcpip():
    if IS_WINDOWS:
        out = run_command("netsh int ip reset")
        return out + "\n\nNote: a reboot is recommended for the TCP/IP reset to fully apply."
    return "TCP/IP stack reset is Windows-only. (No macOS equivalent.)"


def _clear_arp():
    if IS_WINDOWS:
        return run_command("netsh interface ip delete arpcache")
    return run_command("sudo arp -a -d 2>/dev/null || arp -a -d")


def _reset_firewall():
    if IS_WINDOWS:
        return run_command("netsh advfirewall reset")
    return "Firewall reset is Windows-only."


def _restart_adapters():
    if IS_WINDOWS:
        return run_command(
            'powershell -NoProfile -Command '
            '"Get-NetAdapter | Where-Object {$_.Status -ne \'Disabled\'} '
            '| Restart-NetAdapter -Confirm:$false"', timeout=60)
    return run_command("sudo ifconfig en0 down && sudo ifconfig en0 up 2>/dev/null "
                       "|| echo 'Requires sudo on macOS.'")


def _reset_windows_update():
    if not IS_WINDOWS:
        return "Windows Update reset is Windows-only."
    script = (
        "net stop wuauserv & net stop bits & net stop cryptsvc & "
        "ren %systemroot%\\SoftwareDistribution SoftwareDistribution.old & "
        "ren %systemroot%\\System32\\catroot2 catroot2.old & "
        "net start wuauserv & net start bits & net start cryptsvc")
    return run_command(script, timeout=90)


REPAIR_ACTIONS = [
    {"key": "flush_dns", "label": "Flush DNS Cache", "admin": False,
     "description": "Clears the DNS resolver cache (fixes stale/incorrect name resolution).",
     "run": _flush_dns},
    {"key": "renew_ip", "label": "Release & Renew IP", "admin": False,
     "description": "Releases and requests a fresh DHCP lease (fixes bad/expired IP).",
     "run": _renew_ip},
    {"key": "clear_arp", "label": "Clear ARP Cache", "admin": True,
     "description": "Flushes the ARP table (fixes stale MAC↔IP mappings).",
     "run": _clear_arp},
    {"key": "reset_winsock", "label": "Reset Winsock", "admin": True,
     "description": "Resets the Windows Sockets catalog (fixes corrupt network stack). Reboot after.",
     "run": _reset_winsock},
    {"key": "reset_tcpip", "label": "Reset TCP/IP Stack", "admin": True,
     "description": "Rewrites the TCP/IP registry to defaults (fixes deep connectivity issues).",
     "run": _reset_tcpip},
    {"key": "restart_adapters", "label": "Restart Network Adapters", "admin": True,
     "description": "Disables and re-enables all active adapters (fixes hung interfaces).",
     "run": _restart_adapters},
    {"key": "reset_firewall", "label": "Reset Firewall Rules", "admin": True,
     "description": "Restores Windows Firewall to default policy (fixes over-blocking).",
     "run": _reset_firewall},
    {"key": "reset_wu", "label": "Reset Windows Update", "admin": True,
     "description": "Clears the Windows Update cache and restarts its services (fixes stuck updates).",
     "run": _reset_windows_update},
]

_ACTIONS_BY_KEY = {a["key"]: a for a in REPAIR_ACTIONS}


def run_repair(key):
    action = _ACTIONS_BY_KEY.get(key)
    if not action:
        return f"Unknown repair action: {key}"
    try:
        out = action["run"]()
    except Exception as e:
        return f"Error: {e}"
    if isinstance(out, str) and ("Access is denied" in out or "requires elevation" in out.lower()
                                 or "administrator" in out.lower()):
        out += ("\n\n⚠ This fix needs elevated rights. Close the app and relaunch it as "
                "Administrator (right-click → Run as administrator), then retry.")
    return out or "Done."


# --------------------------------------------------------------------------- #
#  Speed test (download throughput + latency)
# --------------------------------------------------------------------------- #
def speed_test(bytes_to_pull=10_000_000):
    """
    Rough download throughput using Cloudflare's speed endpoint, plus latency.
    Returns {down_mbps, latency_ms, bytes, seconds, error}.
    """
    url = f"https://speed.cloudflare.com/__down?bytes={bytes_to_pull}"
    try:
        # latency ping (small request)
        t0 = time.perf_counter()
        requests.get("https://speed.cloudflare.com/__down?bytes=1000",
                     timeout=HTTP_TIMEOUT, verify=False)
        latency = round((time.perf_counter() - t0) * 1000)

        start = time.perf_counter()
        total = 0
        with requests.get(url, stream=True, timeout=30, verify=False) as r:
            for chunk in r.iter_content(chunk_size=65536):
                total += len(chunk)
        secs = max(1e-6, time.perf_counter() - start)
        mbps = round((total * 8) / secs / 1_000_000, 1)
        return {"down_mbps": mbps, "latency_ms": latency,
                "bytes": total, "seconds": round(secs, 2), "error": None}
    except Exception as e:
        return {"down_mbps": None, "latency_ms": None, "bytes": 0,
                "seconds": 0, "error": str(e)}


# --------------------------------------------------------------------------- #
#  DNS benchmark (which resolver is fastest for you)
# --------------------------------------------------------------------------- #
DNS_RESOLVERS = [
    ("Google", "8.8.8.8"),
    ("Cloudflare", "1.1.1.1"),
    ("Quad9", "9.9.9.9"),
    ("OpenDNS", "208.67.222.222"),
]


def dns_benchmark(sample_domains=("google.com", "microsoft.com", "cloudflare.com")):
    """
    Measure each resolver's average lookup time via nslookup. Returns a sorted
    list of {name, ip, avg_ms, ok} (fastest first) and marks the recommended one.
    """
    results = []
    for name, resolver in DNS_RESOLVERS:
        times = []
        ok = True
        for domain in sample_domains:
            t0 = time.perf_counter()
            out = run_command(f"nslookup {domain} {resolver}", timeout=8)
            dt = (time.perf_counter() - t0) * 1000
            if "timed out" in out.lower() or "can't find" in out.lower() or "Error" in out:
                ok = False
            times.append(dt)
        avg = round(sum(times) / len(times)) if times else None
        results.append({"name": name, "ip": resolver, "avg_ms": avg, "ok": ok})
    results.sort(key=lambda r: (r["avg_ms"] is None, r["avg_ms"] or 1e9))
    if results and results[0]["avg_ms"] is not None:
        results[0]["recommended"] = True
    return results
