"""
backend/system_health.py

Troubleshooting data collection for laptop/desktop health. OS-aware: uses the
real Windows sources on Windows and the nearest macOS equivalents on macOS, with
graceful degradation everywhere. Pure logic — no UI. New, additive module;
nothing here changes existing behavior.

Sections:
  • Wi-Fi signal + recommendation
  • Application health (running apps, CPU/memory/disk hogs, installed software,
    startup programs, crash history)
  • Service health (critical services + restart)
  • Event-log analysis (channels, levels, and quick filters)
"""

import os
import re
import io
import csv
import glob
import time
import socket
import datetime
import logging

import psutil

from backend.diagnostics import run_command, IS_WINDOWS, IS_MAC

log = logging.getLogger("NetworkAI.SystemHealth")


def _parse_csv(text):
    if not text or text.strip() in ("", "No output available."):
        return []
    lines = [ln for ln in text.splitlines() if ln.strip()]
    try:
        return [dict(r) for r in csv.DictReader(io.StringIO("\n".join(lines)))]
    except Exception:
        return []


def _ps(command, timeout=60):
    """Run a PowerShell one-liner (Windows)."""
    return run_command(f'powershell -NoProfile -ExecutionPolicy Bypass -Command "{command}"',
                       timeout=timeout)


# --------------------------------------------------------------------------- #
#  Wi-Fi signal analyzer
# --------------------------------------------------------------------------- #
def wifi_signal():
    ssid, pct, rssi, rx = "", None, None, None

    if IS_WINDOWS:
        out = run_command("netsh wlan show interfaces")
        s = re.search(r"^\s*SSID\s*:\s*(.+)$", out, re.M)
        ssid = s.group(1).strip() if s else ""
        sg = re.search(r"Signal\s*:\s*(\d+)%", out)
        pct = int(sg.group(1)) if sg else None
        r = re.search(r"Receive rate \(Mbps\)\s*:\s*([\d.]+)", out)
        rx = r.group(1) if r else None
    elif IS_MAC:
        ap = ("/System/Library/PrivateFrameworks/Apple80211.framework/"
              "Versions/Current/Resources/airport -I")
        out = run_command(ap)
        r = re.search(r"agrCtlRSSI:\s*(-?\d+)", out)
        rssi = int(r.group(1)) if r else None
        s = re.search(r"\bSSID:\s*(.+)$", out, re.M)
        ssid = s.group(1).strip() if s else ""
        if rssi is None:  # airport deprecated on newer macOS — fall back
            sp = run_command("system_profiler SPAirPortDataType")
            r2 = re.search(r"Signal\s*/\s*Noise:\s*(-?\d+)\s*dBm", sp)
            rssi = int(r2.group(1)) if r2 else None
        if rssi is not None:
            pct = max(0, min(100, 2 * (rssi + 100)))  # dBm -> rough %

    if pct is None:
        status, reco = "neutral", ("Wi-Fi status unavailable — you may be on a wired "
                                   "connection, or elevated permissions are required.")
    elif pct >= 70:
        status, reco = "success", "Excellent signal. No action needed."
    elif pct >= 45:
        status, reco = "warning", ("Good, but not ideal. For heavy use move closer to the "
                                   "router or prefer the 5 GHz band.")
    elif pct >= 25:
        status, reco = "warning", ("Weak signal. Reduce distance/obstructions, avoid "
                                   "interference, or use 5 GHz / an extender.")
    else:
        status, reco = "error", ("Very weak. Relocate closer to the access point, check the "
                                 "band, or add a mesh node / extender.")

    return {"ssid": ssid or "—", "signal_pct": pct, "rssi_dbm": rssi,
            "rx_mbps": rx, "status": status, "recommendation": reco}


# --------------------------------------------------------------------------- #
#  Application health — processes
# --------------------------------------------------------------------------- #
def process_snapshot(settle=0.6):
    """
    One CPU-sampled snapshot of all processes. Returns a list of dicts:
        {pid, name, cpu, mem, rss, read_bytes, write_bytes}
    CPU is normalized to overall % (0–100 across all cores).
    """
    procs = []
    for p in psutil.process_iter(["pid", "name"]):
        try:
            p.cpu_percent(None)  # prime
        except Exception:
            pass
        procs.append(p)
    time.sleep(settle)

    ncpu = psutil.cpu_count() or 1
    rows = []
    for p in procs:
        try:
            with p.oneshot():
                cpu = p.cpu_percent(None) / ncpu
                mem = p.memory_percent()
                rss = p.memory_info().rss
                name = p.name()
                pid = p.pid
                rb = wb = None
                try:
                    io_c = p.io_counters()
                    rb, wb = io_c.read_bytes, io_c.write_bytes
                except Exception:
                    pass
            rows.append({"pid": pid, "name": name or "—",
                         "cpu": round(cpu, 1), "mem": round(mem, 1), "rss": rss,
                         "read_bytes": rb, "write_bytes": wb})
        except Exception:
            continue
    return rows


def high_cpu_processes(rows=None, n=10):
    rows = rows if rows is not None else process_snapshot()
    return sorted(rows, key=lambda r: r["cpu"], reverse=True)[:n]


def memory_hogs(rows=None, n=10):
    rows = rows if rows is not None else process_snapshot()
    return sorted(rows, key=lambda r: r["rss"], reverse=True)[:n]


def disk_intensive_processes(rows=None, n=10):
    rows = rows if rows is not None else process_snapshot()
    have_io = [r for r in rows if r.get("read_bytes") is not None]
    have_io.sort(key=lambda r: (r["read_bytes"] + r["write_bytes"]), reverse=True)
    return have_io[:n]


def running_applications(rows=None, n=150):
    rows = rows if rows is not None else process_snapshot()
    return sorted(rows, key=lambda r: r["name"].lower())[:n]


# --------------------------------------------------------------------------- #
#  Application health — inventory
# --------------------------------------------------------------------------- #
def installed_software(limit=400):
    if IS_WINDOWS:
        ps = ("Get-ItemProperty "
              "HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*,"
              "HKLM:\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* "
              "| Where-Object {$_.DisplayName} "
              "| Select-Object DisplayName,DisplayVersion "
              "| Sort-Object DisplayName -Unique | ConvertTo-Csv -NoTypeInformation")
        rows = _parse_csv(_ps(ps, timeout=70))
        return [{"name": r.get("DisplayName", ""), "version": r.get("DisplayVersion") or "—"}
                for r in rows][:limit]
    if IS_MAC:
        out = run_command("ls -1 /Applications 2>/dev/null")
        apps = sorted(ln[:-4] for ln in out.splitlines() if ln.endswith(".app"))
        return [{"name": a, "version": "—"} for a in apps][:limit]
    return []


def startup_programs():
    if IS_WINDOWS:
        ps = ("Get-CimInstance Win32_StartupCommand "
              "| Select-Object Name,Command,Location | ConvertTo-Csv -NoTypeInformation")
        rows = _parse_csv(_ps(ps, timeout=45))
        return [{"name": r.get("Name", ""), "command": r.get("Command", ""),
                 "location": r.get("Location", "")} for r in rows]
    if IS_MAC:
        items = []
        for d in ["~/Library/LaunchAgents", "/Library/LaunchAgents", "/Library/LaunchDaemons"]:
            p = os.path.expanduser(d)
            if os.path.isdir(p):
                for f in sorted(os.listdir(p)):
                    if f.endswith(".plist"):
                        items.append({"name": f[:-6], "command": "—", "location": d})
        try:
            out = run_command(
                "osascript -e 'tell application \"System Events\" to get the name of every login item'")
            for nm in [x.strip() for x in out.split(",") if x.strip()]:
                items.append({"name": nm, "command": "—", "location": "Login Items"})
        except Exception:
            pass
        return items
    return []


def crash_history(limit=25):
    if IS_WINDOWS:
        ps = ("Get-WinEvent -FilterHashtable @{LogName='Application'; Id=1000,1001} "
              f"-MaxEvents {limit} -ErrorAction SilentlyContinue "
              "| Select-Object TimeCreated,ProviderName,"
              "@{n='Msg';e={($_.Message -split \"`n\")[0]}} | ConvertTo-Csv -NoTypeInformation")
        rows = _parse_csv(_ps(ps, timeout=45))
        return [{"time": r.get("TimeCreated", ""), "app": r.get("ProviderName", ""),
                 "detail": r.get("Msg", "")} for r in rows]
    if IS_MAC:
        paths = (glob.glob(os.path.expanduser("~/Library/Logs/DiagnosticReports/*"))
                 + glob.glob("/Library/Logs/DiagnosticReports/*"))
        paths = [p for p in paths if p.endswith((".ips", ".crash", ".panic"))]
        paths.sort(key=lambda p: os.path.getmtime(p), reverse=True)
        res = []
        for p in paths[:limit]:
            t = datetime.datetime.fromtimestamp(os.path.getmtime(p)).strftime("%Y-%m-%d %H:%M")
            base = os.path.basename(p)
            app = re.split(r"[-_]", base)[0]
            res.append({"time": t, "app": app, "detail": base})
        return res
    return []


# --------------------------------------------------------------------------- #
#  Service health
# --------------------------------------------------------------------------- #
CRITICAL_SERVICES_WIN = [
    ("wuauserv", "Windows Update"),
    ("WinDefend", "Microsoft Defender"),
    ("Spooler", "Print Spooler"),
    ("BITS", "Background Intelligent Transfer"),
    ("Dnscache", "DNS Client"),
    ("Dhcp", "DHCP Client"),
    ("W32Time", "Windows Time"),
    ("TermService", "Remote Desktop"),
]

CRITICAL_SERVICES_MAC = [
    ("com.apple.mDNSResponder", "DNS (mDNSResponder)"),
    ("com.apple.timed", "Time Service"),
    ("org.cups.cupsd", "Printing (CUPS)"),
    ("com.apple.softwareupdated", "Software Update"),
    ("com.apple.screensharing", "Screen Sharing / Remote"),
]


def critical_services():
    if IS_WINDOWS:
        res = []
        for key, friendly in CRITICAL_SERVICES_WIN:
            q = run_command(f"sc query {key}")
            state = "Unknown"
            m = re.search(r"STATE\s*:\s*\d+\s+([A-Z_]+)", q)
            if m:
                state = {"RUNNING": "Running", "STOPPED": "Stopped"}.get(
                    m.group(1), m.group(1).title())
            c = run_command(f"sc qc {key}")
            startup = "—"
            sm = re.search(r"START_TYPE\s*:\s*\d+\s+([A-Z_]+)", c)
            if sm:
                startup = {"AUTO_START": "Automatic", "DEMAND_START": "Manual",
                           "DISABLED": "Disabled", "BOOT_START": "Boot",
                           "SYSTEM_START": "System"}.get(sm.group(1), sm.group(1).title())
            res.append({"key": key, "name": friendly, "status": state, "startup": startup})
        return res
    if IS_MAC:
        res = []
        for label, friendly in CRITICAL_SERVICES_MAC:
            out = run_command(f"launchctl print system/{label} 2>/dev/null")
            if "state = running" in out or re.search(r"pid = \d+", out):
                state = "Running"
            elif out and out != "No output available.":
                state = "Loaded"
            else:
                state = "Unknown"
            res.append({"key": label, "name": friendly, "status": state, "startup": "—"})
        return res
    return []


def restart_service(key):
    if IS_WINDOWS:
        stop = run_command(f"sc stop {key}", timeout=25)
        time.sleep(1.5)
        start = run_command(f"sc start {key}", timeout=25)
        if "Access is denied" in stop or "Access is denied" in start:
            return "Access denied — run the app as Administrator to restart services."
        head = start.splitlines()[0] if start else ""
        return f"Restart requested for {key}.  {head}"
    if IS_MAC:
        out = run_command(f"launchctl kickstart -k system/{key} 2>&1")
        if "Could not" in out or "Operation not permitted" in out or "Bootstrap" in out:
            return "Requires elevated privileges (sudo) to restart this service on macOS."
        return f"Restart requested for {key}."
    return "Service restart is not supported on this platform."


# --------------------------------------------------------------------------- #
#  Event-log analysis
# --------------------------------------------------------------------------- #
_LEVELS = {"Critical": "1", "Error": "2", "Warning": "3"}

_WIN_FILTERS = {
    "Disk Errors": ("System",
                    "*[System[Provider[@Name='disk' or @Name='Ntfs' or "
                    "@Name='Microsoft-Windows-Ntfs' or @Name='volmgr']]]"),
    "BSOD": ("System",
             "*[System[(EventID=1001)]][System[Provider"
             "[@Name='Microsoft-Windows-WER-SystemErrorReporting']]]"),
    "Driver Failures": ("System",
                        "*[System[Provider[@Name='Microsoft-Windows-Kernel-PnP'] "
                        "and (Level=1 or Level=2)]]"),
    "Kernel Errors": ("System",
                      "*[System[Provider[@Name='Microsoft-Windows-Kernel-General' or "
                      "@Name='Microsoft-Windows-Kernel-Power'] and (Level=1 or Level=2)]]"),
}

_MAC_FILTERS = {
    "Disk Errors": 'eventMessage CONTAINS[c] "I/O error" || eventMessage CONTAINS[c] "disk error"',
    "BSOD": 'eventMessage CONTAINS[c] "panic"',
    "Driver Failures": 'eventMessage CONTAINS[c] "kext" || eventMessage CONTAINS[c] "driver"',
    "Kernel Errors": 'process == "kernel" && messageType == "error"',
}

EVENT_CHANNELS = ["System", "Application", "Security"]
EVENT_LEVELS = ["All", "Critical", "Error", "Warning"]
QUICK_FILTERS = ["Disk Errors", "BSOD", "Driver Failures", "Kernel Errors"]


def event_logs(channel="System", level="All", count=50):
    if IS_WINDOWS:
        if level in _LEVELS:
            q = f"*[System[(Level={_LEVELS[level]})]]"
        else:
            q = "*"
        cmd = f'wevtutil qe {channel} /q:"{q}" /c:{count} /rd:true /f:text'
        return run_command(cmd, timeout=70)
    if IS_MAC:
        mt = {"Critical": "fault", "Error": "error", "Warning": "default"}.get(level, "error")
        pred = f'messageType == "{mt}"'
        cmd = (f"log show --style syslog --last 1h --predicate '{pred}' 2>/dev/null "
               f"| tail -n {count}")
        return run_command(cmd, timeout=70) or "No matching events."
    return "Event logs are not supported on this platform."


def event_filter(name, count=50):
    if IS_WINDOWS and name in _WIN_FILTERS:
        ch, q = _WIN_FILTERS[name]
        return run_command(f'wevtutil qe {ch} /q:"{q}" /c:{count} /rd:true /f:text', timeout=70)
    if IS_MAC and name in _MAC_FILTERS:
        pred = _MAC_FILTERS[name]
        return run_command(
            f"log show --style syslog --last 3h --predicate '{pred}' 2>/dev/null | tail -n {count}",
            timeout=70) or "No matching events."
    return f"'{name}' analysis is not available on this platform."


# --------------------------------------------------------------------------- #
#  Connections & hardware health  (added features)
# --------------------------------------------------------------------------- #
def active_connections(limit=300):
    """Active/listening sockets with owning process (psutil, cross-platform)."""
    rows = []
    try:
        conns = psutil.net_connections(kind="inet")
    except Exception:
        return rows
    names = {}
    for c in conns:
        try:
            proc = ""
            if c.pid:
                if c.pid not in names:
                    try:
                        names[c.pid] = psutil.Process(c.pid).name()
                    except Exception:
                        names[c.pid] = "—"
                proc = names[c.pid]
            laddr = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "—"
            raddr = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "—"
            proto = "TCP" if c.type == socket.SOCK_STREAM else "UDP"
            rows.append({"proto": proto, "laddr": laddr, "raddr": raddr,
                         "status": c.status, "pid": c.pid or "—", "process": proc or "—"})
        except Exception:
            continue
    # listening first, then established
    rows.sort(key=lambda r: (r["status"] != "LISTEN", r["status"]))
    return rows[:limit]


def listening_ports():
    return [r for r in active_connections(limit=1000) if r["status"] == "LISTEN"]


def disk_health():
    """Per-volume usage plus (Windows) SMART drive status."""
    vols = []
    for part in psutil.disk_partitions(all=False):
        try:
            u = psutil.disk_usage(part.mountpoint)
            vols.append({"device": part.device, "mount": part.mountpoint,
                         "fstype": part.fstype,
                         "total": u.total, "used": u.used, "free": u.free,
                         "percent": u.percent})
        except Exception:
            continue
    drives = []
    if IS_WINDOWS:
        out = _ps("Get-CimInstance Win32_DiskDrive | Select-Object Model,Status,Size "
                  "| ConvertTo-Csv -NoTypeInformation", timeout=30)
        for r in _parse_csv(out):
            drives.append({"model": r.get("Model", ""), "status": r.get("Status", ""),
                           "size": r.get("Size", "")})
    return {"volumes": vols, "drives": drives}


def battery_health():
    try:
        b = psutil.sensors_battery()
    except Exception:
        b = None
    if b is None:
        return {"present": False}
    secs = b.secsleft
    if secs is None or secs < 0:
        remaining = "—"
    else:
        remaining = f"{secs // 3600}h {(secs % 3600) // 60}m"
    return {"present": True, "percent": round(b.percent),
            "plugged": bool(b.power_plugged), "remaining": remaining}


def problem_devices():
    """Hardware with driver/status problems (Windows PnP)."""
    if IS_WINDOWS:
        out = _ps("Get-PnpDevice -Status Error,Degraded -ErrorAction SilentlyContinue "
                  "| Select-Object FriendlyName,Class,Status,InstanceId "
                  "| ConvertTo-Csv -NoTypeInformation", timeout=40)
        rows = _parse_csv(out)
        return [{"name": r.get("FriendlyName", ""), "class": r.get("Class", ""),
                 "status": r.get("Status", ""), "id": r.get("InstanceId", "")} for r in rows]
    return []  # macOS: no direct equivalent
