"""
backend/system_score.py

Desktop-engineer style system health scoring + checks + cleanup advisor.

Everything here is READ-ONLY by default. The cleanup advisor only *measures*
reclaimable space and hands back the exact command to run - it never deletes
anything on its own (that stays a deliberate, user-initiated action in the UI).

Windows-first, with macOS/Linux fallbacks so the same code runs on the dev's
Mac. No existing backend logic is modified; this is a new, additive module.
"""

import os
import re
import sys
import glob
import shutil
import logging
import datetime

import psutil

from backend.diagnostics import run_command, IS_WINDOWS, IS_MAC

log = logging.getLogger("NetworkAI.SystemScore")


# --------------------------------------------------------------------------- #
#  Helpers
# --------------------------------------------------------------------------- #
def _human(n):
    n = float(n or 0)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024:
            return "{:.0f} {}".format(n, unit) if unit == "B" else "{:.1f} {}".format(n, unit)
        n /= 1024
    return "{:.1f} PB".format(n)


def _dir_size(path, max_seconds=4.0):
    """
    Best-effort recursive size. Time-boxed so a giant tree never stalls the
    worker. Returns (bytes, file_count, capped_bool).
    """
    total = 0
    files = 0
    capped = False
    start = datetime.datetime.now()
    try:
        for root, _dirs, names in os.walk(path, topdown=True, onerror=lambda e: None):
            for n in names:
                try:
                    total += os.path.getsize(os.path.join(root, n))
                    files += 1
                except (OSError, ValueError):
                    continue
            if (datetime.datetime.now() - start).total_seconds() > max_seconds:
                capped = True
                break
    except Exception:
        pass
    return total, files, capped


def _clamp(v, lo=0, hi=100):
    return max(lo, min(hi, v))


# --------------------------------------------------------------------------- #
#  Locations that are safe to measure / clean per-OS
# --------------------------------------------------------------------------- #
def _temp_locations():
    """(label, path, clean_command) for junk that is safe to clear."""
    locs = []
    if IS_WINDOWS:
        user_temp = os.environ.get("TEMP") or os.path.join(
            os.environ.get("LOCALAPPDATA", ""), "Temp")
        win_temp = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "Temp")
        prefetch = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "Prefetch")
        wu_cache = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"),
                                "SoftwareDistribution", "Download")
        locs = [
            ("User temp", user_temp,
             'del /q /f /s "%TEMP%\\*" 2>nul & for /d %i in ("%TEMP%\\*") do @rd /s /q "%i" 2>nul'),
            ("Windows temp", win_temp,
             'del /q /f /s "%SystemRoot%\\Temp\\*" 2>nul'),
            ("Prefetch", prefetch,
             'del /q /f "%SystemRoot%\\Prefetch\\*" 2>nul'),
            ("Windows Update cache", wu_cache,
             'net stop wuauserv & rd /s /q "%SystemRoot%\\SoftwareDistribution\\Download" & net start wuauserv'),
        ]
    elif IS_MAC:
        home = os.path.expanduser("~")
        locs = [
            ("User temp", os.environ.get("TMPDIR", "/tmp"), 'rm -rf "$TMPDIR"/* 2>/dev/null'),
            ("User caches", os.path.join(home, "Library", "Caches"),
             'rm -rf ~/Library/Caches/* 2>/dev/null'),
            ("Saved application state", os.path.join(home, "Library", "Saved Application State"),
             'rm -rf ~/Library/"Saved Application State"/* 2>/dev/null'),
        ]
    else:
        home = os.path.expanduser("~")
        locs = [
            ("Temp", "/tmp", 'rm -rf /tmp/* 2>/dev/null'),
            ("User cache", os.path.join(home, ".cache"), 'rm -rf ~/.cache/* 2>/dev/null'),
        ]
    return [(lbl, p, cmd) for (lbl, p, cmd) in locs if p]


def _browser_cache_locations():
    out = []
    home = os.path.expanduser("~")
    if IS_WINDOWS:
        la = os.environ.get("LOCALAPPDATA", "")
        candidates = {
            "Chrome cache": os.path.join(la, r"Google\Chrome\User Data\Default\Cache"),
            "Edge cache": os.path.join(la, r"Microsoft\Edge\User Data\Default\Cache"),
        }
    elif IS_MAC:
        candidates = {
            "Chrome cache": os.path.join(home, "Library/Caches/Google/Chrome"),
            "Safari cache": os.path.join(home, "Library/Caches/com.apple.Safari"),
        }
    else:
        candidates = {"Chrome cache": os.path.join(home, ".cache/google-chrome")}
    for label, path in candidates.items():
        if path and os.path.isdir(path):
            out.append((label, path))
    return out


# --------------------------------------------------------------------------- #
#  Individual health checks
#  Each returns: {key, label, status(ok|warn|crit), score(0-100), value, detail, suggestion}
# --------------------------------------------------------------------------- #
def check_disk():
    try:
        system_drive = os.environ.get("SystemDrive", "C:") + "\\" if IS_WINDOWS else "/"
        u = psutil.disk_usage(system_drive)
        free_pct = 100.0 - u.percent
        if free_pct >= 20:
            status, score = "ok", 100
        elif free_pct >= 10:
            status, score = "warn", 60
        else:
            status, score = "crit", 20
        sug = ""
        if status != "ok":
            sug = ("Free up disk space - run the Cleanup Advisor, empty the Recycle Bin, "
                   "and uninstall unused apps.")
        return {"key": "disk", "label": "Disk free space", "status": status, "score": score,
                "value": "{:.0f}% free".format(free_pct),
                "detail": "{} free of {} on system drive".format(_human(u.free), _human(u.total)),
                "suggestion": sug}
    except Exception as e:
        return _err("disk", "Disk free space", e)


def check_temp_bloat():
    """The signal the user specifically asked for: temp/cache bloat."""
    try:
        total = 0
        files = 0
        parts = []
        for label, path, _cmd in _temp_locations():
            if os.path.isdir(path):
                sz, fc, _ = _dir_size(path, max_seconds=3.0)
                total += sz
                files += fc
                if sz:
                    parts.append("{}: {}".format(label, _human(sz)))
        gb = total / (1024 ** 3)
        if gb < 1.0:
            status, score = "ok", 100
        elif gb < 3.0:
            status, score = "warn", 65
        else:
            status, score = "crit", 30
        sug = ""
        if status != "ok":
            sug = ("{} of temporary/cache files across {:,} files - clearing these is safe "
                   "and usually speeds up the machine.".format(_human(total), files))
        return {"key": "temp", "label": "Temp & cache bloat", "status": status, "score": score,
                "value": _human(total),
                "detail": " · ".join(parts) if parts else "Temp folders are clean",
                "suggestion": sug}
    except Exception as e:
        return _err("temp", "Temp & cache bloat", e)


def check_memory():
    try:
        vm = psutil.virtual_memory()
        used = vm.percent
        if used < 75:
            status, score = "ok", 100
        elif used < 90:
            status, score = "warn", 55
        else:
            status, score = "crit", 25
        sug = ""
        if status != "ok":
            sug = ("Memory is under pressure ({:.0f}% used). Close unused browser tabs/apps; "
                   "check the Memory Hogs list in System Health.".format(used))
        return {"key": "memory", "label": "Memory pressure", "status": status, "score": score,
                "value": "{:.0f}% used".format(used),
                "detail": "{} used of {}".format(_human(vm.total - vm.available), _human(vm.total)),
                "suggestion": sug}
    except Exception as e:
        return _err("memory", "Memory pressure", e)


def check_cpu():
    try:
        load = psutil.cpu_percent(interval=0.6)
        if load < 70:
            status, score = "ok", 100
        elif load < 90:
            status, score = "warn", 60
        else:
            status, score = "crit", 30
        sug = ""
        if status != "ok":
            sug = ("Sustained high CPU ({:.0f}%). Check the High CPU list in System Health for a "
                   "runaway process.".format(load))
        return {"key": "cpu", "label": "CPU load", "status": status, "score": score,
                "value": "{:.0f}%".format(load),
                "detail": "{} logical cores".format(psutil.cpu_count() or "?"),
                "suggestion": sug}
    except Exception as e:
        return _err("cpu", "CPU load", e)


def check_uptime():
    try:
        boot = datetime.datetime.fromtimestamp(psutil.boot_time())
        days = (datetime.datetime.now() - boot).days
        if days < 3:
            status, score = "ok", 100
        elif days < 7:
            status, score = "warn", 70
        else:
            status, score = "crit", 45
        sug = ""
        if status != "ok":
            sug = ("Up for {} days without a restart. A reboot clears memory leaks and applies "
                   "pending updates.".format(days))
        return {"key": "uptime", "label": "Uptime / reboot", "status": status, "score": score,
                "value": "{} days".format(days),
                "detail": "Last boot {}".format(boot.strftime("%Y-%m-%d %H:%M")),
                "suggestion": sug}
    except Exception as e:
        return _err("uptime", "Uptime / reboot", e)


def check_pending_reboot():
    """Windows: registry/file markers that a reboot is pending."""
    if not IS_WINDOWS:
        return {"key": "reboot_pending", "label": "Pending reboot", "status": "ok", "score": 100,
                "value": "n/a", "detail": "Not applicable on this OS", "suggestion": ""}
    try:
        ps = (
            "$p=$false;"
            "if(Test-Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Component Based Servicing\\RebootPending'){$p=$true};"
            "if(Test-Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update\\RebootRequired'){$p=$true};"
            "if(Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager' -Name PendingFileRenameOperations -ErrorAction SilentlyContinue){$p=$true};"
            "Write-Output $p")
        out = run_command('powershell -NoProfile -Command "{}"'.format(ps), timeout=20)
        pending = "true" in out.lower()
        if pending:
            return {"key": "reboot_pending", "label": "Pending reboot", "status": "warn",
                    "score": 60, "value": "Yes",
                    "detail": "Windows is waiting on a restart to finish updates/servicing",
                    "suggestion": "Save work and restart to complete pending updates."}
        return {"key": "reboot_pending", "label": "Pending reboot", "status": "ok", "score": 100,
                "value": "No", "detail": "No reboot is pending", "suggestion": ""}
    except Exception as e:
        return _err("reboot_pending", "Pending reboot", e)


def check_startup_load():
    """Too many startup programs = slow logons."""
    try:
        count = 0
        if IS_WINDOWS:
            out = run_command(
                'powershell -NoProfile -Command "(Get-CimInstance Win32_StartupCommand).Count"',
                timeout=25)
            m = re.search(r"\d+", out or "")
            count = int(m.group(0)) if m else 0
        elif IS_MAC:
            out = run_command(
                "osascript -e 'tell application \"System Events\" to count login items' 2>/dev/null")
            m = re.search(r"\d+", out or "")
            count = int(m.group(0)) if m else 0
        if count <= 12:
            status, score = "ok", 100
        elif count <= 25:
            status, score = "warn", 65
        else:
            status, score = "crit", 40
        sug = ""
        if status != "ok":
            sug = ("{} startup items are slowing logon. Disable the ones you don't need from "
                   "System Health - Startup Programs.".format(count))
        return {"key": "startup", "label": "Startup programs", "status": status, "score": score,
                "value": "{} items".format(count),
                "detail": "Programs launching at login", "suggestion": sug}
    except Exception as e:
        return _err("startup", "Startup programs", e)


def _err(key, label, e):
    return {"key": key, "label": label, "status": "warn", "score": 80,
            "value": "n/a", "detail": "Check unavailable: {}".format(e), "suggestion": ""}


# Weighting: how much each check contributes to the overall score.
_WEIGHTS = {
    "disk": 22, "temp": 18, "memory": 16, "cpu": 12,
    "uptime": 10, "reboot_pending": 10, "startup": 12,
}


def run_all_checks():
    return [
        check_disk(), check_temp_bloat(), check_memory(), check_cpu(),
        check_uptime(), check_pending_reboot(), check_startup_load(),
    ]


def health_score(checks=None):
    """
    Weighted 0-100 system health score, plus grade and the checks that dragged
    it down. Mirrors the network-score idea but for the endpoint itself.
    """
    checks = checks if checks is not None else run_all_checks()
    total_w = 0
    acc = 0.0
    for c in checks:
        w = _WEIGHTS.get(c["key"], 8)
        total_w += w
        acc += (c["score"] / 100.0) * w
    score = int(round((acc / total_w) * 100)) if total_w else 0
    score = _clamp(score)

    if score >= 85:
        grade, status = "Excellent", "success"
    elif score >= 70:
        grade, status = "Good", "success"
    elif score >= 50:
        grade, status = "Fair", "warning"
    else:
        grade, status = "Needs attention", "error"

    issues = [c for c in checks if c["status"] != "ok"]
    issues.sort(key=lambda c: c["score"])
    return {
        "score": score,
        "grade": grade,
        "status": status,
        "checks": checks,
        "issues": issues,
        "suggestions": [c["suggestion"] for c in issues if c.get("suggestion")],
        "generated_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }


# --------------------------------------------------------------------------- #
#  Cleanup advisor  (measure only - never deletes)
# --------------------------------------------------------------------------- #
def _recycle_bin_size():
    if not IS_WINDOWS:
        return None
    try:
        out = run_command(
            'powershell -NoProfile -Command "'
            '$s=0; Get-ChildItem -Path (\'C:\\$Recycle.Bin\') -Recurse -Force '
            '-ErrorAction SilentlyContinue | ForEach-Object { $s += $_.Length }; Write-Output $s"',
            timeout=25)
        m = re.search(r"\d+", out or "")
        return int(m.group(0)) if m else None
    except Exception:
        return None


def cleanup_scan():
    """
    Scan everything that is safe to reclaim and return a per-item breakdown plus
    a total. Includes the exact command for each item so the user (or an admin)
    can act with full transparency.
    """
    items = []
    total = 0

    for label, path, cmd in _temp_locations():
        if os.path.isdir(path):
            sz, fc, capped = _dir_size(path)
            total += sz
            items.append({"label": label, "path": path, "bytes": sz,
                          "human": _human(sz), "files": fc, "capped": capped,
                          "command": cmd})

    for label, path in _browser_cache_locations():
        sz, fc, capped = _dir_size(path)
        total += sz
        clean = ('rd /s /q "{}"'.format(path) if IS_WINDOWS
                 else 'rm -rf "{}"'.format(path))
        items.append({"label": label, "path": path, "bytes": sz, "human": _human(sz),
                      "files": fc, "capped": capped, "command": clean})

    rb = _recycle_bin_size()
    if rb is not None:
        total += rb
        items.append({"label": "Recycle Bin", "path": "C:\\$Recycle.Bin", "bytes": rb,
                      "human": _human(rb), "files": None, "capped": False,
                      "command": 'powershell -NoProfile -Command "Clear-RecycleBin -Force"'})

    items.sort(key=lambda x: x["bytes"], reverse=True)

    # Suggested one-shot command for the biggest safe wins (temp only).
    if IS_WINDOWS:
        one_shot = ('cleanmgr /sagerun:1   ::  or manually: '
                    'del /q /f /s "%TEMP%\\*"')
    elif IS_MAC:
        one_shot = 'rm -rf "$TMPDIR"/* ~/Library/Caches/* 2>/dev/null'
    else:
        one_shot = 'rm -rf /tmp/* ~/.cache/* 2>/dev/null'

    return {
        "total_bytes": total,
        "total_human": _human(total),
        "items": items,
        "one_shot": one_shot,
        "note": ("These are safe to remove; apps will simply rebuild caches as needed. "
                 "The tool measured this - it did not delete anything."),
        "generated_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }


# --------------------------------------------------------------------------- #
#  Cleanup execution (ONLY runs when the user explicitly confirms in the UI)
# --------------------------------------------------------------------------- #
# Whitelist of path prefixes we will ever delete inside. A path must live under
# one of these roots or the delete is refused - defence against a bad argument
# ever wiping something important.
def _safe_roots():
    roots = []
    for _lbl, path, _cmd in _temp_locations():
        if path:
            roots.append(os.path.normcase(os.path.abspath(path)))
    for _lbl, path in _browser_cache_locations():
        roots.append(os.path.normcase(os.path.abspath(path)))
    return roots


def _is_within_safe_root(path):
    try:
        target = os.path.normcase(os.path.abspath(path))
    except Exception:
        return False
    for root in _safe_roots():
        if target == root or target.startswith(root + os.sep):
            return True
    return False


def run_cleanup(path):
    """
    Delete the *contents* of a single scanned location and report bytes freed.

    Safety rules:
      * `path` MUST be inside one of the known temp/cache roots (whitelist).
        Anything else is refused outright.
      * We remove the items *inside* the folder, never the folder itself.
      * Files in use (locked) are skipped, not fatal.
      * This function is only ever reached after an explicit Yes in the UI.

    Returns {ok, freed_bytes, freed_human, removed, skipped, error}.
    """
    result = {"ok": False, "freed_bytes": 0, "freed_human": "0 B",
              "removed": 0, "skipped": 0, "error": None, "path": path}

    if not path or not _is_within_safe_root(path):
        result["error"] = "Refused: '{}' is not a recognised temp/cache location.".format(path)
        return result
    if not os.path.isdir(path):
        result["error"] = "Path no longer exists."
        result["ok"] = True
        return result

    freed = 0
    removed = 0
    skipped = 0
    for entry in os.scandir(path):
        try:
            if entry.is_symlink():
                os.unlink(entry.path)
                removed += 1
                continue
            if entry.is_dir():
                sz, _fc, _cap = _dir_size(entry.path, max_seconds=2.0)
                shutil.rmtree(entry.path, ignore_errors=True)
                if not os.path.exists(entry.path):
                    freed += sz
                    removed += 1
                else:
                    skipped += 1
            else:
                try:
                    sz = entry.stat().st_size
                except OSError:
                    sz = 0
                os.remove(entry.path)
                freed += sz
                removed += 1
        except (OSError, PermissionError):
            skipped += 1
        except Exception:
            skipped += 1

    result.update({"ok": True, "freed_bytes": freed, "freed_human": _human(freed),
                   "removed": removed, "skipped": skipped})
    return result


def run_cleanup_all(paths):
    """Convenience: clean several locations, aggregate the result."""
    total = 0
    removed = 0
    skipped = 0
    errors = []
    for p in paths or []:
        r = run_cleanup(p)
        total += r.get("freed_bytes", 0)
        removed += r.get("removed", 0)
        skipped += r.get("skipped", 0)
        if r.get("error"):
            errors.append(r["error"])
    return {"ok": not errors or removed > 0, "freed_bytes": total, "freed_human": _human(total),
            "removed": removed, "skipped": skipped,
            "error": "; ".join(errors) if errors else None}
