"""
Server / host diagnostic checks used by Server Test and the verification pipeline.
Kept out of the Qt page so packet capture can run without importing PySide6.
"""

from __future__ import annotations

import re
import time
import socket

from backend.diagnostics import run_command, IS_WINDOWS, IS_MAC

MAX_PORTS = 64
_SAFE_HOST = re.compile(r"^[A-Za-z0-9._:\-\[\]]{1,253}$")


def parse_ports(text):
    """
    '80, 443, 8080-8082' -> [80, 443, 8080, 8081, 8082]
    Ignores junk, de-duplicates, preserves order, caps at MAX_PORTS.
    """
    ports = []
    for chunk in re.split(r"[,\s]+", (text or "").strip()):
        if not chunk:
            continue
        m = re.match(r"^(\d{1,5})-(\d{1,5})$", chunk)
        if m:
            lo, hi = int(m.group(1)), int(m.group(2))
            if lo > hi:
                lo, hi = hi, lo
            for p in range(lo, min(hi, 65535) + 1):
                if 0 < p < 65536 and p not in ports:
                    ports.append(p)
                if len(ports) >= MAX_PORTS:
                    return ports
            continue
        if chunk.isdigit():
            p = int(chunk)
            if 0 < p < 65536 and p not in ports:
                ports.append(p)
            if len(ports) >= MAX_PORTS:
                return ports
    return ports


def resolve_host(host):
    """DNS resolution -> {'ok', 'ip', 'error'}."""
    try:
        ip = socket.gethostbyname(host)
        return {"ok": True, "ip": ip, "error": None}
    except Exception as e:
        return {"ok": False, "ip": None, "error": str(e)}


def tcp_port_check(host, port, timeout=3.0):
    """
    Returns {'port', 'state', 'ms', 'detail'} where state is one of
    open / closed / filtered / error.
    """
    t0 = time.perf_counter()
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.close()
        return {"port": port, "state": "open", "ms": round((time.perf_counter() - t0) * 1000),
                "detail": "TCP handshake succeeded"}
    except socket.timeout:
        return {"port": port, "state": "filtered", "ms": round(timeout * 1000),
                "detail": "No response before timeout (silently dropped)"}
    except ConnectionRefusedError:
        return {"port": port, "state": "closed", "ms": round((time.perf_counter() - t0) * 1000),
                "detail": "Connection refused (host up, nothing listening)"}
    except socket.gaierror as e:
        return {"port": port, "state": "error", "ms": None,
                "detail": "DNS resolution failed: {}".format(e)}
    except OSError as e:
        return {"port": port, "state": "error", "ms": None, "detail": str(e)}


def udp_port_check(host, port, timeout=3.0):
    """
    Send a UDP datagram and wait for a reply or ICMP unreachable.
    'open' means a payload came back; 'closed' means ICMP port unreachable;
    'filtered' means silence (normal for UDP).
    """
    t0 = time.perf_counter()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        if int(port) == 53:
            payload = (b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
                       b"\x07example\x03com\x00\x00\x01\x00\x01")
        else:
            payload = b"\x00\x00"
        sock.sendto(payload, (host, port))
        try:
            data, _addr = sock.recvfrom(4096)
            return {"port": port, "state": "open",
                    "ms": round((time.perf_counter() - t0) * 1000),
                    "detail": "UDP response received ({} bytes)".format(len(data))}
        except socket.timeout:
            return {"port": port, "state": "filtered",
                    "ms": round(timeout * 1000),
                    "detail": "No UDP response before timeout (open or filtered)"}
        except ConnectionRefusedError:
            return {"port": port, "state": "closed",
                    "ms": round((time.perf_counter() - t0) * 1000),
                    "detail": "ICMP port unreachable (nothing listening)"}
    except socket.gaierror as e:
        return {"port": port, "state": "error", "ms": None,
                "detail": "DNS resolution failed: {}".format(e)}
    except OSError as e:
        return {"port": port, "state": "error", "ms": None, "detail": str(e)}
    finally:
        sock.close()


def verdict_for(state):
    """Human verdict + palette key for a port state."""
    return {
        "open": ("OPEN - reachable, not blocked", "SUCCESS"),
        "closed": ("CLOSED - host reachable, no service listening (not a firewall block)", "WARNING"),
        "filtered": ("FILTERED - no reply; a firewall is most likely blocking this port", "ERROR"),
        "error": ("ERROR - could not test", "TEXT_SECONDARY"),
    }.get(state, ("UNKNOWN", "TEXT_SECONDARY"))


def cli_port_check(host, port, proto="TCP", timeout=3):
    """The 'via cmd' proof: netcat on macOS/Linux, Test-NetConnection on Windows."""
    if not _SAFE_HOST.match(str(host or "")):
        return "(skipped)", "Host failed validation; command not executed."
    port = int(port)
    if IS_WINDOWS:
        cmd = ('powershell -NoProfile -Command "Test-NetConnection -ComputerName {h} '
               '-Port {p} -InformationLevel Detailed"').format(h=host, p=port)
        return cmd, run_command(cmd, timeout=timeout + 12)
    flag = "-zvu" if proto.upper() == "UDP" else "-zv"
    cmd = "nc {f} -w {t} {h} {p}".format(f=flag, t=int(timeout), h=host, p=port)
    return cmd, run_command(cmd + " 2>&1", timeout=timeout + 8)


def ping_check(host, count=4):
    """ICMP reachability -> {'reachable', 'loss_pct', 'avg_ms', 'cmd', 'raw'}."""
    if not _SAFE_HOST.match(str(host or "")):
        return {"reachable": False, "loss_pct": None, "avg_ms": None,
                "cmd": "", "raw": "Host failed validation; ping not executed."}
    cmd = ("ping -n {c} {h}" if IS_WINDOWS else "ping -c {c} {h}").format(c=count, h=host)
    raw = run_command(cmd, timeout=count * 3 + 8)
    low = raw.lower()
    if IS_WINDOWS:
        recv = re.search(r"received\s*=\s*(\d+)", low)
        loss = re.search(r"\((\d+)%\s*loss\)", raw)
        avg = re.search(r"average\s*=\s*(\d+)\s*ms", low)
        reachable = bool(recv and int(recv.group(1)) > 0)
        return {"reachable": reachable,
                "loss_pct": int(loss.group(1)) if loss else None,
                "avg_ms": int(avg.group(1)) if avg else None, "cmd": cmd, "raw": raw}
    recv = re.search(r"(\d+)\s+packets received", low)
    loss = re.search(r"([\d.]+)%\s*packet loss", raw)
    avg = re.search(r"=\s*[\d.]+/([\d.]+)/", raw)
    reachable = bool(recv and int(recv.group(1)) > 0)
    return {"reachable": reachable,
            "loss_pct": int(round(float(loss.group(1)))) if loss else None,
            "avg_ms": round(float(avg.group(1))) if avg else None, "cmd": cmd, "raw": raw}


def local_firewall_status():
    """Local firewall state -> {'enabled', 'summary', 'cmd', 'raw'}."""
    if IS_WINDOWS:
        cmd = "netsh advfirewall show allprofiles state"
        raw = run_command(cmd, timeout=20)
        enabled = "ON" in raw.upper()
        return {"enabled": enabled,
                "summary": "Windows Firewall is ON for one or more profiles." if enabled
                           else "Windows Firewall appears OFF.",
                "cmd": cmd, "raw": raw}
    if IS_MAC:
        fw = "/usr/libexec/ApplicationFirewall/socketfilterfw"
        cmd = "{fw} --getglobalstate; {fw} --getblockall; {fw} --getstealthmode".format(fw=fw)
        raw = run_command(cmd + " 2>&1", timeout=20)
        enabled = ("state = 1" in raw.lower()) or ("enabled" in raw.lower()
                                                   and "disabled" not in raw.lower())
        summary = ("macOS Application Firewall is ENABLED." if enabled
                   else "macOS Application Firewall is disabled "
                        "(outbound connections are not filtered by it).")
        return {"enabled": enabled, "summary": summary, "cmd": cmd, "raw": raw}
    return {"enabled": None, "summary": "Firewall state unavailable on this platform.",
            "cmd": "", "raw": ""}


def local_listening_ports():
    """What is listening on THIS machine (useful when testing your own server)."""
    if IS_WINDOWS:
        cmd = "netstat -ano | findstr LISTENING"
        return cmd, run_command(cmd, timeout=25)
    cmd = "lsof -nP -iTCP -sTCP:LISTEN"
    raw = run_command(cmd + " 2>/dev/null", timeout=25)
    if not raw or raw == "No output available.":
        cmd = "netstat -an -p tcp | grep LISTEN"
        raw = run_command(cmd, timeout=25)
    return cmd, raw


def is_local_target(host, resolved_ip):
    """True when the target is this machine (loopback / a local address)."""
    candidates = {host, resolved_ip or ""}
    if candidates & {"localhost", "127.0.0.1", "::1", "0.0.0.0"}:
        return True
    try:
        local = socket.gethostbyname(socket.gethostname())
        return resolved_ip == local
    except Exception:
        return False


def run_server_test(host, ports_text, proto="TCP", timeout=3.0):
    """Worker payload: DNS -> ping -> per-port TCP/UDP -> CLI proof for the first port."""
    host = (host or "").strip()
    proto = (proto or "TCP").upper()
    result = {"host": host, "dns": None, "ping": None, "ports": [],
              "raw": [], "local": False, "proto": proto}
    if not host:
        result["error"] = "Enter a hostname or IP."
        return result

    dns = resolve_host(host)
    result["dns"] = dns

    ping = ping_check(host)
    result["ping"] = ping
    result["raw"].append(("Reachability  -  {}".format(ping["cmd"]), ping["raw"]))

    if proto == "ICMP":
        result["local"] = is_local_target(host, dns.get("ip"))
        return result

    ports = parse_ports(ports_text)
    if not ports:
        result["error"] = "Enter at least one valid port (e.g. 443 or 80,443,8080-8082)."
        return result

    checker = udp_port_check if proto == "UDP" else tcp_port_check
    for port in ports:
        result["ports"].append(checker(host, port, timeout=timeout))

    cmd, raw = cli_port_check(host, ports[0], proto=proto, timeout=int(timeout))
    result["raw"].append(("Port check  -  {}".format(cmd), raw))

    result["local"] = is_local_target(host, dns.get("ip"))
    if result["local"]:
        lcmd, lraw = local_listening_ports()
        result["raw"].append(("Local listening ports  -  {}".format(lcmd), lraw))
    return result
