"""
backend/diagnostics.py  (Windows-first, cross-platform)

Public function names and return shapes are stable, so the UI is unchanged. The
OS-specific command lines branch on the platform: Windows uses ping -n, tracert,
ipconfig /all, netsh; macOS uses ping -c, traceroute, route/scutil. On Windows,
subprocesses run hidden (no console flash).
"""

import os
import re
import sys
import socket
import getpass
import ipaddress
import subprocess
import datetime
import locale
import logging
import warnings

import requests
import psutil

from core.constants import HTTP_TIMEOUT, CMD_TIMEOUT

warnings.filterwarnings("ignore", category=UserWarning)
try:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except Exception:
    pass

IS_WINDOWS = sys.platform.startswith("win")
IS_MAC = sys.platform == "darwin"
log = logging.getLogger("NetworkAI.Backend")


# --------------------------------------------------------------------------- #
#  Subprocess helpers (hidden console on Windows, robust decoding)
# --------------------------------------------------------------------------- #
def _no_window_kwargs():
    if not IS_WINDOWS:
        return {}
    startupinfo = subprocess.STARTUPINFO()
    startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    startupinfo.wShowWindow = subprocess.SW_HIDE
    return {"startupinfo": startupinfo, "creationflags": subprocess.CREATE_NO_WINDOW}


def _decode(raw_bytes):
    if not raw_bytes:
        return ""
    encodings = ["utf-8", locale.getpreferredencoding(False)]
    if IS_WINDOWS:
        encodings += ["cp1252", "cp850", "cp437", "latin-1"]
    else:
        encodings += ["latin-1"]
    for enc in encodings:
        try:
            return raw_bytes.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue
    return raw_bytes.decode("utf-8", errors="replace")


def run_command(command, timeout=CMD_TIMEOUT):
    """Run a shell command hidden; return combined stdout/stderr as text."""
    try:
        proc = subprocess.run(command, shell=True, capture_output=True,
                              timeout=timeout, **_no_window_kwargs())
        text = (_decode(proc.stdout) + _decode(proc.stderr)).strip()
        return text or "No output available."
    except subprocess.TimeoutExpired:
        return "Command timed out."
    except Exception as e:
        log.exception("shell command failed: %s", command)
        return f"Error: {e}"


def run_command_args(args, timeout=CMD_TIMEOUT):
    """Run a command from an argument list hidden; return text."""
    try:
        proc = subprocess.run(args, capture_output=True, timeout=timeout,
                              **_no_window_kwargs())
        return (_decode(proc.stdout) + _decode(proc.stderr)).strip() or "No output available."
    except subprocess.TimeoutExpired:
        return "Command timed out."
    except Exception as e:
        log.exception("command failed: %s", args)
        return f"Error running command: {e}"


def _looks_like_ipv4(text):
    try:
        ipaddress.IPv4Address(text.strip())
        return True
    except Exception:
        return False


# --------------------------------------------------------------------------- #
#  Windows: ipconfig /all parsing
# --------------------------------------------------------------------------- #
def _parse_ipconfig():
    raw = run_command("ipconfig /all")
    adapters, current, last_key = [], None, None
    for line in raw.splitlines():
        if not line.strip():
            continue
        if not line[0].isspace():
            if line.rstrip().endswith(":") and "Windows IP Configuration" not in line:
                current = {"name": line.strip().rstrip(":"), "dns": [],
                           "gateway": "", "dhcp": "", "ipv4": ""}
                adapters.append(current)
                last_key = None
            continue
        if current is None:
            continue
        if ":" in line:
            left, right = line.split(":", 1)
            key = left.replace(".", "").strip().lower()
            val = right.strip()
            last_key = key
            if key.startswith("dns servers"):
                if val:
                    current["dns"].append(val)
            elif key.startswith("default gateway"):
                if val and _looks_like_ipv4(val):
                    current["gateway"] = val
            elif key.startswith("dhcp enabled"):
                current["dhcp"] = val
            elif key.startswith("ipv4 address") or key == "ip address":
                current["ipv4"] = val.split("(")[0].strip()
        else:
            val = line.strip()
            if last_key and last_key.startswith("dns servers") and _looks_like_ipv4(val):
                current["dns"].append(val)
            elif last_key and last_key.startswith("default gateway") and _looks_like_ipv4(val):
                if not current["gateway"]:
                    current["gateway"] = val
    return adapters


def _active_adapter():
    adapters = _parse_ipconfig()
    for a in adapters:
        ip = a.get("ipv4", "")
        if ip and not ip.startswith("169.254") and a.get("gateway"):
            return a
    for a in adapters:
        ip = a.get("ipv4", "")
        if ip and not ip.startswith("169.254"):
            return a
    return None


# --------------------------------------------------------------------------- #
#  macOS: route / scutil helpers
# --------------------------------------------------------------------------- #
def _default_route():
    out = run_command("route -n get default 2>/dev/null")
    gw = re.search(r"gateway:\s*([\d.]+)", out)
    iface = re.search(r"interface:\s*([\w.]+)", out)
    return (gw.group(1) if gw else "", iface.group(1) if iface else "")


def _dns_servers_mac():
    out = run_command("scutil --dns")
    servers = re.findall(r"nameserver\[\d+\]\s*:\s*([\d.]+)", out)
    seen = []
    for s in servers:
        if s not in seen:
            seen.append(s)
    return seen


def _dhcp_enabled_mac(iface):
    if not iface:
        return None
    pkt = run_command(f"ipconfig getpacket {iface} 2>/dev/null")
    if not pkt or pkt == "No output available.":
        return False
    return ("yiaddr" in pkt) or ("op =" in pkt)


# --------------------------------------------------------------------------- #
#  Identity / connectivity
# --------------------------------------------------------------------------- #
def get_ad_username():
    try:
        if IS_WINDOWS:
            name = os.environ.get("USERNAME") or getpass.getuser()
            if "\\" in name:
                name = name.split("\\")[-1]
            return name or "user"
        return getpass.getuser() or "user"
    except Exception:
        return os.environ.get("USERNAME") or os.environ.get("USER") or "user"


def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.6)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        try:
            return socket.gethostbyname(socket.gethostname())
        except Exception:
            return "—"


def check_ip_type():
    ip_str = get_local_ip()
    if ip_str in ("—", "127.0.0.1", ""):
        return "Your device is not connected to a LAN or WiFi network."
    try:
        ip = ipaddress.ip_address(ip_str)
        if ip.is_loopback or ip in ipaddress.ip_network("169.254.0.0/16"):
            return "Your device is not connected to a LAN or WiFi network."
        return f"You are connected to a LAN/WiFi. Your IP address is {ip_str}."
    except ValueError:
        return "Invalid IP Address detected."


def check_internet():
    cmd = "ping -n 5 google.com" if IS_WINDOWS else "ping -c 5 google.com"
    result = run_command(cmd)
    low = result.lower()
    recv = re.search(r"received\s*=\s*(\d+)", low) or re.search(r"(\d+)\s+packets received", low)
    if recv and int(recv.group(1)) > 0:
        return "Your internet connection is working fine."
    if ("could not find host" in low or "unknown host" in low
            or "name resolution" in low or "cannot resolve" in low):
        return ("DNS resolution failed — your device can't resolve hostnames.\n"
                "Please check your network / DNS settings.")
    return "Your internet connection appears to be down. Please check your network settings."


def check_default_gateway():
    if IS_WINDOWS:
        adapter = _active_adapter()
        if adapter and adapter.get("gateway"):
            return f"Default Gateway: {adapter['gateway']}  ({adapter['name']})"
    else:
        gw, iface = _default_route()
        if gw:
            return f"Default Gateway: {gw}  ({iface})"
    return "It seems you are not connected to LAN/WiFi. Unable to get gateway details."


def check_dns_servers():
    if IS_WINDOWS:
        adapter = _active_adapter()
        if adapter and adapter.get("dns"):
            return f"DNS Servers: {', '.join(adapter['dns'])}  ({adapter['name']})"
        for a in _parse_ipconfig():
            if a.get("dns"):
                return f"DNS Servers: {', '.join(a['dns'])}  ({a['name']})"
    else:
        dns = _dns_servers_mac()
        if dns:
            return f"DNS Servers: {', '.join(dns)}"
    return "It seems you are not connected to LAN/WiFi. Unable to get DNS details."


def check_dhcp_status():
    if IS_WINDOWS:
        adapter = _active_adapter()
        if adapter and adapter.get("dhcp"):
            if adapter["dhcp"].strip().lower().startswith("yes"):
                return f"DHCP is enabled on your network.  ({adapter['name']})"
            return f"DHCP is not enabled — a static IP appears to be configured.  ({adapter['name']})"
    else:
        gw, iface = _default_route()
        enabled = _dhcp_enabled_mac(iface)
        if enabled is True:
            return f"DHCP is enabled on your network.  ({iface})"
        if enabled is False:
            return f"DHCP is not active — a static IP appears to be configured.  ({iface})"
    return "Unable to determine DHCP status. Please check your network connection."


def check_zscaler():
    url = "https://ip.zscaler.com/index.php?json"
    try:
        response = requests.get(url, verify=False, timeout=HTTP_TIMEOUT)
        j = response.json()
        return (f"Your Gateway IP Address is {j['xff']}\n"
                f"You are connected to Zscaler Internet Access\n"
                f"DataCenter is {j['datacenter']}\n"
                f"Your request is arriving from {j['srcip']}\n"
                f"Your zscaler proxy virtual ip is {j['vip']}")
    except Exception:
        return "You are not connected to Zscaler internet access"


def public_ip():
    """Return a clean public IP string, trying several IPv4 providers."""
    providers = [
        "https://api.ipify.org",
        "https://ipv4.icanhazip.com",
        "https://ifconfig.me/ip",
        "http://ip-api.com/line/?fields=query",
    ]
    for url in providers:
        try:
            r = requests.get(url, timeout=HTTP_TIMEOUT, verify=False)
            ip = (r.text or "").strip().splitlines()[0].strip()
            ipaddress.ip_address(ip)
            return ip
        except Exception:
            continue
    return "Unavailable"


def get_public_ip():
    ip = public_ip()
    if ip == "Unavailable":
        return "Some issues are observed, Kindly raise a ticket"
    return f"Your public IP is: {ip}"


def get_ip_location():
    try:
        response = requests.get("http://ip-api.com/json/", timeout=HTTP_TIMEOUT)
        data = response.json()
        if data.get("status") == "success":
            return (f"IP: {data['query']}\nCity: {data['city']}\n"
                    f"Region: {data['regionName']}\nCountry: {data['country']}\n"
                    f"Latitude: {data['lat']}\nLongitude: {data['lon']}")
        return "Unable to fetch location details."
    except requests.RequestException:
        return "Network error while fetching location details."


def check_system_restart():
    try:
        boot_time = psutil.boot_time()
        reboot_time = datetime.datetime.fromtimestamp(boot_time)
        elapsed = datetime.datetime.now() - reboot_time
        if elapsed.total_seconds() > 52 * 3600:
            days = elapsed.days
            hours = (elapsed.seconds // 3600) % 24
            return (f"Your system is not restarted from last {days} days {hours} hrs.\n"
                    f"Kindly restart once for smooth functioning.")
        return f"Last Reboot Time: {reboot_time.strftime('%Y-%m-%d %H:%M:%S')}"
    except Exception as e:
        return f"Unable to read uptime: {e}"


def uptime_short():
    try:
        delta = datetime.datetime.now() - datetime.datetime.fromtimestamp(psutil.boot_time())
        return f"{delta.days}d {(delta.seconds // 3600) % 24}h"
    except Exception:
        return "—"


def run_traceroute(destination):
    if not destination:
        return "Please enter a target IP or hostname."
    if IS_WINDOWS:
        return run_command_args(["tracert", "-d", "-h", "20", "-w", "1000", destination], timeout=90)
    return run_command_args(
        ["traceroute", "-n", "-w", "1", "-q", "1", "-m", "20", destination], timeout=90)


def run_ping(destination):
    if not destination:
        return "Please enter a target IP or hostname."
    flag = "-n" if IS_WINDOWS else "-c"
    return run_command_args(["ping", flag, "4", destination])


# --------------------------------------------------------------------------- #
#  Structured summaries for the dashboard
# --------------------------------------------------------------------------- #
def network_summary():
    """Adapter facts for KPI / details cards."""
    if IS_WINDOWS:
        adapter = _active_adapter() or {}
        dns_list = adapter.get("dns", [])
        return {
            "local_ip": get_local_ip(),
            "gateway": adapter.get("gateway", "—"),
            "primary_dns": dns_list[0] if dns_list else "—",
            "dhcp": adapter.get("dhcp", "—"),
            "adapter": adapter.get("name", "—"),
        }
    gw, iface = _default_route()
    dns = _dns_servers_mac()
    enabled = _dhcp_enabled_mac(iface)
    return {
        "local_ip": get_local_ip(),
        "gateway": gw or "—",
        "primary_dns": dns[0] if dns else "—",
        "dhcp": "Yes" if enabled else ("No" if enabled is False else "—"),
        "adapter": iface or "—",
    }


def network_quality(host="8.8.8.8", count=5):
    """
    Ping `host`; parse latency + packet-loss + jitter.
      Windows: 'Average = 15ms', '(0% loss)', 'Minimum/Maximum = ..ms'
      macOS  : 'round-trip min/avg/max/stddev = 13.2/15.4/17.8/1.6 ms'
    """
    if IS_WINDOWS:
        out = run_command(f"ping -n {count} {host}")
        loss_m = re.search(r"\((\d+)%\s*loss\)", out)
        avg_m = re.search(r"Average\s*=\s*(\d+)\s*ms", out)
        min_m = re.search(r"Minimum\s*=\s*(\d+)\s*ms", out)
        max_m = re.search(r"Maximum\s*=\s*(\d+)\s*ms", out)
        loss = int(loss_m.group(1)) if loss_m else None
        avg = int(avg_m.group(1)) if avg_m else None
        mn = int(min_m.group(1)) if min_m else None
        mx = int(max_m.group(1)) if max_m else None
        jitter = (mx - mn) if (mn is not None and mx is not None) else None
        reachable = avg is not None and (loss is None or loss < 100)
    else:
        out = run_command(f"ping -c {count} {host}")
        loss_m = re.search(r"([\d.]+)%\s*packet loss", out)
        rtt_m = re.search(r"=\s*([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+)\s*ms", out)
        recv_m = re.search(r"(\d+)\s+packets received", out)
        mn = avg = mx = std = None
        if rtt_m:
            mn, avg, mx, std = (float(x) for x in rtt_m.groups())
        loss = float(loss_m.group(1)) if loss_m else None
        reachable = bool(recv_m and int(recv_m.group(1)) > 0)
        avg = round(avg) if avg is not None else None
        mn = round(mn) if mn is not None else None
        mx = round(mx) if mx is not None else None
        jitter = round(std) if std is not None else None
        loss = int(round(loss)) if loss is not None else None

    return {
        "host": host,
        "latency_ms": avg,
        "loss_pct": loss if loss is not None else (0 if reachable else 100),
        "min_ms": mn,
        "max_ms": mx,
        "jitter_ms": jitter,
        "reachable": reachable,
    }


def parse_traceroute(output):
    """
    Unified parser for Windows `tracert` and macOS `traceroute` output.
    Returns [{"hop", "ip", "avg_ms", "timed_out"}]. Handles integer ('<1 ms')
    and decimal ('2.456 ms') latencies and timed-out ('* * *') hops.
    """
    hops = []
    for line in (output or "").splitlines():
        m = re.match(r"\s*(\d+)\s+(.*)$", line)
        if not m:
            continue
        num = int(m.group(1))
        rest = m.group(2)
        ip_m = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", rest)
        times = [float(t) for t in re.findall(r"([\d.]+)\s*ms", rest)]
        avg = round(sum(times) / len(times)) if times else None
        ip = ip_m.group(1) if ip_m else None
        hops.append({"hop": num, "ip": ip, "avg_ms": avg, "timed_out": ip is None})
    return hops


# --------------------------------------------------------------------------- #
#  Report command set (per-OS troubleshooting outputs)
# --------------------------------------------------------------------------- #
if IS_WINDOWS:
    REPORT_COMMANDS = [
        ("IP Configuration — ipconfig /all", "ipconfig /all"),
        ("Routing Table — route print", "route print"),
        ("ARP Cache — arp -a", "arp -a"),
        ("Active Connections — netstat -ano", "netstat -ano"),
        ("Interface Config — netsh interface ip show config", "netsh interface ip show config"),
        ("Wireless Interfaces — netsh wlan show interfaces", "netsh wlan show interfaces"),
        ("DNS Lookup — nslookup google.com", "nslookup google.com"),
        ("MAC Addresses — getmac /v", "getmac /v"),
        ("Ping Test — ping -n 4 8.8.8.8", "ping -n 4 8.8.8.8"),
        ("Traceroute — tracert -d -h 15 8.8.8.8", "tracert -d -h 15 8.8.8.8"),
    ]
else:
    REPORT_COMMANDS = [
        ("Network Interfaces — ifconfig", "ifconfig"),
        ("Routing Table — netstat -rn", "netstat -rn"),
        ("ARP Cache — arp -a", "arp -a"),
        ("Active Connections — netstat -an", "netstat -an"),
        ("DNS Configuration — scutil --dns", "scutil --dns"),
        ("Hardware Ports — networksetup -listallhardwareports", "networksetup -listallhardwareports"),
        ("Wi-Fi Info — system_profiler SPAirPortDataType", "system_profiler SPAirPortDataType"),
        ("DNS Lookup — nslookup google.com", "nslookup google.com"),
        ("Ping Test — ping -c 4 8.8.8.8", "ping -c 4 8.8.8.8"),
        ("Traceroute — traceroute -n -m 15 8.8.8.8", "traceroute -n -w 1 -q 1 -m 15 8.8.8.8"),
    ]
