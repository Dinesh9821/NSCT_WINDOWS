"""
Windows-first live packet capture.

Capture begins before the diagnostic and is always stopped in a finally
block. Backends (in preference order):

  1. dumpcap  (Wireshark/Npcap) — native pcapng
  2. pktmon   (Windows 10+)     — ETL converted to pcapng
  3. tcpdump                    — pcap/pcapng on Unix
  4. AF_PACKET / NDIS raw       — stdlib sockets + our pcapng writer
  5. scapy                      — only if already installed

No extra Python package is required. Missing Npcap/privileges is reported
without crashing the application.
"""

from __future__ import annotations

import os
import re
import shutil
import signal
import socket
import struct
import threading
import time
import logging
import subprocess

import psutil

from core.constants import PACKET_CAPTURE_TIMEOUT, CAPTURE_INTERFACE, capture_dir
from backend.pcap_io import write_pcapng, file_magic_ok, packet_count, empty_pcapng
from backend.diagnostics import get_local_ip, _no_window_kwargs, IS_WINDOWS

log = logging.getLogger("NetworkAI.Capture")

# Hosts/ports in BPF must be numeric or strict tokens — never raw user strings.
_IPV4 = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
_IPV6 = re.compile(r"^[0-9a-fA-F:]+$")
_IFACE = re.compile(r"^[A-Za-z0-9._\- ]{1,128}$")


def npcap_installed():
    if not IS_WINDOWS:
        return os.path.exists("/usr/lib/x86_64-linux-gnu/libpcap.so.1") or bool(shutil.which("tcpdump"))
    candidates = [
        os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "Npcap", "wpcap.dll"),
        os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "wpcap.dll"),
        os.path.join(os.environ.get("ProgramFiles", r"C:\Program Files"), "Npcap", "NPFInstall.exe"),
    ]
    return any(os.path.isfile(p) for p in candidates)


def dumpcap_path():
    env = os.environ.get("NETWORKAI_DUMPCAP")
    if env and os.path.isfile(env):
        return env
    found = shutil.which("dumpcap")
    if found:
        return found
    if IS_WINDOWS:
        for root in (
            os.environ.get("ProgramFiles", r"C:\Program Files"),
            os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"),
        ):
            candidate = os.path.join(root, "Wireshark", "dumpcap.exe")
            if os.path.isfile(candidate):
                return candidate
    return None


def tcpdump_path():
    return shutil.which("tcpdump")


def pktmon_path():
    if not IS_WINDOWS:
        return None
    return shutil.which("pktmon") or (
        os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "pktmon.exe")
        if os.path.isfile(os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "pktmon.exe"))
        else None
    )


def detect_interface(source_ip=None):
    """Return an OS interface name matching the source IP, if possible."""
    configured = (CAPTURE_INTERFACE or "").strip()
    if configured:
        return configured
    source_ip = source_ip or get_local_ip()
    try:
        for name, addrs in psutil.net_if_addrs().items():
            for a in addrs:
                if a.address == source_ip:
                    return name
    except Exception:
        log.debug("interface enumeration failed", exc_info=True)
    try:
        stats = psutil.net_if_stats()
        for name, st in stats.items():
            if st.isup and name and not name.lower().startswith("lo"):
                return name
    except Exception:
        pass
    return None


def build_capture_filter(dest_ip, protocol=None, port=None, source_ip=None):
    """
    libpcap/BPF filter. Tokens are validated so user input cannot break out
    of the filter expression.
    """
    parts = []
    if source_ip and _valid_ip(source_ip) and dest_ip and _valid_ip(dest_ip):
        parts.append("(host %s and host %s)" % (source_ip, dest_ip))
    elif dest_ip and _valid_ip(dest_ip):
        parts.append("host %s" % dest_ip)
    proto = (protocol or "").upper()
    if proto == "ICMP":
        parts.append("icmp")
    elif proto == "TCP" and _valid_port(port):
        parts.append("tcp port %s" % int(port))
    elif proto == "UDP" and _valid_port(port):
        parts.append("udp port %s" % int(port))
    elif proto == "TCP":
        parts.append("tcp")
    elif proto == "UDP":
        parts.append("udp")
    return " and ".join(parts) if parts else ""


def _valid_ip(value):
    if not value or not isinstance(value, str):
        return False
    value = value.strip()
    if _IPV4.match(value):
        try:
            socket.inet_aton(value)
            return True
        except OSError:
            return False
    if _IPV6.match(value) and ":" in value:
        try:
            socket.inet_pton(socket.AF_INET6, value)
            return True
        except OSError:
            return False
    return False


def _valid_port(port):
    try:
        p = int(port)
        return 0 < p < 65536
    except (TypeError, ValueError):
        return False


def _run_hidden(args, timeout=20, check=False):
    try:
        proc = subprocess.run(
            args, capture_output=True, timeout=timeout, check=check,
            **_no_window_kwargs())
        return proc.returncode, proc.stdout, proc.stderr
    except FileNotFoundError:
        return 127, b"", b"not found"
    except subprocess.TimeoutExpired:
        return 124, b"", b"timeout"
    except Exception as e:
        log.warning("capture helper failed: %s", e)
        return 1, b"", str(e).encode("utf-8", errors="replace")


class PacketCapture:
    """
    Start capture, run the caller's diagnostic, then stop and validate the file.

        cap = PacketCapture(path, dest_ip=..., protocol="TCP", port=443)
        cap.start()
        try:
            run_test()
        finally:
            cap.stop()
    """

    def __init__(self, path, dest_ip=None, protocol=None, port=None,
                 source_ip=None, interface=None, timeout=None):
        self.path = path
        self.dest_ip = dest_ip
        self.protocol = (protocol or "").upper()
        self.port = port
        self.source_ip = source_ip or get_local_ip()
        self.interface = interface or detect_interface(self.source_ip)
        self.timeout = int(timeout or PACKET_CAPTURE_TIMEOUT)
        self.filter = build_capture_filter(
            dest_ip, protocol=self.protocol, port=port, source_ip=self.source_ip)
        self.backend = None
        self.error = None
        self.started = False
        self.packet_count = 0
        self.wireshark_compatible = False
        self._proc = None
        self._thread = None
        self._stop = threading.Event()
        self._frames = []
        self._etl = None
        self._linktype = 1

    def start(self):
        log.info("Capture started path=%s filter=%s iface=%s", self.path, self.filter, self.interface)
        os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
        for name, fn in (
            ("dumpcap", self._start_dumpcap),
            ("pktmon", self._start_pktmon),
            ("tcpdump", self._start_tcpdump),
            ("afpacket", self._start_afpacket),
            ("scapy", self._start_scapy),
        ):
            try:
                if fn():
                    self.backend = name
                    self.started = True
                    log.info("Capture backend=%s", name)
                    time.sleep(0.7)
                    return True
            except Exception:
                log.warning("capture backend %s failed to start", name, exc_info=True)
        self.error = self._unavailable_message()
        log.error("Capture unavailable: %s", self.error)
        try:
            empty_pcapng(self.path)
        except Exception:
            pass
        return False

    def stop(self):
        try:
            if self.backend == "dumpcap":
                self._stop_proc()
            elif self.backend == "tcpdump":
                self._stop_proc()
            elif self.backend == "pktmon":
                self._stop_pktmon()
            elif self.backend in ("afpacket", "scapy"):
                self._stop.set()
                if self._thread:
                    self._thread.join(timeout=5)
                try:
                    write_pcapng(self.path, list(self._frames), linktype=self._linktype)
                except Exception:
                    log.exception("failed to write pcapng")
        except Exception:
            log.exception("error while stopping capture")
        finally:
            self._kill_proc()
            self.started = False
        self._validate()
        log.info("Capture stopped packets=%s file=%s", self.packet_count, self.path)
        return self.as_dict()

    def as_dict(self):
        return {
            "file": self.path,
            "filename": os.path.basename(self.path),
            "wireshark_compatible": self.wireshark_compatible,
            "packet_count": self.packet_count,
            "filter": self.filter,
            "interface": self.interface,
            "backend": self.backend,
            "error": self.error,
            "started": bool(self.backend),
        }

    def _validate(self):
        if self.path and os.path.isfile(self.path) and os.path.getsize(self.path) > 0:
            self.wireshark_compatible = file_magic_ok(self.path)
            try:
                self.packet_count = packet_count(self.path)
            except Exception:
                self.packet_count = 0
            if not self.wireshark_compatible:
                self.error = (self.error or "Capture file is not a valid PCAP/PCAPNG")
        else:
            if not self.error:
                self.error = "Capture file was not created"
            try:
                empty_pcapng(self.path)
                self.wireshark_compatible = file_magic_ok(self.path)
            except Exception:
                pass

    def _unavailable_message(self):
        if IS_WINDOWS:
            np = "installed" if npcap_installed() else "not installed"
            return (
                "Packet capture unavailable. On Windows this requires Npcap "
                "(bundled with Wireshark) or an elevated pktmon session. "
                "Npcap is %s. Run the app as Administrator if capture is "
                "installed but still fails. Network diagnostics will continue."
            ) % np
        return (
            "Packet capture unavailable (permission or backend missing). "
            "Install tcpdump or run with CAP_NET_RAW. Diagnostics will continue."
        )

    # ----- dumpcap --------------------------------------------------------
    def _start_dumpcap(self):
        exe = dumpcap_path()
        if not exe:
            return False
        args = [exe, "-q", "-w", self.path]
        iface = self.interface
        if iface and _IFACE.match(iface):
            args.extend(["-i", iface])
        else:
            args.extend(["-i", "any"] if not IS_WINDOWS else ["-i", "1"])
        if self.filter:
            args.extend(["-f", self.filter])
        return self._spawn(args)

    # ----- tcpdump --------------------------------------------------------
    def _start_tcpdump(self):
        exe = tcpdump_path()
        if not exe:
            return False
        iface_args = []
        if self.interface and _IFACE.match(self.interface):
            iface_args = ["-i", self.interface]
        else:
            iface_args = ["-i", "any"]
        filt = [self.filter] if self.filter else []
        args = [exe, "-n", "-U"]
        if self._tcpdump_flag(exe, b"--immediate-mode"):
            args.append("--immediate-mode")
        if self._tcpdump_supports_pcapng(exe):
            args.append("--pcapng")
        args.extend(["-w", self.path] + iface_args + filt)
        return self._spawn(args)

    @staticmethod
    def _tcpdump_flag(exe, token):
        try:
            proc = subprocess.run(
                [exe, "--help"], capture_output=True, timeout=5, **_no_window_kwargs())
            blob = (proc.stdout or b"") + (proc.stderr or b"")
            return token in blob
        except Exception:
            return False

    @classmethod
    def _tcpdump_supports_pcapng(cls, exe):
        return cls._tcpdump_flag(exe, b"--pcapng")

    def _spawn(self, args):
        log.info("Capture helper: %s", " ".join(args))
        try:
            self._proc = subprocess.Popen(
                args, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                **_no_window_kwargs())
        except OSError as e:
            log.warning("could not spawn %s: %s", args[0], e)
            return False
        time.sleep(0.35)
        if self._proc.poll() is not None:
            err = b""
            try:
                err = self._proc.stderr.read() if self._proc.stderr else b""
            except Exception:
                err = b""
            try:
                if self._proc.stderr:
                    self._proc.stderr.close()
            except Exception:
                pass
            log.warning("capture helper exited early: %s", err[:400])
            self._proc = None
            return False
        return True

    def _stop_proc(self):
        proc = self._proc
        if proc is None:
            return
        if proc.poll() is None:
            try:
                if IS_WINDOWS:
                    proc.terminate()
                else:
                    proc.send_signal(signal.SIGINT)
            except Exception:
                proc.terminate()
            try:
                proc.wait(timeout=4)
            except Exception:
                pass
        self._kill_proc()

    def _kill_proc(self):
        proc = self._proc
        self._proc = None
        if proc is None:
            return
        try:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=2)
        except Exception:
            pass

    # ----- pktmon (Windows) -----------------------------------------------
    def _start_pktmon(self):
        exe = pktmon_path()
        if not exe:
            return False
        self._etl = self.path + ".etl"
        # Reset filters (best-effort); ignore failures.
        _run_hidden([exe, "filter", "remove"])
        filt = [exe, "filter", "add"]
        if self.dest_ip and _valid_ip(self.dest_ip):
            if ":" in self.dest_ip:
                filt.extend(["--ipv6", self.dest_ip])
            else:
                filt.extend(["-i", self.dest_ip])
        proto = self.protocol
        if proto in ("TCP", "UDP", "ICMP"):
            filt.extend(["-t", proto])
        if _valid_port(self.port) and proto in ("TCP", "UDP"):
            filt.extend(["-p", str(int(self.port))])
        code, _o, err = _run_hidden(filt, timeout=15)
        if code not in (0, None) and b"error" in (err or b"").lower():
            log.warning("pktmon filter add: %s", err[:300])
        args = [exe, "start", "--capture", "--pkt-size", "0", "--file-name", self._etl]
        code, _o, err = _run_hidden(args, timeout=15)
        if code != 0:
            log.info("pktmon start failed (%s): %s", code, (err or b"")[:300])
            _run_hidden([exe, "stop"], timeout=10)
            return False
        return True

    def _stop_pktmon(self):
        exe = pktmon_path()
        if exe:
            _run_hidden([exe, "stop"], timeout=20)
            etl = self._etl
            if etl and os.path.isfile(etl):
                code, _o, err = _run_hidden(
                    [exe, "pcapng", etl, "-o", self.path], timeout=30)
                if code != 0:
                    log.warning("pktmon pcapng convert failed: %s", (err or b"")[:300])
                try:
                    os.remove(etl)
                except OSError:
                    pass
            _run_hidden([exe, "filter", "remove"], timeout=10)

    # ----- AF_PACKET / raw (userspace filter) -----------------------------
    def _start_afpacket(self):
        if IS_WINDOWS:
            return False
        try:
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
        except (PermissionError, OSError) as e:
            log.info("AF_PACKET not permitted: %s", e)
            return False
        iface = self.interface
        if iface and iface != "any" and _IFACE.match(iface):
            try:
                sock.bind((iface, 0))
            except OSError as e:
                log.info("AF_PACKET bind failed: %s", e)
                sock.close()
                return False
        sock.settimeout(0.3)
        self._stop.clear()
        self._frames = []
        self._linktype = 1

        def _loop():
            try:
                deadline = time.time() + self.timeout
                while not self._stop.is_set() and time.time() < deadline:
                    try:
                        data, _addr = sock.recvfrom(65535)
                    except socket.timeout:
                        continue
                    except OSError:
                        break
                    if _userspace_match(data, self.dest_ip, self.protocol, self.port, self.source_ip):
                        self._frames.append((time.time(), data))
            finally:
                try:
                    sock.close()
                except Exception:
                    pass

        self._thread = threading.Thread(target=_loop, name="afpacket-capture", daemon=True)
        self._thread.start()
        return True

    # ----- optional scapy -------------------------------------------------
    def _start_scapy(self):
        try:
            from scapy.all import sniff  # type: ignore
        except Exception:
            return False
        self._stop.clear()
        self._frames = []
        self._linktype = 1
        bpf = self.filter or None
        iface = self.interface if self.interface and self.interface != "any" else None

        def _loop():
            try:
                sniff(
                    iface=iface,
                    filter=bpf,
                    store=False,
                    timeout=self.timeout,
                    stop_filter=lambda _p: self._stop.is_set(),
                    prn=lambda p: self._frames.append((time.time(), bytes(p))),
                )
            except Exception:
                log.warning("scapy sniff failed", exc_info=True)

        self._thread = threading.Thread(target=_loop, name="scapy-capture", daemon=True)
        self._thread.start()
        return True


def _userspace_match(frame, dest_ip, protocol, port, source_ip):
    """Cheap Ethernet/IPv4 filter so AF_PACKET does not keep the whole NIC."""
    if not dest_ip and not protocol:
        return True
    if len(frame) < 34:
        return True
    ethertype = struct.unpack("!H", frame[12:14])[0]
    if ethertype == 0x8100 and len(frame) >= 18:
        ethertype = struct.unpack("!H", frame[16:18])[0]
        ip = frame[18:]
    else:
        ip = frame[14:]
    if ethertype != 0x0800 or len(ip) < 20:
        return True
    src = ".".join(str(b) for b in ip[12:16])
    dst = ".".join(str(b) for b in ip[16:20])
    proto = ip[9]
    if dest_ip and dest_ip not in (src, dst):
        return False
    if source_ip and _valid_ip(source_ip) and source_ip not in (src, dst) and dest_ip:
        # still keep dest-related packets (replies)
        pass
    proto_name = {1: "ICMP", 6: "TCP", 17: "UDP"}.get(proto)
    if protocol in ("ICMP", "TCP", "UDP") and proto_name and proto_name != protocol:
        return False
    if port and proto in (6, 17):
        ihl = (ip[0] & 0x0F) * 4
        if len(ip) >= ihl + 4:
            sport, dport = struct.unpack("!HH", ip[ihl:ihl + 4])
            if int(port) not in (sport, dport):
                return False
    return True


def capture_status():
    """Lightweight capability probe for Settings / error messages."""
    return {
        "npcap": npcap_installed(),
        "dumpcap": bool(dumpcap_path()),
        "pktmon": bool(pktmon_path()),
        "tcpdump": bool(tcpdump_path()),
        "interface": detect_interface(),
        "capture_dir": capture_dir(),
        "windows": IS_WINDOWS,
        "admin_hint": IS_WINDOWS,
    }
