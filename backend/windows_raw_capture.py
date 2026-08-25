"""
Self-contained Windows packet observation using only the OS and stdlib.

Windows will not expose Ethernet frames from a NIC without an NDIS filter
driver (Npcap/WinPcap). That is a platform limitation, not something this
app can bundle without installing a kernel driver.

What Windows *does* allow without any third-party capture product:

  SOCK_RAW + SIO_RCVALL (Administrator)
      Receives IPv4 datagrams that hit this host on the bound address,
      including TCP/UDP/ICMP headers of the diagnostic itself (SYN, SYN/ACK,
      echo request/reply, DNS, …). Link-layer (Ethernet) headers are not
      present. Wireshark opens the file as Raw IP (LINKTYPE_RAW = 101).

IPv6 SIO_RCVALL does not return IPv6 headers (Microsoft documented limit).

This module never synthesizes packets. If the raw socket cannot be opened,
it fails and the caller writes an empty valid pcapng plus an error.
"""
from __future__ import annotations

import logging
import socket
import struct
import threading
import time

from core.constants import CAPTURE_MAX_PACKETS

log = logging.getLogger("NetworkAI.WindowsRaw")

SIO_RCVALL = getattr(socket, "SIO_RCVALL", 0x98000001)
RCVALL_ON = getattr(socket, "RCVALL_ON", 1)
RCVALL_OFF = getattr(socket, "RCVALL_OFF", 0)
RCVALL_IPLEVEL = getattr(socket, "RCVALL_IPLEVEL", 3)
WSAEACCES = 10013
SO_RCVBUF_BYTES = 8 * 1024 * 1024


def ip_datagram_match(datagram, dest_ip=None, protocol=None, port=None):
    """Filter a raw IPv4 datagram (no Ethernet header)."""
    if not datagram or len(datagram) < 20:
        return False
    version = datagram[0] >> 4
    if version != 4:
        return True  # let IPv6 through if ever received
    ihl = (datagram[0] & 0x0F) * 4
    if ihl < 20 or len(datagram) < ihl:
        return False
    proto = datagram[9]
    src = ".".join(str(b) for b in datagram[12:16])
    dst = ".".join(str(b) for b in datagram[16:20])
    if dest_ip and dest_ip not in (src, dst):
        return False
    want = (protocol or "").upper()
    proto_name = {1: "ICMP", 6: "TCP", 17: "UDP"}.get(proto)
    if want in ("ICMP", "TCP", "UDP") and proto_name and proto_name != want:
        return False
    if port and proto in (6, 17) and len(datagram) >= ihl + 4:
        sport, dport = struct.unpack("!HH", datagram[ihl:ihl + 4])
        if int(port) not in (sport, dport):
            return False
    return True


class WindowsRawCapture:
    """
    Bind a raw IPv4 socket to ``local_ip`` and enable SIO_RCVALL.
    Observed datagrams are stored as (timestamp, ip_bytes).
    """

    def __init__(self, local_ip, dest_ip=None, protocol=None, port=None, timeout=45):
        self.local_ip = local_ip
        self.dest_ip = dest_ip
        self.protocol = protocol
        self.port = port
        self.timeout = int(timeout or 45)
        self.sock = None
        self._stop = threading.Event()
        self._thread = None
        self._lock = threading.Lock()
        self.frames = []
        self.error = None
        self.max_packets = max(1, int(CAPTURE_MAX_PACKETS or 50000))

    def start(self):
        if not self.local_ip or self.local_ip in ("—", "127.0.0.1", "::1"):
            raise PermissionError(
                "Windows raw capture needs a real interface IPv4 address "
                "(loopback is not supported by SIO_RCVALL)."
            )
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        try:
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, SO_RCVBUF_BYTES)
            except OSError:
                pass
            sock.bind((self.local_ip, 0))
            self._enable_rcvall(sock)
            sock.settimeout(0.25)
        except OSError as exc:
            try:
                sock.close()
            except Exception:
                pass
            winerr = getattr(exc, "winerror", None) or getattr(exc, "errno", None)
            if winerr == WSAEACCES:
                raise PermissionError(
                    "SIO_RCVALL requires Administrator. "
                    "Right-click the app → Run as administrator."
                ) from exc
            raise
        self.sock = sock
        self._stop.clear()
        self.frames = []

        def _loop():
            deadline = time.time() + self.timeout
            while not self._stop.is_set() and time.time() < deadline:
                try:
                    data = sock.recv(65535)
                except socket.timeout:
                    continue
                except OSError:
                    break
                if not ip_datagram_match(data, self.dest_ip, self.protocol, self.port):
                    continue
                frame = (time.time(), bytes(data))
                with self._lock:
                    if len(self.frames) >= self.max_packets:
                        break
                    self.frames.append(frame)

        self._thread = threading.Thread(target=_loop, name="windows-raw-capture", daemon=True)
        self._thread.start()
        log.info(
            "Windows SIO_RCVALL capture started on %s filter dest=%s proto=%s port=%s",
            self.local_ip, self.dest_ip, self.protocol, self.port,
        )
        return True

    def _enable_rcvall(self, sock):
        last = None
        for mode in (RCVALL_ON, RCVALL_IPLEVEL):
            try:
                sock.ioctl(SIO_RCVALL, mode)
                return
            except OSError as exc:
                last = exc
        raise last

    def stop(self):
        self._stop.set()
        sock = self.sock
        self.sock = None
        if sock is not None:
            try:
                sock.ioctl(SIO_RCVALL, RCVALL_OFF)
            except OSError:
                pass
            try:
                sock.close()
            except OSError:
                pass
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None
        with self._lock:
            frames = list(self.frames)
        log.info("Windows SIO_RCVALL capture stopped packets=%s", len(frames))
        return frames
