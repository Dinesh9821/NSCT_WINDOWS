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

This module never synthesizes packets. If the raw socket cannot be opened,
it fails and the caller writes an empty valid pcapng plus an error.
"""

from __future__ import annotations

import logging
import socket
import struct
import threading
import time

log = logging.getLogger("NetworkAI.WindowsRaw")

# Winsock ioctl values (also provided as socket.SIO_RCVALL on Windows).
SIO_RCVALL = getattr(socket, "SIO_RCVALL", 0x98000001)
RCVALL_ON = getattr(socket, "RCVALL_ON", 1)
RCVALL_OFF = getattr(socket, "RCVALL_OFF", 0)


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
        self.frames = []
        self.error = None

    def start(self):
        if not self.local_ip or self.local_ip in ("—", "127.0.0.1", "::1"):
            # Loopback is not reliably visible via SIO_RCVALL.
            raise PermissionError(
                "Windows raw capture needs a real interface IPv4 address "
                "(loopback is not supported by SIO_RCVALL)."
            )
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        try:
            sock.bind((self.local_ip, 0))
            sock.ioctl(SIO_RCVALL, RCVALL_ON)
            sock.settimeout(0.25)
        except OSError:
            try:
                sock.close()
            except Exception:
                pass
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
                if ip_datagram_match(data, self.dest_ip, self.protocol, self.port):
                    self.frames.append((time.time(), data))

        self._thread = threading.Thread(target=_loop, name="windows-raw-capture", daemon=True)
        self._thread.start()
        log.info("Windows SIO_RCVALL capture started on %s filter dest=%s proto=%s port=%s",
                 self.local_ip, self.dest_ip, self.protocol, self.port)
        return True

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
        log.info("Windows SIO_RCVALL capture stopped packets=%s", len(self.frames))
        return list(self.frames)
