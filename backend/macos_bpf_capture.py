"""
Self-contained macOS packet observation using only the OS and stdlib.

macOS does not provide Linux AF_PACKET. Native capture is Berkeley Packet
Filter devices (``/dev/bpf*``), the same kernel facility Apple's inbox
``/usr/sbin/tcpdump`` uses. No Wireshark, Npcap, or dumpcap is required.

Requires root (or a BPF-group membership). Ethernet frames on ``en*``;
loopback ``lo0`` is DLT_NULL (4-byte AF header), not Ethernet.

This module never synthesizes packets.
"""
from __future__ import annotations

import logging
import os
import sys
import struct
import threading
import time

from core.constants import CAPTURE_MAX_PACKETS

log = logging.getLogger("NetworkAI.MacosBpf")

# Darwin sys/ioccom.h
IOC_VOID = 0x20000000
IOC_OUT = 0x40000000
IOC_IN = 0x80000000
IOC_INOUT = IOC_IN | IOC_OUT
IFNAMSIZ = 16
IFREQ_SIZE = 32
DLT_NULL = 0
DLT_EN10MB = 1
DLT_RAW = 12
BPF_MAXDEV = 256


def _ioc(inout, group, num, length):
    return inout | ((length & 0x1FFF) << 16) | (ord(group) << 8) | num


BIOCGBLEN = _ioc(IOC_OUT, "B", 102, 4)
BIOCSBLEN = _ioc(IOC_INOUT, "B", 102, 4)
BIOCSETIF = _ioc(IOC_IN, "B", 108, IFREQ_SIZE)
BIOCPROMISC = _ioc(IOC_VOID, "B", 105, 0)
BIOCGDLT = _ioc(IOC_OUT, "B", 106, 4)
BIOCIMMEDIATE = _ioc(IOC_IN, "B", 112, 4)
BIOCSSEESENT = _ioc(IOC_IN, "B", 119, 4)

# timeval (16) + caplen/datalen (8) + hdrlen (2) on Darwin LP64
_BPF_HDR_MIN = 18


def bpf_wordalign(value):
    """Darwin BPF_WORDALIGN — 4-byte alignment."""
    return (value + 3) & ~3


def parse_bpf_buffer(buf):
    """Yield captured frame bytes from a BPF read() buffer."""
    frames = []
    off = 0
    n = len(buf)
    while off + _BPF_HDR_MIN <= n:
        caplen, datalen, hdrlen = struct.unpack_from("<IIH", buf, off + 16)
        if hdrlen < _BPF_HDR_MIN or caplen > 65535 or caplen > datalen + 64:
            break
        start = off + hdrlen
        end = start + caplen
        if end > n:
            break
        frames.append(bytes(buf[start:end]))
        nxt = bpf_wordalign(off + hdrlen + caplen)
        if nxt <= off:
            break
        off = nxt
    return frames


def dlt_to_linktype(dlt):
    """Map BPF DLT_* to pcap linktype used by pcap_io / Wireshark."""
    if dlt == DLT_NULL:
        return 0
    if dlt == DLT_EN10MB:
        return 1
    if dlt in (DLT_RAW, 14, 101):
        return 101
    return int(dlt or 1)


def ip_from_frame(frame, dlt):
    """Return IPv4 datagram bytes, or None."""
    if not frame:
        return None
    if dlt == DLT_NULL:
        if len(frame) < 5:
            return None
        family = struct.unpack("<I", frame[:4])[0]
        if family in (2, 0x02000000):
            return frame[4:]
        return None
    if dlt == DLT_EN10MB:
        if len(frame) < 14:
            return None
        ethertype = struct.unpack("!H", frame[12:14])[0]
        off = 14
        if ethertype == 0x8100 and len(frame) >= 18:
            ethertype = struct.unpack("!H", frame[16:18])[0]
            off = 18
        if ethertype != 0x0800:
            return None
        return frame[off:]
    if dlt in (DLT_RAW, 14, 101) and (frame[0] >> 4) == 4:
        return frame
    if len(frame) >= 14 and struct.unpack("!H", frame[12:14])[0] in (0x0800, 0x8100):
        return ip_from_frame(frame, DLT_EN10MB)
    if (frame[0] >> 4) == 4:
        return frame
    return None


def frame_matches(frame, dlt, dest_ip=None, protocol=None, port=None):
    from backend.windows_raw_capture import ip_datagram_match

    ip = ip_from_frame(frame, dlt)
    if ip is None:
        return False
    return ip_datagram_match(ip, dest_ip, protocol, port)


def open_bpf_device():
    last = None
    for i in range(BPF_MAXDEV):
        path = "/dev/bpf%d" % i
        try:
            return os.open(path, os.O_RDWR)
        except OSError as exc:
            last = exc
            continue
    if last is not None:
        raise last
    raise PermissionError("No /dev/bpf device could be opened.")


class MacosBpfCapture:
    """
    Bind ``/dev/bpf*`` to ``interface`` and store (timestamp, frame_bytes).
    """

    def __init__(self, interface, dest_ip=None, protocol=None, port=None, timeout=45):
        self.interface = interface
        self.dest_ip = dest_ip
        self.protocol = protocol
        self.port = port
        self.timeout = int(timeout or 45)
        self._fd = None
        self._stop = threading.Event()
        self._thread = None
        self._lock = threading.Lock()
        self.frames = []
        self.dlt = DLT_EN10MB
        self.linktype = 1
        self.error = None
        self.max_packets = max(1, int(CAPTURE_MAX_PACKETS or 50000))
        self._buflen = 65535

    def start(self):
        if sys.platform != "darwin":
            raise PermissionError("macOS BPF capture is only available on Darwin.")
        iface = (self.interface or "").strip()
        if not iface:
            raise PermissionError("macOS BPF capture needs a network interface (e.g. en0).")
        fd = open_bpf_device()
        try:
            self._configure(fd, iface)
        except OSError:
            try:
                os.close(fd)
            except OSError:
                pass
            raise
        self._fd = fd
        self._stop.clear()
        self.frames = []

        def _loop():
            deadline = time.time() + self.timeout
            while not self._stop.is_set() and time.time() < deadline:
                try:
                    blob = os.read(fd, self._buflen)
                except InterruptedError:
                    continue
                except OSError:
                    break
                if not blob:
                    continue
                now = time.time()
                for pkt in parse_bpf_buffer(blob):
                    if not frame_matches(pkt, self.dlt, self.dest_ip, self.protocol, self.port):
                        continue
                    with self._lock:
                        if len(self.frames) >= self.max_packets:
                            self._stop.set()
                            break
                        self.frames.append((now, pkt))

        self._thread = threading.Thread(target=_loop, name="macos-bpf-capture", daemon=True)
        self._thread.start()
        log.info(
            "macOS BPF capture started iface=%s dlt=%s dest=%s proto=%s port=%s",
            iface, self.dlt, self.dest_ip, self.protocol, self.port,
        )
        return True

    def _configure(self, fd, iface):
        import array
        import fcntl

        name = iface.encode("utf-8")[: IFNAMSIZ - 1]
        ifreq = name + b"\x00" * (IFREQ_SIZE - len(name))
        fcntl.ioctl(fd, BIOCSETIF, bytearray(ifreq))

        immediate = array.array("I", [1])
        fcntl.ioctl(fd, BIOCIMMEDIATE, immediate)
        try:
            seesent = array.array("I", [1])
            fcntl.ioctl(fd, BIOCSSEESENT, seesent)
        except OSError:
            pass

        dlt_buf = array.array("I", [0])
        fcntl.ioctl(fd, BIOCGDLT, dlt_buf)
        self.dlt = int(dlt_buf[0])
        self.linktype = dlt_to_linktype(self.dlt)

        blen = array.array("I", [0])
        try:
            fcntl.ioctl(fd, BIOCGBLEN, blen)
            if blen[0] > 0:
                self._buflen = int(blen[0])
        except OSError:
            self._buflen = 65535

    def stop(self):
        self._stop.set()
        fd = self._fd
        self._fd = None
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None
        with self._lock:
            frames = list(self.frames)
        log.info("macOS BPF capture stopped packets=%s", len(frames))
        return frames
