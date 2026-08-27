"""
Npcap / WinPcap (wpcap.dll) live capture via ctypes.

dumpcap.exe is part of Wireshark, not Npcap. Npcap only installs the driver
and wpcap.dll — this module opens that DLL so capture works when Npcap is
installed even if Wireshark/dumpcap and Administrator/pktmon are not.
"""

from __future__ import annotations

import ctypes
import logging
import os
import socket
import sys
from ctypes import (
    POINTER, Structure, byref, c_char, c_char_p, c_int, c_ubyte, c_uint,
    c_uint32, c_void_p, create_string_buffer, string_at,
)

log = logging.getLogger("NetworkAI.Npcap")

PCAP_ERRBUF_SIZE = 256
PCAP_ERROR = -1
PCAP_ERROR_BREAK = -2
DLT_EN10MB = 1
AF_INET = 2


class timeval(Structure):
    _fields_ = [("tv_sec", ctypes.c_long), ("tv_usec", ctypes.c_long)]


class pcap_pkthdr(Structure):
    _fields_ = [("ts", timeval), ("caplen", c_uint32), ("len", c_uint32)]


class sockaddr(Structure):
    _fields_ = [("sa_family", ctypes.c_ushort), ("sa_data", c_char * 14)]


class pcap_addr(Structure):
    pass


pcap_addr._fields_ = [
    ("next", POINTER(pcap_addr)),
    ("addr", POINTER(sockaddr)),
    ("netmask", POINTER(sockaddr)),
    ("broadaddr", POINTER(sockaddr)),
    ("dstaddr", POINTER(sockaddr)),
]


class pcap_if(Structure):
    pass


pcap_if._fields_ = [
    ("next", POINTER(pcap_if)),
    ("name", c_char_p),
    ("description", c_char_p),
    ("addresses", POINTER(pcap_addr)),
    ("flags", c_uint32),
]


class bpf_program(Structure):
    _fields_ = [("bf_len", c_uint), ("bf_insns", c_void_p)]


def npcap_dir():
    root = os.environ.get("SystemRoot", r"C:\Windows")
    for folder in (
        os.path.join(root, "System32", "Npcap"),
        os.path.join(root, "SysWOW64", "Npcap"),
        os.path.join(root, "System32"),
    ):
        if os.path.isfile(os.path.join(folder, "wpcap.dll")):
            return folder
    return None


def _prepare_dll_search():
    folder = npcap_dir()
    if not folder:
        return None
    os.environ["PATH"] = folder + os.pathsep + os.environ.get("PATH", "")
    if hasattr(os, "add_dll_directory"):
        try:
            os.add_dll_directory(folder)
        except OSError:
            pass
    packet = os.path.join(folder, "Packet.dll")
    if os.path.isfile(packet):
        try:
            ctypes.WinDLL(packet)
        except OSError as e:
            log.info("Packet.dll load: %s", e)
    return folder


_wpcap = None


def load_wpcap():
    global _wpcap
    if _wpcap is not None:
        return _wpcap
    if not sys.platform.startswith("win"):
        return None
    folder = _prepare_dll_search()
    candidates = []
    if folder:
        candidates.append(os.path.join(folder, "wpcap.dll"))
    candidates.append("wpcap.dll")
    last = None
    for path in candidates:
        try:
            lib = ctypes.WinDLL(path)
        except OSError as e:
            last = e
            continue
        _bind(lib)
        _wpcap = lib
        log.info("Loaded Npcap wpcap from %s", path)
        return lib
    log.info("wpcap.dll not loaded: %s", last)
    return None


def _bind(lib):
    lib.pcap_findalldevs.argtypes = [POINTER(POINTER(pcap_if)), c_char_p]
    lib.pcap_findalldevs.restype = c_int
    lib.pcap_freealldevs.argtypes = [POINTER(pcap_if)]
    lib.pcap_freealldevs.restype = None
    lib.pcap_open_live.argtypes = [c_char_p, c_int, c_int, c_int, c_char_p]
    lib.pcap_open_live.restype = c_void_p
    lib.pcap_close.argtypes = [c_void_p]
    lib.pcap_close.restype = None
    lib.pcap_compile.argtypes = [c_void_p, POINTER(bpf_program), c_char_p, c_int, c_uint32]
    lib.pcap_compile.restype = c_int
    lib.pcap_setfilter.argtypes = [c_void_p, POINTER(bpf_program)]
    lib.pcap_setfilter.restype = c_int
    lib.pcap_freecode.argtypes = [POINTER(bpf_program)]
    lib.pcap_freecode.restype = None
    lib.pcap_next_ex.argtypes = [
        c_void_p, POINTER(POINTER(pcap_pkthdr)), POINTER(POINTER(c_ubyte))]
    lib.pcap_next_ex.restype = c_int
    lib.pcap_datalink.argtypes = [c_void_p]
    lib.pcap_datalink.restype = c_int
    lib.pcap_geterr.argtypes = [c_void_p]
    lib.pcap_geterr.restype = c_char_p
    if hasattr(lib, "pcap_breakloop"):
        lib.pcap_breakloop.argtypes = [c_void_p]
        lib.pcap_breakloop.restype = None


def _c_str(value):
    if value is None:
        return None
    if isinstance(value, bytes):
        return value
    return value.encode("utf-8", errors="replace")


def _ipv4_from_sockaddr(addr_ptr):
    if not addr_ptr:
        return None
    sa = addr_ptr.contents
    if sa.sa_family != AF_INET:
        return None
    raw = bytes(sa.sa_data[2:6])
    try:
        return socket.inet_ntoa(raw)
    except OSError:
        return None


def list_pcap_devices():
    """Return [{'name', 'description', 'ips'}] using Npcap, or []."""
    lib = load_wpcap()
    if lib is None:
        return []
    err = create_string_buffer(PCAP_ERRBUF_SIZE)
    head = POINTER(pcap_if)()
    if lib.pcap_findalldevs(byref(head), err) != 0:
        log.info("pcap_findalldevs failed: %s", err.value)
        return []
    devices = []
    try:
        node = head
        while node:
            iface = node.contents
            name = (iface.name or b"").decode("utf-8", errors="replace")
            desc = (iface.description or b"").decode("utf-8", errors="replace")
            ips = []
            addr = iface.addresses
            while addr:
                ip = _ipv4_from_sockaddr(addr.contents.addr)
                if ip:
                    ips.append(ip)
                addr = addr.contents.next
            devices.append({"name": name, "description": desc, "ips": ips})
            node = iface.next
    finally:
        lib.pcap_freealldevs(head)
    return devices


def resolve_pcap_device(friendly_name=None, source_ip=None):
    """
    Map a Windows friendly name ('Wi-Fi') or source IP to \\Device\\NPF_{GUID}.
    dumpcap/Npcap cannot open 'Wi-Fi' as a device name.
    """
    devices = list_pcap_devices()
    if not devices:
        return None, []
    want = (friendly_name or "").strip().lower()
    if source_ip:
        for d in devices:
            if source_ip in d["ips"]:
                return d["name"], devices
    if want:
        for d in devices:
            desc = (d["description"] or "").lower()
            name = (d["name"] or "").lower()
            if want == desc or want in desc or want in name:
                return d["name"], devices
        # psutil 'Wi-Fi' vs description 'Microsoft Wi-Fi Direct Virtual Adapter'
        for d in devices:
            desc = (d["description"] or "").lower()
            if want == "wi-fi" and "wi-fi" in desc and "virtual" not in desc and "direct" not in desc:
                return d["name"], devices
    for d in devices:
        if d["ips"] and "loopback" not in (d["description"] or "").lower():
            return d["name"], devices
    return devices[0]["name"], devices


class NpcapLive:
    """Open an Npcap handle and read frames until close()."""

    def __init__(self):
        self.handle = None
        self.linktype = DLT_EN10MB
        self._bpf = None
        self.filtered = False
        self.lib = load_wpcap()

    def open(self, device, snaplen=65535, promisc=1, timeout_ms=200, bpf=None):
        if self.lib is None:
            raise RuntimeError("wpcap.dll not loaded")
        err = create_string_buffer(PCAP_ERRBUF_SIZE)
        handle = self.lib.pcap_open_live(_c_str(device), snaplen, promisc, timeout_ms, err)
        if not handle:
            raise RuntimeError((err.value or b"pcap_open_live failed").decode("utf-8", errors="replace"))
        self.handle = handle
        try:
            self.linktype = int(self.lib.pcap_datalink(handle))
        except Exception:
            self.linktype = DLT_EN10MB
        if bpf:
            prog = bpf_program()
            if self.lib.pcap_compile(handle, byref(prog), _c_str(bpf), 1, 0xFFFFFF) == 0:
                if self.lib.pcap_setfilter(handle, byref(prog)) == 0:
                    self._bpf = prog
                    self.filtered = True
                    log.info("Npcap BPF applied: %s", bpf)
                else:
                    self.lib.pcap_freecode(byref(prog))
                    log.info("Npcap setfilter failed (%s), capturing unfiltered and matching in-process", bpf)
            else:
                msg = self.lib.pcap_geterr(handle)
                log.info("Npcap compile failed (%s): %s", bpf, msg)

    def next_packet(self):
        if not self.handle:
            return None
        hdr_p = POINTER(pcap_pkthdr)()
        data_p = POINTER(c_ubyte)()
        rc = self.lib.pcap_next_ex(self.handle, byref(hdr_p), byref(data_p))
        if rc == 1 and hdr_p and data_p:
            hdr = hdr_p.contents
            caplen = int(hdr.caplen)
            ts = float(hdr.ts.tv_sec) + (float(hdr.ts.tv_usec) / 1_000_000.0)
            return ts, string_at(data_p, caplen)
        if rc == 0:
            return None  # timeout
        if rc == PCAP_ERROR_BREAK:
            return None
        if rc < 0:
            msg = self.lib.pcap_geterr(self.handle)
            raise RuntimeError((msg or b"pcap_next_ex").decode("utf-8", errors="replace"))
        return None

    def breakloop(self):
        if self.handle and self.lib and hasattr(self.lib, "pcap_breakloop"):
            try:
                self.lib.pcap_breakloop(self.handle)
            except Exception:
                pass

    def close(self):
        if self.handle and self.lib:
            try:
                if self._bpf is not None:
                    self.lib.pcap_freecode(byref(self._bpf))
            except Exception:
                pass
            try:
                self.lib.pcap_close(self.handle)
            except Exception:
                pass
        self.handle = None
        self._bpf = None
