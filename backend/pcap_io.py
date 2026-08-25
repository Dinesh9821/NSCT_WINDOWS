"""
Minimal PCAP / PCAPNG reader and writer.

Produces files Wireshark can open packet-by-packet. No third-party capture
libraries are required for I/O — backends in packet_capture.py supply frames.
"""

from __future__ import annotations

import os
import struct
import time

PCAP_MAGIC = 0xA1B2C3D4
PCAP_MAGIC_SWAPPED = 0xD4C3B2A1
PCAPNG_SHB = 0x0A0D0D0A
PCAPNG_BYTE_ORDER = 0x1A2B3C4D
BLOCK_IDB = 0x00000001
BLOCK_EPB = 0x00000006
BLOCK_SPB = 0x00000003
BLOCK_PB = 0x00000002
LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 101
LINKTYPE_LINUX_SLL = 113
LINKTYPE_NULL = 0


def _pad4(n):
    return (4 - (n % 4)) % 4


def write_pcapng(path, packets, linktype=LINKTYPE_ETHERNET, snaplen=65535):
    """
    Write packets as pcapng.

    packets: iterable of (timestamp_seconds: float, raw_bytes)
    """
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "wb") as f:
        # Section Header Block
        shb_body = struct.pack("<IHHQ", PCAPNG_BYTE_ORDER, 1, 0, 0xFFFFFFFFFFFFFFFF)
        _write_block(f, PCAPNG_SHB, shb_body)
        # Interface Description Block
        idb_body = struct.pack("<HHI", linktype, 0, snaplen)
        _write_block(f, BLOCK_IDB, idb_body)
        for ts, data in packets:
            data = bytes(data or b"")
            if not data:
                continue
            if len(data) > snaplen:
                data = data[:snaplen]
            ts_int = int(ts * 1_000_000)
            epb = struct.pack("<III", 0, (ts_int >> 32) & 0xFFFFFFFF, ts_int & 0xFFFFFFFF)
            epb += struct.pack("<II", len(data), len(data))
            epb += data
            epb += b"\x00" * _pad4(len(data))
            _write_block(f, BLOCK_EPB, epb)
    return path


def _write_block(f, block_type, body):
    # total length includes type(4) + total_len(4) + body + trailing total_len(4)
    total = 12 + len(body)
    pad = _pad4(len(body))
    total += pad
    f.write(struct.pack("<II", block_type, total))
    f.write(body)
    f.write(b"\x00" * pad)
    f.write(struct.pack("<I", total))


def write_pcap(path, packets, linktype=LINKTYPE_ETHERNET, snaplen=65535):
    """Classic libpcap file (also Wireshark-compatible)."""
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHIIII", PCAP_MAGIC, 2, 4, 0, 0, snaplen, linktype))
        for ts, data in packets:
            data = bytes(data or b"")
            if not data:
                continue
            if len(data) > snaplen:
                data = data[:snaplen]
            sec = int(ts)
            usec = int(round((ts - sec) * 1_000_000))
            if usec >= 1_000_000:
                sec += 1
                usec -= 1_000_000
            f.write(struct.pack("<IIII", sec, usec, len(data), len(data)))
            f.write(data)
    return path


def file_magic_ok(path):
    """True if the file starts with a PCAP or PCAPNG magic."""
    try:
        with open(path, "rb") as f:
            head = f.read(8)
        if len(head) < 4:
            return False
        magic32 = struct.unpack("<I", head[:4])[0]
        magic32b = struct.unpack(">I", head[:4])[0]
        if magic32 in (PCAP_MAGIC, PCAP_MAGIC_SWAPPED, PCAPNG_SHB):
            return True
        if magic32b in (PCAP_MAGIC, PCAP_MAGIC_SWAPPED, PCAPNG_SHB):
            return True
        return False
    except OSError:
        return False


def read_packets(path):
    """
    Yield dicts: {ts, data, incl_len, orig_len, linktype}.
    Supports classic pcap and pcapng (SHB/IDB/EPB/SPB/PB).
    """
    with open(path, "rb") as f:
        head = f.read(4)
        if len(head) < 4:
            return
        magic = struct.unpack("<I", head)[0]
        f.seek(0)
        if magic == PCAPNG_SHB or struct.unpack(">I", head)[0] == PCAPNG_SHB:
            yield from _read_pcapng(f)
        else:
            yield from _read_pcap(f)


def _read_pcap(f):
    hdr = f.read(24)
    if len(hdr) < 24:
        return
    magic = struct.unpack("<I", hdr[:4])[0]
    swapped = magic == PCAP_MAGIC_SWAPPED
    endian = ">" if swapped else "<"
    if magic not in (PCAP_MAGIC, PCAP_MAGIC_SWAPPED):
        magic_be = struct.unpack(">I", hdr[:4])[0]
        if magic_be == PCAP_MAGIC:
            endian = ">"
        elif magic_be == PCAP_MAGIC_SWAPPED:
            endian = "<"
        else:
            return
    ver_maj, ver_min, _tz, _sig, snaplen, linktype = struct.unpack(endian + "HHIIII", hdr[4:])
    del ver_maj, ver_min, snaplen
    while True:
        ph = f.read(16)
        if len(ph) < 16:
            return
        ts_sec, ts_frac, incl, orig = struct.unpack(endian + "IIII", ph)
        data = f.read(incl)
        if len(data) < incl:
            return
        # distinguish micro vs nano by magic: we treat frac as microseconds
        yield {
            "ts": ts_sec + (ts_frac / 1_000_000.0),
            "data": data,
            "incl_len": incl,
            "orig_len": orig,
            "linktype": linktype,
        }


def _read_pcapng(f):
    linktypes = {}
    next_iface = 0
    data = f.read()
    offset = 0
    endian = "<"

    def u32(pos):
        return struct.unpack(endian + "I", data[pos:pos + 4])[0]

    while offset + 12 <= len(data):
        btype_le = struct.unpack_from("<I", data, offset)[0]
        if btype_le == PCAPNG_SHB or struct.unpack_from(">I", data, offset)[0] == PCAPNG_SHB:
            if offset + 16 > len(data):
                return
            bom_le = struct.unpack_from("<I", data, offset + 8)[0]
            endian = "<" if bom_le == PCAPNG_BYTE_ORDER else ">"
            total = u32(offset + 4)
            if total < 12 or offset + total > len(data):
                return
            offset += total
            continue
        total = u32(offset + 4)
        if total < 12 or offset + total > len(data):
            return
        btype = u32(offset)
        body = data[offset + 8: offset + total - 4]
        if btype == BLOCK_IDB and len(body) >= 2:
            lt = struct.unpack(endian + "H", body[:2])[0]
            linktypes[next_iface] = lt
            next_iface += 1
        elif btype == BLOCK_EPB and len(body) >= 20:
            iface, ts_hi, ts_lo, caplen, orig = struct.unpack(endian + "IIIII", body[:20])
            caplen = min(caplen, max(0, len(body) - 20))
            pkt = body[20:20 + caplen]
            ts = ((ts_hi << 32) | ts_lo) / 1_000_000.0
            yield {
                "ts": ts,
                "data": pkt,
                "incl_len": caplen,
                "orig_len": orig,
                "linktype": linktypes.get(iface, LINKTYPE_ETHERNET),
            }
        elif btype == BLOCK_SPB and len(body) >= 4:
            orig = struct.unpack(endian + "I", body[:4])[0]
            caplen = min(orig, len(body) - 4)
            pkt = body[4:4 + caplen]
            yield {
                "ts": time.time(),
                "data": pkt,
                "incl_len": caplen,
                "orig_len": orig,
                "linktype": linktypes.get(0, LINKTYPE_ETHERNET),
            }
        elif btype == BLOCK_PB and len(body) >= 24:
            iface, _drops, ts_hi, ts_lo, caplen, orig = struct.unpack(endian + "IIIIII", body[:24])
            caplen = min(caplen, max(0, len(body) - 24))
            pkt = body[24:24 + caplen]
            ts = ((ts_hi << 32) | ts_lo) / 1_000_000.0
            yield {
                "ts": ts,
                "data": pkt,
                "incl_len": caplen,
                "orig_len": orig,
                "linktype": linktypes.get(iface, LINKTYPE_ETHERNET),
            }
        offset += total


def packet_count(path):
    n = 0
    try:
        for _ in read_packets(path):
            n += 1
    except Exception:
        return 0
    return n


def empty_pcapng(path, linktype=LINKTYPE_ETHERNET):
    """Valid Wireshark-openable file with zero packets (still evidence)."""
    return write_pcapng(path, [], linktype=linktype)
