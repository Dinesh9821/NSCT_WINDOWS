"""
Protocol analysis of Wireshark-compatible PCAP/PCAPNG files.

Identifies TCP handshake/flags, ICMP echo, UDP, and DNS facts relevant to
the app's diagnostics. Does not invent results — fields stay False/0 when
the packets are not in the file.
"""

from __future__ import annotations

import logging
import struct

from backend.pcap_io import (
    LINKTYPE_ETHERNET, LINKTYPE_LINUX_SLL, LINKTYPE_NULL, LINKTYPE_RAW,
    packet_count, read_packets,
)

log = logging.getLogger("NetworkAI.PacketAnalysis")

TCP_FIN = 0x01
TCP_SYN = 0x02
TCP_RST = 0x04
TCP_PSH = 0x08
TCP_ACK = 0x10
TCP_URG = 0x20


def _yes(flag):
    return "YES" if flag else "NO"


def analyze_pcap(path, protocol="TCP", source_ip=None, dest_ip=None, dest_port=None):
    """
    Return a JSON-serializable analysis dict. Safe on missing/corrupt files.
    """
    protocol = (protocol or "TCP").upper()
    result = {
        "packet_count": 0,
        "wireshark_compatible": False,
        "file": path,
        "protocol": protocol,
        "source_ip": source_ip,
        "dest_ip": dest_ip,
        "dest_port": dest_port,
        "tcp": None,
        "icmp": None,
        "udp": None,
        "dns": None,
        "timing_ms": None,
        "error": None,
        "summary": "",
    }
    if not path:
        result["error"] = "No capture file"
        result["summary"] = "No packet capture file was produced."
        return result
    try:
        frames = list(read_packets(path))
    except Exception as e:
        log.warning("PCAP parse failed: %s", e)
        result["error"] = str(e)
        result["summary"] = "Capture file could not be parsed."
        return result

    result["packet_count"] = len(frames)
    result["wireshark_compatible"] = True
    parsed = []
    for fr in frames:
        rec = _decode_frame(fr.get("data") or b"", fr.get("linktype", LINKTYPE_ETHERNET))
        if rec:
            rec["ts"] = fr.get("ts")
            rec["length"] = fr.get("incl_len") or len(fr.get("data") or b"")
            parsed.append(rec)

    times = [p["ts"] for p in parsed if p.get("ts") is not None]
    if len(times) >= 2:
        result["timing_ms"] = round((max(times) - min(times)) * 1000, 2)
    elif len(times) == 1:
        result["timing_ms"] = 0

    result["tcp"] = _analyze_tcp(parsed, source_ip, dest_ip, dest_port)
    result["icmp"] = _analyze_icmp(parsed, source_ip, dest_ip)
    result["udp"] = _analyze_udp(parsed, source_ip, dest_ip, dest_port)
    result["dns"] = _analyze_dns(parsed)

    result["summary"] = _summary_line(result, protocol)
    return result


def _decode_frame(data, linktype):
    if not data:
        return None
    ip_data = None
    if linktype == LINKTYPE_ETHERNET:
        if len(data) < 14:
            return None
        ethertype = struct.unpack("!H", data[12:14])[0]
        off = 14
        if ethertype == 0x8100 and len(data) >= 18:
            ethertype = struct.unpack("!H", data[16:18])[0]
            off = 18
        if ethertype == 0x0800:
            ip_data = data[off:]
        elif ethertype == 0x86DD:
            return _parse_ipv6(data[off:])
        else:
            return None
    elif linktype == LINKTYPE_LINUX_SLL:
        if len(data) < 16:
            return None
        proto = struct.unpack("!H", data[14:16])[0]
        if proto == 0x0800:
            ip_data = data[16:]
        elif proto == 0x86DD:
            return _parse_ipv6(data[16:])
        else:
            return None
    elif linktype == LINKTYPE_NULL:
        if len(data) < 5:
            return None
        family = struct.unpack("<I", data[:4])[0]
        if family in (2, 0x02000000):  # AF_INET
            ip_data = data[4:]
        else:
            return _parse_ipv6(data[4:]) if len(data) > 4 else None
    elif linktype in (LINKTYPE_RAW, 12, 14):
        version = data[0] >> 4
        if version == 4:
            ip_data = data
        elif version == 6:
            return _parse_ipv6(data)
        else:
            return None
    else:
        # Best-effort: treat as ethernet then raw IPv4
        if len(data) >= 14 and struct.unpack("!H", data[12:14])[0] in (0x0800, 0x86DD, 0x8100):
            return _decode_frame(data, LINKTYPE_ETHERNET)
        if data and (data[0] >> 4) == 4:
            ip_data = data
        else:
            return None
    if not ip_data:
        return None
    return _parse_ipv4(ip_data)


def _parse_ipv4(data):
    if len(data) < 20:
        return None
    vihl = data[0]
    if (vihl >> 4) != 4:
        return None
    ihl = (vihl & 0x0F) * 4
    if ihl < 20 or len(data) < ihl:
        return None
    total_len = struct.unpack("!H", data[2:4])[0]
    proto = data[9]
    src = _dotted(data[12:16])
    dst = _dotted(data[16:20])
    payload = data[ihl:total_len if total_len >= ihl else None]
    rec = {
        "ip_version": 4,
        "ip_src": src,
        "ip_dst": dst,
        "ip_proto": proto,
        "sport": None,
        "dport": None,
        "tcp_flags": 0,
        "tcp_seq": None,
        "tcp_ack": None,
        "icmp_type": None,
        "icmp_code": None,
        "payload": payload,
        "l4": None,
    }
    if proto == 6:
        _fill_tcp(rec, payload)
    elif proto == 17:
        _fill_udp(rec, payload)
    elif proto == 1:
        _fill_icmp(rec, payload)
    return rec


def _parse_ipv6(data):
    if not data or len(data) < 40:
        return None
    if (data[0] >> 4) != 6:
        return None
    next_hdr = data[6]
    src = _v6(data[8:24])
    dst = _v6(data[24:40])
    payload = data[40:]
    rec = {
        "ip_version": 6,
        "ip_src": src,
        "ip_dst": dst,
        "ip_proto": next_hdr,
        "sport": None,
        "dport": None,
        "tcp_flags": 0,
        "tcp_seq": None,
        "tcp_ack": None,
        "icmp_type": None,
        "icmp_code": None,
        "payload": payload,
        "l4": None,
    }
    # skip a single hop-by-hop/routing/fragment header if present
    if next_hdr in (0, 43, 44, 60) and len(payload) >= 2:
        ext_len = (payload[1] + 1) * 8
        next_hdr = payload[0]
        payload = payload[ext_len:]
        rec["ip_proto"] = next_hdr
        rec["payload"] = payload
    if next_hdr == 6:
        _fill_tcp(rec, payload)
    elif next_hdr == 17:
        _fill_udp(rec, payload)
    elif next_hdr in (58, 1):
        _fill_icmp(rec, payload)
    return rec


def _fill_tcp(rec, payload):
    if len(payload) < 20:
        return
    sport, dport, seq, ack, offset_flags = struct.unpack("!HHIIH", payload[:14])
    rec["sport"] = sport
    rec["dport"] = dport
    rec["tcp_seq"] = seq
    rec["tcp_ack"] = ack
    rec["tcp_flags"] = offset_flags & 0x01FF
    rec["l4"] = "TCP"
    data_off = (offset_flags >> 12) * 4
    rec["payload"] = payload[data_off:] if data_off <= len(payload) else b""


def _fill_udp(rec, payload):
    if len(payload) < 8:
        return
    sport, dport, length, _csum = struct.unpack("!HHHH", payload[:8])
    rec["sport"] = sport
    rec["dport"] = dport
    rec["l4"] = "UDP"
    rec["payload"] = payload[8:length if length >= 8 else None]


def _fill_icmp(rec, payload):
    if len(payload) < 4:
        return
    rec["icmp_type"] = payload[0]
    rec["icmp_code"] = payload[1]
    rec["l4"] = "ICMP"
    rec["payload"] = payload[4:]


def _dotted(b):
    return ".".join(str(x) for x in b)


def _v6(b):
    parts = struct.unpack("!8H", b)
    return ":".join("%x" % p for p in parts)


def _involved(rec, source_ip, dest_ip):
    if not source_ip and not dest_ip:
        return True
    ips = {rec.get("ip_src"), rec.get("ip_dst")}
    if dest_ip and dest_ip not in ips:
        return False
    return True


def _port_match(rec, dest_port):
    if not dest_port:
        return True
    return rec.get("sport") == dest_port or rec.get("dport") == dest_port


def _analyze_tcp(parsed, source_ip, dest_ip, dest_port):
    pkts = [p for p in parsed if p.get("l4") == "TCP" and _involved(p, source_ip, dest_ip)]
    if dest_port:
        focused = [p for p in pkts if _port_match(p, dest_port)]
        if focused:
            pkts = focused
    syn = synack = ack = rst = fin = False
    retrans = 0
    seen_seq = {}
    sports, dports = set(), set()
    for p in pkts:
        flags = p.get("tcp_flags") or 0
        if flags & TCP_SYN and not (flags & TCP_ACK):
            syn = True
        if flags & TCP_SYN and flags & TCP_ACK:
            synack = True
        if flags & TCP_ACK and not (flags & TCP_SYN):
            ack = True
        if flags & TCP_RST:
            rst = True
        if flags & TCP_FIN:
            fin = True
        if p.get("sport"):
            sports.add(p["sport"])
        if p.get("dport"):
            dports.add(p["dport"])
        key = (p.get("ip_src"), p.get("ip_dst"), p.get("sport"), p.get("dport"), p.get("tcp_seq"), len(p.get("payload") or b""))
        payload_len = len(p.get("payload") or b"")
        # Retransmission: same 4-tuple + seq with payload, seen before
        if p.get("tcp_seq") is not None and (payload_len > 0 or flags & TCP_SYN):
            if key in seen_seq:
                retrans += 1
            else:
                seen_seq[key] = True
    handshake = syn and synack and ack
    response = synack or rst or (ack and not syn)
    return {
        "packet_count": len(pkts),
        "syn": _yes(syn),
        "syn_ack": _yes(synack),
        "ack": _yes(ack),
        "rst": _yes(rst),
        "fin": _yes(fin),
        "retransmissions": retrans,
        "handshake_complete": handshake,
        "response_received": response,
        "source_ports": sorted(sports),
        "dest_ports": sorted(dports),
        "syn_bool": syn,
        "syn_ack_bool": synack,
        "ack_bool": ack,
        "rst_bool": rst,
    }


def _analyze_icmp(parsed, source_ip, dest_ip):
    pkts = [p for p in parsed if p.get("l4") == "ICMP" and _involved(p, source_ip, dest_ip)]
    requests = sum(1 for p in pkts if p.get("icmp_type") == 8)
    replies = sum(1 for p in pkts if p.get("icmp_type") == 0)
    dest_unreach = sum(1 for p in pkts if p.get("icmp_type") == 3)
    time_exc = sum(1 for p in pkts if p.get("icmp_type") == 11)
    total = requests or (requests + replies)
    loss = None
    if requests:
        loss = max(0, round((1 - (min(replies, requests) / requests)) * 100))
    return {
        "packet_count": len(pkts),
        "echo_request": _yes(requests > 0),
        "echo_reply": _yes(replies > 0),
        "request_count": requests,
        "response_count": replies,
        "packet_loss_pct": loss,
        "dest_unreachable": dest_unreach,
        "time_exceeded": time_exc,
    }


def _analyze_udp(parsed, source_ip, dest_ip, dest_port):
    pkts = [p for p in parsed if p.get("l4") == "UDP" and _involved(p, source_ip, dest_ip)]
    if dest_port:
        focused = [p for p in pkts if _port_match(p, dest_port)]
        if focused:
            pkts = focused
    outbound = inbound = 0
    sports, dports = set(), set()
    for p in pkts:
        if dest_ip and p.get("ip_dst") == dest_ip:
            outbound += 1
        elif dest_ip and p.get("ip_src") == dest_ip:
            inbound += 1
        if p.get("sport"):
            sports.add(p["sport"])
        if p.get("dport"):
            dports.add(p["dport"])
    if not dest_ip:
        outbound = inbound = None
    return {
        "packet_count": len(pkts),
        "outbound": outbound,
        "response_packets": inbound,
        "response_received": bool(inbound),
        "source_ports": sorted(sports),
        "dest_ports": sorted(dports),
    }


def _analyze_dns(parsed):
    pkts = [p for p in parsed if p.get("l4") in ("UDP", "TCP")
            and (p.get("sport") == 53 or p.get("dport") == 53)]
    query_name = None
    response_ip = None
    rcode = None
    has_query = has_resp = False
    dns_server = None
    for p in pkts:
        payload = p.get("payload") or b""
        info = _parse_dns(payload)
        if not info:
            continue
        if info["qr"] == 0:
            has_query = True
            query_name = query_name or info.get("qname")
            if p.get("dport") == 53:
                dns_server = p.get("ip_dst")
        else:
            has_resp = True
            rcode = info.get("rcode")
            response_ip = response_ip or info.get("a_record")
            if p.get("sport") == 53:
                dns_server = p.get("ip_src")
    if not pkts:
        return None
    status = None
    if rcode is not None:
        status = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN"}.get(rcode, str(rcode))
    return {
        "packet_count": len(pkts),
        "dns_request": _yes(has_query),
        "dns_response": _yes(has_resp),
        "query_name": query_name,
        "dns_server": dns_server,
        "response_ip": response_ip,
        "response_status": status,
    }


def _parse_dns(payload):
    if len(payload) < 12:
        return None
    try:
        _id, flags, qd, an, _ns, _ar = struct.unpack("!HHHHHH", payload[:12])
        qr = (flags >> 15) & 1
        rcode = flags & 0xF
        qname, pos = _dns_name(payload, 12)
        a_record = None
        # skip QTYPE/QCLASS
        pos += 4
        for _ in range(an):
            if pos + 10 > len(payload):
                break
            if payload[pos] & 0xC0 == 0xC0:
                pos += 2
            else:
                _, pos = _dns_name(payload, pos)
            if pos + 10 > len(payload):
                break
            rtype, _rclass, _ttl, rdlen = struct.unpack("!HHIH", payload[pos:pos + 10])
            pos += 10
            rdata = payload[pos:pos + rdlen]
            pos += rdlen
            if rtype == 1 and rdlen == 4:
                a_record = _dotted(rdata)
                break
        return {"qr": qr, "rcode": rcode, "qname": qname, "a_record": a_record, "qd": qd}
    except Exception:
        return None


def _dns_name(buf, pos):
    labels = []
    jumped = False
    guard = 0
    end = pos
    while guard < 20 and pos < len(buf):
        guard += 1
        length = buf[pos]
        if length == 0:
            if not jumped:
                end = pos + 1
            break
        if length & 0xC0 == 0xC0:
            if pos + 1 >= len(buf):
                break
            ptr = ((length & 0x3F) << 8) | buf[pos + 1]
            if not jumped:
                end = pos + 2
            pos = ptr
            jumped = True
            continue
        pos += 1
        labels.append(buf[pos:pos + length].decode("ascii", errors="replace"))
        pos += length
        if not jumped:
            end = pos
    return ".".join(labels), end if jumped else end


def _summary_line(result, protocol):
    n = result["packet_count"]
    if protocol == "TCP" and result.get("tcp"):
        t = result["tcp"]
        return ("TCP packets: {n}; SYN={syn} SYN/ACK={sa} ACK={ack} RST={rst} "
                "Retransmissions={r}".format(
                    n=t["packet_count"], syn=t["syn"], sa=t["syn_ack"],
                    ack=t["ack"], rst=t["rst"], r=t["retransmissions"]))
    if protocol == "ICMP" and result.get("icmp"):
        i = result["icmp"]
        return ("ICMP echo request={req} reply={rep} loss={loss}% ({n} ICMP packets)".format(
            req=i["echo_request"], rep=i["echo_reply"],
            loss=i["packet_loss_pct"] if i["packet_loss_pct"] is not None else "n/a",
            n=i["packet_count"]))
    if protocol == "UDP" and result.get("udp"):
        u = result["udp"]
        return "UDP packets: {n}; responses: {r}".format(
            n=u["packet_count"], r=u["response_packets"])
    return "{n} packet(s) in capture.".format(n=n)


def count_packets(path):
    try:
        return packet_count(path)
    except Exception:
        return 0
