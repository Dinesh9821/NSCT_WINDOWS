"""
End-to-end evidence-based network verification:

    source → destination → diagnostic → live capture → pcapng →
    analysis → Verification API → interpreted PASS/FAIL/WARNING
"""

from __future__ import annotations

import glob
import logging
import os
import re
import socket
import threading
import time
from datetime import datetime

from core.constants import capture_dir, PCAP_RETENTION, PACKET_CAPTURE_TIMEOUT
from backend.diagnostics import get_local_ip, run_ping, run_traceroute
from backend.packet_capture import PacketCapture, detect_interface
from backend.packet_analysis import analyze_pcap
from backend.verification import submit_verification

log = logging.getLogger("NetworkAI.NetworkVerify")

_SAFE_HOST = re.compile(r"^[A-Za-z0-9._:\-\[\]]{1,253}$")
_seq_lock = threading.Lock()


def next_test_id():
    """TEST-YYYYMMDD-000123 — unique per capture, process-safe via a counter file."""
    day = datetime.now().strftime("%Y%m%d")
    folder = capture_dir()
    seq_path = os.path.join(folder, ".seq-%s" % day)
    with _seq_lock:
        seq = 1
        try:
            with open(seq_path, "r", encoding="utf-8") as f:
                seq = int(f.read().strip() or "0") + 1
        except Exception:
            seq = 1
        seq = max(1, min(seq, 999999))
        try:
            with open(seq_path, "w", encoding="utf-8") as f:
                f.write(str(seq))
        except Exception:
            seq = int(time.time()) % 1000000
        return "TEST-%s-%06d" % (day, seq)


def prune_captures(keep=None):
    keep = PCAP_RETENTION if keep is None else keep
    folder = capture_dir()
    files = []
    for pat in ("TEST-*.pcapng", "TEST-*.pcap"):
        files.extend(glob.glob(os.path.join(folder, pat)))
    files.sort(key=lambda p: os.path.getmtime(p), reverse=True)
    for stale in files[max(0, int(keep)):]:
        try:
            os.remove(stale)
            log.info("Pruned old capture %s", os.path.basename(stale))
        except OSError:
            pass


def sanitize_host(host):
    host = (host or "").strip()
    if not host or not _SAFE_HOST.match(host):
        return None
    return host


def _resolve(host):
    try:
        ip = socket.gethostbyname(host)
        return {"ok": True, "ip": ip, "error": None}
    except Exception as e:
        return {"ok": False, "ip": None, "error": str(e)}


def run_verified_server_test(host, ports_text, proto="TCP", timeout=3.0):
    """Worker entry used by Server Test. Always returns a dict; never raises to the UI."""
    from backend.server_checks import run_server_test, ping_check, parse_ports

    host = sanitize_host(host) or (host or "").strip()
    proto = (proto or "TCP").upper()
    test_id = next_test_id()
    source_ip = get_local_ip()
    interface = detect_interface(source_ip)
    log.info("Test started id=%s dest=%s proto=%s", test_id, host, proto)

    dns = _resolve(host) if host else {"ok": False, "ip": None, "error": "empty host"}
    dest_ip = dns.get("ip")
    log.info("Source/Destination src=%s dst=%s/%s iface=%s", source_ip, host, dest_ip, interface)

    ports = parse_ports(ports_text) if proto != "ICMP" else []
    dest_port = ports[0] if ports else None

    pcap_name = "%s.pcapng" % test_id
    pcap_path = os.path.join(capture_dir(), pcap_name)

    cap = PacketCapture(
        pcap_path, dest_ip=dest_ip, protocol=proto, port=dest_port,
        source_ip=source_ip, interface=interface,
        timeout=max(PACKET_CAPTURE_TIMEOUT, int(timeout) + 20),
    )
    diagnostic = {}
    try:
        if dest_ip:
            cap.start()
        else:
            from backend.pcap_io import empty_pcapng
            empty_pcapng(pcap_path)
            cap.error = "Capture skipped; destination IP could not be resolved"
            cap.wireshark_compatible = True
            log.info("Capture skipped (unresolved dest) id=%s", test_id)
        log.info("Network test started id=%s", test_id)
        if proto == "ICMP":
            ping = ping_check(host)
            diagnostic = {
                "host": host, "dns": dns, "ping": ping, "ports": [],
                "raw": [("Reachability  -  %s" % ping.get("cmd"), ping.get("raw"))],
                "local": False, "proto": proto,
            }
        else:
            diagnostic = run_server_test(host, ports_text, proto=proto, timeout=timeout)
        time.sleep(0.8)
        log.info("Network test completed id=%s", test_id)
    except Exception as e:
        log.exception("Network test failed id=%s", test_id)
        diagnostic = diagnostic or {
            "host": host, "dns": dns, "ping": None, "ports": [],
            "raw": [], "local": False, "proto": proto, "error": str(e),
        }
        diagnostic["error"] = diagnostic.get("error") or str(e)
    finally:
        cap.stop()

    analysis = analyze_pcap(
        pcap_path, protocol=proto, source_ip=source_ip,
        dest_ip=dest_ip, dest_port=dest_port)
    log.info("PCAP analyzed id=%s packets=%s", test_id, analysis.get("packet_count"))

    bundle = dict(diagnostic)
    bundle.update({
        "test_id": test_id,
        "source": source_ip,
        "source_ip": source_ip,
        "destination": host,
        "destination_ip": dest_ip,
        "protocol": proto,
        "port": dest_port,
        "interface": interface,
        "capture": cap.as_dict(),
        "packet_analysis": analysis,
        "route": None,
    })
    bundle["verification"] = submit_verification(bundle)
    try:
        prune_captures()
    except Exception:
        log.debug("retention prune skipped", exc_info=True)
    return bundle


def run_verified_ping(destination):
    """Ping with capture + verification; returns console text for Network Tools."""
    return _run_simple("ICMP", destination, run_ping, "Ping")


def run_verified_traceroute(destination):
    return _run_simple("ICMP", destination, run_traceroute, "Traceroute")


def _run_simple(protocol, destination, fn, title):
    destination = sanitize_host(destination) or (destination or "").strip()
    test_id = next_test_id()
    source_ip = get_local_ip()
    dns = _resolve(destination) if destination else {"ok": False, "ip": None, "error": "empty"}
    dest_ip = dns.get("ip")
    interface = detect_interface(source_ip)
    pcap_path = os.path.join(capture_dir(), "%s.pcapng" % test_id)
    log.info("Test started id=%s %s dest=%s", test_id, title, destination)
    cap = PacketCapture(
        pcap_path, dest_ip=dest_ip, protocol=protocol,
        source_ip=source_ip, interface=interface)
    output = ""
    try:
        cap.start()
        output = fn(destination)
        time.sleep(0.8)
    except Exception as e:
        output = "Error: %s" % e
        log.exception("%s failed", title)
    finally:
        cap.stop()
    analysis = analyze_pcap(pcap_path, protocol=protocol, source_ip=source_ip, dest_ip=dest_ip)
    ping_meta = {}
    if title == "Ping":
        # Infer reachability from the ping text we already collected (do not ping twice).
        low = (output or "").lower()
        ping_meta = {
            "reachable": ("ttl=" in low) or ("bytes from" in low) or ("reply from" in low),
            "loss_pct": None,
            "avg_ms": None,
        }
    bundle = {
        "test_id": test_id,
        "host": destination,
        "source": source_ip,
        "source_ip": source_ip,
        "destination": destination,
        "destination_ip": dest_ip,
        "protocol": protocol,
        "port": None,
        "interface": interface,
        "dns": dns,
        "ping": ping_meta,
        "ports": [],
        "capture": cap.as_dict(),
        "packet_analysis": analysis,
        "raw_output": output,
    }
    bundle["verification"] = submit_verification(bundle)
    try:
        prune_captures()
    except Exception:
        pass
    return format_evidence_report(bundle, command_output=output)


def format_evidence_report(bundle, command_output=None):
    v = bundle.get("verification") or {}
    cap = bundle.get("capture") or {}
    a = bundle.get("packet_analysis") or {}
    tcp = a.get("tcp") or {}
    icmp = a.get("icmp") or {}
    udp = a.get("udp") or {}
    lines = [
        "Test ID:        %s" % bundle.get("test_id"),
        "Source:         %s" % bundle.get("source_ip"),
        "Destination:    %s (%s)" % (bundle.get("destination"), bundle.get("destination_ip") or "unresolved"),
        "Protocol:       %s" % bundle.get("protocol"),
        "Port:           %s" % (bundle.get("port") if bundle.get("port") is not None else "—"),
        "Interface:      %s" % (bundle.get("interface") or "—"),
        "",
        "Connectivity:   %s" % _conn_line(bundle),
        "Latency:        %s" % _lat_line(bundle),
        "Packet Loss:    %s" % _loss_line(bundle),
        "",
        "Packet Capture:",
        "    File:             %s" % cap.get("filename"),
        "    Path:             %s" % cap.get("file"),
        "    Backend:          %s" % (cap.get("backend") or "unavailable"),
        "    Filter:           %s" % (cap.get("filter") or "(none)"),
        "    Wireshark:        %s" % ("Compatible" if cap.get("wireshark_compatible") else "No"),
        "    Packets:          %s" % cap.get("packet_count"),
    ]
    if cap.get("error"):
        lines.append("    Capture note:    %s" % cap["error"])
    proto = (bundle.get("protocol") or "").upper()
    if proto == "TCP" and tcp:
        lines += [
            "",
            "TCP Analysis:",
            "    SYN:              %s" % tcp.get("syn"),
            "    SYN/ACK:          %s" % tcp.get("syn_ack"),
            "    ACK:              %s" % tcp.get("ack"),
            "    RST:              %s" % tcp.get("rst"),
            "    Retransmissions:  %s" % tcp.get("retransmissions"),
        ]
    if proto == "ICMP" and icmp:
        lines += [
            "",
            "ICMP Analysis:",
            "    Echo Request:     %s" % icmp.get("echo_request"),
            "    Echo Reply:       %s" % icmp.get("echo_reply"),
            "    Request count:    %s" % icmp.get("request_count"),
            "    Response count:   %s" % icmp.get("response_count"),
            "    Packet loss:      %s" % icmp.get("packet_loss_pct"),
        ]
    if proto == "UDP" and udp:
        lines += [
            "",
            "UDP Analysis:",
            "    Packets:          %s" % udp.get("packet_count"),
            "    Responses:        %s" % udp.get("response_packets"),
        ]
    dns = a.get("dns")
    if dns:
        lines += [
            "",
            "DNS Analysis:",
            "    Request:          %s" % dns.get("dns_request"),
            "    Response:         %s" % dns.get("dns_response"),
            "    Query:            %s" % dns.get("query_name"),
            "    Server:           %s" % dns.get("dns_server"),
            "    Response IP:      %s" % dns.get("response_ip"),
            "    Status:           %s" % dns.get("response_status"),
        ]
    lines += [
        "",
        "API Verification:",
        "    Result:           %s" % v.get("result"),
        "    Reason:           %s" % v.get("reason"),
        "    Source:           %s" % v.get("source"),
    ]
    if v.get("root_cause"):
        lines.append("    Root cause:       %s" % v["root_cause"])
    if v.get("recommendation"):
        lines.append("    Recommendation:   %s" % v["recommendation"])
    if v.get("api_error"):
        lines.append("    API note:         %s" % v["api_error"])
    if command_output:
        lines += ["", "----- command output -----", command_output]
    return "\n".join(str(x) for x in lines)


def _conn_line(bundle):
    ports = bundle.get("ports") or []
    if any(p.get("state") == "open" for p in ports):
        return "SUCCESS"
    if any(p.get("state") == "filtered" for p in ports):
        return "FAIL (filtered)"
    if any(p.get("state") == "closed" for p in ports):
        return "FAIL (closed)"
    ping = bundle.get("ping") or {}
    if ping.get("reachable"):
        return "SUCCESS"
    if ping:
        return "FAIL"
    return "—"


def _lat_line(bundle):
    ping = bundle.get("ping") or {}
    if ping.get("avg_ms") is not None:
        return "%s ms" % ping["avg_ms"]
    for p in bundle.get("ports") or []:
        if p.get("ms") is not None:
            return "%s ms" % p["ms"]
    return "—"


def _loss_line(bundle):
    ping = bundle.get("ping") or {}
    if ping.get("loss_pct") is not None:
        return "%s%%" % ping["loss_pct"]
    icmp = (bundle.get("packet_analysis") or {}).get("icmp") or {}
    if icmp.get("packet_loss_pct") is not None:
        return "%s%%" % icmp["packet_loss_pct"]
    return "—"
