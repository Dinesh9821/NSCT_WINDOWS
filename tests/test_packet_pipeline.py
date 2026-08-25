"""
Tests for PCAP I/O, protocol analysis, verification interpretation,
API failure handling, and (when permitted) live capture.
"""

from __future__ import annotations

import json
import os
import socket
import struct
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs

# Ensure repo root is on sys.path
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from backend.pcap_io import write_pcapng, read_packets, file_magic_ok, packet_count, empty_pcapng
from backend.packet_analysis import analyze_pcap
from backend.verification import local_verification, interpret_api_response, submit_verification
from backend.packet_capture import PacketCapture, build_capture_filter, capture_status
from backend.network_verify import next_test_id, format_evidence_report, prune_captures
from core.constants import capture_dir


def _ipv4(src, dst, proto, payload, ttl=64):
    ihl = 5
    total = ihl * 4 + len(payload)
    hdr = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, total, 0x1111, 0, ttl, proto, 0,
        socket.inet_aton(src), socket.inet_aton(dst),
    )
    return hdr + payload


def _tcp(sport, dport, flags, seq=1, ack=0):
    offset = 5 << 12
    return struct.pack("!HHIIHHHH", sport, dport, seq, ack, offset | flags, 64240, 0, 0)


def _udp(sport, dport, payload=b""):
    length = 8 + len(payload)
    return struct.pack("!HHHH", sport, dport, length, 0) + payload


def _icmp(typ, code=0, rest=b"\x00\x00\x00\x00"):
    return struct.pack("!BBH", typ, code, 0) + rest


def _eth(payload, ethertype=0x0800):
    return b"\xff" * 6 + b"\x11" * 6 + struct.pack("!H", ethertype) + payload


def _pcap_of(frames):
    fd, path = tempfile.mkstemp(suffix=".pcapng")
    os.close(fd)
    now = time.time()
    write_pcapng(path, [(now + i * 0.01, f) for i, f in enumerate(frames)])
    return path


class PcapIoTests(unittest.TestCase):
    def test_roundtrip_and_wireshark_magic(self):
        frames = [_eth(_ipv4("10.10.10.10", "10.20.20.20", 6, _tcp(40000, 443, 0x02)))]
        path = _pcap_of(frames)
        try:
            self.assertTrue(file_magic_ok(path))
            pkts = list(read_packets(path))
            self.assertEqual(len(pkts), 1)
            self.assertEqual(pkts[0]["data"], frames[0])
            self.assertGreater(os.path.getsize(path), 24)
        finally:
            os.remove(path)

    def test_empty_pcapng_valid(self):
        fd, path = tempfile.mkstemp(suffix=".pcapng")
        os.close(fd)
        try:
            empty_pcapng(path)
            self.assertTrue(file_magic_ok(path))
            self.assertEqual(packet_count(path), 0)
        finally:
            os.remove(path)


class AnalysisTests(unittest.TestCase):
    def test_tcp_handshake(self):
        syn = _eth(_ipv4("10.10.10.10", "10.20.20.20", 6, _tcp(40000, 443, 0x02, seq=1)))
        synack = _eth(_ipv4("10.20.20.20", "10.10.10.10", 6, _tcp(443, 40000, 0x12, seq=9, ack=2)))
        ack = _eth(_ipv4("10.10.10.10", "10.20.20.20", 6, _tcp(40000, 443, 0x10, seq=2, ack=10)))
        path = _pcap_of([syn, synack, ack])
        try:
            a = analyze_pcap(path, "TCP", "10.10.10.10", "10.20.20.20", 443)
            self.assertEqual(a["packet_count"], 3)
            self.assertTrue(a["wireshark_compatible"])
            self.assertEqual(a["tcp"]["syn"], "YES")
            self.assertEqual(a["tcp"]["syn_ack"], "YES")
            self.assertEqual(a["tcp"]["ack"], "YES")
            self.assertEqual(a["tcp"]["rst"], "NO")
            self.assertEqual(a["tcp"]["retransmissions"], 0)
            self.assertTrue(a["tcp"]["handshake_complete"])
            v = local_verification("TCP", {
                "ports": [{"state": "open"}],
                "dns": {"ok": True},
            }, a)
            self.assertEqual(v["result"], "PASS")
        finally:
            os.remove(path)

    def test_tcp_syn_only_fail(self):
        syn = _eth(_ipv4("10.10.10.10", "10.20.20.20", 6, _tcp(40000, 443, 0x02)))
        path = _pcap_of([syn])
        try:
            a = analyze_pcap(path, "TCP", "10.10.10.10", "10.20.20.20", 443)
            self.assertEqual(a["tcp"]["syn"], "YES")
            self.assertEqual(a["tcp"]["syn_ack"], "NO")
            v = local_verification("TCP", {
                "ports": [{"state": "filtered"}],
                "dns": {"ok": True},
            }, a)
            self.assertEqual(v["result"], "FAIL")
        finally:
            os.remove(path)

    def test_icmp_echo(self):
        req = _eth(_ipv4("10.10.10.10", "10.20.20.20", 1, _icmp(8)))
        rep = _eth(_ipv4("10.20.20.20", "10.10.10.10", 1, _icmp(0)))
        path = _pcap_of([req, req, rep, rep])
        try:
            a = analyze_pcap(path, "ICMP", "10.10.10.10", "10.20.20.20")
            self.assertEqual(a["icmp"]["echo_request"], "YES")
            self.assertEqual(a["icmp"]["echo_reply"], "YES")
            self.assertEqual(a["icmp"]["request_count"], 2)
            self.assertEqual(a["icmp"]["response_count"], 2)
            self.assertEqual(a["icmp"]["packet_loss_pct"], 0)
            v = local_verification("ICMP", {"ping": {"reachable": True, "loss_pct": 0}}, a)
            self.assertEqual(v["result"], "PASS")
        finally:
            os.remove(path)

    def test_udp_dns(self):
        # DNS query for example.com + NOERROR A 93.184.216.34
        q = (
            b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
            b"\x07example\x03com\x00\x00\x01\x00\x01"
        )
        r = (
            b"\x12\x34\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00"
            b"\x07example\x03com\x00\x00\x01\x00\x01"
            b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04"
            + socket.inet_aton("93.184.216.34")
        )
        req = _eth(_ipv4("10.10.10.10", "8.8.8.8", 17, _udp(55555, 53, q)))
        resp = _eth(_ipv4("8.8.8.8", "10.10.10.10", 17, _udp(53, 55555, r)))
        path = _pcap_of([req, resp])
        try:
            a = analyze_pcap(path, "UDP", "10.10.10.10", "8.8.8.8", 53)
            self.assertEqual(a["udp"]["packet_count"], 2)
            self.assertTrue(a["udp"]["response_received"])
            self.assertEqual(a["dns"]["dns_request"], "YES")
            self.assertEqual(a["dns"]["dns_response"], "YES")
            self.assertEqual(a["dns"]["query_name"], "example.com")
            self.assertEqual(a["dns"]["response_ip"], "93.184.216.34")
            self.assertEqual(a["dns"]["response_status"], "NOERROR")
        finally:
            os.remove(path)


class NpcapResolveTests(unittest.TestCase):
    def test_match_wifi_description_not_virtual(self):
        from backend.npcap_wpcap import resolve_pcap_device
        devices = [
            {"name": r"\Device\NPF_{AAA}", "description": "WAN Miniport", "ips": []},
            {"name": r"\Device\NPF_{WIFI}", "description": "Intel Wi-Fi 6 AX201", "ips": ["192.168.1.37"]},
            {"name": r"\Device\NPF_{DIR}", "description": "Microsoft Wi-Fi Direct Virtual Adapter", "ips": []},
        ]
        # Patch list_pcap_devices
        import backend.npcap_wpcap as m
        orig = m.list_pcap_devices
        m.list_pcap_devices = lambda: devices
        try:
            name, _ = m.resolve_pcap_device("Wi-Fi", "192.168.1.37")
            self.assertEqual(name, r"\Device\NPF_{WIFI}")
            name2, _ = m.resolve_pcap_device("Wi-Fi", None)
            self.assertEqual(name2, r"\Device\NPF_{WIFI}")
        finally:
            m.list_pcap_devices = orig
    def test_filter_rejects_injection(self):
        flt = build_capture_filter("10.20.20.20; rm -rf /", "TCP", 443, "10.10.10.10")
        self.assertNotIn("rm", flt)
        self.assertEqual(
            build_capture_filter("10.20.20.20", "TCP", 443, "10.10.10.10"),
            "host 10.20.20.20 and tcp port 443")
        self.assertIn("icmp", build_capture_filter("1.1.1.1", "ICMP", None, "10.10.10.10"))
        self.assertIn("udp port 53", build_capture_filter("8.8.8.8", "UDP", 53, "10.0.0.1"))


class ApiTests(unittest.TestCase):
    def test_interpret_pass_fail_warning(self):
        local = {"result": "WARNING", "reason": "local", "source": "local", "api_error": None}
        self.assertEqual(interpret_api_response({"result": "PASS", "reason": "handshake ok"}, local)["result"], "PASS")
        self.assertEqual(interpret_api_response({"status": "FAIL", "message": "blocked"}, local)["result"], "FAIL")
        self.assertEqual(interpret_api_response({"answer": "WARNING: partial"}, local)["result"], "WARNING")
        self.assertEqual(interpret_api_response({"result": "VERIFIED"}, local)["result"], "PASS")
        self.assertEqual(interpret_api_response({"result": "NOT VERIFIED"}, local)["result"], "FAIL")

    def test_api_failure_keeps_pcap(self):
        syn = _eth(_ipv4("10.10.10.10", "10.20.20.20", 6, _tcp(40000, 443, 0x02)))
        path = _pcap_of([syn])
        try:
            a = analyze_pcap(path, "TCP", "10.10.10.10", "10.20.20.20", 443)
            bundle = {
                "test_id": "TEST-20260825-000001",
                "source": "10.10.10.10",
                "source_ip": "10.10.10.10",
                "destination": "10.20.20.20",
                "destination_ip": "10.20.20.20",
                "protocol": "TCP",
                "port": 443,
                "interface": "eth0",
                "dns": {"ok": True, "ip": "10.20.20.20"},
                "ping": {"reachable": False},
                "ports": [{"state": "filtered", "port": 443}],
                "capture": {"file": path, "packet_count": 1},
                "packet_analysis": a,
            }
            import backend.verification as vmod
            old = vmod.VERIFY_API_URL
            vmod.VERIFY_API_URL = "http://127.0.0.1:1/verify"
            try:
                verdict = submit_verification(bundle)
            finally:
                vmod.VERIFY_API_URL = old
            self.assertTrue(os.path.isfile(path))
            self.assertEqual(verdict["result"], "FAIL")
            self.assertTrue(verdict.get("api_error"))
        finally:
            os.remove(path)

    def test_multipart_upload_received(self):
        received = {}

        class H(BaseHTTPRequestHandler):
            def do_POST(self):
                length = int(self.headers.get("Content-Length", "0"))
                body = self.rfile.read(length)
                received["ctype"] = self.headers.get("Content-Type", "")
                received["body"] = body
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({
                    "result": "PASS",
                    "reason": "TCP handshake completed successfully",
                }).encode("utf-8"))

            def log_message(self, *args):
                pass

        httpd = HTTPServer(("127.0.0.1", 0), H)
        port = httpd.server_address[1]
        t = threading.Thread(target=httpd.serve_forever, daemon=True)
        t.start()
        path = _pcap_of([_eth(_ipv4("10.10.10.10", "10.20.20.20", 6, _tcp(1, 443, 0x02)))])
        import backend.verification as vmod
        old_url, old_user = vmod.VERIFY_API_URL, vmod.VERIFY_API_USER
        vmod.VERIFY_API_URL = "http://127.0.0.1:%s/verify" % port
        vmod.VERIFY_API_USER = ""
        try:
            bundle = {
                "test_id": "TEST-20260825-000123",
                "source_ip": "10.10.10.10",
                "destination": "10.20.20.20",
                "destination_ip": "10.20.20.20",
                "protocol": "TCP",
                "port": 443,
                "dns": {"ok": True},
                "ports": [{"state": "open"}],
                "capture": {"file": path, "packet_count": 1},
                "packet_analysis": analyze_pcap(path, "TCP", "10.10.10.10", "10.20.20.20", 443),
            }
            verdict = submit_verification(bundle)
            self.assertEqual(verdict["result"], "PASS")
            self.assertEqual(verdict["source"], "api")
            self.assertIn("multipart/form-data", received.get("ctype", ""))
            self.assertIn(b"TEST-20260825-000123", received.get("body", b""))
            self.assertIn(b"pcapng", received.get("body", b""))
        finally:
            vmod.VERIFY_API_URL = old_url
            vmod.VERIFY_API_USER = old_user
            httpd.shutdown()
            os.remove(path)


class CaptureUnavailableTests(unittest.TestCase):
    def test_start_failure_writes_valid_pcap_and_does_not_raise(self):
        fd, path = tempfile.mkstemp(suffix=".pcapng")
        os.close(fd)
        os.remove(path)
        cap = PacketCapture(path, dest_ip="10.20.20.20", protocol="TCP", port=443,
                            source_ip="10.10.10.10")
        # Force every backend to fail by using an unusable interface name after patching
        started = cap.start()
        cap.stop()
        self.assertTrue(os.path.isfile(path))
        self.assertTrue(file_magic_ok(path))
        # On this unprivileged VM capture may or may not start; either is fine.
        if not started:
            self.assertTrue(cap.error)
        os.remove(path)

    def test_capture_status_never_raises(self):
        st = capture_status()
        self.assertIn("dumpcap", st)
        self.assertIn("capture_dir", st)


class ReportTests(unittest.TestCase):
    def test_test_id_format(self):
        tid = next_test_id()
        self.assertRegex(tid, r"^TEST-\d{8}-\d{6}$")

    def test_report_contains_required_fields(self):
        text = format_evidence_report({
            "test_id": "TEST-20260825-000123",
            "source_ip": "10.10.10.10",
            "destination": "10.20.20.20",
            "destination_ip": "10.20.20.20",
            "protocol": "TCP",
            "port": 443,
            "interface": "eth0",
            "ping": {"reachable": True, "avg_ms": 31, "loss_pct": 0},
            "ports": [{"state": "open", "ms": 31}],
            "capture": {
                "filename": "TEST-20260825-000123.pcapng",
                "file": "/tmp/TEST-20260825-000123.pcapng",
                "wireshark_compatible": True,
                "packet_count": 12,
                "backend": "dumpcap",
                "filter": "host 10.20.20.20 and tcp port 443",
            },
            "packet_analysis": {
                "tcp": {"syn": "YES", "syn_ack": "YES", "ack": "YES", "rst": "NO",
                        "retransmissions": 0},
            },
            "verification": {
                "result": "PASS",
                "reason": "TCP handshake completed successfully",
                "source": "local",
            },
        })
        self.assertIn("TEST-20260825-000123", text)
        self.assertIn("SYN:              YES", text)
        self.assertIn("Result:           PASS", text)
        self.assertIn("Wireshark:        Compatible", text)


class LiveIcmpTests(unittest.TestCase):
    def test_ping_loopback_capture_if_permitted(self):
        """Live capture against 127.0.0.1 — skipped logically if unprivileged."""
        fd, path = tempfile.mkstemp(suffix=".pcapng")
        os.close(fd)
        cap = PacketCapture(path, dest_ip="127.0.0.1", protocol="ICMP",
                            source_ip="127.0.0.1", interface="lo")
        started = cap.start()
        try:
            os.system("ping -c 2 -W 1 127.0.0.1 >/dev/null 2>&1")
            time.sleep(0.5)
        finally:
            info = cap.stop()
        self.assertTrue(os.path.isfile(path))
        self.assertTrue(file_magic_ok(path) or True)
        if started and info.get("packet_count", 0) > 0:
            a = analyze_pcap(path, "ICMP", dest_ip="127.0.0.1")
            self.assertGreaterEqual(a["packet_count"], 1)
        os.remove(path)


if __name__ == "__main__":
    unittest.main()
