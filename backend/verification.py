"""
Verification API client and local evidence interpreter.

Remote contract (multipart), matching the existing auth mechanism:

    POST {VERIFY_API_URL}
      fields: test_id, source, destination, protocol, port, ...
      file:   packet_capture  (.pcap / .pcapng)

The API is optional: if it is unreachable the PCAP is kept and a local
PASS / FAIL / WARNING is derived from the diagnostic + packet analysis.
Secrets are never logged.
"""

from __future__ import annotations

import json
import logging
import os
import re

import requests

from core.constants import (
    VERIFY_API_URL, VERIFY_API_TIMEOUT, VERIFY_API_USER, VERIFY_API_PASSWORD,
)

log = logging.getLogger("NetworkAI.Verify")

_PASS_WORDS = ("PASS", "VERIFIED", "OK", "SUCCESS", "OPEN")
_FAIL_WORDS = ("FAIL", "FAILED", "NOT VERIFIED", "BLOCKED", "FILTERED", "ERROR")
_WARN_WORDS = ("WARNING", "WARN", "PARTIAL", "CLOSED")


def local_verification(protocol, diagnostic, analysis):
    """
    Derive PASS / FAIL / WARNING from actual diagnostic + packet facts.
    Never fabricates packet fields; missing capture -> WARNING.
    """
    protocol = (protocol or "TCP").upper()
    capture_err = (analysis or {}).get("error")
    tcp = (analysis or {}).get("tcp") or {}
    icmp = (analysis or {}).get("icmp") or {}
    udp = (analysis or {}).get("udp") or {}
    pkt_n = (analysis or {}).get("packet_count") or 0

    if protocol == "TCP":
        ports = (diagnostic or {}).get("ports") or []
        states = [p.get("state") for p in ports]
        handshake = bool(tcp.get("handshake_complete"))
        syn = bool(tcp.get("syn_bool"))
        synack = bool(tcp.get("syn_ack_bool"))
        rst = bool(tcp.get("rst_bool"))
        if "open" in states and handshake:
            return _verdict("PASS", "TCP handshake completed successfully",
                            expected="SYN, SYN/ACK, ACK",
                            actual="SYN=%s SYN/ACK=%s ACK=%s RST=%s" % (
                                tcp.get("syn"), tcp.get("syn_ack"),
                                tcp.get("ack"), tcp.get("rst")),
                            root_cause=None,
                            recommendation="Service is reachable on the tested port.")
        if "open" in states and not handshake:
            return _verdict("WARNING",
                            "Socket connect succeeded but the capture did not show a full handshake",
                            expected="SYN, SYN/ACK, ACK",
                            actual="packets=%s SYN=%s SYN/ACK=%s" % (pkt_n, tcp.get("syn"), tcp.get("syn_ack")),
                            recommendation="Confirm Npcap/Administrator capture; the port still appears open.")
        if "closed" in states or rst:
            return _verdict("WARNING",
                            "Host answered with RST / connection refused — reachable, nothing listening",
                            expected="TCP handshake",
                            actual="RST=%s state=%s" % (tcp.get("rst"), ",".join(states) or "closed"),
                            root_cause="No service listening on the destination port",
                            recommendation="Confirm the service is bound to this port.")
        if "filtered" in states or (syn and not synack and not rst):
            return _verdict("FAIL",
                            "No SYN/ACK or RST observed — packets are likely dropped by a firewall",
                            expected="SYN/ACK or RST",
                            actual="SYN=%s SYN/ACK=%s RST=%s packets=%s" % (
                                tcp.get("syn"), tcp.get("syn_ack"), tcp.get("rst"), pkt_n),
                            root_cause="Silent drop / ACL / firewall",
                            recommendation="Check host firewall, network ACL, and that the path allows TCP.")
        if not (diagnostic or {}).get("dns", {}).get("ok"):
            return _verdict("FAIL", "DNS resolution failed; no network transaction could be verified",
                            expected="Resolvable hostname",
                            actual=(diagnostic or {}).get("dns", {}).get("error"),
                            root_cause="DNS")
        return _verdict("FAIL", "TCP test did not establish a connection",
                        expected="Open port / handshake",
                        actual="states=%s packets=%s" % (states, pkt_n))

    if protocol == "ICMP":
        ping = (diagnostic or {}).get("ping") or diagnostic or {}
        reply = icmp.get("echo_reply") == "YES"
        request = icmp.get("echo_request") == "YES"
        reachable = bool(ping.get("reachable"))
        if reachable and (reply or pkt_n == 0):
            reason = "ICMP echo reply received"
            if reply:
                reason = "Echo Request and Echo Reply observed in the capture"
            return _verdict("PASS", reason,
                            expected="Echo Reply",
                            actual="requests=%s replies=%s loss=%s" % (
                                icmp.get("request_count"), icmp.get("response_count"),
                                ping.get("loss_pct")),
                            recommendation=None)
        if request and not reply:
            return _verdict("FAIL", "Echo Request sent; no Echo Reply in the capture",
                            expected="Echo Reply",
                            actual="requests=%s replies=0" % icmp.get("request_count"),
                            root_cause="Host down, ICMP blocked, or filtered")
        if not reachable:
            return _verdict("FAIL", "No ICMP reply (host may block ping — not always conclusive)",
                            expected="Echo Reply",
                            actual="reachable=false loss=%s" % ping.get("loss_pct"))
        return _verdict("WARNING", "ICMP test completed with incomplete packet evidence",
                        expected="Echo Request + Echo Reply",
                        actual="packets=%s" % pkt_n)

    if protocol == "UDP":
        ports = (diagnostic or {}).get("ports") or []
        states = [p.get("state") for p in ports]
        resp = bool(udp.get("response_received"))
        if resp or "open" in states:
            return _verdict("PASS", "UDP datagrams exchanged or a response was received",
                            expected="UDP request/response",
                            actual="udp_packets=%s responses=%s" % (
                                udp.get("packet_count"), udp.get("response_packets")),
                            )
        if "filtered" in states or not resp:
            return _verdict("WARNING",
                            "UDP sent with no response (open|filtered — UDP is connectionless)",
                            expected="Optional UDP/ICMP response",
                            actual="udp_packets=%s states=%s" % (udp.get("packet_count"), states),
                            recommendation="Absence of a reply does not prove the port is closed.")
        return _verdict("WARNING", "UDP test completed", actual="states=%s" % states)

    if capture_err:
        return _verdict("WARNING", "Diagnostics completed but packet capture was unavailable",
                        actual=capture_err,
                        recommendation="Install Npcap/Wireshark or run elevated to collect evidence.")
    return _verdict("WARNING", "Insufficient evidence to verify the transaction")


def _verdict(result, reason, expected=None, actual=None, root_cause=None, recommendation=None):
    return {
        "result": result,
        "reason": reason,
        "expected": expected,
        "actual": actual,
        "root_cause": root_cause,
        "recommendation": recommendation,
        "source": "local",
        "api_error": None,
    }


def interpret_api_response(payload, local):
    """Map a Verification API JSON/text body onto a verdict without dumping raw JSON to the user."""
    if payload is None:
        return dict(local)
    data = payload
    if isinstance(payload, str):
        text = payload.strip()
        try:
            data = json.loads(text)
        except (json.JSONDecodeError, TypeError, ValueError):
            merged = dict(local)
            merged["reason"] = text[:500] or local.get("reason")
            merged["source"] = "api"
            merged["result"] = _classify_text(text) or local.get("result")
            return merged
    if not isinstance(data, dict):
        merged = dict(local)
        merged["source"] = "api"
        merged["reason"] = str(data)[:500]
        return merged

    # Common field names used by verification / LLM-style APIs
    result_raw = (
        data.get("result") or data.get("status") or data.get("verdict")
        or data.get("verification") or data.get("outcome")
    )
    if isinstance(result_raw, dict):
        result_raw = result_raw.get("result") or result_raw.get("status")
    reason = (
        data.get("reason") or data.get("message") or data.get("explanation")
        or data.get("diagnostic_explanation") or data.get("answer")
        or data.get("detail") or local.get("reason")
    )
    classified = _classify_text(str(result_raw or "")) or _classify_text(str(reason or ""))
    merged = dict(local)
    merged["source"] = "api"
    if classified:
        merged["result"] = classified
    if reason:
        merged["reason"] = str(reason).strip()[:800]
    for key in ("root_cause", "expected", "actual", "recommendation", "expected_result", "actual_result"):
        if data.get(key):
            dest = "expected" if key == "expected_result" else "actual" if key == "actual_result" else key
            merged[dest] = data.get(key)
    return merged


def _classify_text(text):
    u = (text or "").upper()
    if not u:
        return None
    if "NOT VERIFIED" in u or re.search(r"\bFAILED\b", u):
        return "FAIL"
    tokens = set(re.findall(r"[A-Z]+", u))
    if tokens & {"FAIL", "FAILED", "BLOCKED", "FILTERED"}:
        return "FAIL"
    if tokens & {"WARNING", "WARN", "PARTIAL"}:
        return "WARNING"
    if tokens & {"PASS", "VERIFIED", "SUCCESS", "OK", "OPEN"}:
        return "PASS"
    return None


def submit_verification(bundle):
    """
    POST diagnostic + analysis + PCAP. Never raises; never deletes the PCAP.
    Returns (verdict_dict).
    """
    local = local_verification(
        bundle.get("protocol"), bundle, bundle.get("packet_analysis") or {})
    url = (VERIFY_API_URL or "").strip()
    if not url:
        local["api_error"] = "Verification API URL is not configured"
        log.info("API request skipped (no URL)")
        return local

    pcap_path = (bundle.get("capture") or {}).get("file")
    log.info("API request started url=%s test_id=%s", url.split("?")[0], bundle.get("test_id"))
    data = {
        "test_id": bundle.get("test_id") or "",
        "source": bundle.get("source") or "",
        "source_ip": bundle.get("source_ip") or "",
        "destination": bundle.get("destination") or "",
        "destination_ip": bundle.get("destination_ip") or "",
        "protocol": bundle.get("protocol") or "",
        "port": str(bundle.get("port") or ""),
        "interface": bundle.get("interface") or "",
        "connectivity": _connectivity(bundle),
        "latency": _latency(bundle),
        "packet_loss": _loss(bundle),
        "dns_result": json.dumps(bundle.get("dns") or {}, default=str),
        "route_result": bundle.get("route") or "",
        "tcp_result": json.dumps((bundle.get("packet_analysis") or {}).get("tcp") or {}, default=str),
        "packet_count": str((bundle.get("capture") or {}).get("packet_count") or 0),
        "packet_analysis": json.dumps(bundle.get("packet_analysis") or {}, default=str),
        "diagnostic_result": json.dumps(_diagnostic_public(bundle), default=str),
    }
    files = None
    handle = None
    try:
        if pcap_path and os.path.isfile(pcap_path):
            handle = open(pcap_path, "rb")
            filename = os.path.basename(pcap_path)
            mime = "application/vnd.tcpdump.pcap"
            files = {"packet_capture": (filename, handle, mime)}
        auth = None
        user = VERIFY_API_USER
        password = VERIFY_API_PASSWORD
        if user:
            auth = (user, password or "")
        resp = requests.post(
            url, data=data, files=files, auth=auth,
            timeout=VERIFY_API_TIMEOUT,
        )
        log.info("API response received status=%s test_id=%s", resp.status_code, bundle.get("test_id"))
        body = None
        try:
            body = resp.json()
        except ValueError:
            body = (resp.text or "")[:4000]
        if resp.status_code >= 400:
            local = dict(local)
            local["api_error"] = "Verification API HTTP %s" % resp.status_code
            # Still interpret body if present (e.g. {"result":"FAIL"})
            interpreted = interpret_api_response(body if body else None, local)
            interpreted["api_error"] = local["api_error"]
            if not body:
                interpreted["source"] = "local"
            return interpreted
        verdict = interpret_api_response(body, local)
        log.info("Verification result=%s source=%s", verdict.get("result"), verdict.get("source"))
        return verdict
    except requests.Timeout:
        log.warning("Verification API timeout test_id=%s", bundle.get("test_id"))
        local = dict(local)
        local["api_error"] = "Verification API timed out after %ss" % VERIFY_API_TIMEOUT
        return local
    except requests.RequestException as e:
        log.warning("Verification API request failed: %s", e)
        local = dict(local)
        local["api_error"] = "Verification API unreachable (%s)" % e.__class__.__name__
        return local
    except Exception as e:
        log.exception("Verification API unexpected error")
        local = dict(local)
        local["api_error"] = "Verification API error: %s" % e.__class__.__name__
        return local
    finally:
        if handle is not None:
            try:
                handle.close()
            except Exception:
                pass


def _connectivity(bundle):
    ports = bundle.get("ports") or []
    if any(p.get("state") == "open" for p in ports):
        return "SUCCESS"
    ping = bundle.get("ping") or {}
    if ping.get("reachable"):
        return "SUCCESS"
    if ports:
        return "FAIL"
    return "UNKNOWN"


def _latency(bundle):
    ping = bundle.get("ping") or {}
    if ping.get("avg_ms") is not None:
        return str(ping["avg_ms"])
    ports = bundle.get("ports") or []
    for p in ports:
        if p.get("ms") is not None:
            return str(p["ms"])
    return ""


def _loss(bundle):
    ping = bundle.get("ping") or {}
    if ping.get("loss_pct") is not None:
        return str(ping["loss_pct"])
    icmp = (bundle.get("packet_analysis") or {}).get("icmp") or {}
    if icmp.get("packet_loss_pct") is not None:
        return str(icmp["packet_loss_pct"])
    return ""


def _diagnostic_public(bundle):
    """Subset of diagnostic facts (no secrets)."""
    return {
        "host": bundle.get("destination") or bundle.get("host"),
        "dns": bundle.get("dns"),
        "ping": {
            "reachable": (bundle.get("ping") or {}).get("reachable"),
            "loss_pct": (bundle.get("ping") or {}).get("loss_pct"),
            "avg_ms": (bundle.get("ping") or {}).get("avg_ms"),
        } if bundle.get("ping") else None,
        "ports": bundle.get("ports"),
        "proto": bundle.get("protocol"),
    }
