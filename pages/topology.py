"""
pages/topology.py

Live Topology - traceroute rendered as an interactive, icon-based network graph
(pyvis / vis.js inside QWebEngineView), where every hop is labelled with its
REAL owner (ISP / organization) instead of a generic role.

Node caption priority:
    1. ISP / organization name from ip-api.com   e.g. "Reliance Jio"
    2. Reverse-DNS hostname if the lookup failed e.g. "ae-1.r01.mumbai..."
    3. Generic role as last resort               e.g. "Internet / Transit"

Enrichment notes (ip-api.com free tier):
  * Free tier requires HTTP (not HTTPS).
  * The batch endpoint resolves every hop in ONE request (100 IPs/call,
    ~15 calls/min). If it fails we fall back to the per-IP endpoint with the
    1s throttle (45 req/min).
  * Reverse DNS is attempted only for hops the API could not resolve.
  * Results are cached per IP for the session; re-tracing costs nothing.
  * Everything runs on the WorkerManager thread - the UI never blocks.

Private / local hops are never sent to the API.
Backend logic is untouched; this page only consumes run_traceroute +
parse_traceroute.
"""

import os
import sys
import json
import time
import socket
import ipaddress
import tempfile

import requests
import qtawesome as qta

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton, QFrame,
    QCheckBox, QTableWidget, QTableWidgetItem, QHeaderView, QAbstractItemView
)
from PySide6.QtCore import Qt, QUrl, QByteArray, QBuffer, QIODevice
from PySide6.QtGui import QColor

from core.theme import theme
from core import iconkit
from core.workers import WorkerManager
from backend.diagnostics import run_traceroute, parse_traceroute, get_local_ip

try:
    from PySide6.QtWebEngineWidgets import QWebEngineView
    _WEB_OK = True
except Exception:
    _WEB_OK = False

try:
    from pyvis.network import Network
    _PYVIS_OK = True
except Exception:
    _PYVIS_OK = False

_THIS_DEVICE = ("Your Mac" if sys.platform == "darwin"
                else "Your PC" if sys.platform.startswith("win")
                else "This Device")


# =========================================================================== #
#  ISP / geolocation enrichment (ip-api.com free tier + reverse DNS fallback)
# =========================================================================== #
_GEO_FIELDS = ("status,message,country,countryCode,regionName,city,lat,lon,"
               "isp,org,as,query")
_GEO_CACHE = {}          # ip -> normalized dict (session cache)
_RDNS_CACHE = {}         # ip -> hostname or ""
_BATCH_URL = "http://ip-api.com/batch?fields=" + _GEO_FIELDS
_SINGLE_URL = "http://ip-api.com/json/{ip}?fields=" + _GEO_FIELDS


def is_public_ip(ip):
    """True for globally routable addresses (private/CGNAT/local are skipped)."""
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_global and not ip_obj.is_multicast
    except ValueError:
        return False


def _normalize(data):
    """Map an ip-api payload to the compact shape the UI renders."""
    if not data:
        return {"error": "No response"}
    if data.get("status") != "success":
        return {"error": data.get("message", "Lookup failed")}
    return {
        "city": data.get("city") or "",
        "region": data.get("regionName") or "",
        "country": data.get("country") or "",
        "country_code": data.get("countryCode") or "",
        "isp": data.get("isp") or "",
        "org": data.get("org") or "",
        "asn": data.get("as") or "",
        "lat": data.get("lat"),
        "lon": data.get("lon"),
        "error": None,
    }


def _lookup_batch(ips):
    """One request for up to 100 IPs. Returns {ip: raw_payload}."""
    out = {}
    for i in range(0, len(ips), 100):
        chunk = ips[i:i + 100]
        resp = requests.post(_BATCH_URL, json=chunk, timeout=12)
        resp.raise_for_status()
        for entry in resp.json():
            q = entry.get("query")
            if q:
                out[q] = entry
        if i + 100 < len(ips):
            time.sleep(1.0)          # stay inside the batch rate limit
    return out


def _lookup_single(ip):
    """Per-IP fallback with the free-tier throttle (45 requests/minute)."""
    try:
        time.sleep(1.0)
        resp = requests.get(_SINGLE_URL.format(ip=ip), timeout=6)
        if resp.status_code != 200:
            return {"error": "HTTP Error {}".format(resp.status_code)}
        return _normalize(resp.json())
    except Exception as e:
        return {"error": str(e)}


def reverse_dns(ip, timeout=2.0):
    """
    PTR lookup so a hop still gets a real name when ip-api is blocked
    (common behind corporate proxies). Cached; failures return "".
    """
    if ip in _RDNS_CACHE:
        return _RDNS_CACHE[ip]
    host = ""
    old = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(timeout)
        host = socket.gethostbyaddr(ip)[0] or ""
    except Exception:
        host = ""
    finally:
        try:
            socket.setdefaulttimeout(old)
        except Exception:
            pass
    _RDNS_CACHE[ip] = host
    return host


def enrich_hops(hops, enabled=True):
    """
    Attach 'geo' and 'rdns' to every hop:
        geo = {"private": True}                  -> internal hop, never queried
              {"city","country","isp","org",...} -> resolved
              {"error": "..."}                   -> lookup failed
              None                               -> timed-out / lookups disabled
        rdns = PTR hostname (only attempted when geo failed)
    Runs on a worker thread. Mutates and returns the same list.
    """
    if not enabled:
        for h in hops:
            h["geo"] = None
            h["rdns"] = ""
        return hops

    todo = []
    for h in hops:
        ip = h.get("ip")
        if ip and is_public_ip(ip) and ip not in _GEO_CACHE and ip not in todo:
            todo.append(ip)

    if todo:
        resolved = {}
        try:
            raw = _lookup_batch(todo)
            for ip, payload in raw.items():
                resolved[ip] = _normalize(payload)
        except Exception:
            resolved = {}
        for ip in todo:
            _GEO_CACHE[ip] = resolved.get(ip) or _lookup_single(ip)

    for h in hops:
        ip = h.get("ip")
        h["rdns"] = ""
        if not ip:
            h["geo"] = None
        elif not is_public_ip(ip):
            h["geo"] = {"private": True}
        else:
            geo = _GEO_CACHE.get(ip)
            h["geo"] = geo
            # Only pay for a PTR lookup when the API gave us nothing usable.
            if not geo or geo.get("error") or not (geo.get("isp") or geo.get("org")):
                h["rdns"] = reverse_dns(ip)
    return hops


def trace_and_enrich(destination, lookup=True):
    """Worker payload: traceroute -> parse -> enrich."""
    raw = run_traceroute(destination)
    hops = parse_traceroute(raw)
    enrich_hops(hops, enabled=lookup)
    return {"raw": raw, "hops": hops}


# --------------------------------------------------------------------------- #
#  Presentation helpers
# --------------------------------------------------------------------------- #
def _classify(hop, index, total, seen_public):
    """Returns (role_label, icon, accent_key) - role is now a FALLBACK caption."""
    if hop.get("timed_out") or not hop.get("ip"):
        return ("Hidden hop", "fa5s.question", "TEXT_SECONDARY")
    try:
        ip = ipaddress.ip_address(hop["ip"])
    except ValueError:
        return ("Unknown", "fa5s.question", "TEXT_SECONDARY")

    if index == total - 1:
        return ("Destination", "fa5s.bullseye", "SUCCESS")
    if ip.is_private:
        if not seen_public and index <= 1:
            return ("Gateway / Router", "fa5s.network-wired", "ACCENT")
        return ("LAN Switch", "fa5s.ethernet", "INFO")
    if ip in ipaddress.ip_network("100.64.0.0/10"):
        return ("ISP (CGNAT)", "fa5s.satellite-dish", "ACCENT_2")
    if not seen_public:
        return ("ISP Edge", "fa5s.satellite-dish", "ACCENT_2")
    return ("Internet / Transit", "fa5s.cloud", "INFO")


def _latency_key(avg_ms):
    if avg_ms is None:
        return "TEXT_SECONDARY"
    if avg_ms < 40:
        return "SUCCESS"
    if avg_ms < 120:
        return "WARNING"
    return "ERROR"


def _short(text, limit=26):
    text = text or ""
    return text if len(text) <= limit else text[:limit - 1] + "\u2026"


def _short_host(host, limit=30):
    """
    Trim a PTR hostname from the LEFT so the provider domain stays visible:
    'ae-1.r01.mumbai.in.bb.gin.ntt.net' -> '\u2026in.bb.gin.ntt.net'
    """
    host = (host or "").strip().rstrip(".")
    if len(host) <= limit:
        return host
    parts = host.split(".")
    out = parts[-1]
    for piece in reversed(parts[:-1]):
        candidate = piece + "." + out
        if len(candidate) + 1 > limit:
            return "\u2026" + out
        out = candidate
    return out


def _isp_name(geo):
    """Best short owner name from a geo record ('' when unavailable)."""
    if not isinstance(geo, dict) or geo.get("private") or geo.get("error"):
        return ""
    return (geo.get("isp") or geo.get("org") or "").strip()


def _owner_name(hop, role_label):
    """
    THE node caption. ISP / org first, then reverse-DNS, then the generic role.
    This is what replaces 'Internet / Transit' on the map.
    """
    isp = _isp_name(hop.get("geo"))
    if isp:
        return _short(isp, 26)
    rdns = (hop.get("rdns") or "").strip()
    if rdns:
        return _short_host(rdns, 30)
    return role_label


def _location_text(geo):
    if not isinstance(geo, dict):
        return ""
    if geo.get("private"):
        return "Private / Local"
    if geo.get("error"):
        return "Lookup failed"
    parts = [p for p in (geo.get("city"), geo.get("country")) if p]
    return ", ".join(parts) if parts else ""


def _isp_cell(hop, role_label):
    """Text for the 'ISP / Organization' table column."""
    geo = hop.get("geo")
    if isinstance(geo, dict) and geo.get("private"):
        return "Internal network hop"
    isp = _isp_name(geo)
    if isp:
        org = (geo.get("org") or "").strip()
        return "{} ({})".format(isp, org) if org and org != isp else isp
    rdns = (hop.get("rdns") or "").strip()
    if rdns:
        return "{}  [reverse DNS]".format(rdns)
    if isinstance(geo, dict) and geo.get("error"):
        return "Lookup failed: {}".format(geo["error"])
    return role_label


def _icon_data_uri(name, color_hex, size=54):
    """Rasterize a qtawesome icon to a base64 PNG data URI (offline-safe)."""
    pix = qta.icon(name, color=color_hex).pixmap(size, size)
    ba = QByteArray()
    buf = QBuffer(ba)
    buf.open(QIODevice.WriteOnly)
    pix.save(buf, "PNG")
    buf.close()
    b64 = bytes(ba.toBase64()).decode("ascii")
    return "data:image/png;base64,{}".format(b64)


# =========================================================================== #
#  Page
# =========================================================================== #
class TopologyPage(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.workers = WorkerManager()
        self._hops = []
        self._target = ""
        self._html_path = os.path.join(tempfile.gettempdir(), "netai_topology.html")

        root = QVBoxLayout(self)
        root.setContentsMargins(24, 22, 24, 22)
        root.setSpacing(12)

        title = QLabel("Live Topology")
        title.setProperty("role", "title")
        title.setStyleSheet("font-size: 24px; font-weight: 800;")
        sub = QLabel("Every hop is labelled with its real owner (ISP / organization), "
                     "location and latency. Scroll to zoom, drag to pan, hover for detail.")
        sub.setProperty("role", "subtitle")
        sub.setWordWrap(True)
        root.addWidget(title)
        root.addWidget(sub)

        # --- controls ---
        controls = QHBoxLayout()
        controls.setSpacing(10)
        self.txt_target = QLineEdit("8.8.8.8")
        self.txt_target.setProperty("cls", "input")
        self.txt_target.setPlaceholderText("Enter domain or IP to trace (e.g. 1.1.1.1)")
        self.txt_target.setFixedHeight(44)
        self.txt_target.returnPressed.connect(self._trace)
        controls.addWidget(self.txt_target, 1)

        self.btn_trace = QPushButton("  Trace & Visualize")
        self.btn_trace.setProperty("cls", "primary")
        self.btn_trace.setFixedHeight(44)
        self.btn_trace.setCursor(Qt.PointingHandCursor)
        iconkit.button(self.btn_trace, "fa5s.project-diagram", role="ON_ACCENT", size=14)
        self.btn_trace.clicked.connect(self._trace)
        controls.addWidget(self.btn_trace)
        root.addLayout(controls)

        opts = QHBoxLayout()
        opts.setSpacing(12)
        self.chk_lookup = QCheckBox("Resolve ISP / location for public hops")
        self.chk_lookup.setChecked(True)
        self.chk_lookup.setCursor(Qt.PointingHandCursor)
        self.chk_lookup.setStyleSheet(self._check_style())
        opts.addWidget(self.chk_lookup)
        opts.addStretch()
        opts.addWidget(self._build_legend())
        root.addLayout(opts)

        # --- graph canvas ---
        card = QFrame()
        card.setProperty("cls", "card")
        card_lay = QVBoxLayout(card)
        card_lay.setContentsMargins(6, 6, 6, 6)

        if _WEB_OK and _PYVIS_OK:
            self.view = QWebEngineView()
            self.view.setStyleSheet("background: transparent; border: none;")
            card_lay.addWidget(self.view)
        else:
            from widgets.console import ConsoleWidget
            self.view = None
            self.console = ConsoleWidget(self, min_height=240)
            self.console.set_text(self._dependency_hint(), theme.c("TEXT_SECONDARY"))
            card_lay.addWidget(self.console)
        root.addWidget(card, 1)

        # --- hop detail table ---
        table_card = QFrame()
        table_card.setProperty("cls", "card")
        tl = QVBoxLayout(table_card)
        tl.setContentsMargins(14, 12, 14, 12)
        tl.setSpacing(8)
        cap = QLabel("HOP DETAILS")
        cap.setProperty("role", "cardtitle")
        tl.addWidget(cap)

        self.table = QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels(
            ["Hop", "IP Address", "Latency", "Location", "ISP / Organization", "AS"])
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setAlternatingRowColors(True)
        self.table.setShowGrid(False)
        self.table.setMinimumHeight(150)
        self.table.setMaximumHeight(210)
        hh = self.table.horizontalHeader()
        hh.setStretchLastSection(True)
        hh.setSectionResizeMode(3, QHeaderView.Stretch)
        hh.setSectionResizeMode(4, QHeaderView.Stretch)
        tl.addWidget(self.table)
        root.addWidget(table_card)

        self.status = QLabel("Enter a destination and click Trace & Visualize.")
        self.status.setProperty("role", "secondary")
        root.addWidget(self.status)

        theme.changed.connect(self._on_theme)
        self._style_table()
        self._render()

    # ---------------------------------------------------- styling
    def _check_style(self):
        return ("QCheckBox {{ color: {sec}; spacing: 8px; }}"
                "QCheckBox::indicator {{ width: 16px; height: 16px; border-radius: 5px;"
                " border: 1px solid {bd}; background: {elev}; }}"
                "QCheckBox::indicator:checked {{ background: {acc}; border: 1px solid {acc}; }}"
                ).format(sec=theme.c("TEXT_SECONDARY"), bd=theme.c("BORDER"),
                         elev=theme.c("ELEVATED"), acc=theme.c("ACCENT"))

    def _style_table(self):
        self.table.setStyleSheet(
            "QTableWidget {{ background-color: {card}; alternate-background-color: {elev};"
            " color: {fg}; border: 1px solid {bd}; border-radius: 12px;"
            " gridline-color: {bd}; }}"
            "QTableWidget::item {{ padding: 5px 8px; border: none; }}"
            "QTableWidget::item:selected {{ background-color: {acc}; color: {on}; }}"
            "QHeaderView::section {{ background-color: {elev}; color: {sec};"
            " padding: 7px; border: none; font-weight: bold; }}"
            .format(card=theme.c("CARD_BG"), elev=theme.c("ELEVATED"),
                    fg=theme.c("TEXT_PRIMARY"), bd=theme.c("BORDER"),
                    acc=theme.c("ACCENT"), on=theme.c("ON_ACCENT"),
                    sec=theme.c("TEXT_SECONDARY")))

    def _on_theme(self):
        self.chk_lookup.setStyleSheet(self._check_style())
        self._style_table()
        self._fill_table()
        self._render()

    def _dependency_hint(self):
        missing = []
        if not _PYVIS_OK:
            missing.append("pyvis  (pip install pyvis)")
        if not _WEB_OK:
            missing.append("PySide6 WebEngine  (pip install PySide6)")
        return ("The interactive topology needs:\n  \u2022 " + "\n  \u2022 ".join(missing)
                + "\n\nHop details are still listed in the table below.")

    def _build_legend(self):
        holder = QFrame()
        row = QHBoxLayout(holder)
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(14)
        items = [
            ("fa5s.desktop", "You"), ("fa5s.network-wired", "Gateway"),
            ("fa5s.ethernet", "LAN"), ("fa5s.satellite-dish", "ISP"),
            ("fa5s.cloud", "Internet"), ("fa5s.bullseye", "Destination"),
            ("fa5s.question", "Hidden"),
        ]
        for icon, label in items:
            wrap = QFrame()
            wl = QHBoxLayout(wrap)
            wl.setContentsMargins(0, 0, 0, 0)
            wl.setSpacing(5)
            ic = QLabel()
            iconkit.label(ic, icon, role="TEXT_SECONDARY", size=13)
            lb = QLabel(label)
            lb.setProperty("role", "secondary")
            lb.setStyleSheet("font-size: 11px;")
            wl.addWidget(ic)
            wl.addWidget(lb)
            row.addWidget(wrap)
        return holder

    # ---------------------------------------------------- trace
    def _trace(self):
        target = self.txt_target.text().strip()
        if not target:
            return
        self.btn_trace.setEnabled(False)
        lookup = self.chk_lookup.isChecked()
        self.status.setText("Tracing route to {}{}\u2026".format(
            target, " and identifying each hop" if lookup else ""))
        self.workers.run(
            trace_and_enrich, target, lookup,
            on_finished=lambda res, t=target: self._on_trace(t, res),
            on_error=lambda err: self._on_error(str(err)),
            busy_text="Tracing route to {}\u2026".format(target))

    def _on_error(self, message):
        self.btn_trace.setEnabled(True)
        self._hops = []
        self.status.setText("Trace failed: {}".format(message))
        self._fill_table()
        self._render()

    def _on_trace(self, target, result):
        self.btn_trace.setEnabled(True)
        self._target = target
        self._hops = (result or {}).get("hops", [])
        if not self._hops:
            self.status.setText("No hops parsed. Try a different target or check connectivity.")
        else:
            named = sum(1 for h in self._hops
                        if _isp_name(h.get("geo")) or (h.get("rdns") or ""))
            reached = any(not h["timed_out"] for h in self._hops)
            msg = "{} hops to {}".format(len(self._hops), target)
            if named:
                msg += "  \u00b7  {} hops identified".format(named)
            if not reached:
                msg += "  \u00b7  destination did not respond"
            self.status.setText(msg)
        self._fill_table()
        self._render()

    # ---------------------------------------------------- table
    def _fill_table(self):
        hops = self._hops or []
        self.table.setRowCount(len(hops))
        total = len(hops)
        seen_public = False
        for r, hop in enumerate(hops):
            role_label, _icon, _accent = _classify(hop, r, total, seen_public)
            if hop.get("ip"):
                try:
                    if not ipaddress.ip_address(hop["ip"]).is_private:
                        seen_public = True
                except ValueError:
                    pass
            geo = hop.get("geo")
            lat = hop.get("avg_ms")
            values = [
                str(hop.get("hop", r + 1)),
                hop.get("ip") or "* * *",
                "{} ms".format(lat) if lat is not None else "\u2014",
                _location_text(geo) or role_label,
                _isp_cell(hop, role_label),
                geo.get("asn", "") if isinstance(geo, dict) else "",
            ]
            for c, v in enumerate(values):
                item = QTableWidgetItem(str(v))
                if c == 2 and lat is not None:
                    item.setForeground(QColor(theme.c(_latency_key(lat))))
                if c == 1 and hop.get("timed_out"):
                    item.setForeground(QColor(theme.c("TEXT_SECONDARY")))
                if c == 4 and _isp_name(geo):
                    item.setForeground(QColor(theme.c("ACCENT")))
                self.table.setItem(r, c, item)

    # ---------------------------------------------------- render
    def _render(self):
        if self.view is None:
            self._render_text()
            return
        if not self._hops:
            self.view.setHtml(self._placeholder_html())
            return
        try:
            path = self._build_pyvis_html()
            self.view.setUrl(QUrl.fromLocalFile(path))
        except Exception as e:
            self.view.setHtml(self._placeholder_html("Could not render graph: {}".format(e)))

    def _render_text(self):
        if not self._hops:
            self.console.set_text(self._dependency_hint(), theme.c("TEXT_SECONDARY"))
            return
        lines = ["Traceroute to {} \u2014 {} hops\n".format(self._target, len(self._hops))]
        total = len(self._hops)
        seen_public = False
        for i, h in enumerate(self._hops):
            role_label, _i, _a = _classify(h, i, total, seen_public)
            if h.get("ip"):
                try:
                    if not ipaddress.ip_address(h["ip"]).is_private:
                        seen_public = True
                except ValueError:
                    pass
            ip = h["ip"] or "* * *"
            lat = "{} ms".format(h["avg_ms"]) if h["avg_ms"] is not None else "\u2014"
            lines.append("  {:>2}.  {:<18} {:<9} {:<22} {}".format(
                h["hop"], ip, lat, _location_text(h.get("geo")) or role_label,
                _isp_cell(h, role_label)))
        self.console.set_text("\n".join(lines), theme.c("TEXT_PRIMARY"))

    def _build_pyvis_html(self):
        bg = theme.c("BACKGROUND")
        fg = theme.c("TEXT_PRIMARY")
        sub = theme.c("TEXT_SECONDARY")

        net = Network(height="100%", width="100%", directed=True,
                      bgcolor=bg, font_color=fg, cdn_resources="in_line", notebook=False)

        net.add_node(0, label=_THIS_DEVICE, shape="image",
                     image=_icon_data_uri("fa5s.desktop", theme.c("ACCENT")),
                     level=0, size=28,
                     title="This device\n{}".format(get_local_ip()))

        total = len(self._hops)
        seen_public = False
        prev_id = 0
        for i, hop in enumerate(self._hops):
            role_label, icon, accent = _classify(hop, i, total, seen_public)
            if hop.get("ip"):
                try:
                    if not ipaddress.ip_address(hop["ip"]).is_private:
                        seen_public = True
                except ValueError:
                    pass

            nid = i + 1
            ip = hop["ip"] or "* * *"
            lat = hop.get("avg_ms")
            geo = hop.get("geo")

            # ---- caption: ISP / org  ->  reverse DNS  ->  generic role ----
            caption = _owner_name(hop, role_label)
            label = "{}\n{}".format(caption, ip)
            location = _location_text(geo)
            if location and location != "Private / Local" and location != "Lookup failed":
                label += "\n{}".format(_short(location, 24))

            # ---- hover tooltip: full per-hop detail ----
            tip = ["Hop {}".format(hop.get("hop", nid)), "Role: {}".format(role_label), ip]
            if lat is not None:
                tip.append("{} ms".format(lat))
            if isinstance(geo, dict):
                if geo.get("private"):
                    tip.append("Internal network hop (not queried)")
                elif geo.get("error"):
                    tip.append("ISP lookup failed: {}".format(geo["error"]))
                else:
                    if location:
                        tip.append("Location: {}".format(location))
                    if geo.get("region"):
                        tip.append("Region: {}".format(geo["region"]))
                    if geo.get("isp"):
                        tip.append("ISP: {}".format(geo["isp"]))
                    if geo.get("org") and geo.get("org") != geo.get("isp"):
                        tip.append("Org: {}".format(geo["org"]))
                    if geo.get("asn"):
                        tip.append("AS: {}".format(geo["asn"]))
            if hop.get("rdns"):
                tip.append("Reverse DNS: {}".format(hop["rdns"]))

            net.add_node(nid, label=label, shape="image",
                         image=_icon_data_uri(icon, theme.c(accent)),
                         level=nid, size=28, title="\n".join(tip))

            net.add_edge(prev_id, nid,
                         label=("{} ms".format(lat) if lat is not None else ""),
                         color=theme.c(_latency_key(lat)), arrows="to")
            prev_id = nid

        options = {
            "layout": {"hierarchical": {"enabled": True, "direction": "LR",
                                        "sortMethod": "directed",
                                        "levelSeparation": 260, "nodeSpacing": 160}},
            "physics": {"enabled": False},
            "interaction": {"hover": True, "navigationButtons": True,
                            "keyboard": True, "tooltipDelay": 120},
            "nodes": {"font": {"color": fg, "size": 14, "multi": False},
                      "shapeProperties": {"useImageSize": False},
                      "borderWidth": 0, "size": 28},
            "edges": {"font": {"color": sub, "size": 12, "strokeWidth": 0,
                               "align": "top"},
                      "smooth": {"type": "cubicBezier", "roundness": 0.5},
                      "arrows": {"to": {"enabled": True, "scaleFactor": 0.7}}},
        }
        net.set_options(json.dumps(options))

        # Write the HTML ourselves as UTF-8: pyvis.save_graph() uses the platform
        # default codec (cp1252 on Windows) and fails on the inlined vis.js.
        html = net.generate_html(notebook=False)
        if "<meta charset" not in html.lower():
            html = html.replace("<head>", '<head><meta charset="utf-8">', 1)
        with open(self._html_path, "w", encoding="utf-8") as f:
            f.write(html)
        return self._html_path

    def _placeholder_html(self, msg=None):
        bg = theme.c("CARD_BG")
        fg = theme.c("TEXT_SECONDARY")
        text = msg or ("Enter a destination above and click "
                       "<b>&nbsp;Trace &amp; Visualize&nbsp;</b> to map the network path.")
        return ("<!DOCTYPE html><html><head><meta charset='utf-8'><style>"
                "html,body{{margin:0;height:100%;background:{bg};"
                "font-family:'SF Pro Text','Segoe UI','Helvetica Neue',sans-serif;}}"
                "div{{position:absolute;inset:0;display:flex;align-items:center;"
                "justify-content:center;color:{fg};font-size:15px;text-align:center;"
                "padding:0 40px;}}</style></head><body><div>{text}</div></body></html>"
                .format(bg=bg, fg=fg, text=text))
