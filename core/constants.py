"""
core/constants.py
Application-wide constants and configuration.
"""

import os
import tempfile

APP_NAME = "Device and Network Tool"
APP_VERSION = "v6.0.0"
VENDOR = "Carrier"
APP_ARCHITECT = "Dinesh Velapure"
SUPPORT_EMAIL = "dineshvijay.velapure@carrier.com"

# LLM Configuration
LLM_API_URL = "http://cussya5w.carcgl.com:8000/ask"
LLM_API_URL_DC = "http://cussya5w.carcgl.com:8000"
USERNAME = "admin123"
PASSWORD = "cisco123"

# Networking
HTTP_TIMEOUT = 8       # Seconds for outbound HTTP calls
CMD_TIMEOUT = 30       # Seconds for local shell commands

# ---------------------------------------------------------------------------
# Evidence-based network verification (packet capture + Verification API).
# Override with environment variables — never hard-code site secrets here.
# ---------------------------------------------------------------------------
def _env(name, default=""):
    val = os.environ.get(name)
    return default if val is None or val == "" else val


def _env_int(name, default):
    raw = os.environ.get(name)
    if raw is None or str(raw).strip() == "":
        return default
    try:
        return int(raw)
    except (TypeError, ValueError):
        return default


VERIFY_API_URL = _env("NETWORKAI_VERIFY_API_URL", LLM_API_URL_DC.rstrip("/") + "/verify")
VERIFY_API_TIMEOUT = _env_int("NETWORKAI_VERIFY_API_TIMEOUT", 30)
VERIFY_API_USER = _env("NETWORKAI_VERIFY_API_USER", USERNAME)
VERIFY_API_PASSWORD = _env("NETWORKAI_VERIFY_API_PASSWORD", PASSWORD)
PACKET_CAPTURE_TIMEOUT = _env_int("NETWORKAI_CAPTURE_TIMEOUT", 45)
CAPTURE_INTERFACE = _env("NETWORKAI_CAPTURE_INTERFACE", "")  # empty = auto-detect
PCAP_RETENTION = _env_int("NETWORKAI_PCAP_RETENTION", 50)
CAPTURE_MAX_PACKETS = _env_int("NETWORKAI_CAPTURE_MAX_PACKETS", 50000)


def capture_dir():
    """Writable folder for Wireshark-compatible PCAP/PCAPNG evidence files."""
    override = os.environ.get("NETWORKAI_CAPTURE_DIR")
    folder = override if override else os.path.join(log_dir(), "captures")
    try:
        os.makedirs(folder, exist_ok=True)
    except Exception:
        folder = os.path.join(tempfile.gettempdir(), "NetworkAIEnterprise-captures")
        os.makedirs(folder, exist_ok=True)
    return folder

# ---------------------------------------------------------------------------
# Usage analytics (management dashboard). Point this at your Linux server.
# Set TELEMETRY_ENABLED = False to switch all telemetry off completely.
# ---------------------------------------------------------------------------
ANALYTICS_URL = "http://analytics.your-domain.local:8088/api/v1/events"
ANALYTICS_KEY = "change-me-please"          # must match ANALYTICS_API_KEY on the server
TELEMETRY_ENABLED = True
TELEMETRY_ANONYMIZE = False   # True -> server only sees a hashed user id

# UI Scaling & Animation
DEFAULT_ANIMATION_DURATION = 250  # milliseconds


def log_dir():
    """Writable folder for logs (per-user, cross-platform)."""
    base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~") or tempfile.gettempdir()
    folder = os.path.join(base, "NetworkAIEnterprise")
    try:
        os.makedirs(folder, exist_ok=True)
    except Exception:
        folder = tempfile.gettempdir()
    return folder
