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
