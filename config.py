"""
NEVUS - Configuration and default values.
"""

import os

# --- Scan defaults ---
DEFAULT_PORT_MODE = "top1000"      # used when --ports is not provided
DEFAULT_MAX_WORKERS = 5            # hosts scanned in parallel
DEFAULT_PORT_WORKERS = 3           # service detections run in parallel per host
DEFAULT_HOST_TIMEOUT = 300         # seconds, total time budget per host
DEFAULT_PORT_TIMEOUT = 90          # seconds, max time for one version detection
MIN_SERVICE_CONFIDENCE = 5         # nmap 'conf' below this = service not identified

# --- NVD API ---
NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_RATE_LIMIT_NO_KEY = 5          # requests per 30 s window without an API key
NVD_RATE_LIMIT_WITH_KEY = 50       # requests per 30 s window with an API key
NVD_RATE_MARGIN = 1.1              # safety margin on the spacing between requests
NVD_CONNECT_TIMEOUT = 5            # seconds
NVD_READ_TIMEOUT = 15              # seconds
NVD_MAX_RETRIES = 2
NVD_KEYWORD_MAX_RESULTS = 50

# --- Disk cache for NVD answers ---
CACHE_DIR = os.path.join(
    os.environ.get("XDG_CACHE_HOME", os.path.expanduser("~/.cache")), "nevus"
)
CACHE_FILE = os.path.join(CACHE_DIR, "nvd_cache.json")
CACHE_TTL_SECONDS = 24 * 3600

# --- CVSS severity thresholds (lower bound inclusive, evaluated highest first) ---
SEVERITY_THRESHOLDS = [
    (9.0, "CRITICAL"),
    (7.0, "HIGH"),
    (4.0, "MEDIUM"),
    (0.1, "LOW"),
]
SEVERITY_UNKNOWN_LABEL = "UNVERIFIED"

# Recommended action shown in the priority table
SEVERITY_ACTIONS = {
    "CRITICAL": "Update immediately",
    "HIGH": "Update as soon as possible",
    "MEDIUM": "Plan an update",
    "LOW": "Monitor",
}

# --- Legal / ethical notice shown at startup ---
LEGAL_NOTICE = (
    "This tool actively scans network hosts and services.\n"
    "Only use it against networks and devices you own or are explicitly "
    "authorized to test. Unauthorized scanning may be illegal."
)

# --- nmap / ping ---
NMAP_BINARY = "nmap"
ICMP_PING_TIMEOUT = 2  # seconds
