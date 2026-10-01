"""
NEVUS - Data models shared across modules.
"""

import threading
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]


class ScanAborted(Exception):
    """Raised inside worker threads when the scan is interrupted by the user."""


@dataclass
class CVEFinding:
    """A single CVE matched to a detected service or OS."""
    cve_id: str
    cvss_score: Optional[float]
    severity: str  # CRITICAL / HIGH / MEDIUM / LOW / UNVERIFIED
    description: str = ""
    url: str = ""


def worst_severity(cves: List[CVEFinding]) -> str:
    """Return the highest severity label found in a list of CVEs ('' if none)."""
    for level in SEVERITY_ORDER:
        if any(c.severity == level for c in cves):
            return level
    return ""


@dataclass
class PortResult:
    """Result of scanning a single open port."""
    port: int
    protocol: str = "tcp"
    state: str = "open"
    service_name: str = ""
    product: str = ""
    version: str = ""
    extra_info: str = ""
    cpes: List[str] = field(default_factory=list)
    identified: bool = False      # nmap confidently identified the service
    status: str = "detecting"     # detecting -> checking -> done
    started_at: float = 0.0       # time.monotonic() when detection started
    checked: bool = False         # True only if a CVE lookup really completed
    cve_match: str = ""           # "cpe" (exact) or "keyword" (approximate)
    cves: List[CVEFinding] = field(default_factory=list)
    scripts: Dict[str, str] = field(default_factory=dict)
    note: str = ""                # why a port could not be verified
    error: Optional[str] = None   # set if detection or lookup failed

    @property
    def highest_severity(self) -> str:
        if self.error:
            return "ERROR"
        worst = worst_severity(self.cves)
        if worst:
            return worst
        if self.checked:
            return "OK"
        return "UNVERIFIED"


@dataclass
class HostResult:
    """Result of scanning a single host."""
    ip: str
    hostname: str = ""
    alive: bool = False
    icmp_blocked: bool = False    # host ignored ICMP but was scanned anyway
    phase: str = "queued"         # queued/discovery/versions/os_check/done/interrupted
    ports: List[PortResult] = field(default_factory=list)
    os_cpe: str = ""
    os_cves: List[CVEFinding] = field(default_factory=list)
    os_checked: bool = False
    os_note: str = ""
    os_error: Optional[str] = None
    error: Optional[str] = None   # the host scan itself failed

    @property
    def open_ports(self) -> List[PortResult]:
        return [p for p in list(self.ports) if p.state == "open"]


@dataclass
class ScanSummary:
    """Aggregated counters for the final report."""
    hosts_total: int = 0
    hosts_alive: int = 0
    hosts_down: int = 0
    hosts_failed: int = 0
    services_detected: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    ok: int = 0
    unverified: int = 0
    check_failed: int = 0
    incomplete: int = 0
    unique_cves: int = 0
    duration_seconds: float = 0.0
    interrupted: bool = False


@dataclass
class ScanContext:
    """Settings shared by all worker threads during a scan."""
    port_args: List[str]
    host_timeout: int
    port_timeout: int
    port_workers: int
    scripts: bool = False
    stop_event: threading.Event = field(default_factory=threading.Event)
    log: Callable[[str], None] = lambda message: None
