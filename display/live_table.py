"""
NEVUS - Live terminal display, updated as results come in.
"""

import threading
from typing import Dict, List

from rich.console import Console
from rich.live import Live
from rich.table import Table
from rich.text import Text
from rich.tree import Tree

import config
from models import HostResult, PortResult, ScanSummary

_SEVERITY_STYLE = {
    "CRITICAL": "bold red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "cyan",
    "OK": "green",
    "UNVERIFIED": "dim",
    "ERROR": "bold magenta",
}

_HOST_PHASE_LABEL = {
    "queued": "queued...",
    "discovery": "scanning ports...",
    "versions": "detecting services...",
    "os_check": "checking OS/firmware CVEs...",
    "interrupted": "interrupted",
}


def _port_line(port: PortResult) -> str:
    service = port.service_name or "unknown"
    if port.product:
        service += f" ({port.product} {port.version})".rstrip()
    prefix = f"{port.port}/{port.protocol}  {service}"

    if port.error:
        return f"{prefix}  [bold magenta]error: {port.error}[/bold magenta]"
    if port.status != "done":
        step = "detecting version..." if port.status == "detecting" else "checking CVEs..."
        return f"{prefix}  [dim]{step}[/dim]"

    sev = port.highest_severity
    style = _SEVERITY_STYLE.get(sev, "white")

    if sev == "UNVERIFIED":
        note = f" ({port.note})" if port.note else ""
        return f"{prefix}  [{style}]{sev}{note}[/{style}]"

    cve_ids = ", ".join(
        f"{c.cve_id} ({c.cvss_score:.1f})" if c.cvss_score is not None else c.cve_id
        for c in port.cves[:3]
    )
    if len(port.cves) > 3:
        cve_ids += f", +{len(port.cves) - 3} more"
    approx = "  [dim](keyword match, verify manually)[/dim]" if port.cve_match == "keyword" else ""
    tail = f"  {cve_ids}" if cve_ids else ""
    return f"{prefix}{tail}{approx}  [{style}]{sev}[/{style}]"


class ScanDisplay:
    """Redraws a tree (one branch per host) each time a result is updated."""

    def __init__(self, cve_lookup=None):
        self.console = Console()
        self._hosts: Dict[str, HostResult] = {}
        self._order: List[str] = []
        self._live: Live | None = None
        self._lock = threading.Lock()
        self.cve_lookup = cve_lookup

    def __enter__(self):
        self._live = Live(self._render(), console=self.console, refresh_per_second=6)
        self._live.__enter__()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self._live:
            self._live.update(self._render())
            self._live.__exit__(exc_type, exc_val, exc_tb)

    def _render(self) -> Tree:
        tree = Tree("NEVUS scan")
        with self._lock:
            items = [(ip, self._hosts[ip]) for ip in self._order]

        for ip, host in items:
            label = ip
            if host.hostname:
                label += f"  ({host.hostname})"

            if host.error:
                label += f"  [bold magenta]error: {host.error}[/bold magenta]"
            elif host.phase not in ("done",):
                label += f"  [dim]{_HOST_PHASE_LABEL.get(host.phase, host.phase)}[/dim]"
            elif not host.alive:
                label += "  [dim]host down (no response)[/dim]"
            elif not host.open_ports:
                icmp = "  [dim](ICMP blocked, scanned anyway)[/dim]" if host.icmp_blocked else ""
                label += f"  [dim]up, no open ports found[/dim]{icmp}"
            elif host.icmp_blocked:
                label += "  [dim](ICMP blocked, scanned anyway)[/dim]"

            host_branch = tree.add(label)

            for port in list(host.ports):
                host_branch.add(_port_line(port))

            if host.phase in ("os_check", "done") and host.os_cpe:
                if host.os_error:
                    os_line = f"OS: {host.os_cpe}  [bold magenta]error: {host.os_error}[/bold magenta]"
                elif not host.os_checked:
                    os_line = f"OS: {host.os_cpe}  [dim]checking CVEs...[/dim]"
                else:
                    sev = "OK"
                    for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                        if any(c.severity == level for c in host.os_cves):
                            sev = level
                            break
                    style = _SEVERITY_STYLE.get(sev, "white")
                    cve_ids = ", ".join(
                        f"{c.cve_id} ({c.cvss_score:.1f})" if c.cvss_score is not None else c.cve_id
                        for c in host.os_cves[:3]
                    )
                    tail = f"  {cve_ids}" if cve_ids else ""
                    os_line = f"OS: {host.os_cpe}{tail}  [{style}]{sev}[/{style}]"
                host_branch.add(os_line)

        if self.cve_lookup is not None:
            tree.add(
                f"[dim]NVD requests: {self.cve_lookup.requests_made}  "
                f"cache hits: {self.cve_lookup.cache_hits}[/dim]"
            )
        return tree

    def upsert_host(self, host: HostResult) -> None:
        with self._lock:
            if host.ip not in self._hosts:
                self._order.append(host.ip)
            self._hosts[host.ip] = host
        if self._live:
            self._live.update(self._render())

    def refresh(self) -> None:
        if self._live:
            self._live.update(self._render())

    # ------------------------------------------------------------------ final reports
    def print_summary(self, summary: ScanSummary) -> None:
        table = Table(title="Scan summary", show_header=False)
        table.add_row("Hosts scanned", str(summary.hosts_total))
        table.add_row("Hosts alive", str(summary.hosts_alive))
        table.add_row("Hosts down", str(summary.hosts_down))
        if summary.hosts_failed:
            table.add_row("Hosts failed", f"[bold magenta]{summary.hosts_failed}[/bold magenta]")
        table.add_row("Services detected", str(summary.services_detected))
        table.add_row(
            "Severity",
            f"[bold red]Critical: {summary.critical}[/bold red]  "
            f"[red]High: {summary.high}[/red]  "
            f"[yellow]Medium: {summary.medium}[/yellow]  "
            f"[cyan]Low: {summary.low}[/cyan]  "
            f"[green]OK: {summary.ok}[/green]  "
            f"[dim]Unverified: {summary.unverified}[/dim]",
        )
        if summary.check_failed:
            table.add_row("CVE checks failed", f"[bold magenta]{summary.check_failed}[/bold magenta]")
        table.add_row("Unique CVEs found", str(summary.unique_cves))
        table.add_row("Duration", f"{summary.duration_seconds:.1f}s")
        if summary.interrupted:
            table.add_row("Status", "[bold yellow]interrupted by user - partial results[/bold yellow]")
        self.console.print(table)

    def print_priorities(self, hosts: List[HostResult]) -> None:
        """List every finding CRITICAL/HIGH first, across all hosts."""
        rows = []
        for host in hosts:
            for port in host.open_ports:
                for cve in port.cves:
                    if cve.severity in ("CRITICAL", "HIGH"):
                        rows.append((host.ip, f"{port.port}/{port.protocol} ({port.product})", cve))
            for cve in host.os_cves:
                if cve.severity in ("CRITICAL", "HIGH"):
                    rows.append((host.ip, f"OS ({host.os_cpe})", cve))

        if not rows:
            return

        rows.sort(key=lambda r: r[2].cvss_score if r[2].cvss_score is not None else 0, reverse=True)
        table = Table(title="Priority actions")
        table.add_column("Host")
        table.add_column("Service")
        table.add_column("CVE")
        table.add_column("CVSS")
        table.add_column("Action")
        last_ip = None
        for ip, service, cve in rows:
            style = _SEVERITY_STYLE.get(cve.severity, "white")
            score = f"{cve.cvss_score:.1f}" if cve.cvss_score is not None else "?"
            shown_ip = "" if ip == last_ip else ip
            last_ip = ip
            table.add_row(
                shown_ip, service, cve.cve_id, score,
                Text(config.SEVERITY_ACTIONS.get(cve.severity, ""), style=style),
            )
        self.console.print(table)
