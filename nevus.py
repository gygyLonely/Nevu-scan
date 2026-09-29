#!/usr/bin/env python3
"""
NEVUS - Network Vulnerability Scanner

Two-phase scan:
  1. Fast port discovery (open ports shown immediately).
  2. Per-port service/version detection + CVE lookup, updated live.

Usage examples:
  python nevus.py -t 192.168.25.0/24
  python nevus.py -t 192.168.25.1,2,3,54 -p 21,22,23,80,8291 -v
  python nevus.py -t 192.168.25.1 -k YOUR_NVD_KEY -o report.json
"""

import argparse
import json
import signal
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict
from threading import Event

import config
from cve.lookup import CVELookup
from display.live_table import ScanDisplay
from models import HostResult, ScanContext, ScanSummary
from scanner.discovery import parse_targets
from scanner.port_scan import parse_ports_arg, scan_host, terminate_all


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="nevus", description="NEVUS - Network Vulnerability Scanner")
    parser.add_argument("-t", "--target", required=True,
        help="CIDR (192.168.1.0/24), single IP, or comma-separated list "
             "(192.168.1.1,2,3 or 192.168.1.1,192.168.2.5).")
    parser.add_argument("-k", "--nvd-key", default=None,
        help="NVD API key (optional). Without it, requests are slower "
             "due to a stricter rate limit.")
    parser.add_argument("-p", "--ports", default=None,
        help="Ports to scan: 'top1000' (default), a list (21,22,80), or a range (1-1000).")
    parser.add_argument("-v", "--verbose", action="store_true", help="Print debug information.")
    parser.add_argument("-o", "--output", default=None, help="Write the full scan result as JSON.")
    parser.add_argument("-w", "--max-workers", type=int, default=config.DEFAULT_MAX_WORKERS,
        help=f"Hosts scanned in parallel (default: {config.DEFAULT_MAX_WORKERS}).")
    parser.add_argument("--port-workers", type=int, default=config.DEFAULT_PORT_WORKERS,
        help=f"Ports detected in parallel per host (default: {config.DEFAULT_PORT_WORKERS}).")
    parser.add_argument("--host-timeout", type=int, default=config.DEFAULT_HOST_TIMEOUT,
        help=f"Max seconds per host, ports already found are kept (default: {config.DEFAULT_HOST_TIMEOUT}).")
    parser.add_argument("--port-timeout", type=int, default=config.DEFAULT_PORT_TIMEOUT,
        help=f"Max seconds per port version detection (default: {config.DEFAULT_PORT_TIMEOUT}).")
    parser.add_argument("--scripts", action="store_true",
        help="Also run nmap default scripts (-sC). Slower and noisier on the network.")
    parser.add_argument("--no-disk-cache", action="store_true",
        help="Do not read/write the on-disk NVD cache (~/.cache/nevus).")
    parser.add_argument("--dry-run", action="store_true",
        help="Show what would be scanned without running anything.")
    return parser


def update_summary(summary: ScanSummary, host: HostResult, unique_cves: set) -> None:
    summary.hosts_total += 1
    if host.error:
        summary.hosts_failed += 1
        return
    if not host.alive:
        summary.hosts_down += 1
        return
    summary.hosts_alive += 1

    for port in host.open_ports:
        summary.services_detected += 1
        for cve in port.cves:
            unique_cves.add(cve.cve_id)
        sev = port.highest_severity
        if sev == "CRITICAL":
            summary.critical += 1
        elif sev == "HIGH":
            summary.high += 1
        elif sev == "MEDIUM":
            summary.medium += 1
        elif sev == "LOW":
            summary.low += 1
        elif sev == "ERROR":
            summary.check_failed += 1
        elif sev == "UNVERIFIED":
            summary.unverified += 1
        else:
            summary.ok += 1

    for cve in host.os_cves:
        unique_cves.add(cve.cve_id)
    if host.os_error:
        summary.check_failed += 1


def export_json(hosts: list, summary: ScanSummary, path: str) -> None:
    data = {"summary": asdict(summary), "hosts": [asdict(h) for h in hosts]}
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2)


def run_scan(args: argparse.Namespace) -> int:
    print(f"\n[NEVUS] {config.LEGAL_NOTICE}\n")

    try:
        targets = parse_targets(args.target)
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    try:
        port_args = parse_ports_arg(args.ports)
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    if args.dry_run:
        print(f"Would scan {len(targets)} host(s):")
        for ip in targets:
            print(f"  - {ip}")
        print(f"Port selection: {' '.join(port_args)}")
        print(f"Scripts (-sC): {'enabled' if args.scripts else 'disabled'}")
        return 0

    stop_event = Event()

    def handle_sigint(signum, frame):  # noqa: ARG001
        stop_event.set()
        terminate_all()

    signal.signal(signal.SIGINT, handle_sigint)

    log = (lambda message: print(f"[verbose] {message}", file=sys.stderr)) if args.verbose else (lambda message: None)
    if args.verbose:
        log(f"Resolved {len(targets)} target(s): {targets}")
        log(f"nmap port args: {port_args}")

    cve_lookup = CVELookup(
        api_key=args.nvd_key,
        use_disk_cache=not args.no_disk_cache,
        stop_event=stop_event,
        log=log,
    )
    ctx = ScanContext(
        port_args=port_args,
        host_timeout=args.host_timeout,
        port_timeout=args.port_timeout,
        port_workers=args.port_workers,
        scripts=args.scripts,
        stop_event=stop_event,
        log=log,
    )

    summary = ScanSummary()
    unique_cves: set = set()
    results = []
    start_time = time.time()

    with ScanDisplay(cve_lookup=cve_lookup) as display:
        hosts = {ip: HostResult(ip=ip) for ip in targets}
        for host in hosts.values():
            display.upsert_host(host)

        def watch(host: HostResult) -> None:
            # Periodically redraw while the host is still scanning, so
            # port-by-port progress is visible instead of only at the end.
            while host.phase not in ("done", "interrupted") and not stop_event.is_set():
                display.upsert_host(host)
                time.sleep(0.3)
            display.upsert_host(host)

        with ThreadPoolExecutor(max_workers=args.max_workers + len(targets)) as pool:
            scan_futures = [pool.submit(scan_host, hosts[ip], ctx, cve_lookup) for ip in targets]
            watch_futures = [pool.submit(watch, hosts[ip]) for ip in targets]
            for future in scan_futures + watch_futures:
                future.result()

        results = [hosts[ip] for ip in targets]
        for host in results:
            update_summary(summary, host, unique_cves)

        summary.interrupted = stop_event.is_set()
        summary.unique_cves = len(unique_cves)
        summary.duration_seconds = time.time() - start_time

    # Printed after the `with` block so the live region has been closed
    # and frozen first - otherwise these tables would be drawn on top of
    # (or interleaved with) the still-active live display.
    display.print_summary(summary)
    display.print_priorities(results)

    cve_lookup.save_cache()

    if args.output:
        export_json(results, summary, args.output)
        print(f"\nFull report written to: {args.output}")

    if summary.hosts_failed or summary.check_failed:
        return 3
    if summary.critical or summary.high:
        return 1
    return 0


def main() -> None:
    parser = build_arg_parser()
    args = parser.parse_args()
    sys.exit(run_scan(args))


if __name__ == "__main__":
    main()
