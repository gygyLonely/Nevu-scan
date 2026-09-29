"""
NEVUS - Two-phase scanning with nmap (subprocess + XML parsing).

Phase 1: fast port discovery, open ports are shown immediately.
Phase 2: service/version detection, one nmap call per open port, several in
         parallel, each result is shown (and its CVEs looked up) as soon as
         it is ready.
"""

import subprocess
import threading
import time
import xml.etree.ElementTree as ET
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List, Optional, Tuple

import config
from cve.cpe import cpe_part, cpe_version
from cve.lookup import CVELookup
from models import HostResult, PortResult, ScanAborted, ScanContext
from scanner.discovery import is_alive

# nmap processes currently running, so they can all be killed on Ctrl+C
_procs = set()
_procs_lock = threading.Lock()


def terminate_all() -> None:
    """Kill every nmap process started by this program."""
    with _procs_lock:
        procs = list(_procs)
    for proc in procs:
        try:
            proc.kill()
        except OSError:
            pass


def run_nmap(args: List[str], timeout: float, stop_event: Optional[threading.Event] = None) -> str:
    """
    Run nmap and return its stdout (XML). The process is killed if it exceeds
    `timeout` (subprocess.TimeoutExpired is raised) or if the scan is stopped.
    """
    if stop_event is not None and stop_event.is_set():
        raise ScanAborted()

    proc = subprocess.Popen(
        [config.NMAP_BINARY] + args,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    with _procs_lock:
        _procs.add(proc)
    try:
        try:
            out, err = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.communicate()
            raise
    finally:
        with _procs_lock:
            _procs.discard(proc)

    if stop_event is not None and stop_event.is_set():
        raise ScanAborted()
    if proc.returncode != 0 and not out.strip():
        raise RuntimeError(f"nmap failed: {err.strip() or 'unknown error'}")
    return out


def parse_ports_arg(ports_arg: Optional[str]) -> List[str]:
    """
    Translate --ports into nmap arguments, e.g. ["-p", "21,22,80"] or
    ["--top-ports", "1000"]. Raises ValueError on invalid input.
    """
    if not ports_arg or ports_arg == "top1000":
        return ["--top-ports", "1000"]

    for part in ports_arg.split(","):
        part = part.strip()
        if "-" in part:
            bounds = part.split("-")
            if len(bounds) != 2 or not all(b.isdigit() for b in bounds):
                raise ValueError(f"Invalid port range: '{part}'")
            low, high = int(bounds[0]), int(bounds[1])
            if not (0 < low <= 65535 and 0 < high <= 65535 and low <= high):
                raise ValueError(f"Port range out of bounds: '{part}'")
        else:
            if not part.isdigit():
                raise ValueError(f"Invalid port value: '{part}'")
            if not (0 < int(part) <= 65535):
                raise ValueError(f"Port out of range (1-65535): '{part}'")

    return ["-p", ports_arg]


# ---------------------------------------------------------------------- parsing
def _parse_discovery_xml(xml_text: str) -> Tuple[bool, List[Tuple[int, str]], str]:
    """Return (host_is_up, [(port, protocol)], hostname) from phase 1 XML."""
    root = ET.fromstring(xml_text)
    host_el = root.find("host")
    if host_el is None:
        return False, [], ""

    status_el = host_el.find("status")
    up = status_el is not None and status_el.get("state") == "up"

    hostname = ""
    hostname_el = host_el.find("hostnames/hostname")
    if hostname_el is not None:
        hostname = hostname_el.get("name", "")

    ports = []
    for port_el in host_el.findall("ports/port"):
        state_el = port_el.find("state")
        if state_el is not None and state_el.get("state") == "open":
            ports.append((int(port_el.get("portid")), port_el.get("protocol", "tcp")))
    return up, ports, hostname


def _parse_service_xml(xml_text: str, port: int) -> Optional[Dict]:
    """Return the service details of one port from phase 2 XML (None if absent)."""
    root = ET.fromstring(xml_text)
    for port_el in root.findall("host/ports/port"):
        if int(port_el.get("portid")) != port:
            continue
        state_el = port_el.find("state")
        info = {
            "state": state_el.get("state") if state_el is not None else "unknown",
            "service_name": "", "product": "", "version": "", "extra_info": "",
            "conf": None, "cpes": [], "scripts": {},
        }
        service_el = port_el.find("service")
        if service_el is not None:
            info["service_name"] = service_el.get("name", "")
            info["product"] = service_el.get("product", "")
            info["version"] = service_el.get("version", "")
            info["extra_info"] = service_el.get("extrainfo", "")
            conf = service_el.get("conf")
            info["conf"] = int(conf) if conf and conf.isdigit() else None
            info["cpes"] = [c.text for c in service_el.findall("cpe") if c.text]
        for script_el in port_el.findall("script"):
            info["scripts"][script_el.get("id", "")] = script_el.get("output", "")
        return info
    return None


# ---------------------------------------------------------------------- phase 2
def _process_port(host: HostResult, port: PortResult, ctx: ScanContext,
                  cve_lookup: CVELookup, deadline: float) -> None:
    """Detect the service on one port, then look up its CVEs."""
    try:
        remaining = deadline - time.monotonic()
        if remaining <= 1:
            port.note = "skipped: host time limit reached"
            return

        args = ["-n", "-Pn", "-sV", "-p", str(port.port)]
        if ctx.scripts:
            args.append("-sC")
        args += ["-oX", "-", host.ip]
        ctx.log(f"{host.ip}:{port.port} nmap {' '.join(args)}")

        try:
            xml_text = run_nmap(args, min(ctx.port_timeout, remaining), ctx.stop_event)
        except subprocess.TimeoutExpired:
            port.note = "version detection timed out"
            return
        except RuntimeError as exc:
            port.error = str(exc)
            return

        info = _parse_service_xml(xml_text, port.port)
        if info is None:
            port.note = "port not reported by nmap during version detection"
            return

        port.state = info["state"]
        port.service_name = info["service_name"]
        port.product = info["product"]
        port.version = info["version"]
        port.extra_info = info["extra_info"]
        port.cpes = info["cpes"]
        port.scripts = info["scripts"]
        conf = info["conf"]
        port.identified = bool(port.service_name) and (
            conf is None or conf >= config.MIN_SERVICE_CONFIDENCE
        )

        if port.state != "open":
            port.note = f"port became {port.state}"
            return
        if not port.identified:
            port.note = "service not identified"
            return

        port.status = "checking"
        cve_lookup.enrich_port(port)
    except ScanAborted:
        raise
    except Exception as exc:  # noqa: BLE001
        port.error = str(exc)
    finally:
        if not ctx.stop_event.is_set():
            port.status = "done"


def _pick_os_cpe(host: HostResult) -> str:
    """Most frequent OS CPE with a version among the host's services."""
    counter = Counter(
        cpe for port in host.ports for cpe in port.cpes
        if cpe_part(cpe) == "o" and cpe_version(cpe)
    )
    return counter.most_common(1)[0][0] if counter else ""


# ---------------------------------------------------------------------- host scan
def scan_host(host: HostResult, ctx: ScanContext, cve_lookup: CVELookup) -> None:
    """
    Scan one host in place. Results appear in `host` progressively, so the
    display can show them while the scan is still running.
    """
    deadline = time.monotonic() + ctx.host_timeout
    try:
        # Phase 1: port discovery. If the host ignores ICMP, scan it anyway (-Pn).
        host.phase = "discovery"
        alive = is_alive(host.ip)
        host.icmp_blocked = not alive
        args = ["-n", "--open"] + ctx.port_args
        if not alive:
            args.append("-Pn")
        args += ["-oX", "-", host.ip]
        ctx.log(f"{host.ip} nmap {' '.join(args)}")

        try:
            xml_text = run_nmap(args, ctx.host_timeout, ctx.stop_event)
        except subprocess.TimeoutExpired:
            host.error = "port discovery timed out"
            host.phase = "done"
            return

        up, open_ports, hostname = _parse_discovery_xml(xml_text)
        host.hostname = hostname
        host.alive = up or bool(open_ports)
        host.ports = [PortResult(port=p, protocol=proto) for p, proto in open_ports]

        # Phase 2: version detection + CVE lookup, one nmap call per port.
        if host.ports:
            host.phase = "versions"
            with ThreadPoolExecutor(max_workers=ctx.port_workers) as pool:
                futures = [
                    pool.submit(_process_port, host, port, ctx, cve_lookup, deadline)
                    for port in list(host.ports)
                ]
                for future in futures:
                    future.result()

            # OS / firmware level CVEs (what matters for routers and printers)
            host.os_cpe = _pick_os_cpe(host)
            if host.os_cpe:
                host.phase = "os_check"
                cve_lookup.enrich_host_os(host)

        host.phase = "done"
    except ScanAborted:
        host.phase = "interrupted"
    except Exception as exc:  # noqa: BLE001
        host.error = str(exc)
        host.phase = "done"
