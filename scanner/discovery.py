"""
NEVUS - Target parsing and ICMP host discovery.
"""

import ipaddress
import subprocess
from typing import List

from config import ICMP_PING_TIMEOUT


def parse_targets(target_str: str) -> List[str]:
    """
    Parse a --target argument into a flat, de-duplicated list of IP strings.

    Supported formats (comma-separated, can be mixed):
      - CIDR:            192.168.25.0/24
      - Single IP:        192.168.25.1
      - Short list on the same subnet: 192.168.25.1,2,3
        (uses the last full IP seen as the subnet prefix)
      - Full IPs on different subnets: 192.168.25.1,192.168.26.5
    """
    if not target_str:
        raise ValueError("No target specified.")

    ips: List[str] = []
    seen = set()
    last_prefix = None  # e.g. "192.168.25."

    for raw in target_str.split(","):
        token = raw.strip()
        if not token:
            continue

        if "/" in token:
            # CIDR notation
            try:
                network = ipaddress.ip_network(token, strict=False)
            except ValueError as exc:
                raise ValueError(f"Invalid CIDR range '{token}': {exc}")
            for ip in network.hosts():
                ip_str = str(ip)
                if ip_str not in seen:
                    seen.add(ip_str)
                    ips.append(ip_str)
            last_prefix = ".".join(token.split(".")[:3]) + "."
            continue

        if token.count(".") == 3:
            # Full IP address
            try:
                ipaddress.ip_address(token)
            except ValueError as exc:
                raise ValueError(f"Invalid IP address '{token}': {exc}")
            if token not in seen:
                seen.add(token)
                ips.append(token)
            last_prefix = ".".join(token.split(".")[:3]) + "."
            continue

        if token.isdigit():
            # Short notation, e.g. "2" after "192.168.25.1" -> "192.168.25.2"
            if last_prefix is None:
                raise ValueError(
                    f"Short host notation '{token}' used before any full IP "
                    f"was given to infer the subnet."
                )
            ip_str = last_prefix + token
            try:
                ipaddress.ip_address(ip_str)
            except ValueError as exc:
                raise ValueError(f"Invalid short host '{token}' -> '{ip_str}': {exc}")
            if ip_str not in seen:
                seen.add(ip_str)
                ips.append(ip_str)
            continue

        raise ValueError(f"Could not parse target token: '{token}'")

    return ips


def is_alive(ip: str) -> bool:
    """
    Send a single ICMP echo request to check if the host responds.
    Returns False if the host does not answer (it may still be up but
    blocking ICMP - the caller is expected to fall back to a port scan
    with host discovery disabled in that case).
    """
    try:
        result = subprocess.run(
            ["ping", "-c", "1", "-W", str(ICMP_PING_TIMEOUT), ip],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return result.returncode == 0
    except FileNotFoundError:
        # 'ping' not available on this system - assume unknown, let the
        # caller decide to scan anyway.
        return False
