# NEVUS

Network Vulnerability Scanner for heterogeneous network equipment
(routers, printers, cameras, servers...).

Scans a network in two phases (fast port discovery, then per-port service
detection), cross-references detected services and OS/firmware against
known CVEs (NVD), and reports findings live, grouped by host, ranked by
CVSS severity.

## Status
Beta - internship project.

## Requirements
- Python 3.10+
- nmap installed and available in PATH
- A virtual environment is recommended:

      python -m venv .venv
      source .venv/bin/activate
      pip install -r requirements.txt

## Basic usage

    python nevus.py -t 192.168.1.1
    python nevus.py -t 192.168.1.0/24
    python nevus.py -t 192.168.1.1,2,3,54 -p 21,22,23,80,8291 -v
    python nevus.py -t 192.168.1.1 -k YOUR_NVD_KEY -o report.json

## How a scan works

1. **Port discovery** - nmap finds open ports quickly, they appear on
   screen right away.
2. **Service detection** - each open port is checked individually (one
   nmap call per port, several in parallel), so results complete one by
   one instead of all at once at the end.
3. **CVE lookup** - every identified service/version is checked against
   NVD. The OS/firmware (e.g. a router's RouterOS version) is also
   checked separately - this is what finds vulnerabilities on devices
   that expose no per-service CPE (routers, printers, cameras).
4. **Severity ranking** - every finding is labelled CRITICAL, HIGH,
   MEDIUM, LOW, OK, or UNVERIFIED, based on the CVSS score.

## Reading the output

- `CVE-xxxx-xxxx (9.8)` - an exact match found via the device's CPE.
  Reliable.
- `(keyword match, verify manually)` - no exact CPE was available, the
  result comes from a free-text search on the product name. Treat these
  as leads to check manually, not confirmed vulnerabilities.
- `UNVERIFIED (reason)` - NEVUS could not check this port/service at all
  (no version detected, service not identified, etc.). This is never
  shown as "OK" - OK only means a check actually ran and found nothing.
- `ERROR` - the CVE lookup itself failed (network issue, NVD rate
  limit...). Never treated as "no vulnerability found".

At the end of a scan: a summary table, and a "Priority actions" table
listing every CRITICAL/HIGH finding across all hosts, sorted by CVSS
score, with a suggested action.

## Options

    -t, --target          CIDR, single IP, or comma-separated list
                           (192.168.1.1,2,3 or 192.168.1.1,192.168.2.5)
    -k, --nvd-key          NVD API key (optional, raises the rate limit
                           from 5 to 50 requests/30s)
    -p, --ports            top1000 (default) | list (21,22,80) | range (1-1000)
    -v, --verbose          Print debug information (nmap commands, NVD queries)
    -o, --output           Write the full scan result as JSON
    -w, --max-workers      Hosts scanned in parallel (default: 5)
    --port-workers         Ports detected in parallel per host (default: 3)
    --host-timeout         Max seconds per host; ports already found are
                           kept even if the host times out (default: 300)
    --port-timeout         Max seconds for one port's version detection
                           (default: 90 - increase for slow devices like
                           routers, e.g. --port-timeout 240)
    --scripts              Also run nmap default scripts (-sC). Slower
                           and noisier on the network, off by default
    --no-disk-cache        Disable the on-disk NVD cache
                           (~/.cache/nevus), which normally avoids
                           re-querying the same service/version across
                           separate scans for 24h
    --dry-run              Show what would be scanned, no real scan

## Caching and rate limiting

NVD answers are cached both in memory (shared across all threads during
one run) and on disk (24h, reused across separate scans). A failed
request is never cached. Without an API key, requests are spaced out to
respect NVD's 5 requests/30s limit, which can make large scans slow -
pass -k with an API key when scanning many hosts/services.

## Interrupting a scan

Ctrl+C stops all running nmap processes immediately and prints a
summary of whatever was found before the interruption.

## Legal notice
Only scan networks and devices you own or are explicitly authorized to test.
