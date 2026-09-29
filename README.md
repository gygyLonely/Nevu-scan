# NEVUS

Network Vulnerability Scanner for heterogeneous network equipment
(routers, printers, cameras, servers...).

Cross-references detected services against known CVEs (NVD) and reports
findings live, grouped by host, ranked by CVSS severity.

## Status
Beta - internship project.

## Requirements
- Python 3.10+
- nmap installed and available in PATH
- pip install -r requirements.txt

## Usage
    python nevus.py -t 192.168.1.0/24
    python nevus.py -t 192.168.1.1,2,3,54 -p 21,22,23,80,8291 -v
    python nevus.py -t 192.168.1.1 -k YOUR_NVD_KEY -o report.json

## Options
    -t, --target        CIDR, single IP, or comma-separated list
    -k, --nvd-key        NVD API key (optional)
    -p, --ports          top1000 (default) | list | range
    -v, --verbose        Verbose/debug output
    -o, --output         Write full JSON report to file
    -w, --max-workers    Parallel hosts scanned at once
    --host-timeout       Max seconds per host
    --dry-run            Show what would be scanned, no real scan

## Legal notice
Only scan networks and devices you own or are explicitly authorized to test.
