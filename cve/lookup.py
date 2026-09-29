"""
NEVUS - CVE lookup against the NVD API.

Features:
  - CPE 2.2 -> 2.3 conversion (what the NVD API expects)
  - in-memory cache shared by all threads, with in-flight de-duplication
    (two threads asking for the same service wait for one single request)
  - optional on-disk cache (24 h) so repeated scans do not waste NVD requests
  - rate limiting (5 req/30 s without key, 50 req/30 s with key)
  - failures are NEVER cached and NEVER reported as "no CVE"
"""

import json
import os
import threading
import time
from dataclasses import asdict
from typing import Callable, Dict, List, Optional
from urllib.parse import quote, urlencode

import requests

import config
from cve.cpe import cpe_part, cpe_version, to_cpe23
from models import CVEFinding, HostResult, PortResult, ScanAborted


class NVDError(Exception):
    """The NVD API could not answer (network error, rate limit, bad reply)."""


class CPEUnknown(NVDError):
    """NVD does not know this CPE name (HTTP 404) - result is inconclusive."""


class _Entry:
    """Cache slot: the first thread fills it, the others wait for it."""
    __slots__ = ("value", "error", "event")

    def __init__(self):
        self.value = None
        self.error = None
        self.event = threading.Event()


class CVELookup:
    def __init__(
        self,
        api_key: Optional[str] = None,
        use_disk_cache: bool = True,
        stop_event: Optional[threading.Event] = None,
        log: Optional[Callable[[str], None]] = None,
    ):
        self.api_key = api_key
        self.stop = stop_event or threading.Event()
        self.log = log or (lambda message: None)
        self.use_disk_cache = use_disk_cache

        limit = config.NVD_RATE_LIMIT_WITH_KEY if api_key else config.NVD_RATE_LIMIT_NO_KEY
        self._interval = (30.0 / limit) * config.NVD_RATE_MARGIN
        self._next_slot = 0.0

        self._cache: Dict[str, _Entry] = {}
        self._cache_lock = threading.Lock()
        self._rate_lock = threading.Lock()
        self._stats_lock = threading.Lock()
        self._disk_lock = threading.Lock()
        self._disk: Dict[str, dict] = {}

        # Counters shown by the display
        self.requests_made = 0
        self.cache_hits = 0
        self.waiting = 0

        if use_disk_cache:
            self._load_disk_cache()

    # ------------------------------------------------------------------ disk cache
    def _load_disk_cache(self) -> None:
        try:
            with open(config.CACHE_FILE, "r", encoding="utf-8") as handle:
                self._disk = json.load(handle)
        except (OSError, ValueError):
            self._disk = {}

    def _disk_get(self, key: str) -> Optional[List[CVEFinding]]:
        if not self.use_disk_cache:
            return None
        with self._disk_lock:
            entry = self._disk.get(key)
        if not entry or time.time() - entry.get("ts", 0) > config.CACHE_TTL_SECONDS:
            return None
        try:
            return [CVEFinding(**item) for item in entry["findings"]]
        except (TypeError, KeyError):
            return None

    def _disk_put(self, key: str, findings: List[CVEFinding]) -> None:
        if not self.use_disk_cache:
            return
        with self._disk_lock:
            self._disk[key] = {"ts": time.time(), "findings": [asdict(f) for f in findings]}

    def save_cache(self) -> None:
        """Write the disk cache (expired entries removed). Never raises."""
        if not self.use_disk_cache:
            return
        try:
            os.makedirs(config.CACHE_DIR, exist_ok=True)
            now = time.time()
            with self._disk_lock:
                fresh = {k: v for k, v in self._disk.items()
                         if now - v.get("ts", 0) <= config.CACHE_TTL_SECONDS}
            tmp_path = config.CACHE_FILE + ".tmp"
            with open(tmp_path, "w", encoding="utf-8") as handle:
                json.dump(fresh, handle)
            os.replace(tmp_path, config.CACHE_FILE)
        except OSError as exc:
            self.log(f"could not write cache file: {exc}")

    # ------------------------------------------------------------------ rate limit
    def _sleep(self, seconds: float) -> None:
        if self.stop.wait(seconds):
            raise ScanAborted()

    def _throttle(self) -> None:
        """Block until our own request slot is free (respects the NVD limit)."""
        with self._stats_lock:
            self.waiting += 1
        try:
            with self._rate_lock:
                wait = self._next_slot - time.monotonic()
                if wait > 0:
                    self._sleep(wait)
                self._next_slot = max(time.monotonic(), self._next_slot) + self._interval
        finally:
            with self._stats_lock:
                self.waiting -= 1

    # ------------------------------------------------------------------ HTTP
    def _request(self, query: str) -> dict:
        headers = {"apiKey": self.api_key} if self.api_key else {}
        url = f"{config.NVD_BASE_URL}?{query}"
        last_error = "unknown error"

        for attempt in range(config.NVD_MAX_RETRIES + 1):
            self._throttle()
            with self._stats_lock:
                self.requests_made += 1
            self.log(f"NVD request: {query}")
            try:
                resp = requests.get(
                    url,
                    headers=headers,
                    timeout=(config.NVD_CONNECT_TIMEOUT, config.NVD_READ_TIMEOUT),
                )
            except requests.RequestException as exc:
                last_error = f"network error ({exc.__class__.__name__})"
                self._sleep(1 * (attempt + 1))
                continue

            if resp.status_code == 200:
                try:
                    return resp.json()
                except ValueError:
                    raise NVDError("NVD returned an invalid JSON reply")
            if resp.status_code == 404:
                raise CPEUnknown("CPE not known by NVD")
            if resp.status_code in (403, 429, 503):
                last_error = f"NVD returned HTTP {resp.status_code} (rate limit or overload)"
                self._sleep(5 * (attempt + 1))
                continue
            raise NVDError(f"NVD returned HTTP {resp.status_code}")

        raise NVDError(last_error)

    # ------------------------------------------------------------------ parsing
    @staticmethod
    def _severity_from_score(score: Optional[float]) -> str:
        if score is None:
            return config.SEVERITY_UNKNOWN_LABEL
        for threshold, label in config.SEVERITY_THRESHOLDS:
            if score >= threshold:
                return label
        return "LOW"

    @staticmethod
    def _score_from_metrics(metrics: dict) -> Optional[float]:
        for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            entries = metrics.get(key) or []
            if entries:
                score = entries[0].get("cvssData", {}).get("baseScore")
                if score is not None:
                    return float(score)
        return None

    def _parse(self, data: dict) -> List[CVEFinding]:
        findings = []
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            if cve.get("vulnStatus") == "Rejected":
                continue
            cve_id = cve.get("id", "unknown")
            score = self._score_from_metrics(cve.get("metrics", {}))
            description = next(
                (d.get("value", "") for d in cve.get("descriptions", []) if d.get("lang") == "en"),
                "",
            )
            findings.append(CVEFinding(
                cve_id=cve_id,
                cvss_score=score,
                severity=self._severity_from_score(score),
                description=description,
                url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            ))
        findings.sort(key=lambda f: f.cvss_score if f.cvss_score is not None else -1, reverse=True)
        return findings

    # ------------------------------------------------------------------ cache + fetch
    def _cached_fetch(self, key: str, fetch: Callable[[], List[CVEFinding]]) -> List[CVEFinding]:
        with self._cache_lock:
            entry = self._cache.get(key)
            owner = entry is None
            if owner:
                entry = _Entry()
                self._cache[key] = entry

        if not owner:
            # Another thread is already asking NVD for this exact service.
            while not entry.event.wait(0.5):
                if self.stop.is_set():
                    raise ScanAborted()
            with self._stats_lock:
                self.cache_hits += 1
            if entry.error:
                raise entry.error
            return entry.value

        try:
            cached = self._disk_get(key)
            if cached is not None:
                with self._stats_lock:
                    self.cache_hits += 1
                entry.value = cached
            else:
                entry.value = fetch()
                self._disk_put(key, entry.value)
        except BaseException as exc:
            entry.error = exc
            with self._cache_lock:
                self._cache.pop(key, None)   # failures are never cached
            raise
        finally:
            entry.event.set()
        return entry.value

    def lookup_by_cpe(self, cpe: str) -> List[CVEFinding]:
        """Exact lookup: CVEs whose vulnerable configurations match this CPE."""
        cpe23 = to_cpe23(cpe)

        def fetch() -> List[CVEFinding]:
            query = "cpeName=" + quote(cpe23, safe=":*") + "&isVulnerable"
            return self._parse(self._request(query))

        return self._cached_fetch("cpe:" + cpe23, fetch)

    def lookup_by_keyword(self, product: str, version: str) -> List[CVEFinding]:
        """Approximate lookup on free text. Results must be verified manually."""
        keyword = f"{product} {version}".strip()

        def fetch() -> List[CVEFinding]:
            query = urlencode({
                "keywordSearch": keyword,
                "resultsPerPage": config.NVD_KEYWORD_MAX_RESULTS,
            })
            return self._parse(self._request(query))

        return self._cached_fetch("kw:" + keyword.lower(), fetch)

    # ------------------------------------------------------------------ public API
    def enrich_port(self, port: PortResult) -> None:
        """Fill port.cves / port.checked / port.note / port.error in place."""
        if not port.identified or port.state != "open":
            port.note = port.note or "service not identified"
            return

        app_cpes = [c for c in port.cpes if cpe_part(c) == "a" and cpe_version(c)]
        os_cpe_with_version = any(cpe_part(c) == "o" and cpe_version(c) for c in port.cpes)

        try:
            if app_cpes:
                merged: Dict[str, CVEFinding] = {}
                for cpe in app_cpes:
                    for finding in self.lookup_by_cpe(cpe):
                        merged[finding.cve_id] = finding
                port.cves = sorted(
                    merged.values(),
                    key=lambda f: f.cvss_score if f.cvss_score is not None else -1,
                    reverse=True,
                )
                port.cve_match = "cpe"
                port.checked = True
            elif os_cpe_with_version:
                port.note = "no application CPE, see the OS line of this host"
            elif port.product and port.version:
                findings = self.lookup_by_keyword(port.product, port.version)
                if findings:
                    port.cves = findings
                    port.cve_match = "keyword"
                    port.checked = True
                else:
                    port.note = "no exact CPE, keyword search inconclusive"
            else:
                port.note = "no CPE or version detected"
        except CPEUnknown:
            port.note = "CPE not known by NVD"
        except ScanAborted:
            raise
        except Exception as exc:  # noqa: BLE001
            port.error = str(exc)

    def enrich_host_os(self, host: HostResult) -> None:
        """Look up CVEs for the OS/firmware CPE found on this host."""
        if not host.os_cpe:
            return
        try:
            host.os_cves = self.lookup_by_cpe(host.os_cpe)
            host.os_checked = True
        except CPEUnknown:
            host.os_note = "OS CPE not known by NVD"
        except ScanAborted:
            raise
        except Exception as exc:  # noqa: BLE001
            host.os_error = str(exc)
