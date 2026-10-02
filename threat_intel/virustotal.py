"""VirusTotal API v3 client with SQLite-equivalent Mongo cache and rate limiting.

- Key from .env (VT_API_KEY); never hard-coded, never displayed
- Free-tier aware: ~4 requests/minute, 500/day; handles HTTP 429 and timeouts
- Never sends private IPs, internal hostnames, or usernames
- Never fabricates results; source of every reputation is tracked
"""
from __future__ import annotations

import base64
import ipaddress
import time
from collections import deque
from typing import Any

import requests

from config.settings import Settings, get_settings
from database.mongodb import MongoStore
from ioc.extractor import is_enrichable
from models.models import EnrichmentResult


class VirusTotalClient:
    BASE = "https://www.virustotal.com/api/v3"

    def __init__(self, store: MongoStore, settings: Settings | None = None) -> None:
        self.s = settings or get_settings()
        self.store = store
        self._times: deque[float] = deque()
        self._day = time.strftime("%Y-%m-%d")
        self._day_count = 0
        self.available = bool(self.s.vt_api_key)

    # -- rate limiting ---------------------------------------------------
    def _acquire(self) -> bool:
        if not self.available:
            return False
        now = time.time()
        today = time.strftime("%Y-%m-%d")
        if today != self._day:
            self._day, self._day_count = today, 0
        while self._times and now - self._times[0] > 60:
            self._times.popleft()
        if len(self._times) >= self.s.vt_rate_per_minute or self._day_count >= self.s.vt_daily_quota:
            return False
        self._times.append(now)
        self._day_count += 1
        return True

    def _get(self, url: str) -> dict | None:
        if not self._acquire():
            return None
        try:
            r = requests.get(url, headers={"x-apikey": self.s.vt_api_key or ""}, timeout=15)
        except requests.RequestException:
            return None
        if r.status_code == 429:                      # back off once, then give up gracefully
            time.sleep(15)
            return None
        if r.status_code != 200:
            return None
        try:
            return r.json()
        except ValueError:
            return None

    # -- lookups ----------------------------------------------------------
    def _stats(self, data: dict) -> EnrichmentResult:
        attrs = data.get("data", {}).get("attributes", {})
        st = attrs.get("last_analysis_stats", {})
        mal, sus = int(st.get("malicious", 0)), int(st.get("suspicious", 0))
        und = int(st.get("undetected", 0)) + int(st.get("harmless", 0))
        total = mal + sus + und
        rep = "malicious" if mal >= 5 else ("suspicious" if (mal + sus) >= 1 else "clean")
        return EnrichmentResult(ioc_value="", ioc_type="", source="VirusTotal",
                                reputation=rep, malicious=mal, suspicious=sus,
                                undetected=und, total=total)

    def lookup_ip(self, ip: str) -> EnrichmentResult | None:
        res = self._get(f"{self.BASE}/ip_addresses/{ip}")
        return self._stats(res) if res else None

    def lookup_domain(self, domain: str) -> EnrichmentResult | None:
        res = self._get(f"{self.BASE}/domains/{domain}")
        return self._stats(res) if res else None

    def lookup_url(self, url: str) -> EnrichmentResult | None:
        ident = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        res = self._get(f"{self.BASE}/urls/{ident}")
        return self._stats(res) if res else None

    def lookup_hash(self, h: str) -> EnrichmentResult | None:
        res = self._get(f"{self.BASE}/files/{h}")
        return self._stats(res) if res else None

    # -- public API --------------------------------------------------------
    def enrich(self, ioc: dict) -> EnrichmentResult:
        """Enrich one IOC with cache + rate limiting. Never raises."""
        if not is_enrichable(ioc):
            return EnrichmentResult(ioc["value"], ioc["type"], source="Not enriched",
                                    reputation="unknown",
                                    reason="Internal/private indicator - not sent to third parties")
        cached = self.store.cache_get(ioc["value"], self.s.ioc_cache_ttl_hours)
        if cached:
            return EnrichmentResult(ioc["value"], ioc["type"], **cached)
        if not self.available:
            return EnrichmentResult(ioc["value"], ioc["type"], source="Not enriched",
                                    reputation="unknown",
                                    reason="VirusTotal integration unavailable")
        fn = {"ipv4": self.lookup_ip, "ipv6": self.lookup_ip, "domain": self.lookup_domain,
              "url": self.lookup_url, "md5": self.lookup_hash, "sha1": self.lookup_hash,
              "sha256": self.lookup_hash}.get(ioc["type"])
        res = fn(ioc["value"]) if fn else None
        if res is None:
            return EnrichmentResult(ioc["value"], ioc["type"], source="Not enriched",
                                    reputation="unknown",
                                    reason="Threat intelligence service is currently unavailable")
        res.ioc_value, res.ioc_type = ioc["value"], ioc["type"]
        self.store.cache_set(ioc["value"], ioc["type"],
                             {"source": res.source, "reputation": res.reputation,
                              "malicious": res.malicious, "suspicious": res.suspicious,
                              "undetected": res.undetected, "total": res.total, "reason": ""})
        return res


def is_private_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
        doc_ranges = (
            ipaddress.ip_network("192.0.2.0/24"),
            ipaddress.ip_network("198.51.100.0/24"),
            ipaddress.ip_network("203.0.113.0/24"),
        )
        if any(ip in net for net in doc_ranges):
            return False
        return not ip.is_global
    except ValueError:
        return False
