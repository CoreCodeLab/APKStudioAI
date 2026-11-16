"""
Feed Integrations for APKStudioAI 2.1
VirusTotal, URLhaus, Abuse.ch, AlienVault OTX, MISP integrations.
"""
import hashlib
import json
import time
from pathlib import Path
from typing import Dict, List, Any, Optional, Set
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict
from unittest.mock import Mock

try:
    import requests
except ImportError:
    requests = None

from ..config_manager import get_config
from ..logging_setup import get_module_logger

logger = get_module_logger("feed_integrations")


class FeedSource(Enum):
    """Threat intelligence feed sources."""
    VIRUSTOTAL = "virustotal"
    URLHAUS = "urlhaus"
    ABUSE_CH = "abuse_ch"
    ALIENVAULT_OTX = "alienvault_otx"
    MISP = "misp"
    THREATFOX = "threatfox"
    FEEDLY = "feedly"
    CUSTOM = "custom"


@dataclass
class FeedIndicator:
    """Indicator from a threat feed."""
    id: str
    source: FeedSource
    indicator_type: str  # ip, domain, url, hash, etc.
    value: str
    confidence: float
    severity: str
    tags: List[str] = field(default_factory=list)
    malware_families: List[str] = field(default_factory=list)
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    context: Dict[str, Any] = field(default_factory=dict)
    raw_data: Dict[str, Any] = field(default_factory=dict)


@dataclass
class FeedQueryResult:
    """Result of querying a feed."""
    source: FeedSource
    query: str
    query_type: str
    found: bool
    indicators: List[FeedIndicator] = field(default_factory=list)
    error: str = ""
    timestamp: float = field(default_factory=time.time)


class FeedIntegrations:
    """Manages threat intelligence feed integrations."""

    def __init__(self, config: Dict = None):
        self.config = config or get_config().get_all()
        self.feeds_config = self.config.get("threat_intel", {}).get("feeds", {})
        self.cache: Dict[str, FeedQueryResult] = {}
        self.cache_ttl = self.feeds_config.get("cache_ttl", 3600)  # 1 hour
        self.enabled_sources = self.feeds_config.get("enabled", [
            FeedSource.URLHAUS.value,
            FeedSource.ABUSE_CH.value,
        ])

        # API keys
        self.api_keys = self.feeds_config.get("api_keys", {})

        # HTTP client
        self._session = None

    def _get_session(self):
        """Get requests session."""
        if self._session is None:
            if requests is not None:
                self._session = requests.Session()
                self._session.timeout = 30
            else:
                logger.warning("requests_not_available")
        return self._session

    def check_hash(self, file_hash: str) -> List[FeedQueryResult]:
        """Check file hash against all feeds."""
        results = []
        for source_name in self.enabled_sources:
            source = FeedSource(source_name)
            if source == FeedSource.VIRUSTOTAL:
                results.append(self._check_virustotal_hash(file_hash))
            elif source == FeedSource.URLHAUS:
                results.append(self._check_urlhaus_hash(file_hash))
            elif source == FeedSource.ABUSE_CH:
                results.append(self._check_abuse_ch_hash(file_hash))
            elif source == FeedSource.ALIENVAULT_OTX:
                results.append(self._check_otx_hash(file_hash))
            elif source == FeedSource.THREATFOX:
                results.append(self._check_threatfox_hash(file_hash))
        return results

    def check_domain(self, domain: str) -> List[FeedQueryResult]:
        """Check domain against all feeds."""
        results = []
        for source_name in self.enabled_sources:
            source = FeedSource(source_name)
            if source == FeedSource.VIRUSTOTAL:
                results.append(self._check_virustotal_domain(domain))
            elif source == FeedSource.URLHAUS:
                results.append(self._check_urlhaus_domain(domain))
            elif source == FeedSource.ABUSE_CH:
                results.append(self._check_abuse_ch_domain(domain))
            elif source == FeedSource.ALIENVAULT_OTX:
                results.append(self._check_otx_domain(domain))
            elif source == FeedSource.THREATFOX:
                results.append(self._check_threatfox_domain(domain))
        return results

    def check_ip(self, ip: str) -> List[FeedQueryResult]:
        """Check IP against all feeds."""
        results = []
        for source_name in self.enabled_sources:
            source = FeedSource(source_name)
            if source == FeedSource.VIRUSTOTAL:
                results.append(self._check_virustotal_ip(ip))
            elif source == FeedSource.URLHAUS:
                results.append(self._check_urlhaus_ip(ip))
            elif source == FeedSource.ABUSE_CH:
                results.append(self._check_abuse_ch_ip(ip))
            elif source == FeedSource.ALIENVAULT_OTX:
                results.append(self._check_otx_ip(ip))
            elif source == FeedSource.THREATFOX:
                results.append(self._check_threatfox_ip(ip))
        return results

    def check_url(self, url: str) -> List[FeedQueryResult]:
        """Check URL against all feeds."""
        results = []
        for source_name in self.enabled_sources:
            source = FeedSource(source_name)
            if source == FeedSource.VIRUSTOTAL:
                results.append(self._check_virustotal_url(url))
            elif source == FeedSource.URLHAUS:
                results.append(self._check_urlhaus_url(url))
            elif source == FeedSource.ABUSE_CH:
                results.append(self._check_abuse_ch_url(url))
            elif source == FeedSource.ALIENVAULT_OTX:
                results.append(self._check_otx_url(url))
        return results

    # VirusTotal API
    def _check_virustotal_hash(self, file_hash: str) -> FeedQueryResult:
        cache_key = f"vt:hash:{file_hash}"
        if cache_key in self.cache:
            cached = self.cache[cache_key]
            if time.time() - cached.timestamp < self.cache_ttl:
                return cached

        api_key = self.api_keys.get("virustotal")
        if not api_key:
            return FeedQueryResult(FeedSource.VIRUSTOTAL, file_hash, "hash", False,
                                  error="No API key")

        session = self._get_session()
        if not session:
            return FeedQueryResult(FeedSource.VIRUSTOTAL, file_hash, "hash", False,
                                  error="requests not available")

        try:
            headers = {"x-apikey": api_key}
            response = session.get(
                f"https://www.virustotal.com/api/v3/files/{file_hash}",
                headers=headers
            )
            if response.status_code == 200:
                data = response.json()
                indicators = self._parse_virustotal_response(data, file_hash, "hash")
                result = FeedQueryResult(FeedSource.VIRUSTOTAL, file_hash, "hash", True, indicators)
            elif response.status_code == 404:
                result = FeedQueryResult(FeedSource.VIRUSTOTAL, file_hash, "hash", False)
            else:
                result = FeedQueryResult(FeedSource.VIRUSTOTAL, file_hash, "hash", False,
                                        error=f"HTTP {response.status_code}")
        except Exception as e:
            result = FeedQueryResult(FeedSource.VIRUSTOTAL, file_hash, "hash", False,
                                    error=str(e))

        self.cache[cache_key] = result
        return result

    def _check_virustotal_domain(self, domain: str) -> FeedQueryResult:
        cache_key = f"vt:domain:{domain}"
        if cache_key in self.cache:
            cached = self.cache[cache_key]
            if time.time() - cached.timestamp < self.cache_ttl:
                return cached

        api_key = self.api_keys.get("virustotal")
        if not api_key:
            return FeedQueryResult(FeedSource.VIRUSTOTAL, domain, "domain", False,
                                  error="No API key")

        session = self._get_session()
        if not session:
            return FeedQueryResult(FeedSource.VIRUSTOTAL, domain, "domain", False,
                                  error="requests not available")

        try:
            headers = {"x-apikey": api_key}
            response = session.get(
                f"https://www.virustotal.com/api/v3/domains/{domain}",
                headers=headers
            )
            if response.status_code == 200:
                data = response.json()
                indicators = self._parse_virustotal_response(data, domain, "domain")
                result = FeedQueryResult(FeedSource.VIRUSTOTAL, domain, "domain", True, indicators)
            elif response.status_code == 404:
                result = FeedQueryResult(FeedSource.VIRUSTOTAL, domain, "domain", False)
            else:
                result = FeedQueryResult(FeedSource.VIRUSTOTAL, domain, "domain", False,
                                        error=f"HTTP {response.status_code}")
        except Exception as e:
            result = FeedQueryResult(FeedSource.VIRUSTOTAL, domain, "domain", False,
                                    error=str(e))

        self.cache[cache_key] = result
        return result

    def _check_virustotal_ip(self, ip: str) -> FeedQueryResult:
        cache_key = f"vt:ip:{ip}"
        if cache_key in self.cache:
            cached = self.cache[cache_key]
            if time.time() - cached.timestamp < self.cache_ttl:
                return cached

        api_key = self.api_keys.get("virustotal")
        if not api_key:
            return FeedQueryResult(FeedSource.VIRUSTOTAL, ip, "ip", False, error="No API key")

        session = self._get_session()
        if not session:
            return FeedQueryResult(FeedSource.VIRUSTOTAL, ip, "ip", False,
                                  error="requests not available")

        try:
            headers = {"x-apikey": api_key}
            response = session.get(
                f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                headers=headers
            )
            if response.status_code == 200:
                data = response.json()
                indicators = self._parse_virustotal_response(data, ip, "ip")
                result = FeedQueryResult(FeedSource.VIRUSTOTAL, ip, "ip", True, indicators)
            elif response.status_code == 404:
                result = FeedQueryResult(FeedSource.VIRUSTOTAL, ip, "ip", False)
            else:
                result = FeedQueryResult(FeedSource.VIRUSTOTAL, ip, "ip", False,
                                        error=f"HTTP {response.status_code}")
        except Exception as e:
            result = FeedQueryResult(FeedSource.VIRUSTOTAL, ip, "ip", False, error=str(e))

        self.cache[cache_key] = result
        return result

    def _check_virustotal_url(self, url: str) -> FeedQueryResult:
        cache_key = f"vt:url:{hashlib.sha256(url.encode()).hexdigest()[:16]}"
        if cache_key in self.cache:
            cached = self.cache[cache_key]
            if time.time() - cached.timestamp < self.cache_ttl:
                return cached

        api_key = self.api_keys.get("virustotal")
        if not api_key:
            return FeedQueryResult(FeedSource.VIRUSTOTAL, url, "url", False, error="No API key")

        session = self._get_session()
        if not session:
            return FeedQueryResult(FeedSource.VIRUSTOTAL, url, "url", False,
                                  error="requests not available")

        try:
            headers = {"x-apikey": api_key}
            url_id = hashlib.sha256(url.encode()).hexdigest()
            response = session.get(
                f"https://www.virustotal.com/api/v3/urls/{url_id}",
                headers=headers
            )
            if response.status_code == 200:
                data = response.json()
                indicators = self._parse_virustotal_response(data, url, "url")
                result = FeedQueryResult(FeedSource.VIRUSTOTAL, url, "url", True, indicators)
            elif response.status_code == 404:
                result = FeedQueryResult(FeedSource.VIRUSTOTAL, url, "url", False)
            else:
                result = FeedQueryResult(FeedSource.VIRUSTOTAL, url, "url", False,
                                        error=f"HTTP {response.status_code}")
        except Exception as e:
            result = FeedQueryResult(FeedSource.VIRUSTOTAL, url, "url", False, error=str(e))

        self.cache[cache_key] = result
        return result

    def _parse_virustotal_response(self, data: Dict, query: str, query_type: str) -> List[FeedIndicator]:
        indicators = []
        try:
            attrs = data.get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            total = sum(stats.values())

            confidence = (malicious + suspicious) / total if total > 0 else 0
            severity = "critical" if malicious > 5 else "high" if malicious > 0 else "medium" if suspicious > 0 else "low"

            families = []
            for engine, result in attrs.get("last_analysis_results", {}).items():
                if result.get("category") == "malicious" and result.get("result"):
                    families.append(result["result"])

            indicator = FeedIndicator(
                id=hashlib.sha256(f"vt:{query}".encode()).hexdigest()[:16],
                source=FeedSource.VIRUSTOTAL,
                indicator_type=query_type,
                value=query,
                confidence=confidence,
                severity=severity,
                tags=["virustotal"],
                malware_families=list(set(families))[:10],
                context={
                    "malicious_count": malicious,
                    "suspicious_count": suspicious,
                    "total_engines": total,
                    "reputation": attrs.get("reputation", 0),
                    "first_submission": attrs.get("first_submission_date"),
                    "last_analysis": attrs.get("last_analysis_date"),
                },
                raw_data=data,
            )
            indicators.append(indicator)
        except Exception as e:
            logger.error("vt_parse_error", error=str(e))
        return indicators

    # URLhaus API (no auth required)
    def _check_urlhaus_hash(self, file_hash: str) -> FeedQueryResult:
        cache_key = f"urlhaus:hash:{file_hash}"
        if cache_key in self.cache:
            cached = self.cache[cache_key]
            if time.time() - cached.timestamp < self.cache_ttl:
                return cached

        session = self._get_session()
        if not session:
            return FeedQueryResult(FeedSource.URLHAUS, file_hash, "hash", False,
                                  error="requests not available")

        try:
            response = session.post(
                "https://urlhaus-api.abuse.ch/v1/payload/",
                data={"sha256_hash": file_hash}
            )
            if response.status_code == 200:
                data = response.json()
                if data.get("query_status") == "ok":
                    indicators = self._parse_urlhaus_payload(data, file_hash)
                    result = FeedQueryResult(FeedSource.URLHAUS, file_hash, "hash", True, indicators)
                else:
                    result = FeedQueryResult(FeedSource.URLHAUS, file_hash, "hash", False)
            else:
                result = FeedQueryResult(FeedSource.URLHAUS, file_hash, "hash", False,
                                        error=f"HTTP {response.status_code}")
        except Exception as e:
            result = FeedQueryResult(FeedSource.URLHAUS, file_hash, "hash", False, error=str(e))

        self.cache[cache_key] = result
        return result

    def _check_urlhaus_domain(self, domain: str) -> FeedQueryResult:
        cache_key = f"urlhaus:domain:{domain}"
        if cache_key in self.cache:
            cached = self.cache[cache_key]
            if time.time() - cached.timestamp < self.cache_ttl:
                return cached

        session = self._get_session()
        if not session:
            return FeedQueryResult(FeedSource.URLHAUS, domain, "domain", False,
                                  error="requests not available")

        try:
            response = session.post(
                "https://urlhaus-api.abuse.ch/v1/host/",
                data={"host": domain}
            )
            if response.status_code == 200:
                data = response.json()
                if data.get("query_status") == "ok":
                    indicators = self._parse_urlhaus_host(data, domain)
                    result = FeedQueryResult(FeedSource.URLHAUS, domain, "domain", True, indicators)
                else:
                    result = FeedQueryResult(FeedSource.URLHAUS, domain, "domain", False)
            else:
                result = FeedQueryResult(FeedSource.URLHAUS, domain, "domain", False,
                                        error=f"HTTP {response.status_code}")
        except Exception as e:
            result = FeedQueryResult(FeedSource.URLHAUS, domain, "domain", False, error=str(e))

        self.cache[cache_key] = result
        return result

    def _check_urlhaus_url(self, url: str) -> FeedQueryResult:
        cache_key = f"urlhaus:url:{hashlib.sha256(url.encode()).hexdigest()[:16]}"
        if cache_key in self.cache:
            cached = self.cache[cache_key]
            if time.time() - cached.timestamp < self.cache_ttl:
                return cached

        session = self._get_session()
        if not session:
            return FeedQueryResult(FeedSource.URLHAUS, url, "url", False,
                                  error="requests not available")

        try:
            response = session.post(
                "https://urlhaus-api.abuse.ch/v1/url/",
                data={"url": url}
            )
            if response.status_code == 200:
                data = response.json()
                if data.get("query_status") == "ok":
                    indicators = self._parse_urlhaus_url(data, url)
                    result = FeedQueryResult(FeedSource.URLHAUS, url, "url", True, indicators)
                else:
                    result = FeedQueryResult(FeedSource.URLHAUS, url, "url", False)
            else:
                result = FeedQueryResult(FeedSource.URLHAUS, url, "url", False,
                                        error=f"HTTP {response.status_code}")
        except Exception as e:
            result = FeedQueryResult(FeedSource.URLHAUS, url, "url", False, error=str(e))

        self.cache[cache_key] = result
        return result

    def _check_urlhaus_ip(self, ip: str) -> FeedQueryResult:
        # URLhaus doesn't have direct IP lookup, use host lookup
        return FeedQueryResult(FeedSource.URLHAUS, ip, "ip", False,
                              error="IP lookup not supported")

    def _parse_urlhaus_payload(self, data: Dict, query: str) -> List[FeedIndicator]:
        indicators = []
        try:
            payloads = data.get("payloads", [])
            for p in payloads:
                sigs = p.get("signatures", [])
                indicator = FeedIndicator(
                    id=hashlib.sha256(f"urlhaus:payload:{p.get('sha256', '')}".encode()).hexdigest()[:16],
                    source=FeedSource.URLHAUS,
                    indicator_type="hash",
                    value=p.get("sha256", query),
                    confidence=0.9,
                    severity="critical" if sigs else "high",
                    tags=["urlhaus", "malware"],
                    malware_families=sigs,
                    context={
                        "file_type": p.get("file_type"),
                        "file_size": p.get("file_size"),
                        "first_seen": p.get("first_seen"),
                        "last_seen": p.get("last_seen"),
                    },
                    raw_data=p,
                )
                indicators.append(indicator)
        except Exception as e:
            logger.error("urlhaus_parse_error", error=str(e))
        return indicators

    def _parse_urlhaus_host(self, data: Dict, query: str) -> List[FeedIndicator]:
        indicators = []
        try:
            urls = data.get("urls", [])
            for u in urls:
                indicator = FeedIndicator(
                    id=hashlib.sha256(f"urlhaus:url:{u.get('url', '')}".encode()).hexdigest()[:16],
                    source=FeedSource.URLHAUS,
                    indicator_type="url",
                    value=u.get("url", ""),
                    confidence=0.85,
                    severity="high",
                    tags=["urlhaus", "c2"],
                    malware_families=u.get("threat", "").split(",") if u.get("threat") else [],
                    context={
                        "host": u.get("host"),
                        "status": u.get("url_status"),
                        "date_added": u.get("date_added"),
                        "threat": u.get("threat"),
                    },
                    raw_data=u,
                )
                indicators.append(indicator)
        except Exception as e:
            logger.error("urlhaus_host_parse_error", error=str(e))
        return indicators

    def _parse_urlhaus_url(self, data: Dict, query: str) -> List[FeedIndicator]:
        indicators = []
        try:
            u = data
            indicator = FeedIndicator(
                id=hashlib.sha256(f"urlhaus:url:{query}".encode()).hexdigest()[:16],
                source=FeedSource.URLHAUS,
                indicator_type="url",
                value=query,
                confidence=0.9,
                severity="critical",
                tags=["urlhaus", "malware_url"],
                malware_families=u.get("threat", "").split(",") if u.get("threat") else [],
                context={
                    "host": u.get("host"),
                    "payload_sha256": u.get("payload_sha256"),
                    "url_status": u.get("url_status"),
                },
                raw_data=u,
            )
            indicators.append(indicator)
        except Exception as e:
            logger.error("urlhaus_url_parse_error", error=str(e))
        return indicators

    # Abuse.ch (SSL Blacklist, URLhaus, etc.)
    def _check_abuse_ch_hash(self, file_hash: str) -> FeedQueryResult:
        # Use MalwareBazaar API
        cache_key = f"abuse_ch:hash:{file_hash}"
        if cache_key in self.cache:
            cached = self.cache[cache_key]
            if time.time() - cached.timestamp < self.cache_ttl:
                return cached

        session = self._get_session()
        if not session:
            return FeedQueryResult(FeedSource.ABUSE_CH, file_hash, "hash", False,
                                  error="requests not available")

        try:
            response = session.post(
                "https://mb-api.abuse.ch/api/v1/",
                data={"query": "get_info", "hash": file_hash}
            )
            if response.status_code == 200:
                data = response.json()
                if data.get("query_status") == "ok":
                    indicators = self._parse_malwarebazaar(data, file_hash)
                    result = FeedQueryResult(FeedSource.ABUSE_CH, file_hash, "hash", True, indicators)
                else:
                    result = FeedQueryResult(FeedSource.ABUSE_CH, file_hash, "hash", False)
            else:
                result = FeedQueryResult(FeedSource.ABUSE_CH, file_hash, "hash", False,
                                        error=f"HTTP {response.status_code}")
        except Exception as e:
            result = FeedQueryResult(FeedSource.ABUSE_CH, file_hash, "hash", False, error=str(e))

        self.cache[cache_key] = result
        return result

    def _check_abuse_ch_domain(self, domain: str) -> FeedQueryResult:
        return FeedQueryResult(FeedSource.ABUSE_CH, domain, "domain", False,
                              error="Domain lookup via URLhaus")

    def _check_abuse_ch_ip(self, ip: str) -> FeedQueryResult:
        return FeedQueryResult(FeedSource.ABUSE_CH, ip, "ip", False,
                              error="IP lookup not directly supported")

    def _check_abuse_ch_url(self, url: str) -> FeedQueryResult:
        return self._check_urlhaus_url(url)  # URLhaus is part of abuse.ch

    def _parse_malwarebazaar(self, data: Dict, query: str) -> List[FeedIndicator]:
        indicators = []
        try:
            for item in data.get("data", []):
                indicator = FeedIndicator(
                    id=hashlib.sha256(f"mb:{item.get('sha256_hash', '')}".encode()).hexdigest()[:16],
                    source=FeedSource.ABUSE_CH,
                    indicator_type="hash",
                    value=item.get("sha256_hash", query),
                    confidence=0.9,
                    severity="critical",
                    tags=["malwarebazaar", item.get("file_type", "").lower()],
                    malware_families=[item.get("signature", "")] if item.get("signature") else [],
                    context={
                        "file_type": item.get("file_type"),
                        "file_size": item.get("file_size"),
                        "first_seen": item.get("first_seen"),
                        "reporter": item.get("reporter"),
                        "tags": item.get("tags", []),
                    },
                    raw_data=item,
                )
                indicators.append(indicator)
        except Exception as e:
            logger.error("malwarebazaar_parse_error", error=str(e))
        return indicators

    # AlienVault OTX
    def _check_otx_hash(self, file_hash: str) -> FeedQueryResult:
        api_key = self.api_keys.get("alienvault_otx")
        if not api_key:
            return FeedQueryResult(FeedSource.ALIENVAULT_OTX, file_hash, "hash", False,
                                  error="No API key")
        # Implementation would go here
        return FeedQueryResult(FeedSource.ALIENVAULT_OTX, file_hash, "hash", False,
                              error="Not implemented")

    def _check_otx_domain(self, domain: str) -> FeedQueryResult:
        return FeedQueryResult(FeedSource.ALIENVAULT_OTX, domain, "domain", False,
                              error="Not implemented")

    def _check_otx_ip(self, ip: str) -> FeedQueryResult:
        return FeedQueryResult(FeedSource.ALIENVAULT_OTX, ip, "ip", False,
                              error="Not implemented")

    def _check_otx_url(self, url: str) -> FeedQueryResult:
        return FeedQueryResult(FeedSource.ALIENVAULT_OTX, url, "url", False,
                              error="Not implemented")

    # ThreatFox
    def _check_threatfox_hash(self, file_hash: str) -> FeedQueryResult:
        cache_key = f"threatfox:hash:{file_hash}"
        if cache_key in self.cache:
            cached = self.cache[cache_key]
            if time.time() - cached.timestamp < self.cache_ttl:
                return cached

        session = self._get_session()
        if not session:
            return FeedQueryResult(FeedSource.THREATFOX, file_hash, "hash", False,
                                  error="requests not available")

        try:
            response = session.post(
                "https://threatfox-api.abuse.ch/api/v1/",
                json={"query": "search_ioc", "search_term": file_hash}
            )
            if response.status_code == 200:
                data = response.json()
                if data.get("query_status") == "ok":
                    indicators = self._parse_threatfox(data, file_hash, "hash")
                    result = FeedQueryResult(FeedSource.THREATFOX, file_hash, "hash", True, indicators)
                else:
                    result = FeedQueryResult(FeedSource.THREATFOX, file_hash, "hash", False)
            else:
                result = FeedQueryResult(FeedSource.THREATFOX, file_hash, "hash", False,
                                        error=f"HTTP {response.status_code}")
        except Exception as e:
            result = FeedQueryResult(FeedSource.THREATFOX, file_hash, "hash", False, error=str(e))

        self.cache[cache_key] = result
        return result

    def _check_threatfox_domain(self, domain: str) -> FeedQueryResult:
        session = self._get_session()
        if not session:
            return FeedQueryResult(FeedSource.THREATFOX, domain, "domain", False,
                                  error="requests not available")

        try:
            response = session.post(
                "https://threatfox-api.abuse.ch/api/v1/",
                json={"query": "search_ioc", "search_term": domain}
            )
            if response.status_code == 200:
                data = response.json()
                if data.get("query_status") == "ok":
                    indicators = self._parse_threatfox(data, domain, "domain")
                    return FeedQueryResult(FeedSource.THREATFOX, domain, "domain", True, indicators)
        except Exception as e:
            pass
        return FeedQueryResult(FeedSource.THREATFOX, domain, "domain", False, error=str(e))

    def _check_threatfox_ip(self, ip: str) -> FeedQueryResult:
        session = self._get_session()
        if not session:
            return FeedQueryResult(FeedSource.THREATFOX, ip, "ip", False,
                                  error="requests not available")

        try:
            response = session.post(
                "https://threatfox-api.abuse.ch/api/v1/",
                json={"query": "search_ioc", "search_term": ip}
            )
            if response.status_code == 200:
                data = response.json()
                if data.get("query_status") == "ok":
                    indicators = self._parse_threatfox(data, ip, "ip")
                    return FeedQueryResult(FeedSource.THREATFOX, ip, "ip", True, indicators)
        except Exception as e:
            pass
        return FeedQueryResult(FeedSource.THREATFOX, ip, "ip", False, error=str(e))

    def _parse_threatfox(self, data: Dict, query: str, query_type: str) -> List[FeedIndicator]:
        indicators = []
        try:
            for item in data.get("data", []):
                ioc_type = item.get("ioc_type", "")
                indicator = FeedIndicator(
                    id=hashlib.sha256(f"tf:{item.get('ioc', '')}".encode()).hexdigest()[:16],
                    source=FeedSource.THREATFOX,
                    indicator_type=ioc_type,
                    value=item.get("ioc", query),
                    confidence=0.85,
                    severity="high",
                    tags=["threatfox", item.get("malware", "").lower()],
                    malware_families=[item.get("malware", "")] if item.get("malware") else [],
                    context={
                        "confidence": item.get("confidence_level"),
                        "first_seen": item.get("first_seen"),
                        "last_seen": item.get("last_seen"),
                        "reporter": item.get("reporter"),
                    },
                    raw_data=item,
                )
                indicators.append(indicator)
        except Exception as e:
            logger.error("threatfox_parse_error", error=str(e))
        return indicators

    def bulk_check(self, indicators: List[Dict]) -> Dict[str, List[FeedQueryResult]]:
        """Check multiple indicators in bulk."""
        results = defaultdict(list)
        for ind in indicators:
            value = ind.get("value", "")
            itype = ind.get("type", "")
            if itype == "hash":
                for r in self.check_hash(value):
                    results[value].append(r)
            elif itype == "domain":
                for r in self.check_domain(value):
                    results[value].append(r)
            elif itype == "ip":
                for r in self.check_ip(value):
                    results[value].append(r)
            elif itype == "url":
                for r in self.check_url(value):
                    results[value].append(r)
        return dict(results)

    def get_feed_status(self) -> Dict:
        """Get status of all configured feeds."""
        status = {}
        for source_name in self.enabled_sources:
            source = FeedSource(source_name)
            has_key = source.value in self.api_keys
            status[source.value] = {
                "enabled": True,
                "has_api_key": has_key,
                "requires_key": source in [FeedSource.VIRUSTOTAL, FeedSource.ALIENVAULT_OTX],
            }
        return status

    def clear_cache(self):
        """Clear query cache."""
        self.cache.clear()


_feed_integrations_instance = None


def get_feed_integrations(config: Dict = None) -> FeedIntegrations:
    """Get singleton feed integrations instance."""
    global _feed_integrations_instance
    if _feed_integrations_instance is None:
        _feed_integrations_instance = FeedIntegrations(config)
    return _feed_integrations_instance