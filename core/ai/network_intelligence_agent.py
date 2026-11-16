"""
Network Intelligence Agent - Agent 5
Extracts URLs, domains, IPs, identifies C2 infrastructure,
investigates DNS, analyzes HTTP/TLS metadata, correlates network indicators with code.
"""
from pathlib import Path
from typing import Dict, List, Any, Optional
from .agent_base import BaseAgent, AgentTask, AgentResult
from .evidence_repository import Evidence, Severity, AgentID
from ..config_manager import get_config
from ..logging_setup import get_module_logger

logger = get_module_logger("network_intelligence_agent")


class NetworkIntelligenceAgent(BaseAgent):
    """Agent 5: Network Intelligence - IOCs, C2, DNS, TLS, code correlation."""

    def __init__(self, config: Dict = None, evidence_repo = None,
                 ollama_client = None, rag_engine = None):
        super().__init__(AgentID.NETWORK_INTELLIGENCE, config, evidence_repo, ollama_client, rag_engine)

    def investigate(self, task: AgentTask) -> AgentResult:
        """Perform network intelligence analysis."""
        network_analysis = task.input_data.get("network_analysis", {})
        string_analysis = task.input_data.get("string_analysis", {})
        dex_analysis = task.input_data.get("dex_analysis", {})
        advanced_static = task.input_data.get("advanced_static", {})

        evidence_ids = []
        findings = {
            "urls": [],
            "domains": [],
            "ips": [],
            "certificates": [],
            "c2_infrastructure": [],
            "dns_analysis": [],
            "tls_analysis": [],
            "http_analysis": [],
            "code_correlation": [],
            "threat_intel": [],
        }

        # 1. URL Analysis
        urls = self._analyze_urls(network_analysis, string_analysis, dex_analysis)
        findings["urls"] = urls
        evidence_ids.extend(self._create_url_evidence(urls).values())

        # 2. Domain Analysis
        domains = self._analyze_domains(network_analysis, string_analysis, dex_analysis)
        findings["domains"] = domains
        evidence_ids.extend(self._create_domain_evidence(domains).values())

        # 3. IP Analysis
        ips = self._analyze_ips(network_analysis, string_analysis)
        findings["ips"] = ips
        evidence_ids.extend(self._create_ip_evidence(ips).values())

        # 4. Certificate Analysis
        certs = self._analyze_certificates(network_analysis, dex_analysis)
        findings["certificates"] = certs
        evidence_ids.extend(self._create_cert_evidence(certs).values())

        # 5. C2 Infrastructure
        c2 = self._analyze_c2_infrastructure(network_analysis, string_analysis, dex_analysis)
        findings["c2_infrastructure"] = c2
        evidence_ids.extend(self._create_c2_evidence(c2).values())

        # 6. DNS Analysis
        dns = self._analyze_dns(network_analysis, dex_analysis)
        findings["dns_analysis"] = dns
        evidence_ids.extend(self._create_dns_evidence(dns).values())

        # 7. TLS Analysis
        tls = self._analyze_tls(network_analysis, dex_analysis)
        findings["tls_analysis"] = tls
        evidence_ids.extend(self._create_tls_evidence(tls).values())

        # 8. HTTP Analysis
        http = self._analyze_http(network_analysis, dex_analysis)
        findings["http_analysis"] = http
        evidence_ids.extend(self._create_http_evidence(http).values())

        # 9. Code Correlation
        correlation = self._correlate_with_code(network_analysis, dex_analysis, advanced_static)
        findings["code_correlation"] = correlation
        evidence_ids.extend(self._create_correlation_evidence(correlation).values())

        return AgentResult(
            task_id=task.task_id,
            agent_id=self.agent_id,
            success=True,
            evidence_ids=evidence_ids,
            findings=findings,
        )

    def _analyze_urls(self, network: Dict, strings: Dict, dex: Dict) -> List[Dict]:
        """Analyze URLs found in APK."""
        urls = network.get("urls", [])
        analyzed = []

        for url in urls:
            url_str = url.get("url", "") if isinstance(url, dict) else url
            if not url_str:
                continue

            analysis = {
                "url": url_str,
                "source": url.get("source_string", "") if isinstance(url, dict) else "",
                "scheme": self._extract_scheme(url_str),
                "host": self._extract_host(url_str),
                "path": self._extract_path(url_str),
                "is_ip": self._is_ip_host(url_str),
                "suspicious": False,
                "suspicious_reasons": [],
            }

            # Check for suspicious patterns
            if analysis["is_ip"]:
                analysis["suspicious"] = True
                analysis["suspicious_reasons"].append("IP address instead of domain")

            if any(tld in url_str for tld in [".onion", ".top", ".xyz", ".cc", ".tk", ".ml", ".ga", ".cf"]):
                analysis["suspicious"] = True
                analysis["suspicious_reasons"].append("Suspicious TLD")

            if "pastebin" in url_str or "hastebin" in url_str or "github.com" in url_str:
                analysis["suspicious_reasons"].append("Code hosting site (possible payload staging)")

            if any(keyword in url_str.lower() for keyword in ["config", "command", "control", "c2", "cnc", "bot", "update"]):
                analysis["suspicious"] = True
                analysis["suspicious_reasons"].append("C2-related keyword in URL")

            # Find code references
            code_refs = self._find_code_references(url_str, dex)
            analysis["code_references"] = code_refs

            analyzed.append(analysis)

        return analyzed

    def _analyze_domains(self, network: Dict, strings: Dict, dex: Dict) -> List[Dict]:
        """Analyze domains found in APK."""
        domains = network.get("domains", [])
        analyzed = []

        for domain in domains:
            domain_str = domain.get("domain", "") if isinstance(domain, dict) else domain
            if not domain_str:
                continue

            analysis = {
                "domain": domain_str,
                "source": domain.get("source_string", "") if isinstance(domain, dict) else "",
                "is_dga": self._looks_like_dga(domain_str),
                "is_dynamic_dns": self._is_dynamic_dns(domain_str),
                "tld": self._extract_tld(domain_str),
                "subdomain_count": domain_str.count("."),
                "suspicious": False,
                "suspicious_reasons": [],
            }

            if analysis["is_dga"]:
                analysis["suspicious"] = True
                analysis["suspicious_reasons"].append("Possible DGA domain")

            if analysis["is_dynamic_dns"]:
                analysis["suspicious"] = True
                analysis["suspicious_reasons"].append("Dynamic DNS provider")

            if analysis["subdomain_count"] > 3:
                analysis["suspicious_reasons"].append("Many subdomains")

            # Find code references
            code_refs = self._find_code_references(domain_str, dex)
            analysis["code_references"] = code_refs

            analyzed.append(analysis)

        return analyzed

    def _analyze_ips(self, network: Dict, strings: Dict) -> List[Dict]:
        """Analyze IP addresses."""
        ips = network.get("ips", [])
        analyzed = []

        for ip in ips:
            ip_str = ip.get("ip", "") if isinstance(ip, dict) else ip
            if not ip_str:
                continue

            analysis = {
                "ip": ip_str,
                "source": ip.get("source_string", "") if isinstance(ip, dict) else "",
                "is_private": self._is_private_ip(ip_str),
                "is_tor_exit": False,  # Would need Tor exit node list
                "suspicious": not self._is_private_ip(ip_str),
                "suspicious_reasons": [],
            }

            if not analysis["is_private"]:
                analysis["suspicious_reasons"].append("Public IP address")

            analyzed.append(analysis)

        return analyzed

    def _analyze_certificates(self, network: Dict, dex: Dict) -> List[Dict]:
        """Analyze SSL/TLS certificates."""
        certs = network.get("certificates", [])
        analyzed = []

        for cert in certs:
            cert_data = cert.get("certificate", "") if isinstance(cert, dict) else cert
            if not cert_data:
                continue

            analysis = {
                "certificate": cert_data[:500] + "..." if len(cert_data) > 500 else cert_data,
                "length": cert.get("length", 0) if isinstance(cert, dict) else len(cert_data),
                "is_self_signed": "self-signed" in cert_data.lower() or "self signed" in cert_data.lower(),
                "pinned": False,
            }

            # Check for pinning
            api_calls = dex.get("api_calls", [])
            for call in api_calls:
                if any(x in call.get("call", "") for x in ["X509TrustManager", "HostnameVerifier", "checkServerTrusted"]):
                    cert_data_lower = cert_data.lower()
                    if "trustmanager" in cert_data_lower or "hostnameverifier" in cert_data_lower:
                        analysis["pinned"] = True
                        break

            analyzed.append(analysis)

        return analyzed

    def _analyze_c2_infrastructure(self, network: Dict, strings: Dict, dex: Dict) -> List[Dict]:
        """Identify potential C2 infrastructure."""
        c2_indicators = []

        # From network analysis
        c2_config = network.get("c2_config", [])
        for c2 in c2_config:
            c2_indicators.append({
                "type": "c2_config",
                "config": c2,
                "confidence": 80,
                "description": "Explicit C2 configuration found",
            })

        # From URLs
        for url in network.get("urls", []):
            url_str = url.get("url", "") if isinstance(url, dict) else url
            if self._is_c2_url(url_str):
                c2_indicators.append({
                    "type": "c2_url",
                    "url": url_str,
                    "confidence": 70,
                    "description": f"C2-like URL pattern: {url_str}",
                })

        # From domains
        for domain in network.get("domains", []):
            domain_str = domain.get("domain", "") if isinstance(domain, dict) else domain
            if self._is_c2_domain(domain_str):
                c2_indicators.append({
                    "type": "c2_domain",
                    "domain": domain_str,
                    "confidence": 60,
                    "description": f"C2-like domain pattern: {domain_str}",
                })

        # Telegram bots
        telegram = network.get("telegram_bots", [])
        for bot in telegram:
            match = bot.get("match", "") if isinstance(bot, dict) else bot
            c2_indicators.append({
                "type": "telegram_c2",
                "bot_token": match,
                "confidence": 90,
                "description": f"Telegram bot token (C2 channel): {match[:20]}...",
            })

        # Firebase C2
        firebase = network.get("firebase", [])
        for fb in firebase:
            c2_indicators.append({
                "type": "firebase_c2",
                "pattern": fb.get("pattern", ""),
                "source": fb.get("source_string", ""),
                "confidence": 75,
                "description": "Firebase configuration (possible C2)",
            })

        return c2_indicators

    def _is_c2_url(self, url: str) -> bool:
        """Check if URL looks like C2."""
        c2_patterns = [
            "/api/", "/v1/", "/v2/", "/command", "/control", "/config",
            "/update", "/checkin", "/beacon", "/heartbeat", "/task",
            "/download", "/upload", "/exec", "/shell", "/cmd",
        ]
        return any(p in url for p in c2_patterns)

    def _is_c2_domain(self, domain: str) -> bool:
        """Check if domain looks like C2."""
        c2_keywords = ["c2", "cnc", "command", "control", "bot", "rat", "trojan", "panel", "admin"]
        return any(kw in domain.lower() for kw in c2_keywords)

    def _analyze_dns(self, network: Dict, dex: Dict) -> List[Dict]:
        """Analyze DNS-related indicators."""
        findings = []

        # Dynamic DNS providers
        dynamic_dns = [
            "noip.com", "dyndns.org", "ddns.net", "hopto.org", "serveo.net",
            "ngrok.io", "localtunnel.me", "pagekite.me", "serveo.net",
        ]

        for domain in network.get("domains", []):
            domain_str = domain.get("domain", "") if isinstance(domain, dict) else domain
            for ddns in dynamic_dns:
                if ddns in domain_str:
                    findings.append({
                        "type": "dynamic_dns",
                        "domain": domain_str,
                        "provider": ddns,
                        "description": f"Dynamic DNS: {domain_str} ({ddns})",
                        "severity": "high",
                    })

        # DNS over HTTPS/TLS
        api_calls = dex.get("api_calls", [])
        for call in api_calls:
            if "DnsOverHttps" in call.get("call", "") or "DNS-over-HTTPS" in call.get("call", ""):
                findings.append({
                    "type": "doh",
                    "class": call.get("class"),
                    "method": call.get("method"),
                    "description": "DNS over HTTPS usage",
                    "severity": "medium",
                })

        return findings

    def _analyze_tls(self, network: Dict, dex: Dict) -> List[Dict]:
        """Analyze TLS/SSL configuration."""
        findings = []

        # Certificate pinning
        api_calls = dex.get("api_calls", [])
        for call in api_calls:
            call_str = call.get("call", "")
            if any(x in call_str for x in ["CertificatePinner", "pinCertificate", "CertificateTransparency"]):
                findings.append({
                    "type": "certificate_pinning",
                    "class": call.get("class"),
                    "method": call.get("method"),
                    "call": call_str,
                    "description": "Certificate pinning implementation",
                    "severity": "info",
                })

            # Weak TLS
            if any(x in call_str for x in ["TLSv1", "SSLv3", "SSLContext.getInstance", "TrustManager"]):
                if "TLSv1.2" not in call_str and "TLSv1.3" not in call_str:
                    findings.append({
                        "type": "weak_tls",
                        "class": call.get("class"),
                        "method": call.get("method"),
                        "call": call_str,
                        "description": "Potentially weak TLS configuration",
                        "severity": "medium",
                    })

        return findings

    def _analyze_http(self, network: Dict, dex: Dict) -> List[Dict]:
        """Analyze HTTP-specific indicators."""
        findings = []

        api_calls = dex.get("api_calls", [])
        for call in api_calls:
            call_str = call.get("call", "")

            # HTTP client libraries
            if any(x in call_str for x in ["OkHttpClient", "Retrofit", "Volley", "HttpURLConnection"]):
                findings.append({
                    "type": "http_client",
                    "library": self._identify_http_lib(call_str),
                    "class": call.get("class"),
                    "method": call.get("method"),
                    "description": f"HTTP client: {self._identify_http_lib(call_str)}",
                    "severity": "info",
                })

            # Suspicious headers
            if any(x in call_str for x in ["setRequestProperty", "addHeader", "User-Agent"]):
                findings.append({
                    "type": "custom_headers",
                    "class": call.get("class"),
                    "method": call.get("method"),
                    "call": call_str,
                    "description": "Custom HTTP headers (possible fingerprinting evasion)",
                    "severity": "medium",
                })

        return findings

    def _identify_http_lib(self, call: str) -> str:
        """Identify HTTP library from call."""
        if "OkHttpClient" in call:
            return "OkHttp"
        elif "Retrofit" in call:
            return "Retrofit"
        elif "Volley" in call:
            return "Volley"
        elif "HttpURLConnection" in call:
            return "HttpURLConnection"
        return "Unknown"

    def _correlate_with_code(self, network: Dict, dex: Dict, advanced: Dict) -> List[Dict]:
        """Correlate network indicators with code."""
        correlations = []

        # For each network IOC, find the code that uses it
        for url in network.get("urls", []):
            url_str = url.get("url", "") if isinstance(url, dict) else url
            code_refs = self._find_code_references(url_str, dex)
            if code_refs:
                correlations.append({
                    "ioc_type": "url",
                    "ioc": url_str,
                    "code_references": code_refs,
                    "description": f"URL {url_str} referenced in {len(code_refs)} methods",
                })

        for domain in network.get("domains", []):
            domain_str = domain.get("domain", "") if isinstance(domain, dict) else domain
            code_refs = self._find_code_references(domain_str, dex)
            if code_refs:
                correlations.append({
                    "ioc_type": "domain",
                    "ioc": domain_str,
                    "code_references": code_refs,
                    "description": f"Domain {domain_str} referenced in {len(code_refs)} methods",
                })

        # Correlate with taint analysis
        taint = advanced.get("taint", {})
        for path in taint.get("summary", []):
            for sink_type in path.get("sink_types", []):
                if sink_type == "network_send":
                    correlations.append({
                        "ioc_type": "taint_network",
                        "source": path.get("source"),
                        "sink": path.get("sink"),
                        "description": f"Data flows from {path.get('source')} to network sink {path.get('sink')}",
                    })

        return correlations

    def _find_code_references(self, ioc: str, dex: Dict) -> List[Dict]:
        """Find code references to an IOC."""
        refs = []
        api_calls = dex.get("api_calls", [])

        for call in api_calls:
            if ioc in call.get("call", "") or ioc in call.get("class", "") or ioc in call.get("method", ""):
                refs.append({
                    "class": call.get("class"),
                    "method": call.get("method"),
                    "call": call.get("call"),
                })

        # Also check strings
        strings = dex.get("strings", [])
        for s in strings[:100]:  # Limit
            if ioc in s:
                refs.append({
                    "type": "string_reference",
                    "string": s[:200],
                })

        return refs[:10]  # Limit

    # Helper methods
    def _extract_scheme(self, url: str) -> str:
        if "://" in url:
            return url.split("://")[0]
        return ""

    def _extract_host(self, url: str) -> str:
        if "://" in url:
            url = url.split("://")[1]
        return url.split("/")[0].split(":")[0]

    def _extract_path(self, url: str) -> str:
        if "://" in url:
            url = url.split("://")[1]
        parts = url.split("/", 1)
        return "/" + parts[1] if len(parts) > 1 else "/"

    def _is_ip_host(self, url: str) -> bool:
        host = self._extract_host(url)
        parts = host.split(".")
        return len(parts) == 4 and all(p.isdigit() for p in parts)

    def _extract_tld(self, domain: str) -> str:
        parts = domain.split(".")
        return "." + parts[-1] if parts else ""

    def _looks_like_dga(self, domain: str) -> bool:
        parts = domain.split(".")
        if len(parts) < 2:
            return False
        subdomain = parts[0]
        if len(subdomain) > 15:
            import math
            freq = {}
            for c in subdomain:
                freq[c] = freq.get(c, 0) + 1
            entropy = -sum((v/len(subdomain)) * math.log2(v/len(subdomain)) for v in freq.values())
            return entropy > 3.5
        return False

    def _is_dynamic_dns(self, domain: str) -> bool:
        dynamic_dns = ["noip.com", "dyndns.org", "ddns.net", "hopto.org", "serveo.net", "ngrok.io"]
        return any(ddns in domain for ddns in dynamic_dns)

    def _is_private_ip(self, ip: str) -> bool:
        parts = ip.split(".")
        if len(parts) != 4:
            return False
        try:
            p = [int(x) for x in parts]
            # Private ranges
            if p[0] == 10:
                return True
            if p[0] == 172 and 16 <= p[1] <= 31:
                return True
            if p[0] == 192 and p[1] == 168:
                return True
            if p[0] == 127:
                return True
            return False
        except ValueError:
            return False

    def _create_url_evidence(self, urls: List[Dict]) -> Dict[str, str]:
        evidence = {}
        for i, u in enumerate(urls[:20]):
            severity = "high" if u.get("suspicious") else "medium"
            ev = self.create_evidence(
                analysis_module="network_url",
                file_path=u.get("host", "unknown"),
                description=f"URL: {u['url']} ({', '.join(u.get('suspicious_reasons', ['normal']))})",
                raw_data=u,
                confidence=80,
                severity=severity,
                tags=["url", "suspicious" if u.get("suspicious") else "normal"],
            )
            evidence[f"url_{i}"] = ev.evidence_id
        return evidence

    def _create_domain_evidence(self, domains: List[Dict]) -> Dict[str, str]:
        evidence = {}
        for i, d in enumerate(domains[:20]):
            severity = "high" if d.get("suspicious") else "medium"
            ev = self.create_evidence(
                analysis_module="network_domain",
                file_path=d.get("domain", "unknown"),
                description=f"Domain: {d['domain']} ({', '.join(d.get('suspicious_reasons', ['normal']))})",
                raw_data=d,
                confidence=80,
                severity=severity,
                tags=["domain", "dga" if d.get("is_dga") else "normal", "dynamic_dns" if d.get("is_dynamic_dns") else "static"],
            )
            evidence[f"domain_{i}"] = ev.evidence_id
        return evidence

    def _create_ip_evidence(self, ips: List[Dict]) -> Dict[str, str]:
        evidence = {}
        for i, ip in enumerate(ips[:10]):
            severity = "high" if ip.get("suspicious") else "info"
            ev = self.create_evidence(
                analysis_module="network_ip",
                file_path=ip.get("ip", "unknown"),
                description=f"IP: {ip['ip']} ({'public' if ip.get('suspicious') else 'private'})",
                raw_data=ip,
                confidence=85,
                severity=severity,
                tags=["ip", "public" if ip.get("suspicious") else "private"],
            )
            evidence[f"ip_{i}"] = ev.evidence_id
        return evidence

    def _create_cert_evidence(self, certs: List[Dict]) -> Dict[str, str]:
        evidence = {}
        for i, c in enumerate(certs[:10]):
            ev = self.create_evidence(
                analysis_module="network_certificate",
                file_path="certificate",
                description=f"Certificate: {c['length']} bytes, pinned: {c.get('pinned', False)}",
                raw_data=c,
                confidence=80,
                severity="medium" if c.get("is_self_signed") else "info",
                tags=["certificate", "self_signed" if c.get("is_self_signed") else "ca_signed", "pinned" if c.get("pinned") else "not_pinned"],
            )
            evidence[f"cert_{i}"] = ev.evidence_id
        return evidence

    def _create_c2_evidence(self, c2: List[Dict]) -> Dict[str, str]:
        evidence = {}
        for i, c in enumerate(c2):
            severity = "critical" if c.get("confidence", 0) > 80 else "high"
            ev = self.create_evidence(
                analysis_module="c2_infrastructure",
                file_path=c.get("url", c.get("domain", c.get("bot_token", "unknown"))),
                description=c.get("description", "C2 indicator"),
                raw_data=c,
                confidence=c.get("confidence", 50),
                severity=severity,
                tags=["c2", c.get("type", "unknown")],
            )
            evidence[f"c2_{i}"] = ev.evidence_id
        return evidence

    def _create_dns_evidence(self, dns: List[Dict]) -> Dict[str, str]:
        evidence = {}
        for i, d in enumerate(dns):
            ev = self.create_evidence(
                analysis_module="dns_analysis",
                file_path=d.get("domain", "unknown"),
                description=d.get("description", ""),
                raw_data=d,
                confidence=80,
                severity=d.get("severity", "medium"),
                tags=["dns", d.get("type", "unknown")],
            )
            evidence[f"dns_{i}"] = ev.evidence_id
        return evidence

    def _create_tls_evidence(self, tls: List[Dict]) -> Dict[str, str]:
        evidence = {}
        for i, t in enumerate(tls):
            ev = self.create_evidence(
                analysis_module="tls_analysis",
                file_path=t.get("class", "unknown"),
                method_name=t.get("method"),
                description=t.get("description", ""),
                raw_data=t,
                confidence=75,
                severity=t.get("severity", "medium"),
                tags=["tls", t.get("type", "unknown")],
            )
            evidence[f"tls_{i}"] = ev.evidence_id
        return evidence

    def _create_http_evidence(self, http: List[Dict]) -> Dict[str, str]:
        evidence = {}
        for i, h in enumerate(http):
            ev = self.create_evidence(
                analysis_module="http_analysis",
                file_path=h.get("class", "unknown"),
                method_name=h.get("method"),
                description=h.get("description", ""),
                raw_data=h,
                confidence=75,
                severity=h.get("severity", "medium"),
                tags=["http", h.get("type", "unknown")],
            )
            evidence[f"http_{i}"] = ev.evidence_id
        return evidence

    def _create_correlation_evidence(self, correlations: List[Dict]) -> Dict[str, str]:
        evidence = {}
        for i, c in enumerate(correlations):
            ev = self.create_evidence(
                analysis_module="network_code_correlation",
                file_path="multiple",
                description=c.get("description", ""),
                raw_data=c,
                confidence=85,
                severity="high",
                tags=["correlation", c.get("ioc_type", "unknown")],
            )
            evidence[f"correlation_{i}"] = ev.evidence_id
        return evidence