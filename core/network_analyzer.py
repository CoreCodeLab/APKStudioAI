"""
Network analyzer for APKStudioAI 2.1
Extracts C2 configuration, certificate pinning, WebSocket, proxy settings, and network IOCs
"""
import re
import base64
from pathlib import Path
from typing import Dict, List, Any, Set
from .utils import printable_strings, try_decode_string


class NetworkAnalyzer:
    def __init__(self):
        self.suspicious_tlds = {'.xyz', '.top', '.tk', '.ml', '.ga', '.cf', '.gq', '.onion', '.bit'}
        self.known_c2_patterns = [
            r'c2\.',
            r'command\.',
            r'control\.',
            r'panel\.',
            r'admin\.',
            r'api\.',
            r'gate\.',
            r'server\.',
            r'backend\.',
            r'cc\.',
            r'cnc\.',
            r'bot\.',
            r'implant\.',
            r'beacon\.',
            r'heartbeat\.',
            r'checkin\.',
            r'config\.',
            r'settings\.',
            r'update\.',
            r'download\.',
            r'upload\.',
        ]

    def analyze(self, strings: List[str], manifest_data: Dict,
                java_classes: List[Dict] = None, native_libs: List[Dict] = None,
                decoded_strings: List[Dict] = None) -> Dict[str, Any]:
        """Analyze network-related artifacts."""
        all_text = " ".join(strings)
        if decoded_strings:
            all_text += " " + " ".join(d.get("decoded", "") for d in decoded_strings if d.get("decoded"))

        if java_classes:
            for cls in java_classes:
                all_text += " " + cls.get("name", "")
                for method in cls.get("methods", []):
                    all_text += " " + method.get("name", "")

        if native_libs:
            for lib in native_libs:
                all_text += " " + " ".join(lib.get("interesting_strings", []))

        # Extract URLs
        url_details = self._extract_urls(all_text)
        domains = self._extract_domains(all_text)
        ips = self._extract_ips(all_text)

        # C2 configuration
        c2_config = self._extract_c2_config(all_text, strings)

        # Certificate pinning
        certificate_pinning = self._find_certificate_pinning(all_text, strings)

        # WebSocket
        websocket = self._find_websocket(all_text, strings)

        # Proxy
        proxy_config = self._find_proxy_config(all_text, strings)

        # Network security config
        network_security_config = self._analyze_network_security_config(manifest_data)

        # Firebase
        firebase_config = self._extract_firebase(all_text, strings)

        # Telegram
        telegram_bots = self._extract_telegram(all_text, strings)

        # API endpoints
        api_endpoints = self._extract_api_endpoints(all_text)

        # Suspicious indicators
        suspicious_indicators = self._find_suspicious_indicators(domains, ips, url_details, all_text)

        # Return both detailed and simple formats for backward compatibility
        return {
            "urls": [u["url"] for u in url_details],  # Simple list of URL strings for test compatibility
            "url_details": url_details,  # Detailed info
            "domains": [d["domain"] for d in domains],  # Simple list of domain strings
            "domain_details": domains,
            "ips": [i["ip"] for i in ips],
            "ip_details": ips,
            "c2_config": c2_config,
            "certificate_pinning": certificate_pinning,
            "websocket": websocket,
            "proxy_config": proxy_config,
            "network_security_config": network_security_config,
            "firebase_config": firebase_config,
            "telegram_bots": telegram_bots,
            "api_endpoints": api_endpoints,
            "suspicious_indicators": suspicious_indicators
        }

    def _extract_urls(self, text: str) -> List[Dict[str, Any]]:
        """Extract URLs with context."""
        urls = []
        pattern = re.compile(r'https?://[^\s"\'<>\)]+', re.IGNORECASE)
        seen = set()

        for match in pattern.finditer(text):
            url = match.group()
            if url not in seen:
                seen.add(url)
                # Determine if suspicious
                suspicious = self._is_suspicious_url(url)
                urls.append({
                    "url": url,
                    "suspicious": suspicious,
                    "scheme": "https" if url.startswith("https") else "http",
                    "host": self._extract_host(url)
                })

        return urls[:100]

    def _extract_domains(self, text: str) -> List[Dict[str, Any]]:
        """Extract domain names."""
        domains = []
        # More precise domain pattern
        pattern = re.compile(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b')
        seen = set()

        false_positives = {
            'android.com', 'google.com', 'googleapis.com', 'gstatic.com', 'github.com',
            'maven.org', 'gradle.org', 'jcenter.bintray.com', 'dl.google.com',
            'schemas.android.com', 'developer.android.com', 'play.google.com',
            'firebaseio.com', 'firebasedatabase.app', 'googleusercontent.com',
            'android.clients.google.com', 'mtalk.google.com', 'clients.google.com'
        }

        for match in pattern.finditer(text):
            domain = match.group().lower().rstrip('.')
            if domain not in seen and domain not in false_positives:
                if not domain.endswith(('.xml', '.java', '.class', '.so', '.dex', '.png', '.jpg', '.json', '.html', '.css', '.js')):
                    seen.add(domain)
                    suspicious = self._is_suspicious_domain(domain)
                    domains.append({
                        "domain": domain,
                        "suspicious": suspicious,
                        "tld": domain.split('.')[-1] if '.' in domain else ''
                    })

        return domains[:100]

    def _extract_ips(self, text: str) -> List[Dict[str, Any]]:
        """Extract IP addresses."""
        ips = []
        pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
        seen = set()

        for match in pattern.finditer(text):
            ip = match.group()
            if ip not in seen:
                octets = ip.split(".")
                if all(0 <= int(o) <= 255 for o in octets):
                    # Skip private/local IPs unless they look like C2
                    is_private = (octets[0] == '10' or
                                  (octets[0] == '172' and 16 <= int(octets[1]) <= 31) or
                                  (octets[0] == '192' and octets[1] == '168') or
                                  octets[0] == '127' or
                                  octets[0] == '0')
                    seen.add(ip)
                    ips.append({
                        "ip": ip,
                        "private": is_private,
                        "suspicious": not is_private or self._is_suspicious_ip_context(text, ip)
                    })

        return ips[:50]

    def _extract_c2_config(self, text: str, strings: List[str]) -> List[Dict[str, Any]]:
        """Extract potential C2 configuration."""
        c2_configs = []

        # Look for base64 encoded configs
        for s in strings:
            if len(s) > 20:
                decoded = try_decode_string(s)
                # decoded["decoded"] is a list of dicts with "method" and "result" keys
                for dec in decoded.get("decoded", []):
                    result = dec.get("result", "")
                    if result:
                        # Check if decoded looks like config
                        if any(kw in result.lower() for kw in ['host', 'port', 'url', 'server', 'api', 'key', 'token', 'password', 'secret']):
                            c2_configs.append({
                                "type": "encoded_config",
                                "original": s[:100],
                                "decoded": result[:500],
                                "method": dec.get("method", "")
                            })

        # Look for JSON-like configs
        json_pattern = re.compile(r'\{[^{}]*"(?:host|server|url|api|endpoint|port|key|token)"[^{}]*\}')
        for match in json_pattern.finditer(text):
            c2_configs.append({
                "type": "json_config",
                "config": match.group()[:500]
            })

        # Look for URL patterns with suspicious paths
        for kw in self.known_c2_patterns:
            pattern = re.compile(rf'https?://[^\s"\']*{re.escape(kw)}[^\s"\']*', re.IGNORECASE)
            for match in pattern.finditer(text):
                c2_configs.append({
                    "type": "c2_url_pattern",
                    "pattern": kw,
                    "url": match.group()
                })

        return c2_configs[:30]

    def _find_certificate_pinning(self, text: str, strings: List[str]) -> List[Dict[str, Any]]:
        """Find certificate pinning implementations."""
        pinning = []

        # Network Security Config pinning
        patterns = [
            r'pin-set',
            r'pin\s*[:=]\s*["\']?sha256/',
            r'CertificatePinner',
            r'CertificateTransparency',
            r'TrustManager',
            r'X509TrustManager',
            r'checkServerTrusted',
            r'getAcceptedIssuers',
            r'HostnameVerifier',
            r'verify\s*\(',
            r'allowAllHostnameVerifier',
            r'SSLSocketFactory',
            r'createSSLSocketFactory',
            r'pinCertificate',
            r'publicKeyPin',
            r'sha256/[A-Za-z0-9+/=]+'
        ]

        for pattern_str in patterns:
            pattern = re.compile(pattern_str, re.IGNORECASE)
            for match in pattern.finditer(text):
                start = max(0, match.start() - 100)
                end = min(len(text), match.end() + 100)
                pinning.append({
                    "pattern": pattern_str,
                    "match": match.group(),
                    "context": text[start:end]
                })

        # Look for pinned certificates in strings
        for s in strings:
            if 'sha256/' in s and len(s) > 40:
                pinning.append({
                    "type": "pinned_cert",
                    "value": s[:200]
                })

        return pinning[:30]

    def _find_websocket(self, text: str, strings: List[str]) -> List[Dict[str, Any]]:
        """Find WebSocket usage."""
        ws = []

        patterns = [
            r'WebSocket',
            r'ws://',
            r'wss://',
            r'OkHttpClient.*newWebSocket',
            r'WebSocketClient',
            r'WebSocketListener',
            r'onMessage',
            r'onOpen',
            r'onClose',
            r'onFailure',
            r'Socket\.IO',
            r'socket\.io',
            r'engine\.io'
        ]

        for pattern_str in patterns:
            pattern = re.compile(pattern_str, re.IGNORECASE)
            for match in pattern.finditer(text):
                start = max(0, match.start() - 100)
                end = min(len(text), match.end() + 100)
                ws.append({
                    "pattern": pattern_str,
                    "match": match.group(),
                    "context": text[start:end]
                })

        # Extract ws:// and wss:// URLs
        ws_url_pattern = re.compile(r'wss?://[^\s"\'<>\)]+', re.IGNORECASE)
        for match in ws_url_pattern.finditer(text):
            ws.append({
                "type": "websocket_url",
                "url": match.group()
            })

        return ws[:30]

    def _find_proxy_config(self, text: str, strings: List[str]) -> List[Dict[str, Any]]:
        """Find proxy configuration."""
        proxy = []

        patterns = [
            r'Proxy\s*\(',
            r'ProxySelector',
            r'setProxy',
            r'Proxy\.Type',
            r'HTTP_PROXY',
            r'HTTPS_PROXY',
            r'SOCKS',
            r'proxyHost',
            r'proxyPort',
            r'systemProp\.https\.proxyHost',
            r'systemProp\.http\.proxyHost'
        ]

        for pattern_str in patterns:
            pattern = re.compile(pattern_str, re.IGNORECASE)
            for match in pattern.finditer(text):
                start = max(0, match.start() - 100)
                end = min(len(text), match.end() + 100)
                proxy.append({
                    "pattern": pattern_str,
                    "match": match.group(),
                    "context": text[start:end]
                })

        return proxy[:20]

    def _analyze_network_security_config(self, manifest_data: Dict) -> List[Dict[str, Any]]:
        """Analyze network security config from manifest."""
        configs = []

        # Check for networkSecurityConfig attribute
        app_attrs = manifest_data.get("application_attributes", {})
        if "android:networkSecurityConfig" in app_attrs:
            configs.append({
                "type": "network_security_config",
                "resource": app_attrs["android:networkSecurityConfig"]
            })

        # Check for cleartextTraffic
        if "android:usesCleartextTraffic" in app_attrs:
            configs.append({
                "type": "cleartext_traffic",
                "value": app_attrs["android:usesCleartextTraffic"]
            })

        return configs

    def _extract_firebase(self, text: str, strings: List[str]) -> List[Dict[str, Any]]:
        """Extract Firebase configuration."""
        firebase = []

        patterns = [
            r'firebaseio\.com',
            r'firebasedatabase\.app',
            r'googleapis\.com/identitytoolkit',
            r'project_id["\'\s:=]+[A-Za-z0-9_-]+',
            r'api_key["\'\s:=]+[A-Za-z0-9_-]+',
            r'app_id["\'\s:=]+[0-9:]+',
            r'google_app_id["\'\s:=]+[0-9:]+',
            r'databaseURL["\'\s:=]+https://[^"\']+',
            r'storageBucket["\'\s:=]+[^"\']+'
        ]

        for pattern_str in patterns:
            pattern = re.compile(pattern_str, re.IGNORECASE)
            for match in pattern.finditer(text):
                start = max(0, match.start() - 50)
                end = min(len(text), match.end() + 50)
                firebase.append({
                    "pattern": pattern_str,
                    "match": match.group(),
                    "context": text[start:end]
                })

        return firebase[:20]

    def _extract_telegram(self, text: str, strings: List[str]) -> List[Dict[str, Any]]:
        """Extract Telegram bot references."""
        telegram = []

        patterns = [
            r'api\.telegram\.org/bot[0-9]+:[A-Za-z0-9_-]+',
            r't\.me/[A-Za-z0-9_]+',
            r'telegram\.me/[A-Za-z0-9_]+',
            r'bot[0-9]{8,10}:[A-Za-z0-9_-]{35}',
            r'chat_id["\'\s:=]+[-0-9]+',
            r'TelegramBot',
            r'sendMessage',
            r'getUpdates'
        ]

        for pattern_str in patterns:
            pattern = re.compile(pattern_str, re.IGNORECASE)
            for match in pattern.finditer(text):
                start = max(0, match.start() - 100)
                end = min(len(text), match.end() + 100)
                telegram.append({
                    "pattern": pattern_str,
                    "match": match.group(),
                    "context": text[start:end]
                })

        return telegram[:20]

    def _extract_api_endpoints(self, text: str) -> List[Dict[str, Any]]:
        """Extract potential API endpoints."""
        endpoints = []

        # REST-like patterns
        pattern = re.compile(r'https?://[^\s"\']+/api/[^\s"\']*', re.IGNORECASE)
        for match in pattern.finditer(text):
            endpoints.append({
                "type": "rest_api",
                "url": match.group()
            })

        # GraphQL
        graphql_pattern = re.compile(r'https?://[^\s"\']*/graphql', re.IGNORECASE)
        for match in graphql_pattern.finditer(text):
            endpoints.append({
                "type": "graphql",
                "url": match.group()
            })

        # RPC
        rpc_pattern = re.compile(r'https?://[^\s"\']*/rpc', re.IGNORECASE)
        for match in rpc_pattern.finditer(text):
            endpoints.append({
                "type": "rpc",
                "url": match.group()
            })

        return endpoints[:30]

    def _find_suspicious_indicators(self, domains: List[Dict], ips: List[Dict],
                                     urls: List[Dict], text: str) -> List[Dict[str, Any]]:
        """Find suspicious network indicators."""
        indicators = []

        # Suspicious TLDs
        for d in domains:
            domain = d.get("domain", "")
            for tld in self.suspicious_tlds:
                if domain.endswith(tld):
                    indicators.append({
                        "type": "suspicious_tld",
                        "domain": domain,
                        "tld": tld,
                        "severity": "medium"
                    })

        # Dynamic DNS domains
        dns_patterns = ['dyndns', 'no-ip', 'duckdns', 'freedns', 'afraid.org', 'changeip', 'dynalias']
        for d in domains:
            domain = d.get("domain", "")
            for dp in dns_patterns:
                if dp in domain:
                    indicators.append({
                        "type": "dynamic_dns",
                        "domain": domain,
                        "provider": dp,
                        "severity": "high"
                    })

        # IP-based URLs (no domain)
        for u in urls:
            url = u.get("url", "")
            if re.match(r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url):
                indicators.append({
                    "type": "ip_based_url",
                    "url": url,
                    "severity": "high"
                })

        # Non-standard ports
        port_pattern = re.compile(r':(?!80\b|443\b|8080\b|8443\b)\d{2,5}\b')
        for match in port_pattern.finditer(text):
            port = match.group(1)
            if int(port) > 1024:
                indicators.append({
                    "type": "non_standard_port",
                    "port": port,
                    "severity": "low"
                })

        # Long random-looking subdomains (DGA-like)
        for d in domains:
            domain = d.get("domain", "")
            parts = domain.split('.')
            if len(parts) >= 3:
                subdomain = parts[0]
                if len(subdomain) > 20 and re.match(r'^[a-z0-9]+$', subdomain):
                    # Check entropy
                    entropy = self._calculate_entropy(subdomain)
                    if entropy > 3.5:
                        indicators.append({
                            "type": "high_entropy_subdomain",
                            "domain": domain,
                            "subdomain": subdomain,
                            "entropy": round(entropy, 2),
                            "severity": "high"
                        })

        return indicators[:30]

    def _calculate_entropy(self, string: str) -> float:
        """Calculate Shannon entropy."""
        import math
        if not string:
            return 0
        freq = {}
        for c in string:
            freq[c] = freq.get(c, 0) + 1
        entropy = 0
        for count in freq.values():
            p = count / len(string)
            entropy -= p * math.log2(p)
        return entropy

    def _is_suspicious_url(self, url: str) -> bool:
        """Check if URL is suspicious."""
        url_lower = url.lower()
        # IP-based
        if re.match(r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url):
            return True
        # Suspicious keywords in path
        for kw in self.known_c2_patterns:
            if kw in url_lower:
                return True
        # Non-standard port
        if re.search(r':(?!80\b|443\b|8080\b|8443\b)\d{2,5}', url):
            return True
        return False

    def _is_suspicious_domain(self, domain: str) -> bool:
        """Check if domain is suspicious."""
        # Dynamic DNS
        dns_patterns = ['dyndns', 'no-ip', 'duckdns', 'freedns', 'afraid.org', 'changeip']
        for dp in dns_patterns:
            if dp in domain:
                return True
        # Suspicious TLD
        for tld in self.suspicious_tlds:
            if domain.endswith(tld):
                return True
        # High entropy subdomain
        parts = domain.split('.')
        if len(parts) >= 3:
            subdomain = parts[0]
            if len(subdomain) > 20 and re.match(r'^[a-z0-9]+$', subdomain):
                if self._calculate_entropy(subdomain) > 3.5:
                    return True
        return False

    def _is_suspicious_ip_context(self, text: str, ip: str) -> bool:
        """Check if IP appears in suspicious context."""
        idx = text.find(ip)
        if idx >= 0:
            context = text[max(0, idx-100):idx+100].lower()
            for kw in self.known_c2_patterns:
                if kw in context:
                    return True
        return False

    def _extract_host(self, url: str) -> str:
        """Extract host from URL."""
        try:
            return url.split("://")[1].split("/")[0].split(":")[0]
        except Exception:
            return ""