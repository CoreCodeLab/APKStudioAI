"""
String analyzer for APKStudioAI 2.1
Extracts and decodes strings: Base64, Hex, XOR, obfuscated
"""
import re
import base64
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from .utils import printable_strings, printable_strings_utf16, try_decode_string


class StringAnalyzer:
    def __init__(self, min_length: int = 5):
        self.min_length = min_length

    def analyze(self, extract_dir: Path, additional_files: List[Path] = None) -> Dict[str, Any]:
        """Analyze strings from all extracted files."""
        result = {
            "all_strings": [],
            "decoded_strings": [],
            "urls": [],
            "domains": [],
            "ips": [],
            "emails": [],
            "certificates": [],
            "api_keys": [],
            "firebase": [],
            "telegram": [],
            "suspicious": [],
            "by_file": {}
        }

        files_to_scan = list(extract_dir.rglob("*"))
        if additional_files:
            files_to_scan.extend(additional_files)

        for file_path in files_to_scan:
            if not file_path.is_file():
                continue
            if file_path.stat().st_size > 10 * 1024 * 1024:  # 10MB limit
                continue

            try:
                strings = self._extract_strings(file_path)
                if strings:
                    rel_path = str(file_path.relative_to(extract_dir))
                    result["by_file"][rel_path] = strings[:200]
                    result["all_strings"].extend(strings)
            except Exception:
                pass

        # Deduplicate
        result["all_strings"] = list(dict.fromkeys(result["all_strings"]))[:5000]

        # Decode strings
        result["decoded_strings"] = self._decode_all_strings(result["all_strings"])

        # Extract IOCs
        result["urls"] = self._extract_urls(result["all_strings"])
        result["domains"] = self._extract_domains(result["all_strings"])
        result["ips"] = self._extract_ips(result["all_strings"])
        result["emails"] = self._extract_emails(result["all_strings"])
        result["certificates"] = self._extract_certificates(result["all_strings"])
        result["api_keys"] = self._extract_api_keys(result["all_strings"])
        result["firebase"] = self._extract_firebase(result["all_strings"])
        result["telegram"] = self._extract_telegram(result["all_strings"])

        # Suspicious patterns
        result["suspicious"] = self._find_suspicious(result["all_strings"])

        return result

    def _extract_strings(self, file_path: Path) -> List[str]:
        """Extract strings from a file."""
        data = file_path.read_bytes()
        strings = printable_strings(data, self.min_length)
        strings.extend(printable_strings_utf16(data, self.min_length))
        return strings

    def _decode_all_strings(self, strings: List[str]) -> List[Dict[str, Any]]:
        """Try to decode all strings."""
        decoded = []

        for s in strings:
            if len(s) < 8:  # Too short to be encoded
                continue

            result = try_decode_string(s)
            if result["decoded"]:
                # Flatten: each decoded result becomes a separate entry
                for dec in result["decoded"]:
                    decoded.append({
                        "original": s,
                        "method": dec.get("method", ""),
                        "decoded": dec.get("result", "")
                    })

        return decoded[:200]

    def _extract_urls(self, strings: List[str]) -> List[Dict[str, Any]]:
        """Extract URLs from strings."""
        urls = []
        pattern = re.compile(r'https?://[^\s"\'<>\)]+', re.IGNORECASE)

        for s in strings:
            for match in pattern.finditer(s):
                urls.append({
                    "url": match.group(),
                    "source_string": s[:200]
                })

        return urls[:100]

    def _extract_domains(self, strings: List[str]) -> List[Dict[str, Any]]:
        """Extract domain names from strings."""
        domains = []
        # Domain pattern (simplified)
        pattern = re.compile(r'\b[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+\b')

        seen = set()
        for s in strings:
            for match in pattern.finditer(s):
                domain = match.group().lower()
                if domain not in seen and not domain.endswith(('.xml', '.java', '.class', '.so', '.dex', '.png', '.jpg')):
                    seen.add(domain)
                    # Filter out common false positives
                    if not any(fp in domain for fp in ['android.', 'google.', 'googleapis.', 'gstatic.', 'github.', 'maven.']):
                        domains.append({
                            "domain": domain,
                            "source_string": s[:200]
                        })

        return domains[:100]

    def _extract_ips(self, strings: List[str]) -> List[Dict[str, Any]]:
        """Extract IP addresses from strings."""
        ips = []
        pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')

        seen = set()
        for s in strings:
            for match in pattern.finditer(s):
                ip = match.group()
                if ip not in seen:
                    # Validate IP octets
                    octets = ip.split(".")
                    if all(0 <= int(o) <= 255 for o in octets):
                        seen.add(ip)
                        ips.append({
                            "ip": ip,
                            "source_string": s[:200]
                        })

        return ips[:50]

    def _extract_emails(self, strings: List[str]) -> List[Dict[str, Any]]:
        """Extract email addresses from strings."""
        emails = []
        pattern = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')

        seen = set()
        for s in strings:
            for match in pattern.finditer(s):
                email = match.group().lower()
                if email not in seen:
                    seen.add(email)
                    emails.append({
                        "email": email,
                        "source_string": s[:200]
                    })

        return emails[:50]

    def _extract_certificates(self, strings: List[str]) -> List[Dict[str, Any]]:
        """Extract certificates from strings."""
        certs = []
        in_cert = False
        current = []

        for s in strings:
            if "-----BEGIN CERTIFICATE-----" in s:
                in_cert = True
                current = [s]
            elif in_cert:
                current.append(s)
                if "-----END CERTIFICATE-----" in s:
                    certs.append({
                        "certificate": "\n".join(current),
                        "length": len("\n".join(current))
                    })
                    in_cert = False
                    current = []

        return certs[:10]

    def _extract_api_keys(self, strings: List[str]) -> List[Dict[str, Any]]:
        """Extract potential API keys."""
        keys = []
        patterns = {
            "generic": r'(api[_-]?key|access[_-]?token|secret[_-]?key|auth[_-]?token)["\'\s:=]+([A-Za-z0-9_\-]{20,})',
            "aws": r'AKIA[0-9A-Z]{16}',
            "github": r'gh[pousr]_[A-Za-z0-9_]{36,255}',
            "slack": r'xox[baprs]-[A-Za-z0-9-]{10,72}',
            "firebase": r'AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}',
            "google_api": r'AIza[0-9A-Za-z_-]{35}',
        }

        import re
        for s in strings:
            for category, pattern in patterns.items():
                for match in re.finditer(pattern, s, re.IGNORECASE):
                    keys.append({
                        "type": category,
                        "match": match.group(),
                        "source_string": s[:200]
                    })

        return keys[:50]

    def _extract_firebase(self, strings: List[str]) -> List[Dict[str, Any]]:
        """Extract Firebase references."""
        firebase = []
        patterns = [
            r'firebaseio\.com',
            r'firebasedatabase\.app',
            r'googleapis\.com/identitytoolkit',
            r'project_id["\'\s:=]+[A-Za-z0-9_-]+',
            r'api_key["\'\s:=]+[A-Za-z0-9_-]+',
            r'app_id["\'\s:=]+[0-9:]+'
        ]

        import re
        for s in strings:
            for pattern in patterns:
                if re.search(pattern, s, re.IGNORECASE):
                    firebase.append({
                        "pattern": pattern,
                        "source_string": s[:200]
                    })
                    break

        return firebase[:20]

    def _extract_telegram(self, strings: List[str]) -> List[Dict[str, Any]]:
        """Extract Telegram bot references."""
        telegram = []
        patterns = [
            r'api\.telegram\.org/bot[0-9]+:[A-Za-z0-9_-]+',
            r't\.me/[A-Za-z0-9_]+',
            r'telegram\.me/[A-Za-z0-9_]+',
            r'bot[0-9]{8,10}:[A-Za-z0-9_-]{35}',
            r'chat_id["\'\s:=]+[-0-9]+'
        ]

        import re
        for s in strings:
            for pattern in patterns:
                for match in re.finditer(pattern, s):
                    telegram.append({
                        "pattern": pattern,
                        "match": match.group(),
                        "source_string": s[:200]
                    })

        return telegram[:20]

    def _find_suspicious(self, strings: List[str]) -> List[Dict[str, Any]]:
        """Find suspicious strings."""
        suspicious = []
        patterns = {
            "shell_command": [r"/bin/sh", r"/system/bin/sh", r"cmd.exe", r"powershell", r"su\s", r"sudo\s"],
            "exploit": [r"CVE-\d{4}-\d+", r"exploit", r"payload", r"shellcode", r"ROP", r"JOP"],
            "malware": [r"rat\b", r"trojan", r"keylog", r"screenlog", r"clipboard", r"contacts", r"sms", r"calllog"],
            "persistence": [r"boot_completed", r"autostart", r"runatstartup", r"device_admin", r"accessibility"],
            "anti_analysis": [r"emulator", r"xposed", r"frida", r"debugger", r"tracerpid", r"ptrace"],
            "crypto": [r"AES", r"RSA", r"encrypt", r"decrypt", r"cipher", r"keystore"],
            "network": [r"WebSocket", r"Socket", r"HttpURLConnection", r"OkHttp", r"Retrofit"],
            "reflection": [r"Class\.forName", r"Method\.invoke", r"Field\.set", r"DexClassLoader", r"PathClassLoader"],
        }

        import re
        for s in strings:
            for category, pattern_list in patterns.items():
                for pattern in pattern_list:
                    if re.search(pattern, s, re.IGNORECASE):
                        suspicious.append({
                            "category": category,
                            "pattern": pattern,
                            "string": s[:200]
                        })
                        break
                else:
                    continue
                break  # Only first category match per string

        return suspicious[:100]