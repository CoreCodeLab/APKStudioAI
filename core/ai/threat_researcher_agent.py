"""
AI Threat Researcher Agent - Agent 6
Compares artifacts with known malware patterns, identifies families,
investigates similarities, generates hypotheses, requests evidence.
"""
from pathlib import Path
from typing import Dict, List, Any, Optional
from .agent_base import BaseAgent, AgentTask, AgentResult
from .evidence_repository import Evidence, Severity, AgentID
from ..config_manager import get_config
from ..logging_setup import get_module_logger

logger = get_module_logger("threat_researcher_agent")


class ThreatResearcherAgent(BaseAgent):
    """Agent 6: AI Threat Researcher - Malware family attribution, pattern matching."""

    # Known malware families with signatures
    MALWARE_FAMILIES = {
        "banking_trojan": {
            "name": "Banking Trojan",
            "indicators": [
                "SYSTEM_ALERT_WINDOW", "AccessibilityService", "onAccessibilityEvent",
                "sendTextMessage", "abortBroadcast", "USSD", "webview", "addJavascriptInterface",
                "overlay", "keylog", "credential", "bank", "login"
            ],
            "min_matches": 4,
            "severity": "critical",
        },
        "spyware": {
            "name": "Spyware",
            "indicators": [
                "MediaRecorder", "Camera.open", "LocationManager", "ContactsContract",
                "content://sms", "CallLog.Calls", "onKeyDown", "MediaProjection",
                "getLastKnownLocation", "requestLocationUpdates", "getMessageBody"
            ],
            "min_matches": 3,
            "severity": "critical",
        },
        "rat": {
            "name": "RAT (Remote Access Trojan)",
            "indicators": [
                "DexClassLoader", "PathClassLoader", "Runtime.exec", "ProcessBuilder",
                "Socket", "ServerSocket", "HttpURLConnection", "WebSocket",
                "Command", "Shell", "execute", "upload", "download", "keylog",
                "screen", "camera", "mic", "location", "contacts", "sms"
            ],
            "min_matches": 4,
            "severity": "critical",
        },
        "dropper": {
            "name": "Dropper/Downloader",
            "indicators": [
                "download", "exec", "loadDex", "DexClassLoader", "PathClassLoader",
                "FileOutputStream", "chmod", "installPackage", "Runtime.exec",
                "ProcessBuilder", "openConnection", "getOutputStream"
            ],
            "min_matches": 3,
            "severity": "high",
        },
        "ransomware": {
            "name": "Ransomware",
            "indicators": [
                "Cipher.init", "Cipher.doFinal", "listFiles", "delete",
                "DevicePolicyManager.lockNow", "DevicePolicyManager.resetPassword",
                "DevicePolicyManager.wipeData", "bitcoin", "ransom", "encrypt",
                "AES", "RSA", "Cipher.getInstance"
            ],
            "min_matches": 3,
            "severity": "critical",
        },
        "adware": {
            "name": "Adware",
            "indicators": [
                "AdView", "InterstitialAd", "RewardedAd", "AdRequest", "AdMob",
                "AdSize", "loadAd", "MobileAds", "UnityAds", "AppLovin"
            ],
            "min_matches": 2,
            "severity": "medium",
        },
        "sms_trojan": {
            "name": "SMS Trojan",
            "indicators": [
                "sendTextMessage", "sendMultipartTextMessage", "abortBroadcast",
                "SmsManager", "content://sms", "SMS_RECEIVED", "PDU"
            ],
            "min_matches": 2,
            "severity": "high",
        },
        "cryptominer": {
            "name": "Cryptominer",
            "indicators": [
                "stratum", "mining", "miner", "xmrig", "cryptonight", "hashrate",
                "pool", "worker", "monero", "bitcoin", "ethereum", "cpu"
            ],
            "min_matches": 2,
            "severity": "high",
        },
        "root_exploit": {
            "name": "Root Exploit",
            "indicators": [
                "/system/bin/su", "/system/xbin/su", "ROOT", "exploit",
                "dirtycow", "CVE-", "kernel", "privilege", "escalation",
                "mprotect", "mmap", "ptrace"
            ],
            "min_matches": 2,
            "severity": "critical",
        },
    }

    def __init__(self, config: Dict = None, evidence_repo = None,
                 ollama_client = None, rag_engine = None):
        super().__init__(AgentID.THREAT_RESEARCHER, config, evidence_repo, ollama_client, rag_engine)

    def investigate(self, task: AgentTask) -> AgentResult:
        """Perform threat research and family attribution."""
        all_evidence = task.input_data.get("all_evidence", [])
        dex_analysis = task.input_data.get("dex_analysis", {})
        string_analysis = task.input_data.get("string_analysis", {})
        network_analysis = task.input_data.get("network_analysis", {})
        behavior_analysis = task.input_data.get("behavior_analysis", {})
        advanced_static = task.input_data.get("advanced_static", {})
        yara_results = advanced_static.get("yara", {}).get("matches", [])

        evidence_ids = []
        findings = {
            "family_attribution": {},
            "pattern_matches": [],
            "similarities": [],
            "hypotheses": [],
            "yara_matches": [],
            "mitre_techniques": [],
            "confidence": 0,
        }

        # 1. YARA Matches
        findings["yara_matches"] = self._process_yara_matches(yara_results)
        evidence_ids.extend(self._create_yara_evidence(findings["yara_matches"]).values())

        # 2. Family Attribution
        attribution = self._attribute_family(
            dex_analysis, string_analysis, network_analysis,
            behavior_analysis, advanced_static
        )
        findings["family_attribution"] = attribution
        evidence_ids.extend(self._create_attribution_evidence(attribution).values())

        # 3. Pattern Matches
        patterns = self._match_patterns(dex_analysis, string_analysis, network_analysis)
        findings["pattern_matches"] = patterns
        evidence_ids.extend(self._create_pattern_evidence(patterns).values())

        # 4. Similarity Analysis
        similarities = self._analyze_similarities(dex_analysis, network_analysis, advanced_static)
        findings["similarities"] = similarities

        # 5. Generate Hypotheses
        hypotheses = self._generate_hypotheses(findings)
        findings["hypotheses"] = hypotheses

        # 6. MITRE ATT&CK Mapping
        mitre = self._map_mitre_techniques(dex_analysis, behavior_analysis, advanced_static)
        findings["mitre_techniques"] = mitre
        evidence_ids.extend(self._create_mitre_evidence(mitre).values())

        # 7. Overall Confidence
        findings["confidence"] = self._calculate_confidence(findings)

        # 8. Initial Risk Assessment (for verification agent)
        findings["risk"] = self._calculate_initial_risk(findings, dex_analysis, advanced_static)

        return AgentResult(
            task_id=task.task_id,
            agent_id=self.agent_id,
            success=True,
            evidence_ids=evidence_ids,
            findings=findings,
        )

    def _process_yara_matches(self, matches: List[Dict]) -> List[Dict]:
        """Process YARA rule matches."""
        processed = []
        for match in matches:
            if match.get("matched") or match.get("rule"):
                processed.append({
                    "rule": match.get("rule", match.get("name", "unknown")),
                    "file": match.get("file", "unknown"),
                    "description": f"YARA match: {match.get('rule', 'unknown')}",
                    "severity": "high",
                })
        return processed

    def _attribute_family(self, dex: Dict, strings: Dict, network: Dict,
                          behavior: Dict, advanced: Dict) -> Dict:
        """Attribute to malware family."""
        # Collect all indicators
        all_indicators = set()

        # From API calls
        for call in dex.get("api_calls", []):
            all_indicators.add(call.get("call", "").lower())

        # From strings
        for s in strings.get("all_strings", []):
            all_indicators.add(s.lower())

        # From decoded strings
        for dec in strings.get("decoded_strings", []):
            all_indicators.add(dec.get("decoded", "").lower())

        # From network
        for url in network.get("urls", []):
            all_indicators.add(url.get("url", "").lower())
        for domain in network.get("domains", []):
            all_indicators.add(domain.get("domain", "").lower())

        # From behavior
        for det in behavior.get("detected_behaviors", []):
            all_indicators.add(det.get("category", "").lower())

        # From advanced static
        for finding in advanced.get("obfuscation", {}).get("findings", []):
            all_indicators.add(finding.get("type", "").lower())

        # Match against families
        family_scores = {}
        for family_id, family_info in self.MALWARE_FAMILIES.items():
            matches = 0
            matched_indicators = []
            for indicator in family_info["indicators"]:
                for ai in all_indicators:
                    if indicator.lower() in ai:
                        matches += 1
                        matched_indicators.append(indicator)
                        break

            if matches >= family_info["min_matches"]:
                family_scores[family_id] = {
                    "family": family_info["name"],
                    "matches": matches,
                    "matched_indicators": matched_indicators,
                    "min_required": family_info["min_matches"],
                    "severity": family_info["severity"],
                }

        # Sort by matches
        sorted_families = sorted(
            family_scores.items(),
            key=lambda x: x[1]["matches"],
            reverse=True
        )

        primary = None
        if sorted_families:
            primary = {
                "family_id": sorted_families[0][0],
                **sorted_families[0][1]
            }

        return {
            "primary_family": primary,
            "all_matches": {k: v for k, v in sorted_families},
            "total_families_matched": len(sorted_families),
        }

    def _match_patterns(self, dex: Dict, strings: Dict, network: Dict) -> List[Dict]:
        """Match against known malicious patterns."""
        patterns = []

        # Pattern: Credential harvesting
        cred_indicators = ["password", "username", "login", "credential", "auth", "token"]
        cred_matches = sum(1 for s in strings.get("all_strings", []) if any(c in s.lower() for c in cred_indicators))
        if cred_matches > 5:
            patterns.append({
                "pattern": "credential_harvesting",
                "matches": cred_matches,
                "description": f"Potential credential harvesting ({cred_matches} indicators)",
                "severity": "high",
            })

        # Pattern: Keylogging
        key_indicators = ["onkeydown", "dispatchkeyevent", "keylog", "inputmethod"]
        key_matches = sum(1 for call in dex.get("api_calls", []) if any(k in call.get("call", "").lower() for k in key_indicators))
        if key_matches > 0:
            patterns.append({
                "pattern": "keylogging",
                "matches": key_matches,
                "description": f"Keylogging indicators ({key_matches} calls)",
                "severity": "critical",
            })

        # Pattern: Screen capture
        screen_indicators = ["mediaprojection", "createscreencaptureintent", "screenrecord"]
        screen_matches = sum(1 for call in dex.get("api_calls", []) if any(s in call.get("call", "").lower() for s in screen_indicators))
        if screen_matches > 0:
            patterns.append({
                "pattern": "screen_capture",
                "matches": screen_matches,
                "description": f"Screen capture capability ({screen_matches} calls)",
                "severity": "critical",
            })

        # Pattern: Crypto operations
        crypto_matches = sum(1 for call in dex.get("api_calls", []) if "Cipher" in call.get("call", ""))
        if crypto_matches > 5:
            patterns.append({
                "pattern": "crypto_operations",
                "matches": crypto_matches,
                "description": f"Extensive crypto operations ({crypto_matches} calls)",
                "severity": "high",
            })

        # Pattern: Dynamic code loading
        dyn_matches = sum(1 for call in dex.get("api_calls", []) if any(x in call.get("call", "") for x in ["DexClassLoader", "PathClassLoader", "InMemoryDexClassLoader", "DexFile.loadDex"]))
        if dyn_matches > 0:
            patterns.append({
                "pattern": "dynamic_code_loading",
                "matches": dyn_matches,
                "description": f"Dynamic code loading ({dyn_matches} sites)",
                "severity": "critical",
            })

        return patterns

    def _analyze_similarities(self, dex: Dict, network: Dict, advanced: Dict) -> List[Dict]:
        """Analyze similarities with known samples."""
        # This would typically compare against a local malware database
        # For now, return structural similarities
        similarities = []

        # Call graph similarity
        cg = advanced.get("call_graph", {}).get("statistics", {})
        if cg.get("sensitive_apis", 0) > 10:
            similarities.append({
                "type": "call_graph",
                "description": f"High sensitive API count: {cg.get('sensitive_apis')}",
                "similarity": "high",
            })

        # Taint flow similarity
        taint = advanced.get("taint", {}).get("statistics", {})
        if taint.get("source_sink_paths", 0) > 0:
            similarities.append({
                "type": "data_flow",
                "description": f"Source-to-sink paths found: {taint.get('source_sink_paths')}",
                "similarity": "high",
            })

        # ICC similarity
        icc = advanced.get("icc", {}).get("statistics", {})
        if icc.get("unprotected_exported", 0) > 5:
            similarities.append({
                "type": "attack_surface",
                "description": f"Large attack surface: {icc.get('unprotected_exported')} unprotected exported components",
                "similarity": "medium",
            })

        return similarities

    def _generate_hypotheses(self, findings: Dict) -> List[Dict]:
        """Generate investigation hypotheses."""
        hypotheses = []

        # From family attribution
        primary = findings["family_attribution"].get("primary_family")
        if primary:
            hypotheses.append({
                "hypothesis": f"Sample belongs to {primary['family']} family",
                "evidence": primary.get("matched_indicators", []),
                "confidence": min(90, primary.get("matches", 0) * 15),
                "type": "family_attribution",
            })

        # From patterns
        for pattern in findings["pattern_matches"]:
            hypotheses.append({
                "hypothesis": f"Sample exhibits {pattern['pattern'].replace('_', ' ')} behavior",
                "evidence": [f"{pattern['matches']} matches"],
                "confidence": min(85, pattern["matches"] * 10),
                "type": "behavioral_pattern",
            })

        # From YARA
        for yara in findings["yara_matches"]:
            hypotheses.append({
                "hypothesis": f"YARA rule match: {yara['rule']}",
                "evidence": [yara["description"]],
                "confidence": 80,
                "type": "signature_match",
            })

        # From combinations
        if findings["family_attribution"].get("total_families_matched", 0) > 1:
            hypotheses.append({
                "hypothesis": "Sample matches multiple malware families (hybrid or dropper)",
                "evidence": list(findings["family_attribution"].get("all_matches", {}).keys()),
                "confidence": 70,
                "type": "hybrid_malware",
            })

        return hypotheses

    def _map_mitre_techniques(self, dex: Dict, behavior: Dict, advanced: Dict) -> List[Dict]:
        """Map findings to MITRE ATT&CK for Mobile."""
        techniques = []

        # Mapping from findings to techniques
        mappings = {
            # Persistence
            "T1432": ("Boot Receiver", "persistence", ["boot_completed", "BOOT_COMPLETED"]),
            "T1433": ("Exploit via NFC", "initial_access", ["nfc", "NFC"]),
            "T1505": ("Server Software Component", "persistence", ["DexClassLoader", "PathClassLoader", "dynamic_code_loading"]),

            # Privilege Escalation
            "T1659": ("Content Injection", "privilege_escalation", ["overlay", "SYSTEM_ALERT_WINDOW", "AccessibilityService"]),

            # Defense Evasion
            "T1472": ("Data from Local System", "defense_evasion", ["query", "ContactsContract", "ContentResolver"]),
            "T1473": ("Data from Network Shared Drive", "defense_evasion", ["HttpURLConnection", "OkHttpClient", "WebSocket"]),

            # Credential Access
            "T1555": ("Credentials from Password Stores", "credential_access", ["password", "credential", "keystore", "KeyStore"]),

            # Discovery
            "T1474": ("Network Service Discovery", "discovery", ["NetworkInterface", "InetAddress", "WifiManager"]),
            "T1475": ("Application Discovery", "discovery", ["PackageManager", "getInstalledApplications"]),

            # Collection
            "T1476": ("Data from Local System", "collection", ["getLastKnownLocation", "Camera", "MediaRecorder", "ContactsContract"]),
            "T1477": ("Screen Capture", "collection", ["MediaProjection", "createScreenCaptureIntent"]),
            "T1478": ("Audio Capture", "collection", ["MediaRecorder", "AudioRecord"]),

            # Command and Control
            "T1479": ("Ingress Tool Transfer", "command_and_control", ["download", "FileOutputStream", "DexClassLoader"]),
            "T1480": ("Remote Access", "command_and_control", ["Socket", "WebSocket", "HttpURLConnection", "C2"]),

            # Exfiltration
            "T1481": ("Exfiltration Over Web Service", "exfiltration", ["HttpURLConnection", "sendTextMessage", "network_send"]),
            "T1482": ("Exfiltration Over Alternative Protocol", "exfiltration", ["WebSocket", "Socket", "DNS"]),

            # Impact
            "T1483": ("Data Encrypted for Impact", "impact", ["Cipher", "encrypt", "ransomware"]),
            "T1484": ("Device Lock", "impact", ["DevicePolicyManager.lockNow", "resetPassword"]),
            "T1485": ("Data Wiped", "impact", ["DevicePolicyManager.wipeData", "delete"]),
        }

        # Collect all indicators
        all_indicators = set()
        for call in dex.get("api_calls", []):
            all_indicators.add(call.get("call", "").lower())
        for det in behavior.get("detected_behaviors", []):
            all_indicators.add(det.get("category", "").lower())
        for finding in advanced.get("obfuscation", {}).get("findings", []):
            all_indicators.add(finding.get("type", "").lower())

        for tech_id, (name, tactic, indicators) in mappings.items():
            matches = 0
            for ind in indicators:
                for ai in all_indicators:
                    if ind.lower() in ai:
                        matches += 1
                        break
            if matches > 0:
                techniques.append({
                    "technique_id": tech_id,
                    "name": name,
                    "tactic": tactic,
                    "matches": matches,
                    "confidence": min(90, matches * 20),
                })

        # Sort by confidence
        techniques.sort(key=lambda x: x["confidence"], reverse=True)
        return techniques[:20]

    def _calculate_confidence(self, findings: Dict) -> int:
        """Calculate overall confidence."""
        confidence = 0

        # Family attribution
        primary = findings["family_attribution"].get("primary_family")
        if primary:
            confidence += min(40, primary.get("matches", 0) * 5)

        # Patterns
        for p in findings["pattern_matches"]:
            confidence += min(10, p.get("matches", 0) * 2)

        # YARA
        confidence += min(20, len(findings["yara_matches"]) * 5)

        # MITRE
        confidence += min(20, len(findings["mitre_techniques"]) * 2)

        return min(100, confidence)

    def _calculate_initial_risk(self, findings: Dict, dex: Dict, advanced: Dict) -> Dict:
        """Calculate initial risk score for verification agent."""
        score = 0
        factors = []

        # Family attribution severity
        primary = findings["family_attribution"].get("primary_family")
        if primary:
            severity_map = {"critical": 40, "high": 25, "medium": 15, "low": 5}
            score += severity_map.get(primary.get("severity", "medium"), 15)
            factors.append(f"Family: {primary['family']} ({primary['severity']})")

        # YARA matches
        yara_count = len(findings["yara_matches"])
        if yara_count > 0:
            score += min(20, yara_count * 5)
            factors.append(f"YARA matches: {yara_count}")

        # Malicious patterns
        for p in findings["pattern_matches"]:
            severity_map = {"critical": 15, "high": 10, "medium": 5, "low": 2}
            score += severity_map.get(p.get("severity", "medium"), 5)
            factors.append(f"Pattern: {p['pattern']} ({p['severity']})")

        # MITRE techniques
        mitre_count = len(findings["mitre_techniques"])
        if mitre_count > 0:
            score += min(15, mitre_count * 2)
            factors.append(f"MITRE techniques: {mitre_count}")

        # Dangerous API count
        api_count = len(dex.get("api_calls", []))
        if api_count > 20:
            score += 10
            factors.append(f"High API count: {api_count}")

        # Dynamic code loading
        dyn_loading = advanced.get("dynamic_loading", {}).get("load_sites", [])
        if dyn_loading:
            score += 15
            factors.append(f"Dynamic code loading: {len(dyn_loading)} sites")

        # Reflection usage
        reflection = advanced.get("reflection", {}).get("resolved_count", 0)
        if reflection > 0:
            score += 10
            factors.append(f"Reflection: {reflection} resolved")

        # Obfuscation
        obfu_score = advanced.get("obfuscation", {}).get("risk_score", 0)
        if obfu_score > 50:
            score += 10
            factors.append(f"High obfuscation: {obfu_score}")

        # Cap score
        score = min(100, score)

        # Determine level
        if score >= 80:
            level = "Critical"
        elif score >= 60:
            level = "High"
        elif score >= 40:
            level = "Suspicious"
        elif score >= 20:
            level = "Moderate"
        else:
            level = "Low"

        return {
            "score": score,
            "risk_level": level,
            "factors": factors,
        }

    def _create_yara_evidence(self, matches: List[Dict]) -> Dict[str, str]:
        evidence = {}
        for i, m in enumerate(matches):
            ev = self.create_evidence(
                analysis_module="yara_match",
                file_path=m.get("file", "unknown"),
                description=m.get("description", ""),
                raw_data=m,
                confidence=90,
                severity=m.get("severity", "high"),
                tags=["yara", m.get("rule", "unknown")],
            )
            evidence[f"yara_{i}"] = ev.evidence_id
        return evidence

    def _create_attribution_evidence(self, attribution: Dict) -> Dict[str, str]:
        evidence = {}
        primary = attribution.get("primary_family")
        if primary:
            ev = self.create_evidence(
                analysis_module="family_attribution",
                file_path="multiple",
                description=f"Primary family: {primary['family']} ({primary['matches']} matches)",
                raw_data=attribution,
                confidence=85,
                severity=primary.get("severity", "high"),
                tags=["family", primary.get("family_id", "unknown")],
            )
            evidence["primary_family"] = ev.evidence_id

        for fam_id, fam_info in attribution.get("all_matches", {}).items():
            if fam_id != primary.get("family_id") if primary else True:
                ev = self.create_evidence(
                    analysis_module="family_match",
                    file_path="multiple",
                    description=f"Family match: {fam_info['family']} ({fam_info['matches']} matches)",
                    raw_data=fam_info,
                    confidence=75,
                    severity=fam_info.get("severity", "medium"),
                    tags=["family", fam_id],
                )
                evidence[f"family_{fam_id}"] = ev.evidence_id
        return evidence

    def _create_pattern_evidence(self, patterns: List[Dict]) -> Dict[str, str]:
        evidence = {}
        for i, p in enumerate(patterns):
            ev = self.create_evidence(
                analysis_module="malicious_pattern",
                file_path="multiple",
                description=p.get("description", ""),
                raw_data=p,
                confidence=80,
                severity=p.get("severity", "medium"),
                tags=["pattern", p.get("pattern", "unknown")],
            )
            evidence[f"pattern_{i}"] = ev.evidence_id
        return evidence

    def _create_mitre_evidence(self, techniques: List[Dict]) -> Dict[str, str]:
        evidence = {}
        for tech in techniques[:15]:
            ev = self.create_evidence(
                analysis_module="mitre_technique",
                file_path="multiple",
                description=f"MITRE {tech['technique_id']}: {tech['name']} ({tech['tactic']})",
                raw_data=tech,
                confidence=tech.get("confidence", 50),
                severity="high" if tech.get("confidence", 0) > 70 else "medium",
                tags=["mitre", tech["tactic"], tech["technique_id"]],
            )
            evidence[f"mitre_{tech['technique_id']}"] = ev.evidence_id
        return evidence