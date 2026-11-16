"""
Behavioral Analysis Agent - Agent 4
Investigates persistence, surveillance, background execution,
suspicious network activity, file-system operations, runtime events,
behavior combinations.
"""
from pathlib import Path
from typing import Dict, List, Any, Optional
from .agent_base import BaseAgent, AgentTask, AgentResult
from .evidence_repository import Evidence, Severity, AgentID
from ..config_manager import get_config
from ..logging_setup import get_module_logger

logger = get_module_logger("behavioral_agent")


class BehavioralAgent(BaseAgent):
    """Agent 4: Behavioral Analysis - Persistence, surveillance, background, runtime."""

    def __init__(self, config: Dict = None, evidence_repo = None,
                 ollama_client = None, rag_engine = None):
        super().__init__(AgentID.BEHAVIORAL, config, evidence_repo, ollama_client, rag_engine)

    def investigate(self, task: AgentTask) -> AgentResult:
        """Perform behavioral analysis."""
        behavior_analysis = task.input_data.get("behavior_analysis", {})
        manifest_analysis = task.input_data.get("manifest_analysis", {})
        dex_analysis = task.input_data.get("dex_analysis", {})
        network_analysis = task.input_data.get("network_analysis", {})
        advanced_static = task.input_data.get("advanced_static", {})

        evidence_ids = []
        findings = {
            "persistence": [],
            "surveillance": [],
            "background_execution": [],
            "network_behavior": [],
            "file_operations": [],
            "runtime_events": [],
            "behavior_combinations": [],
            "anti_analysis": [],
        }

        # 1. Persistence Mechanisms
        persistence = self._analyze_persistence(manifest_analysis, dex_analysis, behavior_analysis)
        findings["persistence"] = persistence
        evidence_ids.extend(self._create_persistence_evidence(persistence).values())

        # 2. Surveillance Behavior
        surveillance = self._analyze_surveillance(manifest_analysis, dex_analysis, behavior_analysis)
        findings["surveillance"] = surveillance
        evidence_ids.extend(self._create_surveillance_evidence(surveillance).values())

        # 3. Background Execution
        background = self._analyze_background_execution(manifest_analysis, dex_analysis, behavior_analysis)
        findings["background_execution"] = background
        evidence_ids.extend(self._create_background_evidence(background).values())

        # 4. Network Behavior
        network = self._analyze_network_behavior(network_analysis, dex_analysis, advanced_static)
        findings["network_behavior"] = network
        evidence_ids.extend(self._create_network_evidence(network).values())

        # 5. File Operations
        files = self._analyze_file_operations(dex_analysis, behavior_analysis)
        findings["file_operations"] = files
        evidence_ids.extend(self._create_file_evidence(files).values())

        # 6. Runtime Events (from dynamic analysis if available)
        runtime = self._analyze_runtime_events(task.input_data.get("dynamic_analysis", {}))
        findings["runtime_events"] = runtime

        # 7. Anti-Analysis
        anti = self._analyze_anti_analysis(dex_analysis, behavior_analysis, advanced_static)
        findings["anti_analysis"] = anti
        evidence_ids.extend(self._create_anti_evidence(anti).values())

        # 8. Behavior Combinations
        combinations = self._analyze_combinations(findings)
        findings["behavior_combinations"] = combinations
        evidence_ids.extend(self._create_combination_evidence(combinations).values())

        return AgentResult(
            task_id=task.task_id,
            agent_id=self.agent_id,
            success=True,
            evidence_ids=evidence_ids,
            findings=findings,
        )

    def _analyze_persistence(self, manifest: Dict, dex: Dict, behavior: Dict) -> List[Dict]:
        """Analyze persistence mechanisms."""
        findings = []

        # Manifest-based persistence
        for receiver in manifest.get("receivers", []):
            for intent_filter in receiver.get("intent_filters", []):
                for action in intent_filter.get("actions", []):
                    if "BOOT_COMPLETED" in action:
                        findings.append({
                            "type": "boot_receiver",
                            "component": receiver.get("name"),
                            "description": f"Boot receiver: {receiver.get('name')}",
                            "severity": "high",
                        })

        # Service persistence
        for service in manifest.get("services", []):
            if service.get("exported"):
                findings.append({
                    "type": "exported_service",
                    "component": service.get("name"),
                    "description": f"Exported service (persistence vector): {service.get('name')}",
                    "severity": "medium",
                })

        # From behavior analysis
        for detected in behavior.get("detected_behaviors", []):
            if detected.get("category") in ["persistence", "autostart", "boot_completed"]:
                findings.append({
                    "type": "behavior_persistence",
                    "category": detected.get("category"),
                    "confidence": detected.get("confidence"),
                    "methods": detected.get("methods", []),
                    "severity": "high",
                })

        # Device Admin
        for receiver in manifest.get("receivers", []):
            if receiver.get("permission") == "android.permission.BIND_DEVICE_ADMIN":
                findings.append({
                    "type": "device_admin",
                    "component": receiver.get("name"),
                    "description": f"Device admin receiver: {receiver.get('name')}",
                    "severity": "critical",
                })

        return findings

    def _analyze_surveillance(self, manifest: Dict, dex: Dict, behavior: Dict) -> List[Dict]:
        """Analyze surveillance capabilities."""
        findings = []

        # Permissions
        perms = manifest.get("permissions", [])
        if "android.permission.CAMERA" in perms:
            findings.append({
                "type": "camera_access",
                "description": "Camera permission granted",
                "severity": "high",
            })
        if "android.permission.RECORD_AUDIO" in perms:
            findings.append({
                "type": "audio_recording",
                "description": "Audio recording permission granted",
                "severity": "high",
            })
        if "android.permission.ACCESS_FINE_LOCATION" in perms:
            findings.append({
                "type": "location_tracking",
                "description": "Fine location permission granted",
                "severity": "high",
            })
        if "android.permission.READ_CONTACTS" in perms:
            findings.append({
                "type": "contacts_access",
                "description": "Contacts read permission granted",
                "severity": "high",
            })
        if "android.permission.READ_SMS" in perms or "android.permission.RECEIVE_SMS" in perms:
            findings.append({
                "type": "sms_access",
                "description": "SMS access permission granted",
                "severity": "critical",
            })
        if "android.permission.READ_CALL_LOG" in perms:
            findings.append({
                "type": "call_log_access",
                "description": "Call log access permission granted",
                "severity": "high",
            })

        # From DEX analysis - actual usage
        api_calls = dex.get("api_calls", [])
        surveillance_apis = {
            "camera": ["Camera.open", "Camera.takePicture", "MediaProjection"],
            "audio": ["MediaRecorder", "AudioRecord", "startRecording"],
            "location": ["getLastKnownLocation", "requestLocationUpdates", "LocationManager"],
            "contacts": ["ContactsContract", "query"],
            "sms": ["SmsManager", "getMessageBody", "ContentResolver", "content://sms"],
            "call_log": ["CallLog.Calls", "content://call_log"],
            "screen": ["MediaProjection", "createScreenCaptureIntent"],
            "keylog": ["onKeyDown", "dispatchKeyEvent", "AccessibilityService"],
            "clipboard": ["ClipboardManager", "getPrimaryClip"],
        }

        for category, apis in surveillance_apis.items():
            matches = [c for c in api_calls if any(a in c.get("call", "") for a in apis)]
            if matches:
                findings.append({
                    "type": f"surveillance_{category}",
                    "category": category,
                    "call_count": len(matches),
                    "calls": [{"class": c.get("class"), "method": c.get("method"), "call": c.get("call")} for c in matches[:5]],
                    "severity": "critical" if category in ["screen", "keylog", "sms"] else "high",
                })

        return findings

    def _analyze_background_execution(self, manifest: Dict, dex: Dict, behavior: Dict) -> List[Dict]:
        """Analyze background execution capabilities."""
        findings = []

        # Services
        for service in manifest.get("services", []):
            findings.append({
                "type": "service",
                "component": service.get("name"),
                "exported": service.get("exported"),
                "permission": service.get("permission"),
                "description": f"Service: {service.get('name')}",
                "severity": "high" if service.get("exported") else "medium",
            })

        # Foreground service
        api_calls = dex.get("api_calls", [])
        for call in api_calls:
            if "startForeground" in call.get("call", ""):
                findings.append({
                    "type": "foreground_service",
                    "class": call.get("class"),
                    "method": call.get("method"),
                    "description": "Foreground service usage",
                    "severity": "medium",
                })

        # JobScheduler / WorkManager
        for call in api_calls:
            if any(x in call.get("call", "") for x in ["JobScheduler", "WorkManager", "PeriodicWorkRequest"]):
                findings.append({
                    "type": "scheduled_work",
                    "class": call.get("class"),
                    "method": call.get("method"),
                    "call": call.get("call"),
                    "description": "Scheduled background work",
                    "severity": "medium",
                })

        # AlarmManager
        for call in api_calls:
            if "AlarmManager" in call.get("call", ""):
                findings.append({
                    "type": "alarm_manager",
                    "class": call.get("class"),
                    "method": call.get("method"),
                    "description": "AlarmManager usage (persistent scheduling)",
                    "severity": "medium",
                })

        return findings

    def _analyze_network_behavior(self, network: Dict, dex: Dict, advanced: Dict) -> List[Dict]:
        """Analyze network behavior."""
        findings = []

        # C2 indicators
        c2_config = network.get("c2_config", [])
        for c2 in c2_config:
            findings.append({
                "type": "c2_config",
                "description": f"Potential C2 configuration: {c2}",
                "raw": c2,
                "severity": "critical",
            })

        # Suspicious URLs
        urls = network.get("urls", [])
        suspicious_tlds = [".onion", ".top", ".xyz", ".cc", ".tk", ".ml", ".ga"]
        for url in urls:
            if any(tld in url for tld in suspicious_tlds):
                findings.append({
                    "type": "suspicious_tld",
                    "url": url,
                    "description": f"Suspicious TLD in URL: {url}",
                    "severity": "high",
                })

        # WebSocket connections
        for call in dex.get("api_calls", []):
            if "WebSocket" in call.get("call", ""):
                findings.append({
                    "type": "websocket",
                    "class": call.get("class"),
                    "method": call.get("method"),
                    "description": "WebSocket connection (potential C2)",
                    "severity": "high",
                })

        # Certificate pinning bypass
        for call in dex.get("api_calls", []):
            call_str = call.get("call", "")
            if any(x in call_str for x in ["X509TrustManager", "HostnameVerifier", "checkServerTrusted", "verify"]):
                findings.append({
                    "type": "cert_pinning_bypass",
                    "class": call.get("class"),
                    "method": call.get("method"),
                    "call": call_str,
                    "description": "Possible certificate pinning bypass",
                    "severity": "high",
                })

        # DGA indicators
        domains = network.get("domains", [])
        for domain in domains:
            domain_str = domain.get("domain", "") if isinstance(domain, dict) else domain
            if domain_str and self._looks_like_dga(domain_str):
                findings.append({
                    "type": "dga_domain",
                    "domain": domain_str,
                    "description": f"Possible DGA domain: {domain_str}",
                    "severity": "high",
                })

        return findings

    def _looks_like_dga(self, domain: str) -> bool:
        """Check if domain looks like DGA."""
        # Simple heuristic: long random-looking subdomain
        parts = domain.split(".")
        if len(parts) < 2:
            return False
        subdomain = parts[0]
        if len(subdomain) > 15:
            # Check entropy
            import math
            freq = {}
            for c in subdomain:
                freq[c] = freq.get(c, 0) + 1
            entropy = -sum((v/len(subdomain)) * math.log2(v/len(subdomain)) for v in freq.values())
            return entropy > 3.5
        return False

    def _analyze_file_operations(self, dex: Dict, behavior: Dict) -> List[Dict]:
        """Analyze file system operations."""
        findings = []

        api_calls = dex.get("api_calls", [])
        file_apis = {
            "write": ["FileOutputStream", "openFileOutput", "write", "RandomAccessFile"],
            "read": ["FileInputStream", "openFileInput", "read"],
            "delete": ["delete", "deleteFile"],
            "list": ["listFiles", "list"],
            "external": ["getExternalFilesDir", "getExternalStorageDirectory"],
            "crypto": ["CipherOutputStream", "CipherInputStream"],
        }

        for category, apis in file_apis.items():
            matches = [c for c in api_calls if any(a in c.get("call", "") for a in apis)]
            if matches:
                findings.append({
                    "type": f"file_{category}",
                    "category": category,
                    "call_count": len(matches),
                    "calls": [{"class": c.get("class"), "method": c.get("method"), "call": c.get("call")} for c in matches[:5]],
                    "severity": "high" if category in ["write", "delete", "crypto"] else "medium",
                })

        return findings

    def _analyze_runtime_events(self, dynamic: Dict) -> List[Dict]:
        """Analyze runtime events from dynamic analysis."""
        events = []

        for event in dynamic.get("events", []):
            events.append({
                "type": event.get("type"),
                "timestamp": event.get("timestamp"),
                "description": event.get("description"),
                "details": event.get("details"),
                "severity": event.get("severity", "info"),
            })

        return events

    def _analyze_anti_analysis(self, dex: Dict, behavior: Dict, advanced: Dict) -> List[Dict]:
        """Analyze anti-analysis techniques."""
        findings = []

        # From behavior analysis
        for detected in behavior.get("detected_behaviors", []):
            if detected.get("category") in ["anti_emulator", "anti_debug", "anti_analysis"]:
                findings.append({
                    "type": "anti_analysis_behavior",
                    "category": detected.get("category"),
                    "confidence": detected.get("confidence"),
                    "methods": detected.get("methods", []),
                    "severity": "high",
                })

        # From DEX API calls
        api_calls = dex.get("api_calls", [])
        anti_apis = {
            "emulator_check": ["isEmulator", "checkEmulator", "ro.build.tags", "ro.kernel.qemu", "goldfish", "generic"],
            "debugger_check": ["isDebuggerConnected", "waitingForDebugger", "ptrace"],
            "frida_check": ["frida", "Frida", "linjector"],
            "xposed_check": ["xposed", "Xposed", "de.robv.android.xposed"],
            "root_check": ["su", "RootBeer", "RootChecker"],
        }

        for category, apis in anti_apis.items():
            matches = [c for c in api_calls if any(a in c.get("call", "") for a in apis)]
            if matches:
                findings.append({
                    "type": f"anti_{category}",
                    "category": category,
                    "call_count": len(matches),
                    "calls": [{"class": c.get("class"), "method": c.get("method"), "call": c.get("call")} for c in matches[:5]],
                    "severity": "high",
                })

        # From obfuscation
        obfu = advanced.get("obfuscation", {})
        for finding in obfu.get("findings", []):
            if finding.get("type") == "anti_analysis":
                findings.append({
                    "type": "obfuscation_anti_analysis",
                    "description": finding.get("description"),
                    "raw": finding,
                    "severity": "high",
                })

        return findings

    def _analyze_combinations(self, findings: Dict) -> List[Dict]:
        """Analyze dangerous behavior combinations."""
        combinations = []

        # Spyware combo: location + contacts + network exfil
        has_location = any(f.get("type") == "surveillance_location" for f in findings.get("surveillance", []))
        has_contacts = any(f.get("type") == "surveillance_contacts" for f in findings.get("surveillance", []))
        has_network_exfil = any(f.get("type") in ["c2_config", "suspicious_tld", "websocket"] for f in findings.get("network_behavior", []))

        if has_location and has_contacts and has_network_exfil:
            combinations.append({
                "name": "spyware_triad",
                "description": "Location + Contacts + Network Exfiltration = Spyware",
                "components": ["location", "contacts", "network_exfil"],
                "severity": "critical",
            })

        # Banking trojan: overlay + accessibility + SMS intercept
        has_overlay = any(f.get("type") == "surveillance_overlay" or f.get("type") == "overlay" for f in findings.get("surveillance", []))
        has_accessibility = any(f.get("type") == "surveillance_accessibility" for f in findings.get("surveillance", []))
        has_sms = any(f.get("type") == "surveillance_sms" for f in findings.get("surveillance", []))

        if has_overlay and has_accessibility and has_sms:
            combinations.append({
                "name": "banking_trojan",
                "description": "Overlay + Accessibility + SMS = Banking Trojan",
                "components": ["overlay", "accessibility", "sms"],
                "severity": "critical",
            })

        # RAT: dynamic loading + command execution + C2
        has_dynload = len(findings.get("persistence", [])) > 0  # Using persistence as proxy
        has_exec = any(f.get("type") == "surveillance_execution" for f in findings.get("surveillance", []))
        has_c2 = any(f.get("type") == "c2_config" for f in findings.get("network_behavior", []))

        if has_dynload and has_exec and has_c2:
            combinations.append({
                "name": "rat",
                "description": "Dynamic Loading + Command Execution + C2 = RAT",
                "components": ["dynload", "execution", "c2"],
                "severity": "critical",
            })

        # Ransomware: file encryption + device admin + lock screen
        has_crypto = any(f.get("type") == "file_crypto" for f in findings.get("file_operations", []))
        has_device_admin = any(f.get("type") == "device_admin" for f in findings.get("persistence", []))
        has_lock = any("lockNow" in str(f) for f in findings.get("surveillance", []))

        if has_crypto and has_device_admin:
            combinations.append({
                "name": "ransomware",
                "description": "File Encryption + Device Admin = Ransomware",
                "components": ["crypto", "device_admin"],
                "severity": "critical",
            })

        return combinations

    def _create_persistence_evidence(self, findings: List[Dict]) -> Dict[str, str]:
        evidence = {}
        for i, f in enumerate(findings):
            ev = self.create_evidence(
                analysis_module="persistence",
                file_path=f.get("component", "AndroidManifest.xml"),
                description=f.get("description", ""),
                raw_data=f,
                confidence=85,
                severity=f.get("severity", "medium"),
                tags=["persistence", f.get("type", "unknown")],
            )
            evidence[f"persistence_{i}"] = ev.evidence_id
        return evidence

    def _create_surveillance_evidence(self, findings: List[Dict]) -> Dict[str, str]:
        evidence = {}
        for i, f in enumerate(findings):
            ev = self.create_evidence(
                analysis_module="surveillance",
                file_path=f.get("class", f.get("component", "unknown")),
                method_name=f.get("method"),
                description=f.get("description", ""),
                raw_data=f,
                confidence=80,
                severity=f.get("severity", "medium"),
                tags=["surveillance", f.get("type", "unknown")],
            )
            evidence[f"surveillance_{i}"] = ev.evidence_id
        return evidence

    def _create_background_evidence(self, findings: List[Dict]) -> Dict[str, str]:
        evidence = {}
        for i, f in enumerate(findings):
            ev = self.create_evidence(
                analysis_module="background_execution",
                file_path=f.get("component", f.get("class", "unknown")),
                method_name=f.get("method"),
                description=f.get("description", ""),
                raw_data=f,
                confidence=75,
                severity=f.get("severity", "medium"),
                tags=["background", f.get("type", "unknown")],
            )
            evidence[f"background_{i}"] = ev.evidence_id
        return evidence

    def _create_network_evidence(self, findings: List[Dict]) -> Dict[str, str]:
        evidence = {}
        for i, f in enumerate(findings):
            ev = self.create_evidence(
                analysis_module="network_behavior",
                file_path=f.get("class", f.get("url", f.get("domain", "unknown"))),
                method_name=f.get("method"),
                description=f.get("description", ""),
                raw_data=f,
                confidence=80,
                severity=f.get("severity", "medium"),
                tags=["network", f.get("type", "unknown")],
            )
            evidence[f"network_{i}"] = ev.evidence_id
        return evidence

    def _create_file_evidence(self, findings: List[Dict]) -> Dict[str, str]:
        evidence = {}
        for i, f in enumerate(findings):
            ev = self.create_evidence(
                analysis_module="file_operations",
                file_path=f.get("class", "unknown"),
                method_name=f.get("method"),
                description=f.get("description", ""),
                raw_data=f,
                confidence=75,
                severity=f.get("severity", "medium"),
                tags=["file_ops", f.get("type", "unknown")],
            )
            evidence[f"file_{i}"] = ev.evidence_id
        return evidence

    def _create_anti_evidence(self, findings: List[Dict]) -> Dict[str, str]:
        evidence = {}
        for i, f in enumerate(findings):
            ev = self.create_evidence(
                analysis_module="anti_analysis",
                file_path=f.get("class", "unknown"),
                method_name=f.get("method"),
                description=f.get("description", ""),
                raw_data=f,
                confidence=80,
                severity=f.get("severity", "medium"),
                tags=["anti_analysis", f.get("type", "unknown")],
            )
            evidence[f"anti_{i}"] = ev.evidence_id
        return evidence

    def _create_combination_evidence(self, findings: List[Dict]) -> Dict[str, str]:
        evidence = {}
        for combo in findings:
            ev = self.create_evidence(
                analysis_module="behavior_combination",
                file_path="multiple",
                description=combo.get("description", ""),
                raw_data=combo,
                confidence=90,
                severity=combo.get("severity", "critical"),
                tags=["combination", combo.get("name", "unknown")],
            )
            evidence[combo.get("name", "unknown")] = ev.evidence_id
        return evidence