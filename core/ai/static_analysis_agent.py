"""
Static Analysis Agent - Agent 2
Analyzes manifest, permissions, Java/Kotlin code, DEX/Smali,
identifies dangerous API usage, suspicious method sequences, hidden functionality.
"""
from pathlib import Path
from typing import Dict, List, Any, Optional
from .agent_base import BaseAgent, AgentTask, AgentResult
from .evidence_repository import Evidence, Severity, AgentID
from ..config_manager import get_config
from ..logging_setup import get_module_logger

logger = get_module_logger("static_analysis_agent")


class StaticAnalysisAgent(BaseAgent):
    """Agent 2: Static Analysis - Manifest, permissions, code, APIs, behaviors."""

    def __init__(self, config: Dict = None, evidence_repo = None,
                 ollama_client = None, rag_engine = None):
        super().__init__(AgentID.STATIC_ANALYSIS, config, evidence_repo, ollama_client, rag_engine)

    def investigate(self, task: AgentTask) -> AgentResult:
        """Perform static analysis."""
        manifest_analysis = task.input_data.get("manifest_analysis", {})
        dex_analysis = task.input_data.get("dex_analysis", {})
        string_analysis = task.input_data.get("string_analysis", {})
        behavior_analysis = task.input_data.get("behavior_analysis", {})
        network_analysis = task.input_data.get("network_analysis", {})
        advanced_static = task.input_data.get("advanced_static", {})

        evidence_ids = []
        findings = {
            "manifest": {},
            "permissions": [],
            "dangerous_apis": [],
            "suspicious_sequences": [],
            "hidden_functionality": [],
            "code_patterns": {},
        }

        # 1. Manifest Analysis
        manifest_findings = self._analyze_manifest(manifest_analysis)
        findings["manifest"] = manifest_findings
        evidence_ids.extend(self._create_manifest_evidence(manifest_findings).values())

        # 2. Permission Analysis
        perm_findings = self._analyze_permissions(manifest_analysis)
        findings["permissions"] = perm_findings
        evidence_ids.extend(self._create_permission_evidence(perm_findings).values())

        # 3. Dangerous API Usage
        api_findings = self._analyze_dangerous_apis(dex_analysis, advanced_static)
        findings["dangerous_apis"] = api_findings
        evidence_ids.extend(self._create_api_evidence(api_findings).values())

        # 4. Suspicious Method Sequences
        seq_findings = self._analyze_suspicious_sequences(dex_analysis, behavior_analysis)
        findings["suspicious_sequences"] = seq_findings
        evidence_ids.extend(self._create_sequence_evidence(seq_findings).values())

        # 5. Hidden Functionality
        hidden_findings = self._analyze_hidden_functionality(dex_analysis, string_analysis, advanced_static)
        findings["hidden_functionality"] = hidden_findings
        evidence_ids.extend(self._create_hidden_evidence(hidden_findings).values())

        # 6. Code Patterns
        patterns = self._analyze_code_patterns(dex_analysis, advanced_static)
        findings["code_patterns"] = patterns

        return AgentResult(
            task_id=task.task_id,
            agent_id=self.agent_id,
            success=True,
            evidence_ids=evidence_ids,
            findings=findings,
        )

    def _analyze_manifest(self, manifest: Dict) -> Dict:
        """Analyze manifest for security issues."""
        issues = []

        # Debuggable
        if manifest.get("debuggable", False):
            issues.append({
                "type": "debuggable",
                "description": "Application is debuggable in production",
                "severity": "medium",
            })

        # Cleartext traffic
        if manifest.get("uses_cleartext_traffic", False):
            issues.append({
                "type": "cleartext_traffic",
                "description": "Application allows cleartext HTTP traffic",
                "severity": "high",
            })

        # Backup allowed
        if manifest.get("allow_backup", True):
            issues.append({
                "type": "backup_allowed",
                "description": "Application allows backup (data extraction risk)",
                "severity": "low",
            })

        # Shared user ID
        if manifest.get("shared_user_id"):
            issues.append({
                "type": "shared_user_id",
                "description": f"Shared user ID: {manifest['shared_user_id']}",
                "severity": "medium",
            })

        # Exported components without permission
        for comp_type in ["activities", "services", "receivers", "providers"]:
            for comp in manifest.get(comp_type, []):
                if comp.get("exported") and not comp.get("permission"):
                    issues.append({
                        "type": "unprotected_exported",
                        "description": f"Exported {comp_type[:-1]} without permission: {comp.get('name')}",
                        "component": comp.get("name"),
                        "component_type": comp_type[:-1],
                        "severity": "high",
                    })

        return {
            "issues": issues,
            "package": manifest.get("package"),
            "permissions": manifest.get("permissions", []),
        }

    def _analyze_permissions(self, manifest: Dict) -> List[Dict]:
        """Analyze requested permissions."""
        dangerous_perms = {
            "android.permission.READ_PHONE_STATE": {"risk": "high", "category": "device_id"},
            "android.permission.READ_SMS": {"risk": "critical", "category": "sms"},
            "android.permission.RECEIVE_SMS": {"risk": "critical", "category": "sms"},
            "android.permission.SEND_SMS": {"risk": "critical", "category": "sms"},
            "android.permission.READ_CONTACTS": {"risk": "high", "category": "contacts"},
            "android.permission.ACCESS_FINE_LOCATION": {"risk": "high", "category": "location"},
            "android.permission.ACCESS_COARSE_LOCATION": {"risk": "medium", "category": "location"},
            "android.permission.CAMERA": {"risk": "high", "category": "camera"},
            "android.permission.RECORD_AUDIO": {"risk": "high", "category": "audio"},
            "android.permission.READ_EXTERNAL_STORAGE": {"risk": "medium", "category": "storage"},
            "android.permission.WRITE_EXTERNAL_STORAGE": {"risk": "medium", "category": "storage"},
            "android.permission.SYSTEM_ALERT_WINDOW": {"risk": "high", "category": "overlay"},
            "android.permission.BIND_ACCESSIBILITY_SERVICE": {"risk": "critical", "category": "accessibility"},
            "android.permission.BIND_DEVICE_ADMIN": {"risk": "critical", "category": "device_admin"},
            "android.permission.BIND_VPN_SERVICE": {"risk": "critical", "category": "vpn"},
            "android.permission.INTERNET": {"risk": "low", "category": "network"},
            "android.permission.ACCESS_NETWORK_STATE": {"risk": "low", "category": "network"},
        }

        findings = []
        for perm in manifest.get("permissions", []):
            if perm in dangerous_perms:
                info = dangerous_perms[perm]
                findings.append({
                    "permission": perm,
                    "risk": info["risk"],
                    "category": info["category"],
                    "description": f"Dangerous permission: {perm}",
                })

        return findings

    def _analyze_dangerous_apis(self, dex: Dict, advanced: Dict) -> List[Dict]:
        """Analyze dangerous API usage."""
        findings = []

        # From DEX analysis
        api_calls = dex.get("api_calls", [])

        # Sensitive API categories
        sensitive_categories = {
            "device_id": ["getDeviceId", "getSubscriberId", "getSimSerialNumber", "getImei", "getMeid"],
            "location": ["getLastKnownLocation", "requestLocationUpdates", "getLatitude", "getLongitude"],
            "contacts": ["query", "ContactsContract"],
            "sms": ["sendTextMessage", "sendMultipartTextMessage", "getMessageBody"],
            "camera": ["Camera.open", "takePicture"],
            "audio": ["MediaRecorder", "AudioRecord"],
            "network": ["HttpURLConnection", "OkHttpClient", "WebSocket", "Socket"],
            "crypto": ["Cipher.getInstance", "Cipher.init", "Cipher.doFinal", "MessageDigest"],
            "execution": ["Runtime.exec", "ProcessBuilder", "loadLibrary", "load"],
            "dynamic_loading": ["DexClassLoader", "PathClassLoader", "InMemoryDexClassLoader", "DexFile.loadDex"],
            "reflection": ["Class.forName", "Method.invoke", "Field.set", "Constructor.newInstance"],
            "overlay": ["SYSTEM_ALERT_WINDOW", "addContentView"],
            "accessibility": ["AccessibilityService", "onAccessibilityEvent"],
            "device_admin": ["DevicePolicyManager", "lockNow", "resetPassword", "wipeData"],
        }

        # Group by category
        by_category = {}
        for call in api_calls:
            call_str = call.get("call", "")
            for category, patterns in sensitive_categories.items():
                if any(p in call_str for p in patterns):
                    if category not in by_category:
                        by_category[category] = []
                    by_category[category].append({
                        "class": call.get("class"),
                        "method": call.get("method"),
                        "call": call_str,
                    })
                    break

        # Add advanced static findings
        if advanced:
            taint = advanced.get("taint", {})
            for path in taint.get("summary", []):
                findings.append({
                    "type": "taint_flow",
                    "category": "data_flow",
                    "source": path.get("source"),
                    "sink": path.get("sink"),
                    "path": path.get("path"),
                    "severity": "high",
                })

            icc = advanced.get("icc", {})
            for flow in icc.get("sensitive_flows", []):
                findings.append({
                    "type": "icc_sensitive_flow",
                    "category": "icc",
                    "source": flow.get("source"),
                    "sink": flow.get("sink"),
                    "method": flow.get("method"),
                    "severity": "high",
                })

        for category, calls in by_category.items():
            findings.append({
                "type": "dangerous_api",
                "category": category,
                "call_count": len(calls),
                "calls": calls[:10],  # Limit
                "severity": self._get_category_severity(category),
            })

        return findings

    def _get_category_severity(self, category: str) -> str:
        """Get severity for API category."""
        critical = ["execution", "dynamic_loading", "accessibility", "device_admin", "overlay"]
        high = ["device_id", "location", "contacts", "sms", "camera", "audio", "crypto", "reflection"]
        medium = ["network"]

        if category in critical:
            return "critical"
        elif category in high:
            return "high"
        elif category in medium:
            return "medium"
        return "low"

    def _analyze_suspicious_sequences(self, dex: Dict, behavior: Dict) -> List[Dict]:
        """Analyze suspicious method sequences."""
        findings = []

        # From behavior analysis
        for detected in behavior.get("detected_behaviors", []):
            if detected.get("confidence", 0) > 70:
                findings.append({
                    "type": "behavior_pattern",
                    "category": detected.get("category"),
                    "confidence": detected.get("confidence"),
                    "methods": detected.get("methods", []),
                    "severity": "high" if detected.get("confidence", 0) > 85 else "medium",
                })

        # Look for sequences in API calls
        api_calls = dex.get("api_calls", [])
        by_method = {}
        for call in api_calls:
            key = f"{call.get('class')}.{call.get('method')}"
            if key not in by_method:
                by_method[key] = []
            by_method[key].append(call.get("call", ""))

        # Check for suspicious combinations in same method
        suspicious_combos = [
            (["getDeviceId", "getSubscriberId"], ["HttpURLConnection", "sendTextMessage"], "device_id_exfil"),
            (["getLastKnownLocation"], ["HttpURLConnection", "WebSocket"], "location_exfil"),
            (["query", "ContactsContract"], ["HttpURLConnection"], "contacts_exfil"),
            (["DexClassLoader", "loadClass"], ["Runtime.exec"], "dynamic_load_exec"),
            (["Class.forName", "Method.invoke"], ["Cipher"], "reflection_crypto"),
        ]

        for method, calls in by_method.items():
            for sources, sinks, name in suspicious_combos:
                has_source = any(any(s in c for c in calls) for s in sources)
                has_sink = any(any(s in c for c in calls) for s in sinks)
                if has_source and has_sink:
                    findings.append({
                        "type": "suspicious_sequence",
                        "name": name,
                        "method": method,
                        "source_apis": [c for c in calls if any(s in c for s in sources)],
                        "sink_apis": [c for c in calls if any(s in c for s in sinks)],
                        "severity": "high",
                    })

        return findings

    def _analyze_hidden_functionality(self, dex: Dict, strings: Dict, advanced: Dict) -> List[Dict]:
        """Analyze hidden functionality."""
        findings = []

        # Dynamic code loading
        dyn_loading = advanced.get("dynamic_loading", {})
        for site in dyn_loading.get("load_sites", []):
            findings.append({
                "type": "dynamic_code_loading",
                "loader": site.get("loader_type"),
                "class": site.get("class"),
                "method": site.get("method"),
                "risk": site.get("risk_level"),
                "severity": "critical" if site.get("risk_level") == "critical" else "high",
            })

        # Reflection
        reflection = advanced.get("reflection", {})
        if reflection.get("resolved_count", 0) > 0:
            findings.append({
                "type": "reflection_usage",
                "resolved_count": reflection.get("resolved_count"),
                "total_calls": reflection.get("total_reflection_calls"),
                "resolutions": reflection.get("resolutions", {}),
                "severity": "high",
            })

        # Obfuscation
        obfu = advanced.get("obfuscation", {})
        if obfu.get("total_findings", 0) > 0:
            for finding in obfu.get("findings", [])[:10]:
                findings.append({
                    "type": "obfuscation",
                    "obfuscation_type": finding.get("type"),
                    "description": finding.get("description"),
                    "severity": finding.get("severity", "medium"),
                })

        # Hidden strings (decoded)
        for decoded in strings.get("decoded_strings", [])[:20]:
            if any(kw in decoded.get("decoded", "").lower() for kw in ["password", "key", "secret", "token", "api"]):
                findings.append({
                    "type": "hidden_string",
                    "original": decoded.get("original"),
                    "decoded": decoded.get("decoded"),
                    "method": decoded.get("method"),
                    "severity": "high",
                })

        return findings

    def _analyze_code_patterns(self, dex: Dict, advanced: Dict) -> Dict:
        """Analyze code patterns."""
        patterns = {}

        # Call graph stats
        cg = advanced.get("call_graph", {}).get("statistics", {})
        patterns["call_graph"] = {
            "nodes": cg.get("nodes", 0),
            "edges": cg.get("edges", 0),
            "sensitive_apis": cg.get("sensitive_apis", 0),
            "entry_points": cg.get("entry_points", 0),
        }

        # Taint stats
        taint = advanced.get("taint", {}).get("statistics", {})
        patterns["taint"] = {
            "tainted_methods": taint.get("tainted_methods", 0),
            "source_sink_paths": taint.get("source_sink_paths", 0),
        }

        # ICC stats
        icc = advanced.get("icc", {}).get("statistics", {})
        patterns["icc"] = {
            "total_edges": icc.get("total_icc_edges", 0),
            "exported_components": icc.get("exported_components", 0),
        }

        return patterns

    def _create_manifest_evidence(self, findings: Dict) -> Dict[str, str]:
        """Create evidence for manifest issues."""
        evidence = {}
        package = findings.get("package") or "unknown"
        for issue in findings.get("issues", []):
            ev = self.create_evidence(
                analysis_module="manifest_analysis",
                file_path=package,
                description=issue.get("description", ""),
                raw_data=issue,
                confidence=85,
                severity=issue.get("severity", "medium"),
                tags=["manifest", issue.get("type", "issue")],
            )
            evidence[issue.get("type", "issue")] = ev.evidence_id
        return evidence

    def _create_permission_evidence(self, findings: List[Dict]) -> Dict[str, str]:
        """Create evidence for permissions."""
        evidence = {}
        for perm in findings:
            ev = self.create_evidence(
                analysis_module="permission_analysis",
                file_path="AndroidManifest.xml",
                description=perm.get("description", ""),
                raw_data=perm,
                confidence=90,
                severity=perm.get("risk", "medium"),
                tags=["permission", perm.get("category", "unknown")],
            )
            evidence[perm.get("permission", "unknown")] = ev.evidence_id
        return evidence

    def _create_api_evidence(self, findings: List[Dict]) -> Dict[str, str]:
        """Create evidence for dangerous APIs."""
        evidence = {}
        for api in findings:
            # Only create evidence for dangerous_api type findings
            if api.get("type") != "dangerous_api":
                continue
            calls = api.get("calls") or []
            first_class = calls[0].get("class") if calls else None
            file_path = first_class or "unknown"
            ev = self.create_evidence(
                analysis_module="dangerous_api",
                file_path=file_path,
                description=f"Dangerous API ({api['category']}): {api.get('call_count', 0)} calls",
                raw_data=api,
                confidence=80,
                severity=api.get("severity", "medium"),
                tags=["api", api.get("category", "unknown")],
            )
            evidence[api.get("category", "unknown")] = ev.evidence_id
        return evidence

    def _create_sequence_evidence(self, findings: List[Dict]) -> Dict[str, str]:
        """Create evidence for suspicious sequences."""
        evidence = {}
        for seq in findings:
            file_path = seq.get("method") or "unknown"
            ev = self.create_evidence(
                analysis_module="suspicious_sequence",
                file_path=file_path,
                description=f"Suspicious sequence: {seq.get('name', seq.get('type', 'unknown'))}",
                raw_data=seq,
                confidence=75,
                severity=seq.get("severity", "medium"),
                tags=["sequence", seq.get("type", "unknown")],
            )
            evidence[seq.get("name", seq.get("type", "unknown"))] = ev.evidence_id
        return evidence

    def _create_hidden_evidence(self, findings: List[Dict]) -> Dict[str, str]:
        """Create evidence for hidden functionality."""
        evidence = {}
        for hidden in findings:
            file_path = hidden.get("class") or hidden.get("method") or "unknown"
            ev = self.create_evidence(
                analysis_module="hidden_functionality",
                file_path=file_path,
                description=f"Hidden functionality: {hidden.get('type', 'unknown')}",
                raw_data=hidden,
                confidence=70,
                severity=hidden.get("severity", "medium"),
                tags=["hidden", hidden.get("type", "unknown")],
            )
            evidence[hidden.get("type", "unknown")] = ev.evidence_id
        return evidence