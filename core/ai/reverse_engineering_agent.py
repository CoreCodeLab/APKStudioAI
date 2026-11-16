"""
Reverse Engineering Agent - Agent 3
Investigates obfuscated code, reconstructs execution paths, identifies
dynamically loaded classes, analyzes reflection, investigates native libraries,
reconstructs call relationships, explains suspicious methods.
"""
from pathlib import Path
from typing import Dict, List, Any, Optional
from .agent_base import BaseAgent, AgentTask, AgentResult
from .evidence_repository import Evidence, Severity, AgentID
from ..config_manager import get_config
from ..logging_setup import get_module_logger

logger = get_module_logger("reverse_engineering_agent")


class ReverseEngineeringAgent(BaseAgent):
    """Agent 3: Reverse Engineering - Obfuscation, execution paths, native, reflection."""

    def __init__(self, config: Dict = None, evidence_repo = None,
                 ollama_client = None, rag_engine = None):
        super().__init__(AgentID.REVERSE_ENGINEERING, config, evidence_repo, ollama_client, rag_engine)

    def investigate(self, task: AgentTask) -> AgentResult:
        """Perform reverse engineering analysis."""
        dex_analysis = task.input_data.get("dex_analysis", {})
        advanced_static = task.input_data.get("advanced_static", {})
        native_analysis = task.input_data.get("native_analysis", {})
        jadx_output = task.input_data.get("jadx_output", {})

        evidence_ids = []
        findings = {
            "obfuscation": {},
            "execution_paths": [],
            "dynamic_loading": [],
            "reflection": {},
            "native_analysis": {},
            "call_reconstruction": {},
            "suspicious_methods": [],
        }

        # 1. Obfuscation Analysis
        obfu = advanced_static.get("obfuscation", {})
        findings["obfuscation"] = self._analyze_obfuscation(obfu)
        evidence_ids.extend(self._create_obfu_evidence(findings["obfuscation"]).values())

        # 2. Execution Path Reconstruction
        paths = self._reconstruct_execution_paths(dex_analysis, advanced_static)
        findings["execution_paths"] = paths
        evidence_ids.extend(self._create_path_evidence(paths).values())

        # 3. Dynamic Code Loading
        dyn = advanced_static.get("dynamic_loading", {})
        findings["dynamic_loading"] = self._analyze_dynamic_loading(dyn)
        evidence_ids.extend(self._create_dynload_evidence(findings["dynamic_loading"]).values())

        # 4. Reflection Analysis
        refl = advanced_static.get("reflection", {})
        findings["reflection"] = self._analyze_reflection(refl, dex_analysis)
        evidence_ids.extend(self._create_refl_evidence(findings["reflection"]).values())

        # 5. Native Library Analysis
        findings["native_analysis"] = self._analyze_native(native_analysis)
        evidence_ids.extend(self._create_native_evidence(findings["native_analysis"]).values())

        # 6. Call Relationship Reconstruction
        cg = advanced_static.get("call_graph", {})
        findings["call_reconstruction"] = self._reconstruct_calls(cg, dex_analysis)
        evidence_ids.extend(self._create_call_evidence(findings["call_reconstruction"]).values())

        # 7. Suspicious Methods Explanation
        findings["suspicious_methods"] = self._explain_suspicious_methods(
            dex_analysis, advanced_static, jadx_output
        )
        evidence_ids.extend(self._create_suspicious_method_evidence(findings["suspicious_methods"]).values())

        return AgentResult(
            task_id=task.task_id,
            agent_id=self.agent_id,
            success=True,
            evidence_ids=evidence_ids,
            findings=findings,
        )

    def _analyze_obfuscation(self, obfu: Dict) -> Dict:
        """Analyze obfuscation findings."""
        return {
            "total_findings": obfu.get("total_findings", 0),
            "risk_score": obfu.get("risk_score", 0),
            "by_type": obfu.get("by_type", {}),
            "findings": obfu.get("findings", []),
            "has_string_encryption": "string_encryption" in obfu.get("by_type", {}),
            "has_reflection": "reflection" in obfu.get("by_type", {}),
            "has_dynamic_loading": "dynamic_code_loading" in obfu.get("by_type", {}),
            "has_packers": "packer_detected" in obfu.get("by_type", {}),
            "has_anti_analysis": "anti_analysis" in obfu.get("by_type", {}),
            "packers_detected": obfu.get("by_type", {}).get("packer_detected", []),
        }

    def _reconstruct_execution_paths(self, dex: Dict, advanced: Dict) -> List[Dict]:
        """Reconstruct key execution paths."""
        paths = []

        # Entry point paths
        cg = advanced.get("call_graph", {})
        sensitive_paths = cg.get("sensitive_paths", [])

        for path in sensitive_paths[:20]:
            paths.append({
                "type": "entry_to_sensitive",
                "path": path,
                "length": len(path),
                "description": f"Path from entry point to sensitive API ({len(path)} hops)",
            })

        # Taint paths
        taint = advanced.get("taint", {})
        for summary in taint.get("summary", []):
            paths.append({
                "type": "taint_flow",
                "source": summary.get("source"),
                "sink": summary.get("sink"),
                "path": summary.get("path"),
                "source_types": summary.get("source_types"),
                "sink_types": summary.get("sink_types"),
                "flow_type": summary.get("flow_type"),
                "description": f"Taint flow: {summary.get('source')} -> {summary.get('sink')}",
            })

        return paths

    def _analyze_dynamic_loading(self, dyn: Dict) -> List[Dict]:
        """Analyze dynamic code loading sites."""
        sites = []
        for site in dyn.get("load_sites", []):
            sites.append({
                "loader_type": site.get("loader_type"),
                "class": site.get("class"),
                "method": site.get("method"),
                "dex_path": site.get("dex_path"),
                "optimized_dir": site.get("optimized_directory"),
                "library_path": site.get("library_path"),
                "risk_level": site.get("risk_level"),
                "description": f"{site.get('loader_type')} in {site.get('class')}.{site.get('method')}",
            })
        return sites

    def _analyze_reflection(self, refl: Dict, dex: Dict) -> Dict:
        """Analyze reflection usage."""
        return {
            "total_calls": refl.get("total_reflection_calls", 0),
            "resolved_count": refl.get("resolved_count", 0),
            "resolutions": refl.get("resolutions", {}),
            "unresolved": refl.get("total_reflection_calls", 0) - refl.get("resolved_count", 0),
            "reflection_types": self._categorize_reflection(dex.get("api_calls", [])),
        }

    def _categorize_reflection(self, api_calls: List[Dict]) -> Dict:
        """Categorize reflection calls by type."""
        categories = {
            "class_loading": [],
            "method_invocation": [],
            "field_access": [],
            "constructor": [],
            "accessibility": [],
        }

        for call in api_calls:
            call_str = call.get("call", "")
            if "Class.forName" in call_str:
                categories["class_loading"].append(call)
            elif "Method.invoke" in call_str:
                categories["method_invocation"].append(call)
            elif "Field.get" in call_str or "Field.set" in call_str:
                categories["field_access"].append(call)
            elif "Constructor.newInstance" in call_str or "Class.newInstance" in call_str:
                categories["constructor"].append(call)
            elif "setAccessible" in call_str:
                categories["accessibility"].append(call)

        return {k: len(v) for k, v in categories.items()}

    def _analyze_native(self, native: Dict) -> Dict:
        """Analyze native libraries."""
        libs = native.get("libraries", [])

        analysis = {
            "total_libraries": len(libs),
            "libraries": [],
            "has_jni_onload": False,
            "total_native_methods": 0,
            "suspicious_native": [],
        }

        for lib in libs:
            lib_info = {
                "name": lib.get("name"),
                "path": lib.get("path"),
                "architecture": lib.get("architecture"),
                "exports": len(lib.get("exports", [])),
                "imports": len(lib.get("imports", [])),
                "jni_onload": lib.get("jni_onload", {}).get("found", False),
                "native_methods": len(lib.get("native_methods", [])),
            }

            if lib_info["jni_onload"]:
                analysis["has_jni_onload"] = True

            analysis["total_native_methods"] += lib_info["native_methods"]
            analysis["libraries"].append(lib_info)

            # Check for suspicious native patterns
            for method in lib.get("native_methods", []):
                name = method.get("name", "")
                if any(sus in name.lower() for sus in ["decrypt", "encrypt", "hide", "obfusc", "anti", "shell"]):
                    analysis["suspicious_native"].append({
                        "library": lib.get("name"),
                        "method": name,
                        "address": method.get("address"),
                    })

        return analysis

    def _reconstruct_calls(self, cg: Dict, dex: Dict) -> Dict:
        """Reconstruct call relationships."""
        return {
            "statistics": cg.get("statistics", {}),
            "sensitive_paths": cg.get("sensitive_paths", [])[:20],
            "key_call_chains": self._find_key_chains(dex.get("api_calls", [])),
        }

    def _find_key_chains(self, api_calls: List[Dict]) -> List[Dict]:
        """Find key call chains."""
        chains = []

        # Group by class
        by_class = {}
        for call in api_calls:
            cls = call.get("class", "")
            if cls not in by_class:
                by_class[cls] = []
            by_class[cls].append(call)

        # Find classes with multiple sensitive APIs
        for cls, calls in by_class.items():
            sensitive = [c for c in calls if self._is_sensitive(c.get("call", ""))]
            if len(sensitive) >= 3:
                chains.append({
                    "class": cls,
                    "sensitive_call_count": len(sensitive),
                    "calls": [c.get("call") for c in sensitive],
                })

        return chains

    def _is_sensitive(self, call: str) -> bool:
        """Check if call is sensitive."""
        sensitive = ["exec", "loadLibrary", "DexClassLoader", "Class.forName", "Method.invoke",
                     "Cipher", "sendTextMessage", "HttpURLConnection", "Socket", "DevicePolicyManager"]
        return any(s in call for s in sensitive)

    def _explain_suspicious_methods(self, dex: Dict, advanced: Dict, jadx: Dict) -> List[Dict]:
        """Explain suspicious methods."""
        methods = []

        # From taint analysis
        taint = advanced.get("taint", {})
        for path in taint.get("summary", []):
            methods.append({
                "method": path.get("sink", "").split(".")[-1] if "." in path.get("sink", "") else path.get("sink"),
                "class": ".".join(path.get("sink", "").split(".")[:-1]) if "." in path.get("sink", "") else "",
                "reason": f"Data flow from {path.get('source')} to {path.get('sink')}",
                "source_types": path.get("source_types"),
                "sink_types": path.get("sink_types"),
                "flow_type": path.get("flow_type"),
            })

        # From YARA matches
        yara = advanced.get("yara", {})
        for match in yara.get("matches", [])[:10]:
            if match.get("matched"):
                methods.append({
                    "method": "N/A",
                    "class": "N/A",
                    "reason": f"YARA rule match: {match.get('rule')}",
                    "rule": match.get("rule"),
                })

        # From behavior analysis
        api_calls = dex.get("api_calls", [])
        for call in api_calls:
            call_str = call.get("call", "")
            if any(s in call_str for s in ["DexClassLoader", "InMemoryDexClassLoader", "Runtime.exec",
                                            "ProcessBuilder", "DevicePolicyManager.lockNow",
                                            "DevicePolicyManager.wipeData", "AccessibilityService"]):
                methods.append({
                    "method": call.get("method"),
                    "class": call.get("class"),
                    "reason": f"Suspicious API: {call_str}",
                    "call": call_str,
                })

        return methods[:30]

    def _create_obfu_evidence(self, findings: Dict) -> Dict[str, str]:
        """Create obfuscation evidence."""
        evidence = {}
        if findings.get("total_findings", 0) > 0:
            ev = self.create_evidence(
                analysis_module="obfuscation_analysis",
                file_path="multiple",
                description=f"Obfuscation detected: {findings['total_findings']} findings, risk score {findings['risk_score']}",
                raw_data=findings,
                confidence=85,
                severity="high" if findings.get("risk_score", 0) > 50 else "medium",
                tags=["obfuscation"] + list(findings.get("by_type", {}).keys()),
            )
            evidence["obfuscation_summary"] = ev.evidence_id
        return evidence

    def _create_path_evidence(self, paths: List[Dict]) -> Dict[str, str]:
        """Create execution path evidence."""
        evidence = {}
        for i, path in enumerate(paths[:10]):
            ev = self.create_evidence(
                analysis_module="execution_path",
                file_path=path.get("source", path.get("class", "unknown")),
                description=f"Execution path ({path.get('type', 'unknown')}): {path.get('description', '')}",
                raw_data=path,
                confidence=75,
                severity="high" if path.get("type") == "taint_flow" else "medium",
                tags=["execution_path", path.get("type", "unknown")],
            )
            evidence[f"path_{i}"] = ev.evidence_id
        return evidence

    def _create_dynload_evidence(self, sites: List[Dict]) -> Dict[str, str]:
        """Create dynamic loading evidence."""
        evidence = {}
        for site in sites:
            ev = self.create_evidence(
                analysis_module="dynamic_loading",
                file_path=site.get("class", "unknown"),
                description=site.get("description", ""),
                method_name=site.get("method"),
                raw_data=site,
                confidence=80,
                severity="critical" if site.get("risk_level") == "critical" else "high",
                tags=["dynamic_loading", site.get("loader_type", "unknown")],
            )
            evidence[f"dynload_{site.get('class')}_{site.get('method')}"] = ev.evidence_id
        return evidence

    def _create_refl_evidence(self, findings: Dict) -> Dict[str, str]:
        """Create reflection evidence."""
        evidence = {}
        if findings.get("total_calls", 0) > 0:
            ev = self.create_evidence(
                analysis_module="reflection_analysis",
                file_path="multiple",
                description=f"Reflection: {findings['total_calls']} calls, {findings['resolved_count']} resolved",
                raw_data=findings,
                confidence=80,
                severity="high" if findings.get("unresolved", 0) > 5 else "medium",
                tags=["reflection"] + [k for k, v in findings.get("reflection_types", {}).items() if v > 0],
            )
            evidence["reflection_summary"] = ev.evidence_id
        return evidence

    def _create_native_evidence(self, findings: Dict) -> Dict[str, str]:
        """Create native analysis evidence."""
        evidence = {}
        if findings.get("total_libraries", 0) > 0:
            ev = self.create_evidence(
                analysis_module="native_analysis",
                file_path="native_libs",
                description=f"Native: {findings['total_libraries']} libs, {findings['total_native_methods']} methods, JNI_OnLoad: {findings['has_jni_onload']}",
                raw_data=findings,
                confidence=85,
                severity="high" if findings.get("suspicious_native") else "medium",
                tags=["native", "jni_onload" if findings.get("has_jni_onload") else "no_jni_onload"],
            )
            evidence["native_summary"] = ev.evidence_id

        for sus in findings.get("suspicious_native", [])[:5]:
            ev = self.create_evidence(
                analysis_module="suspicious_native",
                file_path=sus.get("library"),
                description=f"Suspicious native method: {sus['method']}",
                raw_data=sus,
                confidence=70,
                severity="high",
                tags=["native", "suspicious"],
            )
            evidence[f"sus_native_{sus['library']}_{sus['method']}"] = ev.evidence_id
        return evidence

    def _create_call_evidence(self, findings: Dict) -> Dict[str, str]:
        """Create call reconstruction evidence."""
        evidence = {}
        stats = findings.get("statistics", {})
        if stats.get("nodes", 0) > 0:
            ev = self.create_evidence(
                analysis_module="call_graph",
                file_path="call_graph",
                description=f"Call graph: {stats.get('nodes')} nodes, {stats.get('edges')} edges, {stats.get('sensitive_apis')} sensitive APIs",
                raw_data=findings,
                confidence=80,
                severity="medium",
                tags=["call_graph"],
            )
            evidence["call_graph"] = ev.evidence_id
        return evidence

    def _create_suspicious_method_evidence(self, methods: List[Dict]) -> Dict[str, str]:
        """Create suspicious method evidence."""
        evidence = {}
        for i, method in enumerate(methods[:15]):
            ev = self.create_evidence(
                analysis_module="suspicious_method",
                file_path=method.get("class", "unknown"),
                method_name=method.get("method"),
                description=method.get("reason", "Suspicious method"),
                raw_data=method,
                confidence=70,
                severity="high",
                tags=["suspicious_method"],
            )
            evidence[f"sus_method_{i}"] = ev.evidence_id
        return evidence