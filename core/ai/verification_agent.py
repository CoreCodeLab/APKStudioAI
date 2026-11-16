"""
Verification Agent - Agent 7
Independent review of other agents' findings.
Challenges unsupported conclusions, identifies false positives,
detects contradictions, verifies source references, recalculates risk scores.
"""
from pathlib import Path
from typing import Dict, List, Any, Optional
from .agent_base import BaseAgent, AgentTask, AgentResult
from .evidence_repository import Evidence, Severity, AgentID, VerificationStatus
from ..config_manager import get_config
from ..logging_setup import get_module_logger

logger = get_module_logger("verification_agent")


class VerificationAgent(BaseAgent):
    """Agent 7: Independent Verification - Challenges findings, detects false positives."""

    def __init__(self, config: Dict = None, evidence_repo = None,
                 ollama_client = None, rag_engine = None):
        super().__init__(AgentID.VERIFICATION, config, evidence_repo, ollama_client, rag_engine)

    def investigate(self, task: AgentTask) -> AgentResult:
        """Verify other agents' findings."""
        all_evidence = task.input_data.get("all_evidence", [])
        agent_results = task.input_data.get("agent_results", {})

        evidence_ids = []
        findings = {
            "verified": [],
            "refuted": [],
            "contradictions": [],
            "false_positives": [],
            "missing_evidence": [],
            "risk_recalculation": {},
            "verification_summary": {},
        }

        # 1. Verify each piece of evidence
        for evidence_data in all_evidence:
            verification = self._verify_evidence(evidence_data)
            if verification["status"] == "verified":
                findings["verified"].append(verification)
            elif verification["status"] == "refuted":
                findings["refuted"].append(verification)
            elif verification["status"] == "contradicted":
                findings["contradictions"].append(verification)

            # Update evidence verification status in repo
            if self.evidence_repo and evidence_data.get("evidence_id"):
                self.evidence_repo.verify_evidence(
                    evidence_data["evidence_id"],
                    VerificationStatus(verification["status"]),
                    self.agent_id,
                    verification.get("notes", "")
                )

        # 2. Detect contradictions between agents
        contradictions = self._detect_contradictions(all_evidence)
        findings["contradictions"].extend(contradictions)

        # 3. Identify false positives
        false_positives = self._identify_false_positives(all_evidence, agent_results)
        findings["false_positives"] = false_positives

        # 4. Check for missing investigation steps
        missing = self._check_missing_steps(all_evidence, agent_results)
        findings["missing_evidence"] = missing

        # 5. Recalculate risk scores
        risk_recalc = self._recalculate_risk(all_evidence, agent_results)
        findings["risk_recalculation"] = risk_recalc

        # 6. Verification summary
        # Get original risk from threat_researcher agent
        threat_research = agent_results.get("threat_researcher", {})
        original_risk = threat_research.get("risk", {}).get("score", 0)

        findings["verification_summary"] = {
            "total_evidence": len(all_evidence),
            "verified_count": len(findings["verified"]),
            "refuted_count": len(findings["refuted"]),
            "contradiction_count": len(findings["contradictions"]),
            "false_positive_count": len(findings["false_positives"]),
            "missing_steps_count": len(findings["missing_evidence"]),
            "original_risk": original_risk,
            "recalculated_risk": risk_recalc.get("recalculated_score", risk_recalc.get("score", 0)),
        }

        # Create verification evidence
        for item in findings["verified"] + findings["refuted"] + findings["contradictions"]:
            evidence_ids.append(self._create_verification_evidence(item).evidence_id)

        for fp in findings["false_positives"]:
            evidence_ids.append(self._create_fp_evidence(fp).evidence_id)

        return AgentResult(
            task_id=task.task_id,
            agent_id=self.agent_id,
            success=True,
            evidence_ids=evidence_ids,
            findings=findings,
        )

    def _verify_evidence(self, evidence: Dict) -> Dict:
        """Verify a single piece of evidence."""
        evidence_id = evidence.get("evidence_id", "")
        agent_id = evidence.get("agent_id", "")
        module = evidence.get("analysis_module", "")
        description = evidence.get("description", "")
        raw_data = evidence.get("raw_data", {})
        confidence = evidence.get("confidence", 50)
        severity = evidence.get("severity", "medium")

        verification = {
            "evidence_id": evidence_id,
            "agent_id": agent_id,
            "module": module,
            "status": "verified",
            "confidence_adjustment": 0,
            "notes": "",
            "checks": [],
        }

        checks = []

        # Modules that require code references
        code_modules = ["dangerous_api", "suspicious_sequence", "hidden_functionality",
                        "dynamic_loading", "reflection_analysis", "suspicious_method",
                        "execution_path", "taint_flow", "icc_sensitive_flow",
                        "surveillance", "persistence", "network_behavior", "file_operations",
                        "anti_analysis", "obfuscation_analysis", "native_analysis"]

        # Modules that require source references
        source_modules = ["yara_match", "family_attribution", "family_match",
                          "malicious_pattern", "mitre_technique", "c2_infrastructure"]

        # Check 1: Source reference validity (only for modules that should have it)
        if module in source_modules:
            if evidence.get("source_reference"):
                checks.append({
                    "check": "source_reference",
                    "passed": True,
                    "detail": f"Source reference present: {evidence['source_reference'][:100]}",
                })
            else:
                checks.append({
                    "check": "source_reference",
                    "passed": False,
                    "detail": "No source reference provided for signature-based finding",
                })
                verification["confidence_adjustment"] -= 10
        else:
            checks.append({
                "check": "source_reference",
                "passed": True,
                "detail": "Not required for this module type",
            })

        # Check 2: Code reference validity (only for code-level findings)
        class_name = evidence.get("class_name")
        method_name = evidence.get("method_name")
        if module in code_modules:
            if class_name and method_name:
                checks.append({
                    "check": "code_reference",
                    "passed": True,
                    "detail": f"Code reference: {class_name}.{method_name}",
                })
            else:
                checks.append({
                    "check": "code_reference",
                    "passed": False,
                    "detail": "Missing class/method reference for code-level finding",
                })
                verification["confidence_adjustment"] -= 5
        else:
            checks.append({
                "check": "code_reference",
                "passed": True,
                "detail": "Not required for this module type",
            })

        # Check 3: Confidence reasonableness
        if confidence > 90 and not evidence.get("source_reference") and module in source_modules:
            checks.append({
                "check": "confidence_calibration",
                "passed": False,
                "detail": "High confidence without source reference for signature-based finding",
            })
            verification["confidence_adjustment"] -= 15
            verification["status"] = "refuted"
            verification["notes"] = "High confidence claim without supporting evidence"
        else:
            checks.append({
                "check": "confidence_calibration",
                "passed": True,
                "detail": f"Confidence {confidence}% seems calibrated",
            })

        # Check 4: Severity alignment
        expected_severity = self._expected_severity(module, raw_data)
        if expected_severity and expected_severity != severity:
            checks.append({
                "check": "severity_alignment",
                "passed": False,
                "detail": f"Severity {severity} differs from expected {expected_severity}",
            })
            verification["confidence_adjustment"] -= 10
        else:
            checks.append({
                "check": "severity_alignment",
                "passed": True,
                "detail": f"Severity {severity} aligns with findings",
            })

        # Check 5: Raw data consistency
        if raw_data:
            checks.append({
                "check": "raw_data_present",
                "passed": True,
                "detail": f"Raw data keys: {list(raw_data.keys())}",
            })
        else:
            checks.append({
                "check": "raw_data_present",
                "passed": False,
                "detail": "No raw data provided",
            })
            verification["confidence_adjustment"] -= 5

        verification["checks"] = checks

        # Determine final status - only refute for clear contradictions
        failed_checks = [c for c in checks if not c["passed"]]
        critical_failures = [c for c in failed_checks if c["check"] in ["confidence_calibration", "severity_alignment"]]

        if len(critical_failures) >= 1:
            verification["status"] = "refuted"
            verification["notes"] = f"Critical verification failure: {critical_failures[0]['detail']}"
        elif len(failed_checks) >= 3:
            verification["status"] = "pending"
            verification["notes"] = f"Multiple checks failed ({len(failed_checks)})"
        elif len(failed_checks) >= 1:
            verification["status"] = "verified"  # Minor issues don't refute
            verification["notes"] = f"Minor issue: {failed_checks[0]['detail']}"

        return verification

    def _expected_severity(self, module: str, raw_data: Dict) -> Optional[str]:
        """Determine expected severity based on module and data."""
        critical_modules = ["dynamic_loading", "c2_infrastructure", "family_attribution", "suspicious_method"]
        high_modules = ["dangerous_api", "surveillance", "persistence", "network_behavior", "mitre_technique"]

        if module in critical_modules:
            return "critical"
        elif module in high_modules:
            return "high"
        elif module in ["permission", "manifest_analysis", "file_operations"]:
            return "medium"
        return None

    def _detect_contradictions(self, all_evidence: List[Dict]) -> List[Dict]:
        """Detect contradictions between evidence from different agents."""
        contradictions = []

        # Group by file/method
        by_location = {}
        for ev in all_evidence:
            key = f"{ev.get('file_path', '')}:{ev.get('method_name', '')}"
            if key not in by_location:
                by_location[key] = []
            by_location[key].append(ev)

        # Check for contradictory severity/confidence
        for location, evidences in by_location.items():
            if len(evidences) < 2:
                continue

            severities = [e.get("severity") for e in evidences if e.get("severity")]
            if len(set(severities)) > 1:
                # Check if it's a real contradiction (e.g., critical vs info)
                severity_order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
                max_sev = max(severities, key=lambda s: severity_order.get(s, 0))
                min_sev = min(severities, key=lambda s: severity_order.get(s, 0))
                if severity_order[max_sev] - severity_order[min_sev] >= 3:
                    contradictions.append({
                        "type": "severity_contradiction",
                        "location": location,
                        "evidence_ids": [e.get("evidence_id") for e in evidences],
                        "severities": severities,
                        "agents": [e.get("agent_id") for e in evidences],
                        "description": f"Contradictory severities at {location}: {min_sev} vs {max_sev}",
                    })

        return contradictions

    def _identify_false_positives(self, all_evidence: List[Dict], agent_results: Dict) -> List[Dict]:
        """Identify likely false positives."""
        false_positives = []

        # Common false positive patterns
        fp_patterns = {
            "legitimate_ad_sdk": {
                "modules": ["dangerous_api", "network_behavior"],
                "indicators": ["AdView", "AdMob", "AdRequest", "loadAd", "InterstitialAd"],
                "description": "Legitimate advertising SDK detected as suspicious",
            },
            "legitimate_analytics": {
                "modules": ["network_behavior", "dangerous_api"],
                "indicators": ["FirebaseAnalytics", "GoogleAnalytics", "Mixpanel", "Amplitude"],
                "description": "Legitimate analytics framework",
            },
            "legitimate_crash_reporting": {
                "modules": ["dangerous_api", "network_behavior"],
                "indicators": ["Crashlytics", "Bugsnag", "Sentry", "ACRA"],
                "description": "Legitimate crash reporting",
            },
            "legitimate_payment": {
                "modules": ["dangerous_api", "surveillance"],
                "indicators": ["Stripe", "PayPal", "Braintree", "GooglePay", "ApplePay"],
                "description": "Legitimate payment processing",
            },
            "legitimate_push": {
                "modules": ["network_behavior", "dangerous_api"],
                "indicators": ["FirebaseMessaging", "OneSignal", "Pushwoosh", "GCM", "FCM"],
                "description": "Legitimate push notifications",
            },
        }

        for ev in all_evidence:
            module = ev.get("analysis_module", "")
            description = ev.get("description", "").lower()
            raw_data = ev.get("raw_data", {})

            for fp_name, fp_info in fp_patterns.items():
                if module in fp_info["modules"]:
                    for indicator in fp_info["indicators"]:
                        if indicator.lower() in description or indicator.lower() in str(raw_data).lower():
                            false_positives.append({
                                "evidence_id": ev.get("evidence_id"),
                                "pattern": fp_name,
                                "description": fp_info["description"],
                                "indicator": indicator,
                                "original_severity": ev.get("severity"),
                                "suggested_severity": "info",
                                "confidence": 80,
                            })
                            break

        return false_positives

    def _check_missing_steps(self, all_evidence: List[Dict], agent_results: Dict) -> List[Dict]:
        """Check for missing investigation steps."""
        missing = []

        # Check which agents ran
        agents_run = set()
        for ev in all_evidence:
            agents_run.add(ev.get("agent_id", ""))

        expected_agents = {
            "apk_intelligence",
            "static_analysis",
            "reverse_engineering",
            "behavioral",
            "network_intelligence",
            "threat_researcher",
        }

        for expected in expected_agents:
            if expected not in agents_run:
                missing.append({
                    "type": "missing_agent",
                    "agent": expected,
                    "description": f"Agent {expected} did not produce evidence",
                    "severity": "medium",
                })

        # Check for key analyses
        modules_covered = set(ev.get("analysis_module", "") for ev in all_evidence)
        key_modules = [
            "manifest_analysis", "permission_analysis", "dangerous_api",
            "dynamic_loading", "obfuscation_analysis", "call_graph",
            "taint_analysis", "icc_analysis", "c2_infrastructure",
            "family_attribution", "mitre_technique",
        ]

        for module in key_modules:
            if not any(module in m for m in modules_covered):
                missing.append({
                    "type": "missing_analysis",
                    "module": module,
                    "description": f"Key analysis module {module} not found",
                    "severity": "medium",
                })

        return missing

    def _recalculate_risk(self, all_evidence: List[Dict], agent_results: Dict) -> Dict:
        """Recalculate risk score based on verified evidence."""
        original_score = agent_results.get("risk", {}).get("score", 0)

        # Count verified evidence by severity
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for ev in all_evidence:
            sev = ev.get("severity", "medium")
            if sev in severity_counts:
                severity_counts[sev] += 1

        # Weighted scoring
        weights = {"critical": 25, "high": 15, "medium": 8, "low": 3, "info": 1}
        recalculated = sum(severity_counts[s] * weights[s] for s in severity_counts)
        recalculated = min(100, recalculated)

        # Adjust for false positives
        fp_count = len([e for e in all_evidence if e.get("analysis_module") in ["yara_match"]])
        # Don't penalize for YARA matches, they're signatures

        return {
            "original_score": original_score,
            "recalculated_score": recalculated,
            "recalculated_risk": recalculated,  # Alias for compatibility
            "difference": recalculated - original_score,
            "severity_breakdown": severity_counts,
            "explanation": f"Recalculated from {sum(severity_counts.values())} evidence items",
        }

    def _create_verification_evidence(self, verification: Dict) -> Evidence:
        status = verification.get("status", "verified")
        severity = "info" if status == "verified" else "high" if status == "refuted" else "medium"

        return self.create_evidence(
            analysis_module="verification",
            file_path=verification.get("evidence_id", "unknown"),
            description=f"Verification {status}: {verification.get('notes', 'Passed checks')}",
            raw_data=verification,
            confidence=90,
            severity=severity,
            tags=["verification", status, verification.get("module", "unknown")],
        )

    def _create_fp_evidence(self, fp: Dict) -> Evidence:
        return self.create_evidence(
            analysis_module="false_positive",
            file_path=fp.get("evidence_id", "unknown"),
            description=f"False positive detected: {fp['description']} (indicator: {fp['indicator']})",
            raw_data=fp,
            confidence=fp.get("confidence", 80),
            severity="info",
            tags=["false_positive", fp.get("pattern", "unknown")],
        )