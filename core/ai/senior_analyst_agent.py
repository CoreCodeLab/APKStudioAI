"""
Senior Malware Analyst Agent - Agent 8
Combines all verified findings, builds investigation timeline,
explains overall threat, identifies most suspicious components,
produces final technical assessment.
"""
from pathlib import Path
from typing import Dict, List, Any, Optional
from .agent_base import BaseAgent, AgentTask, AgentResult
from .evidence_repository import Evidence, Severity, AgentID, VerificationStatus
from ..config_manager import get_config
from ..logging_setup import get_module_logger

logger = get_module_logger("senior_analyst_agent")


class SeniorAnalystAgent(BaseAgent):
    """Agent 8: Senior Malware Analyst - Final synthesis and assessment."""

    def __init__(self, config: Dict = None, evidence_repo = None,
                 ollama_client = None, rag_engine = None):
        super().__init__(AgentID.SENIOR_ANALYST, config, evidence_repo, ollama_client, rag_engine)

    def investigate(self, task: AgentTask) -> AgentResult:
        """Produce final assessment."""
        all_evidence = task.input_data.get("all_evidence", [])
        agent_results = task.input_data.get("agent_results", {})
        verification_results = task.input_data.get("verification_results", {})

        evidence_ids = []
        findings = {
            "executive_summary": "",
            "threat_assessment": {},
            "investigation_timeline": [],
            "key_findings": [],
            "most_suspicious_components": [],
            "risk_assessment": {},
            "mitre_coverage": {},
            "recommendations": [],
            "limitations": [],
            "confidence": 0,
        }

        # Filter to verified evidence only
        verified_evidence = [
            e for e in all_evidence
            if e.get("verification_status") != "refuted"
        ]

        # 1. Executive Summary
        findings["executive_summary"] = self._generate_executive_summary(
            verified_evidence, agent_results, verification_results
        )

        # 2. Threat Assessment
        findings["threat_assessment"] = self._assess_threat(
            verified_evidence, agent_results
        )

        # 3. Investigation Timeline
        findings["investigation_timeline"] = self._build_timeline(agent_results)

        # 4. Key Findings (top verified evidence)
        findings["key_findings"] = self._extract_key_findings(verified_evidence)
        evidence_ids.extend(self._create_key_finding_evidence(findings["key_findings"]).values())

        # 5. Most Suspicious Components
        findings["most_suspicious_components"] = self._identify_suspicious_components(verified_evidence)
        evidence_ids.extend(self._create_component_evidence(findings["most_suspicious_components"]).values())

        # 6. Risk Assessment
        findings["risk_assessment"] = self._assess_risk(
            verified_evidence, agent_results, verification_results
        )

        # 7. MITRE Coverage
        findings["mitre_coverage"] = self._analyze_mitre_coverage(verified_evidence)

        # 8. Recommendations
        findings["recommendations"] = self._generate_recommendations(findings)

        # 9. Limitations
        findings["limitations"] = self._identify_limitations(verified_evidence, agent_results)

        # 10. Overall Confidence
        findings["confidence"] = self._calculate_confidence(findings, verification_results)

        return AgentResult(
            task_id=task.task_id,
            agent_id=self.agent_id,
            success=True,
            evidence_ids=evidence_ids,
            findings=findings,
        )

    def _generate_executive_summary(self, evidence: List[Dict], agent_results: Dict,
                                    verification: Dict) -> str:
        """Generate executive summary."""
        # Get primary threat info
        threat_research = agent_results.get("threat_researcher", {})
        primary_family = threat_research.get("family_attribution", {}).get("primary_family")
        risk = threat_research.get("risk", {})

        family_name = primary_family.get("family", "Unknown") if primary_family else "Unknown"
        risk_level = risk.get("risk_level", "UNKNOWN")
        risk_score = risk.get("score", 0)

        # Count critical findings
        critical_count = sum(1 for e in evidence if e.get("severity") == "critical")
        high_count = sum(1 for e in evidence if e.get("severity") == "high")

        # Get verification stats
        verified = verification.get("verification_summary", {})
        verified_count = verified.get("verified_count", 0)
        refuted_count = verified.get("refuted_count", 0)

        summary = f"""This APK has been analyzed by the APKStudioAI multi-agent system and classified as {risk_level} risk (score: {risk_score}/100).
The primary threat attribution is {family_name} with {verified_count} verified findings and {refuted_count} refuted claims.
{critical_count} critical and {high_count} high-severity issues were confirmed.
The application exhibits {'malicious' if risk_score >= 60 else 'suspicious' if risk_score >= 40 else 'potentially unwanted' if risk_score >= 20 else 'benign'} behavior requiring {'immediate attention' if risk_score >= 60 else 'further investigation' if risk_score >= 40 else 'standard review'}."""

        return summary.strip()

    def _assess_threat(self, evidence: List[Dict], agent_results: Dict) -> Dict:
        """Assess overall threat."""
        threat_research = agent_results.get("threat_researcher", {})
        primary = threat_research.get("family_attribution", {}).get("primary_family")

        return {
            "classification": primary.get("family", "Unknown") if primary else "Unknown",
            "confidence": threat_research.get("confidence", 0),
            "severity": primary.get("severity", "medium") if primary else "medium",
            "categories": list(threat_research.get("family_attribution", {}).get("all_matches", {}).keys()),
            "behavioral_profile": self._build_behavioral_profile(evidence),
            "capabilities": self._extract_capabilities(evidence),
        }

    def _build_behavioral_profile(self, evidence: List[Dict]) -> List[str]:
        """Build behavioral profile from evidence."""
        behaviors = set()
        for ev in evidence:
            module = ev.get("analysis_module", "")
            if module in ["surveillance", "persistence", "network_behavior", "dangerous_api"]:
                behaviors.add(module)
            for tag in ev.get("tags", []):
                if tag in ["surveillance", "persistence", "exfiltration", "c2", "obfuscation", "dynamic_loading"]:
                    behaviors.add(tag)
        return sorted(list(behaviors))

    def _extract_capabilities(self, evidence: List[Dict]) -> Dict[str, bool]:
        """Extract confirmed capabilities."""
        caps = {
            "data_exfiltration": False,
            "credential_theft": False,
            "surveillance": False,
            "persistence": False,
            "dynamic_code_loading": False,
            "root_exploit": False,
            "ransomware": False,
            "c2_communication": False,
            "anti_analysis": False,
            "obfuscation": False,
        }

        for ev in evidence:
            desc = ev.get("description", "").lower()
            module = ev.get("analysis_module", "")
            tags = ev.get("tags", [])

            if "exfil" in desc or "network_send" in desc:
                caps["data_exfiltration"] = True
            if "credential" in desc or "password" in desc or "keylog" in desc:
                caps["credential_theft"] = True
            if any(t in tags for t in ["surveillance", "camera", "audio", "location", "contacts", "sms"]):
                caps["surveillance"] = True
            if "persistence" in module or "boot" in desc or "device_admin" in desc:
                caps["persistence"] = True
            if "dynamic_loading" in module or "DexClassLoader" in desc:
                caps["dynamic_code_loading"] = True
            if "root" in desc or "exploit" in desc or "privilege" in desc:
                caps["root_exploit"] = True
            if "ransom" in desc or "encrypt" in desc or "wipe" in desc:
                caps["ransomware"] = True
            if "c2" in module or "c2" in desc:
                caps["c2_communication"] = True
            if "anti_analysis" in module or "emulator" in desc or "debugger" in desc:
                caps["anti_analysis"] = True
            if "obfuscation" in module or "string_encryption" in tags:
                caps["obfuscation"] = True

        return caps

    def _build_timeline(self, agent_results: Dict) -> List[Dict]:
        """Build investigation timeline."""
        timeline = []

        for agent_id, result in agent_results.items():
            if isinstance(result, dict) and "findings" in result:
                completed_at = result.get("completed_at", "")
                if completed_at:
                    timeline.append({
                        "timestamp": completed_at,
                        "agent": agent_id,
                        "action": f"Completed {agent_id} analysis",
                        "evidence_count": len(result.get("evidence_ids", [])),
                        "success": result.get("success", False),
                    })

        # Sort by timestamp
        timeline.sort(key=lambda x: x.get("timestamp", ""))
        return timeline

    def _extract_key_findings(self, evidence: List[Dict]) -> List[Dict]:
        """Extract top verified findings."""
        # Sort by severity and confidence
        severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

        sorted_ev = sorted(
            evidence,
            key=lambda e: (severity_order.get(e.get("severity", "medium"), 2), e.get("confidence", 0)),
            reverse=True
        )

        key_findings = []
        for ev in sorted_ev[:20]:
            key_findings.append({
                "evidence_id": ev.get("evidence_id"),
                "module": ev.get("analysis_module"),
                "description": ev.get("description"),
                "severity": ev.get("severity"),
                "confidence": ev.get("confidence"),
                "agent": ev.get("agent_id"),
                "tags": ev.get("tags", []),
            })

        return key_findings

    def _identify_suspicious_components(self, evidence: List[Dict]) -> List[Dict]:
        """Identify most suspicious components (classes/files)."""
        component_scores = {}

        for ev in evidence:
            file_path = ev.get("file_path", "")
            class_name = ev.get("class_name", "")
            method_name = ev.get("method_name", "")
            severity = ev.get("severity", "medium")
            confidence = ev.get("confidence", 50)

            # Score components
            severity_weight = {"critical": 25, "high": 15, "medium": 8, "low": 3, "info": 1}.get(severity, 5)
            score = severity_weight * (confidence / 100)

            # Key by class
            if class_name:
                key = class_name
                if key not in component_scores:
                    component_scores[key] = {"score": 0, "file": file_path, "methods": set(), "evidence": []}
                component_scores[key]["score"] += score
                if method_name:
                    component_scores[key]["methods"].add(method_name)
                component_scores[key]["evidence"].append(ev.get("evidence_id"))

        # Sort and return top
        sorted_components = sorted(
            component_scores.items(),
            key=lambda x: x[1]["score"],
            reverse=True
        )

        return [
            {
                "class": cls,
                "file": info["file"],
                "score": round(info["score"], 1),
                "methods": list(info["methods"])[:10],
                "evidence_count": len(info["evidence"]),
            }
            for cls, info in sorted_components[:15]
        ]

    def _assess_risk(self, evidence: List[Dict], agent_results: Dict,
                     verification: Dict) -> Dict:
        """Final risk assessment."""
        # Get original risk from threat_researcher agent
        threat_research = agent_results.get("threat_researcher", {})
        original = threat_research.get("risk", {})
        verification_summary = verification.get("verification_summary", {})

        return {
            "original_score": original.get("score", 0),
            "original_level": original.get("risk_level", "UNKNOWN"),
            "verified_evidence_count": len(evidence),
            "refuted_count": verification_summary.get("refuted_count", 0),
            "final_score": verification_summary.get("recalculated_risk", original.get("score", 0)),
            "final_level": self._score_to_level(
                verification_summary.get("recalculated_risk", original.get("score", 0))
            ),
            "confidence": self._calculate_risk_confidence(evidence, verification),
            "factors": original.get("factors", []),
        }

    def _score_to_level(self, score: int) -> str:
        if score >= 80: return "Critical"
        elif score >= 60: return "High"
        elif score >= 40: return "Suspicious"
        elif score >= 20: return "Moderate"
        return "Low"

    def _calculate_risk_confidence(self, evidence: List[Dict], verification: Dict) -> int:
        """Calculate confidence in risk assessment."""
        if not evidence:
            return 0

        verified = verification.get("verification_summary", {})
        total = verified.get("total_evidence", len(evidence))
        verified_count = verified.get("verified_count", 0)
        refuted_count = verified.get("refuted_count", 0)

        if total == 0:
            return 0

        verification_rate = verified_count / total
        refutation_rate = refuted_count / total

        # Base confidence from verification
        confidence = int(verification_rate * 80)

        # Boost for critical/high findings
        critical_high = sum(1 for e in evidence if e.get("severity") in ["critical", "high"])
        confidence += min(20, critical_high * 2)

        # Penalty for refutations
        confidence -= int(refutation_rate * 30)

        return max(0, min(100, confidence))

    def _analyze_mitre_coverage(self, evidence: List[Dict]) -> Dict:
        """Analyze MITRE ATT&CK coverage."""
        techniques = set()
        tactics = set()

        for ev in evidence:
            module = ev.get("analysis_module", "")
            if module == "mitre_technique":
                raw = ev.get("raw_data", {})
                tech_id = raw.get("technique_id")
                tactic = raw.get("tactic")
                if tech_id:
                    techniques.add(tech_id)
                if tactic:
                    tactics.add(tactic)
            for tag in ev.get("tags", []):
                if tag.startswith("T1"):  # MITRE technique ID
                    techniques.add(tag)

        # Map tactics to count
        tactic_counts = {}
        for tech in techniques:
            # Would need full mapping, simplified here
            pass

        return {
            "techniques_identified": sorted(list(techniques)),
            "technique_count": len(techniques),
            "tactics_covered": sorted(list(tactics)),
            "coverage_percentage": round(len(techniques) / 50 * 100, 1),  # ~50 mobile techniques
        }

    def _generate_recommendations(self, findings: Dict) -> List[str]:
        """Generate actionable recommendations."""
        recommendations = []

        threat = findings.get("threat_assessment", {})
        risk = findings.get("risk_assessment", {})
        capabilities = threat.get("capabilities", {})

        if risk.get("final_level") in ["Critical", "High"]:
            recommendations.append("IMMEDIATE: Block/quarantine this application. Do not install on production devices.")

        if capabilities.get("data_exfiltration"):
            recommendations.append("Investigate data exfiltration paths. Monitor network traffic for suspicious connections.")

        if capabilities.get("credential_theft"):
            recommendations.append("Rotate any credentials that may have been exposed. Monitor for account takeover attempts.")

        if capabilities.get("surveillance"):
            recommendations.append("Review privacy implications. Notify users if surveillance capabilities were active.")

        if capabilities.get("dynamic_code_loading"):
            recommendations.append("Dynamic code loading detected. Perform dynamic analysis to identify payloads.")

        if capabilities.get("c2_communication"):
            recommendations.append("Block identified C2 infrastructure at network perimeter. Monitor for beaconing.")

        if capabilities.get("anti_analysis"):
            recommendations.append("Anti-analysis techniques present. Use advanced dynamic analysis with anti-evasion.")

        if capabilities.get("obfuscation"):
            recommendations.append("Code is obfuscated. Allocate additional time for manual reverse engineering.")

        if findings.get("limitations"):
            recommendations.append(f"Analysis limitations identified: {'; '.join(findings['limitations'][:3])}")

        recommendations.append("Conduct dynamic analysis in isolated environment to confirm behavioral findings.")
        recommendations.append("Share IOCs with threat intelligence team for infrastructure tracking.")

        return recommendations

    def _identify_limitations(self, evidence: List[Dict], agent_results: Dict) -> List[str]:
        """Identify analysis limitations."""
        limitations = []

        # Check for dynamic analysis
        dynamic = agent_results.get("dynamic_analysis", {})
        if not dynamic or not dynamic.get("completed"):
            limitations.append("No dynamic analysis performed - runtime behavior unconfirmed")

        # Check for native analysis depth
        native_evidence = [e for e in evidence if e.get("analysis_module") == "native_analysis"]
        if not native_evidence:
            limitations.append("Limited native library analysis - native code behavior unknown")

        # Check for encryption
        crypto_evidence = [e for e in evidence if "crypto" in e.get("analysis_module", "")]
        if crypto_evidence:
            limitations.append("Encrypted strings/payloads detected - content not fully analyzed")

        # Check for packed/obfuscated
        obfu_evidence = [e for e in evidence if e.get("analysis_module") == "obfuscation_analysis"]
        if obfu_evidence and obfu_evidence[0].get("raw_data", {}).get("risk_score", 0) > 50:
            limitations.append("Heavy obfuscation detected - static analysis may miss hidden functionality")

        # Check for reflection
        refl_evidence = [e for e in evidence if e.get("analysis_module") == "reflection_analysis"]
        if refl_evidence and refl_evidence[0].get("raw_data", {}).get("unresolved", 0) > 0:
            limitations.append(f"Unresolved reflection calls ({refl_evidence[0]['raw_data']['unresolved']}) - targets unknown")

        # Check for multidex
        dex_evidence = [e for e in evidence if "dex" in e.get("analysis_module", "")]
        if not dex_evidence:
            limitations.append("DEX analysis incomplete - some classes may not have been analyzed")

        return limitations

    def _calculate_confidence(self, findings: Dict, verification: Dict) -> int:
        """Calculate overall assessment confidence."""
        risk_conf = findings.get("risk_assessment", {}).get("confidence", 50)
        threat_conf = findings.get("threat_assessment", {}).get("confidence", 50)
        key_count = len(findings.get("key_findings", []))

        confidence = int((risk_conf + threat_conf) / 2)
        confidence += min(10, key_count)
        return min(100, confidence)

    def _create_key_finding_evidence(self, findings: List[Dict]) -> Dict[str, str]:
        evidence = {}
        for i, f in enumerate(findings):
            ev = self.create_evidence(
                analysis_module="key_finding",
                file_path=f.get("file", "unknown"),
                method_name=f.get("method"),
                description=f"Key finding: {f['description']}",
                raw_data=f,
                confidence=f.get("confidence", 80),
                severity=f.get("severity", "medium"),
                tags=["key_finding", f.get("module", "unknown")],
            )
            evidence[f"key_finding_{i}"] = ev.evidence_id
        return evidence

    def _create_component_evidence(self, components: List[Dict]) -> Dict[str, str]:
        evidence = {}
        for i, c in enumerate(components):
            ev = self.create_evidence(
                analysis_module="suspicious_component",
                file_path=c.get("file", "unknown"),
                description=f"Suspicious component: {c['class']} (score: {c['score']}, {len(c['methods'])} methods)",
                raw_data=c,
                confidence=85,
                severity="high" if c.get("score", 0) > 30 else "medium",
                tags=["suspicious_component"],
            )
            evidence[f"component_{i}"] = ev.evidence_id
        return evidence