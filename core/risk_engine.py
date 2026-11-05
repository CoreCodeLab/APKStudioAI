"""
Risk engine for APKStudioAI 2.1
Calculates 0-100 risk score with evidence classification
"""
from typing import Dict, List, Any
from .permission_analyzer import PermissionAnalyzer


class RiskEngine:
    def __init__(self):
        self.permission_analyzer = PermissionAnalyzer()

        # Weight configuration
        self.weights = {
            # Permission-based (max 30 points)
            "permission_base": 30,

            # Malware detection (max 40 points)
            "malware_confirmed": 40,
            "malware_likely": 25,
            "malware_possible": 15,
            "malware_suspected": 8,

            # Behavior analysis (max 20 points)
            "behavior_high": 20,
            "behavior_medium": 12,
            "behavior_low": 5,

            # Network IOCs (max 15 points)
            "network_c2": 15,
            "network_suspicious": 8,
            "network_telegram": 12,
            "network_firebase": 5,

            # Native code (max 10 points)
            "native_jni_onload": 5,
            "native_many_exports": 5,
            "native_suspicious_strings": 5,

            # Obfuscation/anti-analysis (max 10 points)
            "anti_analysis": 10,
            "obfuscation": 5,
            "hidden_payload": 8,

            # Static analysis quality (negative - max -10 points for clean)
            "clean_manifest": -3,
            "standard_permissions": -2,
            "no_native": -2,
            "no_dynamic_loading": -2
        }

        # Thresholds
        self.thresholds = {
            "critical": 80,
            "high": 60,
            "medium": 40,
            "low": 20,
            "minimal": 0
        }

    def calculate(self, findings: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate overall risk score 0-100."""
        score = 0
        evidence = {
            "indicators": [],      # Direct observable evidence
            "capabilities": [],    # Capability-based (permissions, APIs)
            "confirmed": [],       # Confirmed malicious artifacts
            "hypothesis": [],      # Hypothetical based on patterns
            "unverifiable": []     # Requires dynamic analysis
        }
        breakdown = {}

        # 1. Permission risk (0-30)
        perm_score, perm_evidence = self._score_permissions(findings.get("permissions", []))
        score += perm_score
        breakdown["permissions"] = perm_score
        for e in perm_evidence:
            evidence[e["type"]].append(e)

        # 2. Malware detection (0-40)
        malware_score, malware_evidence = self._score_malware(findings.get("malware", {}))
        score += malware_score
        breakdown["malware_detection"] = malware_score
        for e in malware_evidence:
            evidence[e["type"]].append(e)

        # 3. Behavior analysis (0-20)
        behavior_score, behavior_evidence = self._score_behavior(findings.get("behavior", {}))
        score += behavior_score
        breakdown["behavior"] = behavior_score
        for e in behavior_evidence:
            evidence[e["type"]].append(e)

        # 4. Network IOCs (0-15)
        network_score, network_evidence = self._score_network(findings.get("network", {}))
        score += network_score
        breakdown["network"] = network_score
        for e in network_evidence:
            evidence[e["type"]].append(e)

        # 5. Native code analysis (0-10)
        native_score, native_evidence = self._score_native(findings.get("native", {}))
        score += native_score
        breakdown["native"] = native_score
        for e in native_evidence:
            evidence[e["type"]].append(e)

        # 6. Anti-analysis/obfuscation (0-10)
        anti_score, anti_evidence = self._score_anti_analysis(findings)
        score += anti_score
        breakdown["anti_analysis"] = anti_score
        for e in anti_evidence:
            evidence[e["type"]].append(e)

        # 7. Clean indicators (negative scoring)
        clean_score, clean_evidence = self._score_clean_indicators(findings)
        score += clean_score
        breakdown["clean_indicators"] = clean_score
        for e in clean_evidence:
            evidence[e["type"]].append(e)

        # Clamp to 0-100
        final_score = max(0, min(100, score))

        # Determine risk level
        risk_level = self._get_risk_level(final_score)

        # Generate summary
        summary = self._generate_summary(final_score, risk_level, breakdown, evidence)

        return {
            "score": final_score,
            "risk_level": risk_level,
            "breakdown": breakdown,
            "evidence": evidence,
            "summary": summary,
            "thresholds": self.thresholds
        }

    def _score_permissions(self, permissions: List[str]) -> tuple:
        """Score based on permissions."""
        if not permissions:
            return 0, [{"type": "indicators", "detail": "No permissions found", "score": 0}]

        perm_result = self.permission_analyzer.analyze(permissions)
        risk_score = perm_result.get("risk_score", 0)

        # Scale permission risk (max 30) to our weight
        score = min(self.weights["permission_base"], int(risk_score * 0.3))

        evidence = []
        for risk_level in ["critical", "high"]:
            for perm in perm_result.get("by_risk", {}).get(risk_level, []):
                evidence.append({
                    "type": "capabilities",
                    "detail": f"{risk_level.capitalize()} permission: {perm['permission']}",
                    "permission": perm["permission"],
                    "category": perm["category"],
                    "score": 3 if risk_level == "critical" else 2
                })

        # Capability combinations
        caps = perm_result.get("capabilities", {})
        if caps.get("sms_control") and caps.get("device_admin"):
            evidence.append({
                "type": "confirmed",
                "detail": "SMS control + Device Admin = RAT capability",
                "score": 10
            })
        if caps.get("surveillance") and caps.get("network_intercept"):
            evidence.append({
                "type": "confirmed",
                "detail": "Surveillance + Network interception = Spyware capability",
                "score": 8
            })

        return score, evidence

    def _score_malware(self, malware_findings: Dict) -> tuple:
        """Score based on malware detections."""
        detections = malware_findings.get("detections", [])
        if not detections:
            return 0, [{"type": "indicators", "detail": "No malware categories detected", "score": 0}]

        score = 0
        evidence = []

        for det in detections:
            classification = det.get("classification", "unlikely")
            conf_score = det.get("confidence_score", 0)

            if classification == "confirmed":
                score += self.weights["malware_confirmed"]
                evidence.append({
                    "type": "confirmed",
                    "detail": f"Confirmed: {det['category']} (confidence: {conf_score}%)",
                    "category": det["category"],
                    "score": self.weights["malware_confirmed"]
                })
            elif classification == "likely":
                score += self.weights["malware_likely"]
                evidence.append({
                    "type": "indicators",
                    "detail": f"Likely: {det['category']} (confidence: {conf_score}%)",
                    "category": det["category"],
                    "score": self.weights["malware_likely"]
                })
            elif classification == "possible":
                score += self.weights["malware_possible"]
                evidence.append({
                    "type": "hypothesis",
                    "detail": f"Possible: {det['category']} (confidence: {conf_score}%)",
                    "category": det["category"],
                    "score": self.weights["malware_possible"]
                })
            elif classification == "suspected":
                score += self.weights["malware_suspected"]
                evidence.append({
                    "type": "hypothesis",
                    "detail": f"Suspected: {det['category']} (confidence: {conf_score}%)",
                    "category": det["category"],
                    "score": self.weights["malware_suspected"]
                })

        # Cap at max malware weight
        score = min(score, self.weights["malware_confirmed"])

        return score, evidence

    def _score_behavior(self, behavior_findings: Dict) -> tuple:
        """Score based on behavior analysis."""
        behaviors = behavior_findings.get("detected_behaviors", [])
        if not behaviors:
            return 0, [{"type": "indicators", "detail": "No suspicious behaviors detected", "score": 0}]

        score = 0
        evidence = []

        for beh in behaviors:
            confidence = beh.get("confidence", 0)
            category = beh.get("category", "unknown")

            if confidence >= 70:
                score += self.weights["behavior_high"]
                evidence.append({
                    "type": "indicators",
                    "detail": f"High-confidence behavior: {category} ({confidence}%)",
                    "category": category,
                    "score": self.weights["behavior_high"]
                })
            elif confidence >= 40:
                score += self.weights["behavior_medium"]
                evidence.append({
                    "type": "indicators",
                    "detail": f"Medium-confidence behavior: {category} ({confidence}%)",
                    "category": category,
                    "score": self.weights["behavior_medium"]
                })
            else:
                score += self.weights["behavior_low"]
                evidence.append({
                    "type": "hypothesis",
                    "detail": f"Low-confidence behavior: {category} ({confidence}%)",
                    "category": category,
                    "score": self.weights["behavior_low"]
                })

        # Cap
        score = min(score, self.weights["behavior_high"])

        # Malware categories from behavior
        for mc in behavior_findings.get("malware_categories", []):
            evidence.append({
                "type": "hypothesis",
                "detail": f"Behavior maps to: {mc['category']} ({mc['confidence']} confidence)",
                "score": 5
            })

        return score, evidence

    def _score_network(self, network_findings: Dict) -> tuple:
        """Score based on network IOCs."""
        score = 0
        evidence = []

        # C2 config
        c2_configs = network_findings.get("c2_config", [])
        if c2_configs:
            score += self.weights["network_c2"]
            evidence.append({
                "type": "confirmed",
                "detail": f"C2 configuration detected ({len(c2_configs)} indicators)",
                "score": self.weights["network_c2"]
            })

        # Telegram bots
        telegram = network_findings.get("telegram_bots", [])
        if telegram:
            score += self.weights["network_telegram"]
            evidence.append({
                "type": "confirmed",
                "detail": f"Telegram bot C2 detected ({len(telegram)} bots)",
                "score": self.weights["network_telegram"]
            })

        # Firebase
        firebase = network_findings.get("firebase_config", [])
        if firebase:
            score += self.weights["network_firebase"]
            evidence.append({
                "type": "capabilities",
                "detail": f"Firebase configuration found ({len(firebase)} indicators)",
                "score": self.weights["network_firebase"]
            })

        # Suspicious indicators
        suspicious = network_findings.get("suspicious_indicators", [])
        high_sev = [s for s in suspicious if s.get("severity") == "high"]
        if high_sev:
            score += self.weights["network_suspicious"]
            evidence.append({
                "type": "indicators",
                "detail": f"High-severity network indicators: {len(high_sev)}",
                "score": self.weights["network_suspicious"]
            })

        # Certificate pinning (can be legitimate but also malware)
        pinning = network_findings.get("certificate_pinning", [])
        if pinning:
            evidence.append({
                "type": "capabilities",
                "detail": f"Certificate pinning detected ({len(pinning)} indicators)",
                "score": 3
            })
            score += 3

        # WebSocket
        ws = network_findings.get("websocket", [])
        if ws:
            evidence.append({
                "type": "capabilities",
                "detail": f"WebSocket communication ({len(ws)} indicators)",
                "score": 2
            })
            score += 2

        return min(score, 15), evidence

    def _score_native(self, native_findings: Dict) -> tuple:
        """Score based on native code analysis."""
        score = 0
        evidence = []

        libraries = native_findings.get("libraries", [])
        if not libraries:
            return 0, [{"type": "indicators", "detail": "No native libraries found", "score": 0}]

        for lib in libraries:
            # JNI_OnLoad
            if lib.get("jni_onload", {}).get("found"):
                score += self.weights["native_jni_onload"]
                evidence.append({
                    "type": "capabilities",
                    "detail": f"JNI_OnLoad found in {lib.get('name', 'unknown')}",
                    "library": lib.get("name"),
                    "score": self.weights["native_jni_onload"]
                })

            # Many native methods
            method_count = len(lib.get("native_methods", []))
            if method_count > 20:
                score += self.weights["native_many_exports"]
                evidence.append({
                    "type": "indicators",
                    "detail": f"Many native methods ({method_count}) in {lib.get('name', 'unknown')}",
                    "library": lib.get("name"),
                    "score": self.weights["native_many_exports"]
                })

            # Suspicious strings in native
            suspicious = lib.get("suspicious_strings", [])
            if suspicious:
                score += self.weights["native_suspicious_strings"]
                evidence.append({
                    "type": "indicators",
                    "detail": f"Suspicious strings in native lib {lib.get('name', 'unknown')}: {len(suspicious)}",
                    "library": lib.get("name"),
                    "score": self.weights["native_suspicious_strings"]
                })

        return min(score, 10), evidence

    def _score_anti_analysis(self, findings: Dict) -> tuple:
        """Score based on anti-analysis and obfuscation."""
        score = 0
        evidence = []

        # Check behavior for anti-analysis
        behavior = findings.get("behavior", {})
        for beh in behavior.get("detected_behaviors", []):
            if beh.get("category") == "anti_analysis":
                score += self.weights["anti_analysis"]
                evidence.append({
                    "type": "indicators",
                    "detail": f"Anti-analysis detected (confidence: {beh.get('confidence', 0)}%)",
                    "score": self.weights["anti_analysis"]
                })
                break

        # Check behavior for obfuscation
        for beh in behavior.get("detected_behaviors", []):
            if beh.get("category") == "obfuscation":
                score += self.weights["obfuscation"]
                evidence.append({
                    "type": "indicators",
                    "detail": f"Code obfuscation detected (confidence: {beh.get('confidence', 0)}%)",
                    "score": self.weights["obfuscation"]
                })
                break

        # Check for hidden payload
        for beh in behavior.get("detected_behaviors", []):
            if beh.get("category") == "hidden_payload":
                score += self.weights["hidden_payload"]
                evidence.append({
                    "type": "indicators",
                    "detail": f"Hidden/encrypted payload indicators (confidence: {beh.get('confidence', 0)}%)",
                    "score": self.weights["hidden_payload"]
                })
                break

        # String-based anti-analysis
        strings = findings.get("strings", {}).get("suspicious", [])
        anti_strings = [s for s in strings if s.get("category") == "anti_analysis"]
        if anti_strings:
            evidence.append({
                "type": "indicators",
                "detail": f"Anti-analysis strings found: {len(anti_strings)}",
                "score": 3
            })
            score += 3

        return min(score, 15), evidence

    def _score_clean_indicators(self, findings: Dict) -> tuple:
        """Negative scoring for clean indicators."""
        score = 0
        evidence = []

        manifest = findings.get("manifest", {})
        permissions = findings.get("permissions", [])
        native = findings.get("native", {})
        strings = findings.get("strings", {})

        # Clean manifest
        if not manifest.get("debuggable") and not manifest.get("allow_backup"):
            score += self.weights["clean_manifest"]
            evidence.append({
                "type": "indicators",
                "detail": "Manifest: not debuggable, no backup allowed",
                "score": self.weights["clean_manifest"]
            })

        # Standard permissions only
        perm_result = self.permission_analyzer.analyze(permissions)
        if perm_result.get("risk_score", 100) < 20:
            score += self.weights["standard_permissions"]
            evidence.append({
                "type": "indicators",
                "detail": "Low permission risk score",
                "score": self.weights["standard_permissions"]
            })

        # No native code
        if not native.get("libraries"):
            score += self.weights["no_native"]
            evidence.append({
                "type": "indicators",
                "detail": "No native libraries",
                "score": self.weights["no_native"]
            })

        # No dynamic loading
        behavior = findings.get("behavior", {})
        has_dynamic = any(b.get("category") == "dynamic_code_loading" for b in behavior.get("detected_behaviors", []))
        if not has_dynamic:
            score += self.weights["no_dynamic_loading"]
            evidence.append({
                "type": "indicators",
                "detail": "No dynamic code loading detected",
                "score": self.weights["no_dynamic_loading"]
            })

        return score, evidence

    def _get_risk_level(self, score: int) -> str:
        """Get risk level from score."""
        if score >= self.thresholds["critical"]:
            return "CRITIQUE"
        elif score >= self.thresholds["high"]:
            return "TRÈS ÉLEVÉ"
        elif score >= self.thresholds["medium"]:
            return "ÉLEVÉ"
        elif score >= self.thresholds["low"]:
            return "MODÉRÉ"
        else:
            return "FAIBLE"

    def _generate_summary(self, score: int, risk_level: str,
                          breakdown: Dict, evidence: Dict) -> Dict[str, Any]:
        """Generate human-readable summary."""
        confirmed_count = len(evidence.get("confirmed", []))
        indicator_count = len(evidence.get("indicators", []))
        capability_count = len(evidence.get("capabilities", []))
        hypothesis_count = len(evidence.get("hypothesis", []))
        unverifiable_count = len(evidence.get("unverifiable", []))

        # Top risk factors
        top_factors = []
        for category, cat_score in sorted(breakdown.items(), key=lambda x: x[1], reverse=True):
            if cat_score > 0:
                top_factors.append(f"{category}: +{cat_score}")
            elif cat_score < 0:
                top_factors.append(f"{category}: {cat_score}")

        # Risk description
        descriptions = {
            "CRITIQUE": "Menace immédiate - malware confirmé avec haute confiance",
            "TRÈS ÉLEVÉ": "Menace sérieuse - multiples indicateurs forts de comportement malveillant",
            "ÉLEVÉ": "Menace modérée - patterns suspects nécessitant investigation",
            "MODÉRÉ": "Menace faible - quelques indicateurs suspects mais probablement bénin",
            "FAIBLE": "Menace minime - apparaît propre sans résultats significatifs"
        }

        return {
            "score": score,
            "risk_level": risk_level,
            "description": descriptions.get(risk_level, "Inconnu"),
            "evidence_summary": {
                "confirmed": confirmed_count,
                "indicators": indicator_count,
                "capabilities": capability_count,
                "hypothesis": hypothesis_count,
                "unverifiable": unverifiable_count,
                "total": confirmed_count + indicator_count + capability_count + hypothesis_count + unverifiable_count
            },
            "top_factors": top_factors[:5],
            "recommendation": self._get_recommendation(risk_level)
        }

    def _get_recommendation(self, risk_level: str) -> str:
        """Get recommendation based on risk level."""
        recommendations = {
            "CRITIQUE": "Isolement immédiat et analyse médico-légale requise. Ne pas exécuter sur aucun appareil.",
            "TRÈS ÉLEVÉ": "Ne pas installer. Effectuer une analyse dynamique détaillée en environnement isolé.",
            "ÉLEVÉ": "Examiner attentivement. Considérer une analyse dynamique avant d'autoriser sur appareils d'entreprise.",
            "MODÉRÉ": "Probablement sûr mais revoir permissions et comportement réseau.",
            "FAIBLE": "Apparaît bénin. Revue de sécurité standard suffisante."
        }
        return recommendations.get(risk_level, "Revue manuelle recommandée.")