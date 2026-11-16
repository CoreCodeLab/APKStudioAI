"""
Enhanced Ollama client for APKStudioAI 2.1
Supports timeout, chunking, context preservation, no-AI mode
"""
import json
import time
import re
import requests
from typing import Dict, List, Any, Optional, Generator
from pathlib import Path
from .utils import run_command
from .config_manager import get_config


class OllamaClient:
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}

        # Get ollama config section
        if "ollama" in self.config:
            ollama_config = self.config["ollama"]
        else:
            global_config = get_config()
            ollama_config = global_config.get("ollama", {})

        self.base_url = ollama_config.get("api_url", "http://127.0.0.1:11434")
        self.model = ollama_config.get("model", "qwen2.5-coder:3b")
        self.timeout = ollama_config.get("timeout", 180)
        self.max_tokens = ollama_config.get("max_tokens", 4096)
        self.temperature = ollama_config.get("temperature", 0.1)
        self.no_ai_mode = ollama_config.get("no_ai", False)
        self.enable_streaming = ollama_config.get("enable_streaming", True)
        self.max_chunk_chars = ollama_config.get("max_chunk_chars", 8000)
        self.fallback_enabled = ollama_config.get("fallback_enabled", True)

        # Context management
        self.conversation_history = []
        self.max_context_length = 8192
        self.system_prompt = self._get_system_prompt()

        # Statistics
        self.stats = {
            "requests": 0,
            "total_tokens": 0,
            "total_time": 0,
            "errors": 0
        }

    def _get_system_prompt(self) -> str:
        return """You are an expert Android malware analyst. Analyze the provided APK static analysis data and produce a concise, structured security assessment.

Focus on:
1. Malware category classification (spyware, RAT, trojan, banker, dropper, etc.)
2. Specific malicious behaviors with evidence
3. MITRE ATT&CK for Mobile technique mapping
4. Risk severity assessment (Critical/High/Medium/Low)
5. Actionable recommendations

Output format: JSON with keys: malware_category, confidence, behaviors, mitre_techniques, risk_level, summary, recommendations"""

    def _sanitize_input(self, value: Any, max_length: int = 1000) -> Any:
        """Sanitize input to prevent prompt injection."""
        if isinstance(value, str):
            # Remove potential prompt injection patterns
            sanitized = value
            # Remove instruction-like patterns
            injection_patterns = [
                r'(?i)ignore\s+(?:previous|above|all)\s+instructions?',
                r'(?i)disregard\s+(?:previous|above|all)\s+instructions?',
                r'(?i)new\s+instructions?\s*:',
                r'(?i)system\s*:\s*',
                r'(?i)assistant\s*:\s*',
                r'(?i)user\s*:\s*',
                r'```\s*(?:json|python|javascript|bash|shell)\s*',
                r'<[^>]*script[^>]*>',
                r'(?i)<\s*prompt\s*>',
                r'(?i)<\s*/\s*prompt\s*>',
            ]
            for pattern in injection_patterns:
                sanitized = re.sub(pattern, '[FILTERED]', sanitized)
            # Limit length
            if len(sanitized) > max_length:
                sanitized = sanitized[:max_length] + '...[TRUNCATED]'
            return sanitized
        elif isinstance(value, list):
            return [self._sanitize_input(v, max_length // max(len(value), 1)) for v in value[:50]]
        elif isinstance(value, dict):
            return {k: self._sanitize_input(v, max_length // max(len(value), 1)) for k, v in list(value.items())[:20]}
        return value

    def is_available(self) -> bool:
        """Check if Ollama is running and model is available."""
        if self.no_ai_mode:
            return False

        try:
            # Check if Ollama is running
            resp = requests.get(f"{self.base_url}/api/tags", timeout=5)
            if resp.status_code != 200:
                return False

            # Check if model exists
            models = resp.json().get("models", [])
            model_names = [m.get("name", "") for m in models]
            return any(self.model in name for name in model_names)
        except Exception:
            return False

    def pull_model(self) -> Dict[str, Any]:
        """Pull the model if not available."""
        try:
            resp = requests.post(
                f"{self.base_url}/api/pull",
                json={"name": self.model},
                timeout=300
            )
            return {"success": resp.status_code == 200, "output": resp.text}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def analyze(self, findings: Dict[str, Any], stream: bool = False) -> Dict[str, Any]:
        """Analyze findings using Ollama."""
        if self.no_ai_mode:
            return self._no_ai_analysis(findings)

        if not self.is_available():
            pull_result = self.pull_model()
            if not pull_result.get("success"):
                return {
                    "success": False,
                    "error": "Ollama not available and model pull failed",
                    "fallback": self._no_ai_analysis(findings)
                }

        # Prepare prompt with findings
        prompt = self._build_prompt(findings)

        # Handle large prompts via chunking
        if len(prompt) > self.max_chunk_chars:
            return self._analyze_chunked(findings, stream)

        return self._single_request(prompt, stream)

    def _build_prompt(self, findings: Dict[str, Any]) -> str:
        """Build analysis prompt from findings."""
        # Summarize findings for prompt
        raw_summary = {
            "package": findings.get("manifest", {}).get("package", "unknown"),
            "permissions": findings.get("permissions", [])[:30],
            "risk_score": findings.get("risk", {}).get("score", 0),
            "risk_level": findings.get("risk", {}).get("risk_level", "UNKNOWN"),
            "malware_detections": [
                {
                    "category": d["category"],
                    "classification": d["classification"],
                    "confidence": d["confidence_score"]
                }
                for d in findings.get("malware", {}).get("detections", [])[:10]
            ],
            "behaviors": [
                {
                    "category": b["category"],
                    "confidence": b["confidence"]
                }
                for b in findings.get("behavior", {}).get("detected_behaviors", [])[:10]
            ],
            "network_iocs": {
                "urls": findings.get("network", {}).get("urls", [])[:20],
                "domains": findings.get("network", {}).get("domains", [])[:20],
                "telegram_bots": findings.get("network", {}).get("telegram_bots", [])[:5],
                "c2_configs": findings.get("network", {}).get("c2_config", [])[:5]
            },
            "native_analysis": {
                "libraries": len(findings.get("native", {}).get("libraries", [])),
                "jni_onload": any(l.get("jni_onload", {}).get("found") for l in findings.get("native", {}).get("libraries", [])),
                "total_native_methods": sum(len(l.get("native_methods", [])) for l in findings.get("native", {}).get("libraries", []))
            },
            "strings_summary": {
                "total": len(findings.get("strings", {}).get("all_strings", [])),
                "decoded": len(findings.get("strings", {}).get("decoded_strings", [])),
                "suspicious": len(findings.get("strings", {}).get("suspicious", []))
            }
        }

        # Sanitize all user-controlled data to prevent prompt injection
        summary = self._sanitize_input(raw_summary, max_length=5000)

        prompt = f"""Analyze this Android APK static analysis data and provide a security assessment.

APK Data:
{json.dumps(summary, indent=2)}

Provide your analysis as JSON with these fields:
- malware_category: primary category (spyware, rat, trojan, banker, dropper, downloader, screen_capture, keylogger, accessibility_abuse, device_admin_abuse, vpn_abuse, overlay_attack, sms_stealer, credential_theft, data_exfiltration, dynamic_code_loading, persistence, anti_analysis, obfuscation, hidden_payload, ransomware, benign)
- confidence: 0-100
- behaviors: list of specific malicious behaviors observed with evidence
- mitre_techniques: list of MITRE ATT&CK for Mobile technique IDs
- risk_level: Critical/High/Medium/Low/Minimal
- summary: 2-3 sentence executive summary
- recommendations: list of actionable recommendations"""

        return prompt

    def _single_request(self, prompt: str, stream: bool = False) -> Dict[str, Any]:
        """Make a single request to Ollama."""
        start_time = time.time()

        payload = {
            "model": self.model,
            "prompt": prompt,
            "system": self.system_prompt,
            "stream": stream,
            "options": {
                "temperature": self.temperature,
                "num_predict": self.max_tokens,
                "top_k": 40,
                "top_p": 0.9
            }
        }

        try:
            if stream:
                return self._stream_request(payload)
            else:
                resp = requests.post(
                    f"{self.base_url}/api/generate",
                    json=payload,
                    timeout=self.timeout
                )

                elapsed = time.time() - start_time
                self.stats["requests"] += 1
                self.stats["total_time"] += elapsed

                if resp.status_code == 200:
                    result = resp.json()
                    response_text = result.get("response", "")

                    # Try to parse JSON from response
                    analysis = self._parse_response(response_text)

                    return {
                        "success": True,
                        "analysis": analysis,
                        "raw_response": response_text,
                        "elapsed": elapsed,
                        "model": self.model
                    }
                else:
                    self.stats["errors"] += 1
                    return {
                        "success": False,
                        "error": f"Ollama error: {resp.status_code} - {resp.text}",
                        "fallback": self._no_ai_analysis({})
                    }

        except requests.exceptions.Timeout:
            self.stats["errors"] += 1
            return {
                "success": False,
                "error": f"Request timeout after {self.timeout}s",
                "fallback": self._no_ai_analysis({})
            }
        except Exception as e:
            self.stats["errors"] += 1
            return {
                "success": False,
                "error": str(e),
                "fallback": self._no_ai_analysis({})
            }

    def _stream_request(self, payload: Dict) -> Dict[str, Any]:
        """Stream request for real-time output."""
        try:
            resp = requests.post(
                f"{self.base_url}/api/generate",
                json=payload,
                timeout=self.timeout,
                stream=True
            )

            full_response = ""
            for line in resp.iter_lines():
                if line:
                    data = json.loads(line.decode())
                    chunk = data.get("response", "")
                    full_response += chunk
                    if data.get("done"):
                        break

            analysis = self._parse_response(full_response)
            return {
                "success": True,
                "analysis": analysis,
                "raw_response": full_response,
                "model": self.model
            }

        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "fallback": self._no_ai_analysis({})
            }

    def _analyze_chunked(self, findings: Dict[str, Any], stream: bool = False) -> Dict[str, Any]:
        """Analyze large findings by chunking."""
        # Split findings into chunks
        chunks = self._create_chunks(findings)

        if len(chunks) == 1:
            return self._single_request(self._build_prompt(chunks[0]), stream)

        # Analyze each chunk
        chunk_results = []
        for i, chunk in enumerate(chunks):
            prompt = f"""Analyze part {i+1}/{len(chunks)} of this APK analysis:

{json.dumps(chunk, indent=2)}

Provide JSON with: malware_category, confidence, behaviors, mitre_techniques, risk_level, summary"""

            result = self._single_request(prompt, stream)
            if result.get("success"):
                chunk_results.append(result["analysis"])

        # Synthesize results
        return self._synthesize_chunks(chunk_results)

    def _create_chunks(self, findings: Dict[str, Any]) -> List[Dict]:
        """Split findings into manageable chunks."""
        chunks = []

        # Base info always included
        base = {
            "manifest": findings.get("manifest", {}),
            "permissions": findings.get("permissions", []),
            "risk": findings.get("risk", {})
        }

        # Chunk 1: Malware + Behavior
        chunk1 = base.copy()
        chunk1["malware"] = findings.get("malware", {})
        chunk1["behavior"] = findings.get("behavior", {})
        chunks.append(chunk1)

        # Chunk 2: Network + Strings
        chunk2 = base.copy()
        chunk2["network"] = findings.get("network", {})
        chunk2["strings"] = {
            "urls": findings.get("network", {}).get("urls", []),
            "domains": findings.get("network", {}).get("domains", []),
            "telegram_bots": findings.get("network", {}).get("telegram_bots", []),
            "suspicious_count": len(findings.get("strings", {}).get("suspicious", []))
        }
        chunks.append(chunk2)

        # Chunk 3: Native + DEX
        chunk3 = base.copy()
        chunk3["native"] = findings.get("native", {})
        chunk3["dex"] = findings.get("dex", {})
        chunks.append(chunk3)

        return chunks

    def _synthesize_chunks(self, chunk_results: List[Dict]) -> Dict[str, Any]:
        """Synthesize multiple chunk analyses."""
        if not chunk_results:
            return {"success": False, "error": "No chunk results"}

        # Take highest confidence result as base
        best = max(chunk_results, key=lambda x: x.get("confidence", 0))

        # Merge behaviors and MITRE
        all_behaviors = []
        all_mitre = set()
        all_recommendations = []

        for r in chunk_results:
            all_behaviors.extend(r.get("behaviors", []))
            all_mitre.update(r.get("mitre_techniques", []))
            all_recommendations.extend(r.get("recommendations", []))

        # Deduplicate
        seen_beh = set()
        unique_behaviors = []
        for b in all_behaviors:
            key = str(b)[:100]
            if key not in seen_beh:
                seen_beh.add(key)
                unique_behaviors.append(b)

        return {
            "success": True,
            "analysis": {
                "malware_category": best.get("malware_category", "unknown"),
                "confidence": best.get("confidence", 0),
                "behaviors": unique_behaviors[:20],
                "mitre_techniques": list(all_mitre),
                "risk_level": best.get("risk_level", "UNKNOWN"),
                "summary": best.get("summary", ""),
                "recommendations": list(dict.fromkeys(all_recommendations))[:10]
            },
            "synthesized_from": len(chunk_results)
        }

    def _parse_response(self, response: str) -> Dict[str, Any]:
        """Parse JSON from model response."""
        # Try direct JSON parse
        try:
            return json.loads(response)
        except json.JSONDecodeError:
            pass

        # Try to extract JSON from markdown code blocks
        import re
        json_match = re.search(r'```(?:json)?\s*(\{.*?\})\s*```', response, re.DOTALL)
        if json_match:
            try:
                return json.loads(json_match.group(1))
            except json.JSONDecodeError:
                pass

        # Try to find JSON object in text
        json_match = re.search(r'(\{.*\})', response, re.DOTALL)
        if json_match:
            try:
                return json.loads(json_match.group(1))
            except json.JSONDecodeError:
                pass

        # Fallback: return structured error
        return {
            "malware_category": "unknown",
            "confidence": 0,
            "behaviors": [],
            "mitre_techniques": [],
            "risk_level": "UNKNOWN",
            "summary": "Failed to parse AI response",
            "recommendations": ["Manual review required"],
            "raw_response": response[:500]
        }

    def _no_ai_analysis(self, findings: Dict[str, Any]) -> Dict[str, Any]:
        """Provide rule-based analysis when AI is disabled."""
        malware = findings.get("malware", {})
        detections = malware.get("detections", [])

        if detections:
            best = detections[0]
            return {
                "success": True,
                "analysis": {
                    "malware_category": best.get("category", "unknown"),
                    "confidence": best.get("confidence_score", 0),
                    "behaviors": [{"behavior": d["category"], "evidence": d.get("evidence", {})} for d in detections[:5]],
                    "mitre_techniques": best.get("mitre_techniques", []),
                    "risk_level": findings.get("risk", {}).get("risk_level", "UNKNOWN"),
                    "summary": f"Rule-based analysis: {best['category']} detected with {best['classification']} confidence",
                    "recommendations": [
                        "Review permissions and capabilities",
                        "Analyze network IOCs",
                        "Check for dynamic code loading",
                        "Verify with dynamic analysis"
                    ]
                },
                "mode": "rule_based"
            }

        return {
            "success": True,
            "analysis": {
                "malware_category": "benign",
                "confidence": 50,
                "behaviors": [],
                "mitre_techniques": [],
                "risk_level": findings.get("risk", {}).get("risk_level", "MINIMAL"),
                "summary": "No malware categories detected by rule engine",
                "recommendations": ["Standard security review"]
            },
            "mode": "rule_based"
        }

    def get_stats(self) -> Dict[str, Any]:
        """Get client statistics."""
        return self.stats.copy()

    def clear_history(self):
        """Clear conversation history."""
        self.conversation_history = []