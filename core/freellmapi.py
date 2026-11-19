"""
FreeLLMAPI Client for APKStudioAI
Aggregates free LLM inference tiers from 87 providers behind a single OpenAI-compatible endpoint.
Supports fallback to local Ollama and rule-based analysis for malware testing.
"""

import json
import time
import re
import requests
from typing import Dict, List, Any, Optional, Generator, Union
from pathlib import Path
from dataclasses import dataclass, field
from enum import Enum

from .utils import run_command
from .config_manager import get_config
from .logging_setup import get_module_logger

logger = get_module_logger("freellmapi")


class LLMBackend(Enum):
    """Supported LLM backends."""
    FREELLM_API = "freellmapi"
    OLLAMA = "ollama"
    RULE_BASED = "rule_based"


@dataclass
class LLMConfig:
    """Configuration for LLM backends."""
    # FreeLLMAPI settings
    freellmapi_url: str = "http://localhost:3001/v1"
    freellmapi_key: str = ""
    freellmapi_model: str = "auto"  # auto, auto:fast, auto:smart, or specific model
    freellmapi_timeout: int = 120
    freellmapi_enabled: bool = True

    # Ollama settings (fallback)
    ollama_url: str = "http://127.0.0.1:11434"
    ollama_model: str = "qwen2.5-coder:3b"
    ollama_timeout: int = 180
    ollama_enabled: bool = True

    # Rule-based fallback
    rule_based_enabled: bool = True

    # Common settings
    max_chunk_chars: int = 8000
    temperature: float = 0.1
    max_tokens: int = 4096

    # Fallback chain
    fallback_order: List[LLMBackend] = field(default_factory=lambda: [
        LLMBackend.FREELLM_API,
        LLMBackend.OLLAMA,
        LLMBackend.RULE_BASED
    ])


class FreeLLMAPIClient:
    """
    OpenAI-compatible client for FreeLLMAPI with automatic fallback to Ollama and rule-based analysis.

    Usage:
        client = FreeLLMAPIClient(config)
        result = client.analyze(findings)
    """

    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self._load_config()

        # Statistics
        self.stats = {
            "requests": 0,
            "success": 0,
            "failures": 0,
            "total_tokens": 0,
            "total_time": 0.0,
            "backend_usage": {b.value: 0 for b in LLMBackend}
        }

        # Session for connection pooling
        self.session = requests.Session()
        self.session.headers.update({
            "Content-Type": "application/json",
            "User-Agent": "APKStudioAI-FreeLLMAPI/1.0"
        })

        # Add API key if configured
        if self.llm_config.freellmapi_key:
            self.session.headers["Authorization"] = f"Bearer {self.llm_config.freellmapi_key}"

        # System prompt for malware analysis
        self.system_prompt = self._get_system_prompt()

        # --- Backward-compatible attributes (OllamaClient API) ---
        self.no_ai_mode = False
        self.conversation_history = []
        self.max_context_length = 8192

    @property
    def model(self) -> str:
        """Active model name (OllamaClient compatibility)."""
        return self.llm_config.freellmapi_model

    @model.setter
    def model(self, value: str):
        """Set the active model name (OllamaClient compatibility)."""
        self.llm_config.freellmapi_model = value

    def clear_history(self):
        """Clear conversation history (OllamaClient compatibility)."""
        self.conversation_history = []

    def is_available(self) -> bool:
        """Check if any LLM backend is available (OllamaClient compatibility)."""
        if self.no_ai_mode:
            return False
        return any([
            self.is_freellmapi_available(),
            self.is_ollama_available(),
            self.llm_config.rule_based_enabled
        ])

    def pull_model(self) -> Dict[str, Any]:
        """Pull the Ollama model (OllamaClient compatibility)."""
        return self.pull_ollama_model()

    def _load_config(self):
        """Load configuration from config dict or global config."""
        # Check for freellmapi section
        if "freellmapi" in self.config:
            freellmapi_config = self.config["freellmapi"]
        else:
            global_config = get_config()
            freellmapi_config = global_config.get("freellmapi", {})

        # Check for ollama section
        if "ollama" in self.config:
            ollama_config = self.config["ollama"]
        else:
            global_config = get_config()
            ollama_config = global_config.get("ollama", {})

        # Build LLMConfig
        self.llm_config = LLMConfig(
            freellmapi_url=freellmapi_config.get("api_url", "http://localhost:3001/v1"),
            freellmapi_key=freellmapi_config.get("api_key", ""),
            freellmapi_model=freellmapi_config.get("model", "auto"),
            freellmapi_timeout=freellmapi_config.get("timeout", 120),
            freellmapi_enabled=freellmapi_config.get("enabled", True),
            ollama_url=ollama_config.get("api_url", "http://127.0.0.1:11434"),
            ollama_model=ollama_config.get("model", "qwen2.5-coder:3b"),
            ollama_timeout=ollama_config.get("timeout", 180),
            ollama_enabled=ollama_config.get("enabled", True),
            rule_based_enabled=freellmapi_config.get("rule_based_fallback", True),
            max_chunk_chars=freellmapi_config.get("max_chunk_chars", 8000),
            temperature=freellmapi_config.get("temperature", 0.1),
            max_tokens=freellmapi_config.get("max_tokens", 4096),
        )

        # Parse fallback order
        fallback_order_str = freellmapi_config.get("fallback_order",
            "freellmapi,ollama,rule_based")
        self.llm_config.fallback_order = [
            LLMBackend(b.strip()) for b in fallback_order_str.split(",")
            if b.strip() in [b.value for b in LLMBackend]
        ]

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
            sanitized = value
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
            if len(sanitized) > max_length:
                sanitized = sanitized[:max_length] + '...[TRUNCATED]'
            return sanitized
        elif isinstance(value, list):
            return [self._sanitize_input(v, max_length // max(len(value), 1)) for v in value[:50]]
        elif isinstance(value, dict):
            return {k: self._sanitize_input(v, max_length // max(len(value), 1)) for k, v in list(value.items())[:20]}
        return value

    def is_freellmapi_available(self) -> bool:
        """Check if FreeLLMAPI is running and reachable."""
        if not self.llm_config.freellmapi_enabled:
            return False
        try:
            resp = self.session.get(
                f"{self.llm_config.freellmapi_url}/models",
                timeout=5
            )
            return resp.status_code == 200
        except Exception:
            return False

    def is_ollama_available(self) -> bool:
        """Check if Ollama is running and model is available."""
        if not self.llm_config.ollama_enabled:
            return False
        try:
            resp = requests.get(f"{self.llm_config.ollama_url}/api/tags", timeout=5)
            if resp.status_code != 200:
                return False
            models = resp.json().get("models", [])
            model_names = [m.get("name", "") for m in models]
            return any(self.llm_config.ollama_model in name for name in model_names)
        except Exception:
            return False

    def pull_ollama_model(self) -> Dict[str, Any]:
        """Pull the Ollama model if not available."""
        try:
            resp = requests.post(
                f"{self.llm_config.ollama_url}/api/pull",
                json={"name": self.llm_config.ollama_model},
                timeout=300
            )
            return {"success": resp.status_code == 200, "output": resp.text}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def analyze(self, findings: Dict[str, Any], stream: bool = False) -> Dict[str, Any]:
        """
        Analyze findings using the configured LLM backend with automatic fallback.

        Args:
            findings: Dictionary containing APK static analysis results
            stream: Whether to stream the response

        Returns:
            Dictionary with analysis results and metadata
        """
        start_time = time.time()
        last_error = None

        # Try each backend in fallback order
        for backend in self.llm_config.fallback_order:
            try:
                if backend == LLMBackend.FREELLM_API:
                    if self.is_freellmapi_available():
                        result = self._analyze_freellmapi(findings, stream)
                        if result.get("success"):
                            self._record_success(backend, time.time() - start_time)
                            return result
                        last_error = result.get("error")
                    else:
                        last_error = "FreeLLMAPI not available"

                elif backend == LLMBackend.OLLAMA:
                    if self.is_ollama_available():
                        result = self._analyze_ollama(findings, stream)
                        if result.get("success"):
                            self._record_success(backend, time.time() - start_time)
                            return result
                        last_error = result.get("error")
                    else:
                        # Try pulling model
                        pull_result = self.pull_ollama_model()
                        if pull_result.get("success"):
                            result = self._analyze_ollama(findings, stream)
                            if result.get("success"):
                                self._record_success(backend, time.time() - start_time)
                                return result
                            last_error = result.get("error")
                        else:
                            last_error = "Ollama model not available and pull failed"

                elif backend == LLMBackend.RULE_BASED:
                    if self.llm_config.rule_based_enabled:
                        result = self._no_ai_analysis(findings)
                        self._record_success(backend, time.time() - start_time)
                        return result
                    last_error = "Rule-based analysis disabled"

            except Exception as e:
                last_error = str(e)
                logger.warning("backend_failed", backend=backend.value, error=str(e))
                continue

        # All backends failed
        self.stats["failures"] += 1
        return {
            "success": False,
            "error": f"All backends failed. Last error: {last_error}",
            "analysis": None,
            "backend": None,
            "elapsed": time.time() - start_time
        }

    def _analyze_freellmapi(self, findings: Dict[str, Any], stream: bool = False) -> Dict[str, Any]:
        """Analyze using FreeLLMAPI (OpenAI-compatible endpoint)."""
        start_time = time.time()

        prompt = self._build_prompt(findings)

        # Handle large prompts via chunking
        if len(prompt) > self.llm_config.max_chunk_chars:
            return self._analyze_chunked(findings, stream, backend=LLMBackend.FREELLM_API)

        payload = {
            "model": self.llm_config.freellmapi_model,
            "messages": [
                {"role": "system", "content": self.system_prompt},
                {"role": "user", "content": prompt}
            ],
            "temperature": self.llm_config.temperature,
            "max_tokens": self.llm_config.max_tokens,
            "stream": stream
        }

        try:
            if stream:
                return self._stream_freellmapi(payload)
            else:
                resp = self.session.post(
                    f"{self.llm_config.freellmapi_url}/chat/completions",
                    json=payload,
                    timeout=self.llm_config.freellmapi_timeout
                )

                elapsed = time.time() - start_time

                if resp.status_code == 200:
                    result = resp.json()
                    response_text = result.get("choices", [{}])[0].get("message", {}).get("content", "")

                    analysis = self._parse_response(response_text)

                    # Extract token usage if available
                    usage = result.get("usage", {})
                    tokens = usage.get("total_tokens", 0)

                    return {
                        "success": True,
                        "analysis": analysis,
                        "raw_response": response_text,
                        "elapsed": elapsed,
                        "model": self.llm_config.freellmapi_model,
                        "backend": "freellmapi",
                        "tokens": tokens
                    }
                else:
                    return {
                        "success": False,
                        "error": f"FreeLLMAPI error: {resp.status_code} - {resp.text}",
                        "backend": "freellmapi"
                    }

        except requests.exceptions.Timeout:
            return {
                "success": False,
                "error": f"FreeLLMAPI timeout after {self.llm_config.freellmapi_timeout}s",
                "backend": "freellmapi"
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "backend": "freellmapi"
            }

    def _stream_freellmapi(self, payload: Dict) -> Dict[str, Any]:
        """Stream request for real-time output from FreeLLMAPI."""
        try:
            resp = self.session.post(
                f"{self.llm_config.freellmapi_url}/chat/completions",
                json=payload,
                timeout=self.llm_config.freellmapi_timeout,
                stream=True
            )

            full_response = ""
            for line in resp.iter_lines():
                if line:
                    line = line.decode()
                    if line.startswith("data: "):
                        data_str = line[6:]
                        if data_str.strip() == "[DONE]":
                            break
                        try:
                            data = json.loads(data_str)
                            chunk = data.get("choices", [{}])[0].get("delta", {}).get("content", "")
                            full_response += chunk
                        except json.JSONDecodeError:
                            pass

            analysis = self._parse_response(full_response)
            return {
                "success": True,
                "analysis": analysis,
                "raw_response": full_response,
                "model": self.llm_config.freellmapi_model,
                "backend": "freellmapi"
            }

        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "backend": "freellmapi"
            }

    def _analyze_ollama(self, findings: Dict[str, Any], stream: bool = False) -> Dict[str, Any]:
        """Analyze using local Ollama."""
        start_time = time.time()

        prompt = self._build_prompt(findings)

        if len(prompt) > self.llm_config.max_chunk_chars:
            return self._analyze_chunked(findings, stream, backend=LLMBackend.OLLAMA)

        payload = {
            "model": self.llm_config.ollama_model,
            "prompt": prompt,
            "system": self.system_prompt,
            "stream": stream,
            "options": {
                "temperature": self.llm_config.temperature,
                "num_predict": self.llm_config.max_tokens,
                "top_k": 40,
                "top_p": 0.9
            }
        }

        try:
            if stream:
                return self._stream_ollama(payload)
            else:
                resp = requests.post(
                    f"{self.llm_config.ollama_url}/api/generate",
                    json=payload,
                    timeout=self.llm_config.ollama_timeout
                )

                elapsed = time.time() - start_time

                if resp.status_code == 200:
                    result = resp.json()
                    response_text = result.get("response", "")

                    analysis = self._parse_response(response_text)

                    return {
                        "success": True,
                        "analysis": analysis,
                        "raw_response": response_text,
                        "elapsed": elapsed,
                        "model": self.llm_config.ollama_model,
                        "backend": "ollama"
                    }
                else:
                    return {
                        "success": False,
                        "error": f"Ollama error: {resp.status_code} - {resp.text}",
                        "backend": "ollama"
                    }

        except requests.exceptions.Timeout:
            return {
                "success": False,
                "error": f"Ollama timeout after {self.llm_config.ollama_timeout}s",
                "backend": "ollama"
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "backend": "ollama"
            }

    def _stream_ollama(self, payload: Dict) -> Dict[str, Any]:
        """Stream request for real-time output from Ollama."""
        try:
            resp = requests.post(
                f"{self.llm_config.ollama_url}/api/generate",
                json=payload,
                timeout=self.llm_config.ollama_timeout,
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
                "model": self.llm_config.ollama_model,
                "backend": "ollama"
            }

        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "backend": "ollama"
            }

    def _analyze_chunked(self, findings: Dict[str, Any], stream: bool = False,
                         backend: LLMBackend = LLMBackend.FREELLM_API) -> Dict[str, Any]:
        """Analyze large findings by chunking."""
        chunks = self._create_chunks(findings)

        if len(chunks) == 1:
            if backend == LLMBackend.FREELLM_API:
                return self._analyze_freellmapi(chunks[0], stream)
            else:
                return self._analyze_ollama(chunks[0], stream)

        # Analyze each chunk
        chunk_results = []
        for i, chunk in enumerate(chunks):
            if backend == LLMBackend.FREELLM_API:
                result = self._analyze_freellmapi(chunk, stream)
            else:
                result = self._analyze_ollama(chunk, stream)

            if result.get("success"):
                chunk_results.append(result["analysis"])

        # Synthesize results
        return self._synthesize_chunks(chunk_results, backend)

    def _create_chunks(self, findings: Dict[str, Any]) -> List[Dict]:
        """Split findings into manageable chunks."""
        chunks = []

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

    def _synthesize_chunks(self, chunk_results: List[Dict],
                          backend: LLMBackend) -> Dict[str, Any]:
        """Synthesize multiple chunk analyses."""
        if not chunk_results:
            return {"success": False, "error": "No chunk results", "backend": backend.value}

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
            "synthesized_from": len(chunk_results),
            "backend": backend.value
        }

    def _build_prompt(self, findings: Dict[str, Any]) -> str:
        """Build analysis prompt from findings."""
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

        # Sanitize all user-controlled data
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

    def _parse_response(self, response: str) -> Dict[str, Any]:
        """Parse JSON from model response."""
        # Try direct JSON parse
        try:
            return json.loads(response)
        except json.JSONDecodeError:
            pass

        # Try to extract JSON from markdown code blocks
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
                "mode": "rule_based",
                "backend": "rule_based"
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
            "mode": "rule_based",
            "backend": "rule_based"
        }

    def _record_success(self, backend: LLMBackend, elapsed: float):
        """Record successful request statistics."""
        self.stats["requests"] += 1
        self.stats["success"] += 1
        self.stats["total_time"] += elapsed
        self.stats["backend_usage"][backend.value] += 1

    def get_stats(self) -> Dict[str, Any]:
        """Get client statistics."""
        stats = self.stats.copy()
        if stats["success"] > 0:
            stats["avg_response_time"] = stats["total_time"] / stats["success"]
        else:
            stats["avg_response_time"] = 0
        return stats

    def get_available_backends(self) -> Dict[str, bool]:
        """Get availability status of all backends."""
        return {
            "freellmapi": self.is_freellmapi_available() if self.llm_config.freellmapi_enabled else False,
            "ollama": self.is_ollama_available() if self.llm_config.ollama_enabled else False,
            "rule_based": self.llm_config.rule_based_enabled
        }

    def test_backends(self) -> Dict[str, Any]:
        """Test all backends and return their status."""
        results = {}

        # Test FreeLLMAPI
        results["freellmapi"] = {
            "enabled": self.llm_config.freellmapi_enabled,
            "available": self.is_freellmapi_available(),
            "url": self.llm_config.freellmapi_url,
            "model": self.llm_config.freellmapi_model
        }

        # Test Ollama
        results["ollama"] = {
            "enabled": self.llm_config.ollama_enabled,
            "available": self.is_ollama_available(),
            "url": self.llm_config.ollama_url,
            "model": self.llm_config.ollama_model
        }

        # Test rule-based
        results["rule_based"] = {
            "enabled": self.llm_config.rule_based_enabled,
            "available": True
        }

        return results


# Factory function for easy integration
def create_freellmapi_client(config: Dict[str, Any] = None) -> FreeLLMAPIClient:
    """Factory function to create FreeLLMAPI client."""
    return FreeLLMAPIClient(config)


# Backward compatibility alias
OllamaClient = FreeLLMAPIClient
"""
This alias maintains backward compatibility with existing code that uses OllamaClient.
The FreeLLMAPIClient supports all OllamaClient methods plus FreeLLMAPI integration.
"""

if __name__ == "__main__":
    # Quick test
    import sys
    client = FreeLLMAPIClient()
    print("Backends:", client.get_available_backends())
    print("Test results:", client.test_backends())