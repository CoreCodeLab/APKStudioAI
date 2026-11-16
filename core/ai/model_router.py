"""
Model Router for APKStudioAI 2.1
Intelligent model selection based on task, hardware, and model capabilities.
"""
import json
import subprocess
from pathlib import Path
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from ..config_manager import get_config
from ..logging_setup import get_module_logger

logger = get_module_logger("model_router")


@dataclass
class ModelInfo:
    """Information about an available model."""
    name: str
    size_gb: float
    context_length: int
    capabilities: List[str]  # e.g., "tool_calling", "structured_output", "reasoning", "code"
    parameter_count: str  # e.g., "3b", "7b", "14b", "32b"
    quantization: str  # e.g., "q4_k_m", "q8_0"
    family: str  # e.g., "qwen", "llama", "codellama", "deepseek"
    is_local: bool = True


@dataclass
class TaskRequirements:
    """Requirements for a specific task."""
    task_type: str  # "code_explanation", "smali_analysis", "reverse_engineering", "evidence_correlation", "report_generation", "embedding"
    min_context: int = 4096
    needs_tool_calling: bool = False
    needs_structured_output: bool = False
    needs_reasoning: bool = False
    needs_code_specialization: bool = False
    max_model_size_gb: Optional[float] = None


class ModelRouter:
    """Intelligent model selection and routing."""

    # Task to model capability mapping
    TASK_REQUIREMENTS = {
        "code_explanation": TaskRequirements(
            task_type="code_explanation",
            min_context=4096,
            needs_code_specialization=True,
            needs_structured_output=True,
        ),
        "smali_analysis": TaskRequirements(
            task_type="smali_analysis",
            min_context=8192,
            needs_code_specialization=True,
            needs_structured_output=True,
            needs_reasoning=True,
        ),
        "reverse_engineering": TaskRequirements(
            task_type="reverse_engineering",
            min_context=16384,
            needs_code_specialization=True,
            needs_reasoning=True,
            needs_structured_output=True,
        ),
        "evidence_correlation": TaskRequirements(
            task_type="evidence_correlation",
            min_context=8192,
            needs_reasoning=True,
            needs_structured_output=True,
        ),
        "report_generation": TaskRequirements(
            task_type="report_generation",
            min_context=4096,
            needs_structured_output=True,
        ),
        "embedding": TaskRequirements(
            task_type="embedding",
            min_context=2048,
        ),
        "general": TaskRequirements(
            task_type="general",
            min_context=4096,
        ),
    }

    # Model family preferences by task
    TASK_FAMILY_PREFERENCES = {
        "code_explanation": ["qwen", "codellama", "deepseek", "llama"],
        "smali_analysis": ["qwen", "deepseek", "codellama"],
        "reverse_engineering": ["qwen", "deepseek", "codellama"],
        "evidence_correlation": ["qwen", "llama", "deepseek"],
        "report_generation": ["qwen", "llama", "mistral"],
        "embedding": ["nomic", "bge", "e5", "all-minilm"],
    }

    def __init__(self, config: Dict = None, ollama_url: str = "http://127.0.0.1:11434"):
        self.config = config or get_config().get_all()
        self.ollama_url = ollama_url
        self.models: Dict[str, ModelInfo] = {}
        self.hardware_info = self._detect_hardware()
        self._discover_models()

    def _detect_hardware(self) -> Dict[str, Any]:
        """Detect available hardware resources."""
        info = {
            "cpu_cores": 0,
            "ram_gb": 0,
            "gpu_available": False,
            "gpu_vram_gb": 0,
            "gpu_name": "",
        }

        try:
            # CPU cores
            info["cpu_cores"] = len(open("/proc/cpuinfo").read().split("processor\t:")) - 1
        except Exception:
            info["cpu_cores"] = 4

        try:
            # RAM
            with open("/proc/meminfo") as f:
                for line in f:
                    if line.startswith("MemTotal:"):
                        info["ram_gb"] = int(line.split()[1]) / (1024 * 1024)
                        break
        except Exception:
            info["ram_gb"] = 8

        try:
            # GPU detection (NVIDIA)
            result = subprocess.run(
                ["nvidia-smi", "--query-gpu=memory.total,name", "--format=csv,noheader,nounits"],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0 and result.stdout.strip():
                lines = result.stdout.strip().split("\n")
                info["gpu_available"] = True
                info["gpu_vram_gb"] = max(int(l.split(",")[0]) for l in lines) / 1024
                info["gpu_name"] = lines[0].split(",")[1].strip()
        except Exception:
            pass

        logger.info("hardware_detected", **info)
        return info

    def _discover_models(self):
        """Discover available Ollama models."""
        import requests

        try:
            resp = requests.get(f"{self.ollama_url}/api/tags", timeout=10)
            if resp.status_code != 200:
                logger.warning("ollama_not_reachable", url=self.ollama_url)
                return

            models_data = resp.json().get("models", [])
            for m in models_data:
                name = m.get("name", "")
                size_bytes = m.get("size", 0)

                # Parse model info from name
                model_info = self._parse_model_name(name, size_bytes)
                self.models[name] = model_info

            logger.info("models_discovered", count=len(self.models))

        except Exception as e:
            logger.warning("model_discovery_failed", error=str(e))

    def _parse_model_name(self, name: str, size_bytes: int) -> ModelInfo:
        """Parse model name to extract capabilities."""
        # Default values
        info = ModelInfo(
            name=name,
            size_gb=size_bytes / (1024 ** 3),
            context_length=4096,
            capabilities=[],
            parameter_count="unknown",
            quantization="unknown",
            family="unknown",
        )

        name_lower = name.lower()

        # Detect family
        for family in ["qwen", "llama", "codellama", "deepseek", "mistral", "phi", "gemma", "nomic", "bge", "e5", "all-minilm"]:
            if family in name_lower:
                info.family = family
                break

        # Detect parameter count
        for param in ["0.5b", "1b", "1.5b", "2b", "3b", "4b", "7b", "8b", "13b", "14b", "32b", "34b", "70b", "72b"]:
            if param in name_lower:
                info.parameter_count = param
                break

        # Detect quantization
        for quant in ["q2_k", "q3_k_m", "q4_k_m", "q4_k_s", "q5_k_m", "q5_k_s", "q6_k", "q8_0", "fp16", "f16"]:
            if quant in name_lower:
                info.quantization = quant
                break

        # Set capabilities based on family and size
        info.capabilities = self._infer_capabilities(info)

        # Set context length based on model
        if "qwen" in info.family and "2.5" in name_lower:
            info.context_length = 32768
        elif "llama" in info.family and "3.1" in name_lower:
            info.context_length = 131072
        elif "deepseek" in info.family:
            info.context_length = 32768
        elif "mistral" in info.family:
            info.context_length = 32768

        return info

    def _infer_capabilities(self, info: ModelInfo) -> List[str]:
        """Infer model capabilities from family and size."""
        caps = []

        # Code specialization
        if info.family in ["qwen", "codellama", "deepseek"]:
            caps.append("code_specialization")

        # Reasoning (larger models)
        try:
            param_num = float(info.parameter_count.replace("b", ""))
            if param_num >= 7:
                caps.append("reasoning")
        except Exception:
            pass

        # Structured output (most modern models)
        caps.append("structured_output")

        # Tool calling (check specific models)
        if info.family in ["qwen", "llama"] and "2.5" in info.name.lower():
            caps.append("tool_calling")
        elif info.family == "llama" and "3.1" in info.name.lower():
            caps.append("tool_calling")

        # Embedding models
        if info.family in ["nomic", "bge", "e5", "all-minilm"]:
            caps = ["embedding"]

        return caps

    def select_model(self, task_type: str, available_models: List[str] = None) -> Optional[str]:
        """Select the best model for a task."""
        requirements = self.TASK_REQUIREMENTS.get(task_type, self.TASK_REQUIREMENTS["general"])
        candidates = available_models or list(self.models.keys())

        if not candidates:
            logger.warning("no_models_available")
            return None

        # Filter by requirements
        scored = []
        for model_name in candidates:
            if model_name not in self.models:
                continue
            model = self.models[model_name]

            # Skip embedding models for non-embedding tasks
            if requirements.task_type != "embedding" and "embedding" in model.capabilities:
                continue
            if requirements.task_type == "embedding" and "embedding" not in model.capabilities:
                continue

            # Check context length
            if model.context_length < requirements.min_context:
                continue

            # Check hardware constraints
            if requirements.max_model_size_gb and model.size_gb > requirements.max_model_size_gb:
                continue

            # Check specific capabilities
            if requirements.needs_code_specialization and "code_specialization" not in model.capabilities:
                continue
            if requirements.needs_reasoning and "reasoning" not in model.capabilities:
                continue
            if requirements.needs_tool_calling and "tool_calling" not in model.capabilities:
                continue
            if requirements.needs_structured_output and "structured_output" not in model.capabilities:
                continue

            # Score the model
            score = self._score_model(model, requirements)
            scored.append((score, model_name))

        if not scored:
            logger.warning("no_suitable_model", task=task_type)
            return None

        # Return highest scored
        scored.sort(reverse=True, key=lambda x: x[0])
        selected = scored[0][1]
        logger.info("model_selected", task=task_type, model=selected, score=scored[0][0])
        return selected

    def _score_model(self, model: ModelInfo, requirements: TaskRequirements) -> float:
        """Score a model for a task."""
        score = 0.0

        # Family preference
        preferred = self.TASK_FAMILY_PREFERENCES.get(requirements.task_type, [])
        try:
            score += (len(preferred) - preferred.index(model.family)) * 10
        except ValueError:
            pass

        # Size preference (larger is better for reasoning, but respect hardware)
        try:
            param_num = float(model.parameter_count.replace("b", ""))
            if requirements.needs_reasoning:
                score += min(param_num * 2, 50)
            else:
                score += min(param_num, 20)
        except Exception:
            pass

        # Capability bonuses
        if requirements.needs_code_specialization and "code_specialization" in model.capabilities:
            score += 15
        if requirements.needs_reasoning and "reasoning" in model.capabilities:
            score += 15
        if requirements.needs_tool_calling and "tool_calling" in model.capabilities:
            score += 10

        # Context length bonus
        score += min(model.context_length / 1000, 20)

        # Quantization quality bonus
        if model.quantization in ["q4_k_m", "q5_k_m", "q6_k", "q8_0", "fp16", "f16"]:
            score += 5

        # Hardware fit bonus
        if model.size_gb <= self.hardware_info["ram_gb"] * 0.7:
            score += 10
        elif model.size_gb <= self.hardware_info["ram_gb"]:
            score += 5

        return score

    def get_model_info(self, model_name: str) -> Optional[ModelInfo]:
        """Get info for a specific model."""
        return self.models.get(model_name)

    def list_models(self, task_type: str = None) -> List[Dict]:
        """List available models, optionally filtered by task."""
        models = []
        for name, info in self.models.items():
            model_data = {
                "name": name,
                "family": info.family,
                "size_gb": round(info.size_gb, 2),
                "context_length": info.context_length,
                "capabilities": info.capabilities,
                "parameter_count": info.parameter_count,
                "quantization": info.quantization,
            }
            if task_type:
                req = self.TASK_REQUIREMENTS.get(task_type)
                if req:
                    model_data["suitable"] = self._is_suitable(info, req)
            models.append(model_data)
        return models

    def _is_suitable(self, model: ModelInfo, requirements: TaskRequirements) -> bool:
        """Check if model meets requirements."""
        if model.context_length < requirements.min_context:
            return False
        if requirements.needs_code_specialization and "code_specialization" not in model.capabilities:
            return False
        if requirements.needs_reasoning and "reasoning" not in model.capabilities:
            return False
        if requirements.needs_tool_calling and "tool_calling" not in model.capabilities:
            return False
        if requirements.needs_structured_output and "structured_output" not in model.capabilities:
            return False
        if requirements.max_model_size_gb and model.size_gb > requirements.max_model_size_gb:
            return False
        return True


def get_model_router(config: Dict = None, ollama_url: str = "http://127.0.0.1:11434") -> ModelRouter:
    """Get singleton model router instance."""
    return ModelRouter(config, ollama_url)