"""
Configuration manager for APKStudioAI 2.1
Loads, validates, and provides access to configuration with defaults.
"""
import json
import os
from pathlib import Path
from typing import Dict, Any, Optional, List
from .utils import get_project_root

try:
    import jsonschema
    HAS_JSONSCHEMA = True
except ImportError:
    HAS_JSONSCHEMA = False
    jsonschema = None


class ConfigManager:
    """Manages configuration loading, validation, and access."""

    _instance: Optional['ConfigManager'] = None
    _config: Dict[str, Any] = {}

    def __new__(cls, config_path: Optional[str] = None):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self, config_path: Optional[str] = None):
        if self._initialized:
            return
        self._initialized = True
        self.config_path = config_path or self._find_config()
        self._load_config()

    def _find_config(self) -> str:
        """Find config.json in standard locations."""
        # Check current directory
        local = Path("config.json")
        if local.exists():
            return str(local)

        # Check project root
        project_root = get_project_root()
        root_config = project_root / "config.json"
        if root_config.exists():
            return str(root_config)

        # Check user config directory
        user_config = Path.home() / ".apkstudioai" / "config.json"
        if user_config.exists():
            return str(user_config)

        # Return default location (will be created)
        return str(project_root / "config.json")

    def _load_config(self):
        """Load configuration from file with defaults."""
        # Start with comprehensive defaults
        self._config = self._get_defaults()

        # Load from file if exists
        if self.config_path and Path(self.config_path).exists():
            try:
                with open(self.config_path, 'r', encoding='utf-8') as f:
                    file_config = json.load(f)
                self._merge_config(self._config, file_config)
            except Exception as e:
                print(f"Warning: Failed to load config from {self.config_path}: {e}")

        # Apply environment variable overrides
        self._apply_env_overrides()

        # Auto-detect tools if enabled
        if self._config.get("tools", {}).get("auto_detect_tools", True):
            self._auto_detect_tools()

        # Validate and fix config
        self._validate_config()

    def _get_defaults(self) -> Dict[str, Any]:
        """Get default configuration."""
        return {
            "tools": {
                "jadx_path": "",
                "apktool_path": "",
                "java_path": "java",
                "auto_detect_tools": True
            },
            "ollama": {
                "api_url": "http://127.0.0.1:11434",
                "model": "qwen2.5-coder:3b",
                "timeout": 180,
                "enable_streaming": True,
                "max_chunk_chars": 8000,
                "fallback_enabled": True
            },
            "analysis": {
                "max_strings_length": 100000,
                "max_dex_size_mb": 50,
                "max_file_size_mb": 100,
                "max_total_extract_mb": 500,
                "enable_ai": True,
                "min_string_length": 5,
                "entropy_threshold": 3.5,
                "base64_min_length": 20,
                "hex_min_length": 16
            },
            "timeouts": {
                "apktool": 300,
                "jadx": 600,
                "elf_analysis": 60,
                "string_extraction": 30,
                "command_default": 300
            },
            "limits": {
                "max_java_file_size_kb": 500,
                "max_classes_per_dex": 500,
                "max_methods_total": 1000,
                "max_strings_total": 5000,
                "max_decoded_strings": 200,
                "max_suspicious_patterns": 200,
                "max_signature_matches": 50
            },
            "risk_engine": {
                "weights": {
                    "permission_base": 30,
                    "malware_confirmed": 40,
                    "malware_likely": 25,
                    "malware_possible": 15,
                    "malware_suspected": 8,
                    "behavior_high": 20,
                    "behavior_medium": 12,
                    "behavior_low": 5,
                    "network_c2": 15,
                    "network_suspicious": 8,
                    "network_telegram": 12,
                    "network_firebase": 5,
                    "native_jni_onload": 5,
                    "native_many_exports": 5,
                    "native_suspicious_strings": 5,
                    "anti_analysis": 10,
                    "obfuscation": 5,
                    "hidden_payload": 8,
                    "clean_manifest": -3,
                    "standard_permissions": -2,
                    "no_native": -2,
                    "no_dynamic_loading": -2
                },
                "thresholds": {
                    "critical": 80,
                    "high": 60,
                    "medium": 40,
                    "low": 20,
                    "minimal": 0
                },
                "permission_weights": {
                    "critical": 15,
                    "high": 8,
                    "medium": 4,
                    "low": 1,
                    "info": 0
                }
            },
            "scanner": {
                "stage_weights": {
                    "archive": 5,
                    "extract": 10,
                    "manifest": 20,
                    "dex": 30,
                    "jadx": 40,
                    "smali": 50,
                    "native": 60,
                    "jni": 65,
                    "strings": 70,
                    "permissions": 75,
                    "behavior": 80,
                    "network": 85,
                    "malware": 90,
                    "risk": 95,
                    "ai": 98,
                    "complete": 100
                },
                "parallel_stages": {
                    "enabled": False,
                    "max_workers": 4,
                    "parallel_groups": [
                        ["dex", "jadx", "smali"],
                        ["native", "strings"],
                        ["permissions", "behavior", "network"]
                    ]
                },
                "cache": {
                    "enabled": True,
                    "cache_dir": ".apkstudio_cache",
                    "max_age_days": 30,
                    "max_size_mb": 2000
                }
            },
            "behavior": {
                "min_confidence": 30,
                "min_matches_default": 2,
                "rule_categories": [
                    "suspicious_api_usage",
                    "malware_families",
                    "permission_abuse",
                    "network_iocs",
                    "string_obfuscation",
                    "jni_patterns"
                ]
            },
            "network": {
                "dga_entropy_threshold": 4.0,
                "dga_min_length": 12,
                "dynamic_dns_providers": [
                    "no-ip.com", "dyndns.org", "duckdns.org", "freedns.afraid.org",
                    "changeip.com", "dnsdynamic.org", "hopto.org", "ddns.net"
                ],
                "suspicious_tlds": [
                    "tk", "ml", "ga", "cf", "gq", "xyz", "top", "club", "work", "online"
                ],
                "cert_pinning_keywords": [
                    "CertificatePinner", "pinning", "sha256/", "trustManager", "X509TrustManager"
                ]
            },
            "string_analysis": {
                "xor_keys_to_try": [85, 170, 255, 0, 51, 204],
                "encoding_detection": {
                    "base64": True,
                    "hex": True,
                    "xor_single_byte": True,
                    "string_concatenation": True,
                    "reflection_based": True
                }
            },
            "reporting": {
                "html_template": "embedded",
                "include_raw_xml": True,
                "include_all_strings": False,
                "max_evidence_per_category": 20,
                "collapsible_sections": True
            },
            "gui": {
                "theme": "system",
                "window_size": "1200x800",
                "font_size": 10,
                "auto_scroll_logs": True,
                "show_tooltips": True
            }
        }

    def _merge_config(self, base: Dict, override: Dict):
        """Recursively merge override config into base."""
        for key, value in override.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                self._merge_config(base[key], value)
            else:
                base[key] = value

    def _apply_env_overrides(self):
        """Apply environment variable overrides."""
        env_mappings = {
            "APKSTUDIO_JADX_PATH": ("tools", "jadx_path"),
            "APKSTUDIO_APKTOOL_PATH": ("tools", "apktool_path"),
            "APKSTUDIO_JAVA_PATH": ("tools", "java_path"),
            "APKSTUDIO_OLLAMA_URL": ("ollama", "api_url"),
            "APKSTUDIO_OLLAMA_MODEL": ("ollama", "model"),
            "APKSTUDIO_ENABLE_AI": ("analysis", "enable_ai"),
            "APKSTUDIO_CACHE_DIR": ("scanner", "cache", "cache_dir"),
            "APKSTUDIO_CONFIG_FILE": None  # Special handling
        }

        for env_var, config_path in env_mappings.items():
            if config_path is None:
                continue
            value = os.environ.get(env_var)
            if value is not None:
                self._set_nested(self._config, config_path, value)

    def _set_nested(self, config: Dict, path: tuple, value: Any):
        """Set nested config value."""
        current = config
        for key in path[:-1]:
            current = current.setdefault(key, {})
        # Try to convert to appropriate type
        current[path[-1]] = self._convert_value(value)

    def _convert_value(self, value: str) -> Any:
        """Convert string value to appropriate type."""
        # Boolean
        if value.lower() in ("true", "yes", "1", "on"):
            return True
        if value.lower() in ("false", "no", "0", "off"):
            return False
        # Integer
        try:
            return int(value)
        except ValueError:
            pass
        # Float
        try:
            return float(value)
        except ValueError:
            pass
        # List (comma-separated)
        if "," in value:
            return [v.strip() for v in value.split(",")]
        return value

    def _auto_detect_tools(self):
        """Auto-detect tool paths."""
        tools = self._config.get("tools", {})

        # JADX detection
        if not tools.get("jadx_path"):
            jadx_paths = self._find_jadx()
            if jadx_paths:
                tools["jadx_path"] = jadx_paths[0]

        # Apktool detection
        if not tools.get("apktool_path"):
            apktool_paths = self._find_apktool()
            if apktool_paths:
                tools["apktool_path"] = apktool_paths[0]

        # Java detection (usually in PATH)
        if not tools.get("java_path") or tools["java_path"] == "java":
            tools["java_path"] = "java"

    def _find_jadx(self) -> List[str]:
        """Find JADX executable."""
        candidates = []
        project_root = get_project_root()
        # Common locations
        common = [
            "jadx",
            "jadx.bat",
            "jadx.cmd",
            "/usr/local/bin/jadx",
            "/opt/jadx/bin/jadx",
            str(project_root / "tools" / "jadx" / "bin" / "jadx.bat"),
            str(project_root / "tools" / "jadx" / "bin" / "jadx"),
        ]
        for c in common:
            if Path(c).exists():
                candidates.append(str(Path(c).resolve()))

        # Check PATH
        import shutil
        path_jadx = shutil.which("jadx")
        if path_jadx:
            candidates.insert(0, path_jadx)

        return candidates

    def _find_apktool(self) -> List[str]:
        """Find Apktool JAR."""
        candidates = []
        project_root = get_project_root()
        common = [
            "apktool.jar",
            "/usr/local/bin/apktool.jar",
            "/opt/apktool/apktool.jar",
            str(project_root / "tools" / "apktool.jar"),
        ]
        for c in common:
            if Path(c).exists():
                candidates.append(str(Path(c).resolve()))

        # Check for apktool wrapper script
        import shutil
        path_apktool = shutil.which("apktool")
        if path_apktool:
            candidates.insert(0, path_apktool)

        return candidates

    def _validate_config(self):
        """Validate and fix configuration values."""
        # JSON Schema validation with auto-correction
        if HAS_JSONSCHEMA:
            schema_path = Path(get_project_root()) / "config_schema.json"
            if schema_path.exists():
                try:
                    with open(schema_path, 'r', encoding='utf-8') as f:
                        schema = json.load(f)
                    # Validate and collect errors
                    validator = jsonschema.Draft7Validator(schema)
                    errors = list(validator.iter_errors(self._config))
                    for error in errors:
                        print(f"Config validation warning: {error.message} at {'/'.join(str(p) for p in error.path)}")
                        # Attempt auto-correction for common type mismatches
                        self._auto_correct_config(error)
                except Exception as e:
                    print(f"Config schema validation error: {e}")

        # Ensure numeric values are correct type
        numeric_paths = [
            ("analysis", "max_strings_length"),
            ("analysis", "max_dex_size_mb"),
            ("analysis", "max_file_size_mb"),
            ("analysis", "max_total_extract_mb"),
            ("analysis", "min_string_length"),
            ("analysis", "entropy_threshold"),
            ("analysis", "base64_min_length"),
            ("analysis", "hex_min_length"),
            ("timeouts", "apktool"),
            ("timeouts", "jadx"),
            ("timeouts", "elf_analysis"),
            ("timeouts", "string_extraction"),
            ("timeouts", "command_default"),
            ("limits", "max_java_file_size_kb"),
            ("limits", "max_classes_per_dex"),
            ("limits", "max_methods_total"),
            ("limits", "max_strings_total"),
            ("limits", "max_decoded_strings"),
            ("limits", "max_suspicious_patterns"),
            ("limits", "max_signature_matches"),
            ("risk_engine", "permission_weights", "critical"),
            ("risk_engine", "permission_weights", "high"),
            ("risk_engine", "permission_weights", "medium"),
            ("risk_engine", "permission_weights", "low"),
            ("risk_engine", "permission_weights", "info"),
            ("behavior", "min_confidence"),
            ("behavior", "min_matches_default"),
            ("network", "dga_entropy_threshold"),
            ("network", "dga_min_length"),
            ("scanner", "parallel_stages", "max_workers"),
            ("scanner", "cache", "max_age_days"),
            ("scanner", "cache", "max_size_mb"),
            ("gui", "font_size"),
        ]

        for path in numeric_paths:
            value = self._get_nested(self._config, path)
            if value is not None:
                try:
                    if isinstance(value, str):
                        # Only convert strings to numbers
                        if '.' in value:
                            converted = float(value)
                        else:
                            converted = int(value)
                        self._set_nested(self._config, path, converted)
                except (ValueError, TypeError):
                    pass  # Keep original

        # Ensure thresholds are ordered
        thresholds = self._config.get("risk_engine", {}).get("thresholds", {})
        if thresholds:
            # Ensure descending order
            sorted_thresholds = dict(sorted(thresholds.items(), key=lambda x: x[1], reverse=True))
            self._config["risk_engine"]["thresholds"] = sorted_thresholds

    def _auto_correct_config(self, error: 'jsonschema.ValidationError'):
        """Attempt to auto-correct config based on schema validation error."""
        try:
            path = list(error.path)
            if not path:
                return

            # Get the expected type from the schema
            schema = error.schema
            for p in path:
                schema = schema.get("properties", {}).get(p, {})
                if "type" in schema:
                    expected_type = schema["type"]
                    break
            else:
                return

            # Get current value
            current = self._config
            for p in path[:-1]:
                if isinstance(current, dict) and p in current:
                    current = current[p]
                else:
                    return
            key = path[-1]
            if key not in current:
                return

            value = current[key]

            # Auto-correct based on expected type
            if expected_type == "boolean" and isinstance(value, str):
                if value.lower() in ("true", "yes", "1", "on"):
                    current[key] = True
                elif value.lower() in ("false", "no", "0", "off"):
                    current[key] = False
                print(f"  Auto-corrected {'.'.join(path)}: {value} -> {current[key]}")

            elif expected_type == "integer" and isinstance(value, (str, float)):
                try:
                    if isinstance(value, float) or (isinstance(value, str) and '.' in value):
                        current[key] = int(float(value))
                    else:
                        current[key] = int(value)
                    print(f"  Auto-corrected {'.'.join(path)}: {value} -> {current[key]}")
                except (ValueError, TypeError):
                    pass

            elif expected_type == "number" and isinstance(value, str):
                try:
                    current[key] = float(value)
                    print(f"  Auto-corrected {'.'.join(path)}: {value} -> {current[key]}")
                except (ValueError, TypeError):
                    pass

            elif expected_type == "string" and isinstance(value, (int, float, bool)):
                current[key] = str(value)
                print(f"  Auto-corrected {'.'.join(path)}: {value} -> {current[key]}")

        except Exception:
            pass  # Silently ignore correction failures

    def _get_nested(self, config: Dict, path: tuple, default: Any = None) -> Any:
        """Get nested config value."""
        current = config
        for key in path:
            if isinstance(current, dict) and key in current:
                current = current[key]
            else:
                return default
        return current

    def get(self, *args, default: Any = None) -> Any:
        """Get configuration value by path.

        Usage:
            config.get('section', 'key')
            config.get('section', 'key', default=value)
            config.get('section', default=value)  # legacy: dict as 2nd positional arg

        Note: For section-only with default, use keyword argument:
            config.get('section', default={})
        """
        if not args:
            return self._config

        # Handle legacy call: config.get('section', {}) where {} is meant as default
        # If last arg is a dict and it's the second positional arg, treat as default
        path = list(args)
        if len(args) == 2 and isinstance(args[1], dict) and default is None:
            default = args[1]
            path = [args[0]]

        # Validate path elements are strings
        for p in path:
            if not isinstance(p, str):
                raise TypeError(f"Path elements must be strings, got {type(p).__name__}")

        return self._get_nested(self._config, tuple(path), default=default)

    def get_section(self, section: str) -> Dict[str, Any]:
        """Get entire configuration section."""
        return self._config.get(section, {})

    def get_all(self) -> Dict[str, Any]:
        """Get all configuration."""
        return self._config.copy()

    def update(self, *path: str, value: Any) -> bool:
        """Update configuration value."""
        try:
            self._set_nested(self._config, path, value)
            return True
        except Exception:
            return False

    def save(self, path: Optional[str] = None) -> bool:
        """Save configuration to file."""
        save_path = path or self.config_path
        try:
            Path(save_path).parent.mkdir(parents=True, exist_ok=True)
            with open(save_path, 'w', encoding='utf-8') as f:
                json.dump(self._config, f, indent=2, ensure_ascii=False)
            return True
        except Exception as e:
            print(f"Failed to save config: {e}")
            return False

    def reset_to_defaults(self):
        """Reset configuration to defaults."""
        self._config = self._get_defaults()
        self._apply_env_overrides()
        if self._config.get("tools", {}).get("auto_detect_tools", True):
            self._auto_detect_tools()
        self._validate_config()

    def validate_tools(self) -> Dict[str, bool]:
        """Validate that configured tools exist."""
        tools = self._config.get("tools", {})
        result = {}
        for tool in ["jadx_path", "apktool_path", "java_path"]:
            path = tools.get(tool, "")
            if tool == "java_path":
                import shutil
                result[tool] = shutil.which(path) is not None
            else:
                result[tool] = bool(path and Path(path).exists())
        return result


# Global instance getter
def get_config(config_path: Optional[str] = None) -> ConfigManager:
    """Get global ConfigManager instance."""
    return ConfigManager(config_path)


def get_config_value(*path: str, default: Any = None) -> Any:
    """Convenience function to get config value."""
    return get_config().get(*path, default=default)