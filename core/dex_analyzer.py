"""
DEX file analyzer with multi-DEX support and individual JADX analysis
Includes bytecode-level analysis for deep inspection without external dependencies.
Now with streaming DEX parser and structured logging.
"""
import hashlib
import subprocess
from pathlib import Path
from typing import Dict, List, Any, Optional
from .utils import run_command, is_dex_file, sha256_file
from .config_manager import get_config
from .dex_bytecode_analyzer import DEXBytecodeAnalyzer
from .streaming_dex_parser import StreamingDEXParser, get_streaming_dex_parser
from .logging_setup import get_module_logger

logger = get_module_logger("dex")


class DexAnalyzer:
    def __init__(self, config: Dict[str, Any] = None, max_file_mb: int = 100):
        """Initialize with config dict or string path."""
        if isinstance(config, str):
            self.jadx_path = config
        elif isinstance(config, dict):
            self.jadx_path = config.get("jadx", config.get("jadx_path", ""))
        else:
            global_config = get_config()
            tools_config = global_config.get("tools", {})
            self.jadx_path = tools_config.get("jadx_path", tools_config.get("jadx", ""))

        # Get max file size from config
        if isinstance(config, dict) and "analysis" in config:
            max_file_mb = config["analysis"].get("max_dex_size_mb", max_file_mb)
        else:
            global_config = get_config()
            max_file_mb = global_config.get("analysis", {}).get("max_dex_size_mb", max_file_mb)

        self.max_file_bytes = max_file_mb * 1024 * 1024
        self.config = config

        # Initialize streaming parser
        self.streaming_parser = get_streaming_dex_parser(config)

        # Initialize bytecode analyzer for backward compatibility
        # DEXBytecodeAnalyzer expects config_path (str) or uses global config
        self.bytecode_analyzer = DEXBytecodeAnalyzer(None)

    def analyze(self, apk_path: Path, extract_dir: Optional[Path] = None,
                jadx_output_dir: Optional[Path] = None) -> Dict[str, Any]:
        """Analyze all DEX files in the APK using streaming parser."""
        logger.info("dex_analysis_started", apk=str(apk_path))

        if extract_dir is None:
            import tempfile
            extract_dir = Path(tempfile.mkdtemp(prefix="apkstudio_dex_"))

        if jadx_output_dir is None:
            import tempfile
            jadx_output_dir = Path(tempfile.mkdtemp(prefix="apkstudio_jadx_"))

        # Use streaming parser for multidex analysis
        streaming_results = self.streaming_parser.parse_multidex(apk_path, extract_dir)

        # Also run JADX analysis if available
        jadx_results = []
        if self.jadx_path and Path(self.jadx_path).exists():
            from .jadx_engine import JadxEngine
            jadx_engine = JadxEngine(self.config)
            for i, dex_result in enumerate(streaming_results):
                # Find the DEX file path
                dex_files = list(extract_dir.rglob("classes*.dex"))
                dex_files.sort(key=lambda x: x.name)
                if i < len(dex_files):
                    jadx_result = jadx_engine.decompile_dex(
                        dex_files[i], jadx_output_dir / f"dex_{i}"
                    )
                    jadx_results.append(jadx_result)

        # Combine streaming and JADX results
        dex_files = []
        dex_analysis = []

        for i, stream_result in enumerate(streaming_results):
            # Dex file info
            dex_info = {
                "index": i,
                "sha256": stream_result.sha256,
                "size_bytes": stream_result.size_bytes,
                "size_formatted": self._format_size(stream_result.size_bytes),
                "class_count": stream_result.class_count,
                "method_count": stream_result.method_count,
                "string_count": stream_result.string_count,
                "valid": stream_result.header.valid
            }
            dex_files.append(dex_info)

            # Combined analysis
            analysis = {
                "dex_info": dex_info,
                "streaming_analysis": {
                    "classes": stream_result.classes,
                    "methods": stream_result.methods,
                    "strings": stream_result.strings,
                    "api_calls": stream_result.api_calls,
                    "suspicious_patterns": stream_result.suspicious_patterns,
                    "errors": stream_result.errors,
                    "warnings": stream_result.warnings
                },
                "jadx": jadx_results[i] if i < len(jadx_results) else {"status": "not_run"},
                "bytecode_analysis": {}  # For backward compat
            }
            dex_analysis.append(analysis)

        # Aggregate findings
        all_api_calls = []
        all_suspicious = []
        all_strings = []
        for result in streaming_results:
            all_api_calls.extend(result.api_calls)
            all_suspicious.extend(result.suspicious_patterns)
            all_strings.extend(result.strings)

        call_strings = [c.get("call", "") for c in all_api_calls if isinstance(c, dict)]

        logger.info("dex_analysis_completed",
                   apk=str(apk_path),
                   dex_count=len(dex_files),
                   total_classes=sum(r.class_count for r in streaming_results),
                   total_methods=sum(r.method_count for r in streaming_results))

        return {
            "dex_count": len(dex_files),
            "dex_files": dex_files,
            "dex_analysis": dex_analysis,
            "total_classes": sum(r.class_count for r in streaming_results),
            "total_methods": sum(r.method_count for r in streaming_results),
            "bytecode_summary": {
                "total_api_calls": len(all_api_calls),
                "unique_api_calls": len(set(call_strings)),
                "suspicious_patterns": all_suspicious[:200],
                "top_strings": all_strings[:500],
                "categories": self._categorize_findings(all_suspicious)
            }
        }

    def _analyze_dex_file(self, dex_path: Path) -> Dict[str, Any]:
        """Analyze a single DEX file header and structure (legacy method)."""
        info = {
            "name": dex_path.name,
            "size": dex_path.stat().st_size,
            "sha256": sha256_file(dex_path),
            "valid": False,
            "header": {},
            "class_count": 0,
            "method_count": 0,
            "field_count": 0
        }

        try:
            with open(dex_path, "rb") as f:
                header = f.read(112)  # DEX header is 112 bytes

            if len(header) >= 112 and header.startswith(b"dex\n"):
                info["valid"] = True
                import struct
                try:
                    values = struct.unpack("<8sII20sIIIIIIIIIIIIIIII", header[:112])
                    info["header"] = {
                        "magic": values[0].decode("ascii", errors="ignore"),
                        "checksum": values[1],
                        "file_size": values[4],
                        "header_size": values[5],
                        "endian_tag": hex(values[6]),
                        "string_ids_size": values[9],
                        "type_ids_size": values[11],
                        "proto_ids_size": values[13],
                        "field_ids_size": values[15],
                        "method_ids_size": values[17],
                        "class_defs_size": values[19]
                    }
                    info["class_count"] = values[19]
                    info["method_count"] = values[17]
                    info["field_count"] = values[15]
                except Exception:
                    pass
        except Exception as e:
            info["error"] = str(e)

        return info

    def _format_size(self, size_bytes: int) -> str:
        """Format bytes as human-readable string."""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size_bytes < 1024:
                return f"{size_bytes:.1f} {unit}"
            size_bytes /= 1024
        return f"{size_bytes:.1f} TB"

    def _categorize_findings(self, findings: List[Dict]) -> Dict[str, int]:
        """Categorize suspicious findings by type."""
        categories = {}
        for f in findings:
            cat = f.get("category", f.get("type", "unknown"))
            categories[cat] = categories.get(cat, 0) + 1
        return dict(sorted(categories.items(), key=lambda x: x[1], reverse=True))

    def _get_config_for_bytecode(self) -> Optional[Dict]:
        """Get config dict suitable for bytecode analyzer."""
        global_config = get_config()
        return {
            "analysis": global_config.get("analysis", {}),
            "limits": global_config.get("limits", {})
        }