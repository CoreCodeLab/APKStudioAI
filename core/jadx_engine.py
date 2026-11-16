"""
JADX decompiler engine wrapper for APKStudioAI 2.1
"""
import subprocess
import hashlib
import json
import logging
from pathlib import Path
from typing import Dict, List, Any, Optional
from .utils import run_command
from .config_manager import get_config
from .cache_manager import get_cache
from .logging_setup import get_module_logger

logger = get_module_logger("jadx")


class JadxEngine:
    def __init__(self, config: Dict[str, Any] = None, timeout: int = 600):
        """Initialize with config dict or string path."""
        if isinstance(config, str):
            self.jadx_path = config
        elif isinstance(config, dict):
            self.jadx_path = config.get("jadx", config.get("jadx_path", ""))
        else:
            global_config = get_config()
            tools_config = global_config.get("tools", {})
            self.jadx_path = tools_config.get("jadx_path", tools_config.get("jadx", ""))

        # Get timeout from config
        if isinstance(config, dict) and "timeouts" in config:
            self.timeout = config["timeouts"].get("jadx", timeout)
        else:
            global_config = get_config()
            self.timeout = global_config.get("timeouts", {}).get("jadx", timeout)

        self.available = bool(self.jadx_path and Path(self.jadx_path).exists())

        # Initialize cache
        self.cache = get_cache()
        self._cache_enabled = self.cache.enabled if self.cache else False

    def _get_cache_key(self, input_path: Path, no_res: bool, no_imports: bool) -> str:
        """Generate cache key based on file hash and options."""
        file_hash = self._get_file_hash(input_path)
        options_hash = hashlib.md5(f"{no_res}:{no_imports}".encode()).hexdigest()[:8]
        return f"jadx:{file_hash}:{options_hash}"

    def _get_file_hash(self, file_path: Path) -> str:
        """Get SHA256 hash of file (first 1MB for speed on large files)."""
        hasher = hashlib.sha256()
        with open(file_path, "rb") as f:
            # Read first 1MB + last 1KB for hash
            chunk = f.read(1024 * 1024)
            hasher.update(chunk)
            file_size = file_path.stat().st_size
            if file_size > 1024 * 1024 + 1024:
                f.seek(file_size - 1024)
                chunk = f.read(1024)
                hasher.update(chunk)
        return hasher.hexdigest()[:32]

    def _get_cached_result(self, cache_key: str, output_dir: Path) -> Optional[Dict[str, Any]]:
        """Retrieve cached result and restore to output_dir if possible."""
        if not self._cache_enabled:
            return None

        cached = self.cache.get("jadx", cache_key)
        if cached and cached.get("success"):
            # Check if output directory already exists with content
            if output_dir.exists() and any(output_dir.rglob("*.java")):
                logger.info("jadx_cache_hit", cache_key=cache_key, output_dir=str(output_dir))
                cached["output_dir"] = str(output_dir)
                cached["cached"] = True
                return cached
        return None

    def _cache_result(self, cache_key: str, result: Dict[str, Any]) -> None:
        """Cache decompilation result."""
        if not self._cache_enabled:
            return
        # Only cache successful results
        if result.get("success"):
            # Remove large fields before caching
            cache_data = {k: v for k, v in result.items() if k not in ("stdout", "stderr")}
            self.cache.set("jadx", cache_data, cache_key, tags=["jadx"])
            logger.info("jadx_result_cached", cache_key=cache_key)

    def decompile_apk(self, apk_path: Path, output_dir: Path,
                      no_res: bool = True, no_imports: bool = True) -> Dict[str, Any]:
        """Decompile full APK with JADX (with caching)."""
        if not self.available:
            return {"success": False, "error": "JADX not configured", "output_dir": str(output_dir)}

        # Check cache
        cache_key = self._get_cache_key(apk_path, no_res, no_imports)
        cached = self._get_cached_result(cache_key, output_dir)
        if cached:
            return cached

        logger.info("jadx_decompile_started", apk=str(apk_path), output_dir=str(output_dir))

        output_dir.mkdir(parents=True, exist_ok=True)
        cmd = self._build_cmd(apk_path, output_dir, no_res, no_imports)

        result = run_command(cmd, timeout=self.timeout)
        # Convert SimpleNamespace to dict if needed
        if hasattr(result, '__dict__'):
            result_dict = {
                "returncode": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "success": result.success,
                "output_dir": str(output_dir)
            }
        else:
            result_dict = dict(result)
            result_dict["output_dir"] = str(output_dir)

        if result_dict["success"]:
            result_dict["stats"] = self._get_decompile_stats(output_dir)
            # Cache successful result
            self._cache_result(cache_key, result_dict)
            logger.info("jadx_decompile_completed", apk=str(apk_path), stats=result_dict["stats"])
        else:
            logger.warning("jadx_decompile_failed", apk=str(apk_path), error=result_dict.get("stderr"))

        return result_dict

    def decompile_dex(self, dex_path: Path, output_dir: Path) -> Dict[str, Any]:
        """Decompile a single DEX file (with caching)."""
        if not self.available:
            return {"success": False, "error": "JADX not configured", "output_dir": str(output_dir)}

        # Check cache
        cache_key = self._get_cache_key(dex_path, True, True)
        cached = self._get_cached_result(cache_key, output_dir)
        if cached:
            return cached

        logger.info("jadx_decompile_dex_started", dex=str(dex_path), output_dir=str(output_dir))

        output_dir.mkdir(parents=True, exist_ok=True)
        cmd = self._build_cmd(dex_path, output_dir, no_res=True, no_imports=True)

        result = run_command(cmd, timeout=self.timeout)
        # Convert SimpleNamespace to dict if needed
        if hasattr(result, '__dict__'):
            result_dict = {
                "returncode": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "success": result.success,
                "output_dir": str(output_dir)
            }
        else:
            result_dict = dict(result)
            result_dict["output_dir"] = str(output_dir)

        if result_dict["success"]:
            result_dict["stats"] = self._get_decompile_stats(output_dir)
            # Cache successful result
            self._cache_result(cache_key, result_dict)
            logger.info("jadx_decompile_dex_completed", dex=str(dex_path), stats=result_dict["stats"])
        else:
            logger.warning("jadx_decompile_dex_failed", dex=str(dex_path), error=result_dict.get("stderr"))

        return result_dict

    def _build_cmd(self, input_path: Path, output_dir: Path,
                   no_res: bool, no_imports: bool) -> List[str]:
        """Build JADX command line."""
        jadx = self.jadx_path
        if str(jadx).lower().endswith((".bat", ".cmd")):
            base = ["cmd.exe", "/c", jadx]
        else:
            base = [jadx]

        cmd = base + ["-d", str(output_dir)]

        if no_res:
            cmd.append("--no-res")
        if no_imports:
            cmd.append("--no-imports")

        # Additional useful flags
        cmd.extend([
            "--show-bad-code",      # Show code that failed to decompile
            "--no-debug-info",      # Skip debug info
            "--threads-count", "4", # Parallel decompilation
            str(input_path)
        ])

        return cmd

    def _get_decompile_stats(self, output_dir: Path) -> Dict[str, Any]:
        """Get statistics from decompiled output."""
        stats = {
            "java_files": 0,
            "total_lines": 0,
            "packages": set(),
            "classes": 0,
            "methods": 0,
            "errors": 0
        }

        for java_file in output_dir.rglob("*.java"):
            try:
                stats["java_files"] += 1
                content = java_file.read_text(encoding="utf-8", errors="ignore")
                stats["total_lines"] += content.count("\n")

                # Count classes
                import re
                stats["classes"] += len(re.findall(r'\bclass\s+\w+', content))
                stats["methods"] += len(re.findall(r'\b\w+\s+\w+\s*\([^)]*\)\s*\{', content))

                # Extract package
                pkg_match = re.search(r'^package\s+([\w.]+);', content, re.MULTILINE)
                if pkg_match:
                    stats["packages"].add(pkg_match.group(1))

            except Exception:
                stats["errors"] += 1

        stats["packages"] = list(stats["packages"])
        return stats

    def extract_source_for_ai(self, output_dir: Path, max_files: int = 300,
                              max_file_size: int = 256000, max_chars_per_file: int = 5000) -> str:
        """Extract bounded source code excerpts for AI analysis."""
        parts = []
        count = 0

        for java_file in output_dir.rglob("*.java"):
            if count >= max_files:
                break
            try:
                if java_file.stat().st_size > max_file_size:
                    continue
                content = java_file.read_text(encoding="utf-8", errors="ignore")
                if len(content) > max_chars_per_file:
                    content = content[:max_chars_per_file]
                rel_path = java_file.relative_to(output_dir)
                parts.append(f"\n// FILE: {rel_path}\n{content}")
                count += 1
            except Exception:
                pass

        return "\n".join(parts)

    def find_patterns(self, output_dir: Path, patterns: Dict[str, List[str]]) -> Dict[str, List[Dict]]:
        """Search for code patterns in decompiled output."""
        results = {category: [] for category in patterns}

        for java_file in output_dir.rglob("*.java"):
            try:
                if java_file.stat().st_size > 500_000:
                    continue
                content = java_file.read_text(encoding="utf-8", errors="ignore")
                class_name = self._get_class_name(content)

                for category, pattern_list in patterns.items():
                    for pattern in pattern_list:
                        import re
                        for match in re.finditer(pattern, content):
                            start = max(0, match.start() - 150)
                            end = min(len(content), match.end() + 150)
                            context = content[start:end].replace("\n", " ")

                            results[category].append({
                                "file": str(java_file.relative_to(output_dir)),
                                "class": class_name,
                                "pattern": pattern,
                                "context": context[:500]
                            })
            except Exception:
                pass

        # Limit results per category
        for category in results:
            results[category] = results[category][:50]

        return results

    def _get_class_name(self, content: str) -> str:
        import re
        match = re.search(r'(class|interface|enum)\s+(\w+)', content)
        return match.group(2) if match else "Unknown"