"""
JADX decompiler engine wrapper for APKStudioAI 2.1
"""
import subprocess
from pathlib import Path
from typing import Dict, List, Any, Optional
from .utils import run_command


class JadxEngine:
    def __init__(self, jadx_path: str = "", timeout: int = 600):
        self.jadx_path = jadx_path
        self.timeout = timeout
        self.available = bool(jadx_path and Path(jadx_path).exists())

    def decompile_apk(self, apk_path: Path, output_dir: Path,
                      no_res: bool = True, no_imports: bool = True) -> Dict[str, Any]:
        """Decompile full APK with JADX."""
        if not self.available:
            return {"success": False, "error": "JADX not configured", "output_dir": str(output_dir)}

        output_dir.mkdir(parents=True, exist_ok=True)
        cmd = self._build_cmd(apk_path, output_dir, no_res, no_imports)

        result = run_command(cmd, timeout=self.timeout)
        result["output_dir"] = str(output_dir)

        if result["success"]:
            result["stats"] = self._get_decompile_stats(output_dir)

        return result

    def decompile_dex(self, dex_path: Path, output_dir: Path) -> Dict[str, Any]:
        """Decompile a single DEX file."""
        if not self.available:
            return {"success": False, "error": "JADX not configured", "output_dir": str(output_dir)}

        output_dir.mkdir(parents=True, exist_ok=True)
        cmd = self._build_cmd(dex_path, output_dir, no_res=True, no_imports=True)

        result = run_command(cmd, timeout=self.timeout)
        result["output_dir"] = str(output_dir)

        if result["success"]:
            result["stats"] = self._get_decompile_stats(output_dir)

        return result

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