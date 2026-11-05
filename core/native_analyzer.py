"""
Native library analyzer for APKStudioAI 2.1
Analyzes .so files: ELF headers, architecture, sections, symbols, imports, exports, strings
"""
import subprocess
import os
from pathlib import Path
from typing import Dict, List, Any, Optional
from .utils import run_command, is_elf_file, get_architecture_from_elf, printable_strings, printable_strings_utf16
from .elf_analyzer import ELFAnalyzer


class NativeAnalyzer:
    def __init__(self, max_file_mb: int = 50):
        self.max_file_bytes = max_file_mb * 1024 * 1024
        self.elf_analyzer = ELFAnalyzer()

    def analyze(self, extract_dir: Path) -> Dict[str, Any]:
        """Analyze all native libraries in extracted APK."""
        results = {
            "libraries": [],
            "architectures": set(),
            "total_libraries": 0,
            "total_size": 0,
            "suspicious_findings": []
        }

        lib_dirs = [
            extract_dir / "lib" / "arm64-v8a",
            extract_dir / "lib" / "armeabi-v7a",
            extract_dir / "lib" / "x86",
            extract_dir / "lib" / "x86_64",
            extract_dir / "lib" / "mips",
            extract_dir / "lib" / "mips64",
        ]

        for lib_dir in lib_dirs:
            if not lib_dir.exists():
                continue

            arch = lib_dir.name
            results["architectures"].add(arch)

            for so_file in lib_dir.glob("*.so"):
                if so_file.stat().st_size > self.max_file_bytes:
                    results["suspicious_findings"].append({
                        "file": str(so_file.relative_to(extract_dir)),
                        "issue": f"File too large ({so_file.stat().st_size} bytes)",
                        "severity": "info"
                    })
                    continue

                lib_result = self._analyze_library(so_file, arch, extract_dir)
                results["libraries"].append(lib_result)
                results["total_size"] += so_file.stat().st_size

        results["total_libraries"] = len(results["libraries"])
        results["architectures"] = list(results["architectures"])

        return results

    def _analyze_library(self, so_path: Path, arch: str, extract_dir: Path) -> Dict[str, Any]:
        """Analyze a single .so library."""
        result = {
            "name": so_path.name,
            "path": str(so_path.relative_to(extract_dir)),
            "architecture": arch,
            "size": so_path.stat().st_size,
            "sha256": None,
            "is_elf": False,
            "elf_info": {},
            "strings": [],
            "interesting_strings": [],
            "suspicious_strings": [],
            "imports": [],
            "exports": [],
            "jni_functions": [],
            "jni_onload": None,
            "register_natives": [],
            "system_calls": [],
            "errors": []
        }

        # Calculate hash
        try:
            import hashlib
            result["sha256"] = hashlib.sha256(so_path.read_bytes()).hexdigest()
        except Exception:
            pass

        # Verify ELF
        if not is_elf_file(so_path):
            result["errors"].append("Not a valid ELF file")
            return result

        result["is_elf"] = True

        # Basic ELF info
        elf_arch = get_architecture_from_elf(so_path)
        if elf_arch:
            result["elf_info"]["detected_arch"] = elf_arch

        # Deep ELF analysis
        try:
            elf_info = self.elf_analyzer.analyze(so_path)
            result["elf_info"].update(elf_info)

            # Extract JNI functions
            result["jni_functions"] = self._find_jni_functions(elf_info)
            result["jni_onload"] = self._find_jni_onload(elf_info)
            result["register_natives"] = self._find_register_natives(elf_info)

        except Exception as e:
            result["errors"].append(f"ELF analysis error: {e}")

        # Extract strings
        try:
            raw = so_path.read_bytes()
            strings = printable_strings(raw, 5)
            strings.extend(printable_strings_utf16(raw, 5))
            result["strings"] = strings[:500]

            # Find interesting strings
            result["interesting_strings"] = self._filter_interesting_strings(strings)
            result["suspicious_strings"] = self._filter_suspicious_strings(strings)

        except Exception as e:
            result["errors"].append(f"String extraction error: {e}")

        return result

    def _filter_interesting_strings(self, strings: List[str]) -> List[str]:
        """Filter for security-relevant strings."""
        keywords = [
            "accessibility", "screen", "image", "media", "vpn", "socket",
            "http", "upload", "camera", "deviceadmin", "register",
            "jni", "native", "register", "loadlibrary", "load",
            "shell", "exec", "command", "runtime", "process",
            "crypt", "encrypt", "decrypt", "cipher", "secret",
            "key", "token", "password", "auth", "credential",
            "firebase", "telegram", "bot", "api", "endpoint",
            "c2", "command", "control", "beacon", "heartbeat"
        ]

        interesting = []
        for s in strings:
            low = s.lower()
            if any(k in low for k in keywords):
                interesting.append(s)
        return interesting[:200]

    def _filter_suspicious_strings(self, strings: List[str]) -> List[Dict[str, Any]]:
        """Filter for highly suspicious strings with context."""
        suspicious = []
        patterns = {
            "hardcoded_ip": r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",
            "url": r"https?://[^\s\"']+",
            "base64": r"[A-Za-z0-9+/]{20,}={0,2}",
            "hex": r"[0-9a-fA-F]{32,}",
            "jwt": r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
            "private_key": r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
            "cert": r"-----BEGIN CERTIFICATE-----",
            "api_key": r"(api[_-]?key|access[_-]?token|secret)[=:]\s*[A-Za-z0-9_-]{16,}"
        }

        import re
        for s in strings:
            for category, pattern in patterns.items():
                if re.search(pattern, s):
                    suspicious.append({
                        "category": category,
                        "string": s[:200],
                        "pattern": pattern
                    })
                    break
        return suspicious[:50]

    def _find_jni_functions(self, elf_info: Dict) -> List[Dict[str, Any]]:
        """Find JNI native functions from ELF exports."""
        jni_functions = []

        for exp in elf_info.get("exports", []):
            name = exp.get("name", "")
            if name.startswith("Java_") or name.startswith("JNI_"):
                jni_functions.append({
                    "name": name,
                    "address": exp.get("address"),
                    "type": "JNI" if name.startswith("JNI_") else "Java_native"
                })

        return jni_functions

    def _find_jni_onload(self, elf_info: Dict) -> Optional[Dict[str, Any]]:
        """Find JNI_OnLoad function."""
        for exp in elf_info.get("exports", []):
            if exp.get("name") == "JNI_OnLoad":
                return {
                    "address": exp.get("address"),
                    "found": True
                }
        return {"found": False}

    def _find_register_natives(self, elf_info: Dict) -> List[Dict[str, Any]]:
        """Find RegisterNatives calls and JNINativeMethod tables."""
        registers = []

        # Look for RegisterNatives in imports or strings
        for imp in elf_info.get("imports", []):
            if "RegisterNatives" in imp.get("name", ""):
                registers.append({
                    "type": "import",
                    "function": imp.get("name"),
                    "library": imp.get("library")
                })

        # The actual JNINativeMethod table analysis is done in jni_analyzer.py
        return registers