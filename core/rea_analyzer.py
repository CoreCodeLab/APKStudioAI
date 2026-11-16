"""
REA (Reverse Engineering Assistant) Analyzer for APKStudioAI
Integrates REA's MCP tools for enhanced reverse engineering capabilities
"""
import os
import json
import subprocess
import asyncio
import sys
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime


class REAAnalyzer:
    """Analyzer that uses REA's MCP tools for advanced reverse engineering"""

    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.rea_config = self.config.get("rea", {})
        self.enabled = self.rea_config.get("enabled", True)
        self.ghidra_path = self.rea_config.get("ghidra_path", "")
        self.skill_path = self.rea_config.get("skill_path", "")
        self.mcp_command = self.rea_config.get("mcp_command", "npx -y rea-agents@latest mcp")

        # REA tool categories available
        self.tool_families = {
            "ghidra": ["analyze", "decompile", "list_functions", "get_strings", "xrefs", "search"],
            "decompiler": ["decompile_function", "decompile_range", "get_pcode"],
            "binary": ["info", "sections", "symbols", "imports", "exports"],
            "analysis": ["dataflow", "callgraph", "cfg", "taint"],
            "search": ["pattern", "bytes", "instructions", "constants"],
        }

        self.results = {}
        self.errors = []
        self.warnings = []
        self._availability_cache = None  # Cache for is_available()

        # Windows uses npx.cmd
        self._npx_cmd = "npx.cmd" if sys.platform == "win32" else "npx"

    def _run_rea_command(self, args: List[str], timeout: int = 30) -> subprocess.CompletedProcess:
        """Run REA command with proper Windows handling."""
        cmd = [self._npx_cmd, "rea-agents@latest"] + args
        # Use shell=True on Windows to find npx.cmd in PATH
        use_shell = sys.platform == "win32"
        return subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=use_shell
        )

    def is_available(self) -> bool:
        """Check if REA is available and configured (cached)"""
        if not self.enabled:
            return False

        # Return cached result if available
        if self._availability_cache is not None:
            return self._availability_cache

        # Check if REA CLI is available (increased timeout for slower environments)
        try:
            result = self._run_rea_command(["--version"], timeout=60)
            self._availability_cache = (result.returncode == 0)
            if not self._availability_cache:
                print(f"DEBUG: REA version check failed, returncode={result.returncode}, stderr={result.stderr[:200]}")
            return self._availability_cache
        except Exception as e:
            print(f"DEBUG: REA version check exception: {e}")
            self._availability_cache = False
            return False

    def get_doctor_status(self) -> Dict[str, Any]:
        """Get REA doctor status"""
        try:
            result = self._run_rea_command(["doctor", "--format", "json"], timeout=30)
            # Parse JSON even if returncode != 0 (doctor returns non-zero when healthy=false)
            if result.stdout:
                return json.loads(result.stdout)
        except Exception as e:
            self.errors.append(f"REA doctor failed: {e}")
        return {}

    def analyze_apk_with_rea(self, apk_path: str, extract_dir: str) -> Dict[str, Any]:
        """Analyze APK using REA's Ghidra integration for native libraries"""
        # Note: availability is checked by caller (scanner), but we check again for safety
        if not self.enabled:
            self.warnings.append("REA not enabled, skipping REA analysis")
            return {"enabled": False, "error": "REA not enabled"}

        results = {
            "enabled": True,
            "native_libraries": [],
            "ghidra_analysis": {},
            "decompiler_results": {},
            "cross_references": {},
            "patterns": [],
        }

        # Find native libraries in extract_dir
        native_libs = self._find_native_libraries(extract_dir)
        results["native_libraries"] = native_libs

        if not native_libs:
            self.warnings.append("No native libraries found for REA analysis")
            return results

        # Analyze each native library with REA/Ghidra
        for lib in native_libs:
            lib_path = lib["path"]
            lib_name = lib["name"]
            arch = lib.get("arch", "unknown")

            try:
                # Run Ghidra headless analysis via REA
                analysis = self._run_ghidra_analysis(lib_path, arch)
                results["ghidra_analysis"][lib_name] = analysis

                # Get decompiler output for key functions
                decomp = self._get_decompiler_output(lib_path, arch)
                results["decompiler_results"][lib_name] = decomp

                # Get cross-references
                xrefs = self._get_cross_references(lib_path, arch)
                results["cross_references"][lib_name] = xrefs

                # Search for suspicious patterns
                patterns = self._search_suspicious_patterns(lib_path, arch)
                results["patterns"].extend(patterns)

            except Exception as e:
                self.errors.append(f"REA analysis failed for {lib_name}: {e}")
                results["ghidra_analysis"][lib_name] = {"error": str(e)}

        return results

    def _find_native_libraries(self, extract_dir: str) -> List[Dict[str, Any]]:
        """Find native .so libraries in extracted APK"""
        libs = []
        lib_dirs = [
            Path(extract_dir) / "lib",
            Path(extract_dir) / "jni",
        ]

        for lib_dir in lib_dirs:
            if lib_dir.exists():
                for arch_dir in lib_dir.iterdir():
                    if arch_dir.is_dir():
                        arch = arch_dir.name
                        for so_file in arch_dir.glob("*.so"):
                            libs.append({
                                "name": so_file.name,
                                "path": str(so_file),
                                "arch": arch,
                                "size": so_file.stat().st_size,
                            })

        return libs

    def _run_ghidra_analysis(self, lib_path: str, arch: str) -> Dict[str, Any]:
        """Run Ghidra headless analysis via REA MCP"""
        # Use REA MCP to run Ghidra analyzeHeadless
        # This would typically use the MCP protocol, but we'll use CLI for now
        try:
            # Build Ghidra command
            ghidra_home = self.ghidra_path or os.environ.get("GHIDRA_INSTALL_DIR", "")
            if not ghidra_home:
                return {"error": "GHIDRA_INSTALL_DIR not configured"}

            analyze_headless = os.path.join(ghidra_home, "support", "analyzeHeadless.bat")
            if not os.path.exists(analyze_headless):
                return {"error": "analyzeHeadless.bat not found"}

            # Create temporary project
            import tempfile
            with tempfile.TemporaryDirectory() as tmpdir:
                project_dir = os.path.join(tmpdir, "ghidra_project")
                os.makedirs(project_dir, exist_ok=True)

                # Run analysis
                cmd = [
                    analyze_headless,
                    project_dir,
                    "REA_Analysis",
                    "-import", lib_path,
                    "-postScript", "ExportFunctions.java",
                    "-deleteProject",
                ]

                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=300
                )

                return {
                    "success": result.returncode == 0,
                    "stdout": result.stdout[-5000:] if result.stdout else "",
                    "stderr": result.stderr[-5000:] if result.stderr else "",
                    "arch": arch,
                }
        except subprocess.TimeoutExpired:
            return {"error": "Ghidra analysis timed out"}
        except Exception as e:
            return {"error": f"Ghidra analysis failed: {e}"}

    def _get_decompiler_output(self, lib_path: str, arch: str) -> Dict[str, Any]:
        """Get decompiler output for functions"""
        # This would use REA's decompiler MCP tools
        # For now, return placeholder
        return {
            "functions": [],
            "note": "Decompiler integration via REA MCP not yet implemented"
        }

    def _get_cross_references(self, lib_path: str, arch: str) -> Dict[str, Any]:
        """Get cross-references (XREFs) for functions"""
        return {
            "xrefs": [],
            "note": "XREF analysis via REA MCP not yet implemented"
        }

    def _search_suspicious_patterns(self, lib_path: str, arch: str) -> List[Dict[str, Any]]:
        """Search for suspicious patterns in native code"""
        patterns = []

        # Known suspicious patterns in native code
        suspicious_patterns = {
            "JNI_OnLoad": {
                "pattern": b"JNI_OnLoad",
                "type": "jni_entry",
                "severity": "high",
                "description": "JNI entry point - potential for native registration"
            },
            "RegisterNatives": {
                "pattern": b"RegisterNatives",
                "type": "jni_registration",
                "severity": "high",
                "description": "Dynamic JNI method registration"
            },
            "dlopen": {
                "pattern": b"dlopen",
                "type": "dynamic_loading",
                "severity": "medium",
                "description": "Dynamic library loading"
            },
            "dlsym": {
                "pattern": b"dlsym",
                "type": "symbol_resolution",
                "severity": "medium",
                "description": "Dynamic symbol resolution"
            },
            "system": {
                "pattern": b"system",
                "type": "command_execution",
                "severity": "critical",
                "description": "Potential command execution"
            },
            "exec": {
                "pattern": b"exec",
                "type": "command_execution",
                "severity": "critical",
                "description": "Potential command execution"
            },
            "pthread_create": {
                "pattern": b"pthread_create",
                "type": "threading",
                "severity": "low",
                "description": "Thread creation"
            },
            "socket": {
                "pattern": b"socket",
                "type": "network",
                "severity": "medium",
                "description": "Network socket creation"
            },
            "connect": {
                "pattern": b"connect",
                "type": "network",
                "severity": "medium",
                "description": "Network connection"
            },
            "SSL_CTX_new": {
                "pattern": b"SSL_CTX_new",
                "type": "crypto",
                "severity": "low",
                "description": "SSL/TLS context creation"
            },
            "crypto": {
                "pattern": b"EVP_",
                "type": "crypto",
                "severity": "low",
                "description": "OpenSSL crypto operations"
            },
        }

        try:
            with open(lib_path, "rb") as f:
                data = f.read()

            for name, info in suspicious_patterns.items():
                pattern = info["pattern"]
                offsets = []
                start = 0
                while True:
                    idx = data.find(pattern, start)
                    if idx == -1:
                        break
                    offsets.append(hex(idx))
                    start = idx + 1
                    if len(offsets) > 20:  # Limit matches
                        break

                if offsets:
                    patterns.append({
                        "pattern": name,
                        "type": info["type"],
                        "severity": info["severity"],
                        "description": info["description"],
                        "matches": len(offsets),
                        "offsets": offsets[:20],
                    })
        except Exception as e:
            self.errors.append(f"Pattern search failed: {e}")

        return patterns

    def analyze_dex_with_rea(self, dex_path: str) -> Dict[str, Any]:
        """Analyze DEX files using REA (future: JADX provider)"""
        return {
            "enabled": False,
            "note": "DEX analysis via REA JADX provider not yet configured. Set REA_JADX_MCP_JAR env var."
        }

    def get_capabilities(self) -> Dict[str, Any]:
        """Get REA analyzer capabilities"""
        doctor = self.get_doctor_status()

        # Extract available providers from providerInspections
        providers = []
        for p in doctor.get("providerInspections", []):
            if p.get("available"):
                providers.append(p.get("id"))

        return {
            "enabled": self.enabled,
            "available": self.is_available(),
            "ghidra_configured": bool(self.ghidra_path or os.environ.get("GHIDRA_INSTALL_DIR")),
            "ghidra_path": self.ghidra_path or os.environ.get("GHIDRA_INSTALL_DIR", ""),
            "skill_path": self.skill_path,
            "skill_status": doctor.get("identity", {}).get("skill", {}),
            "providers": providers,
            "tool_families": self.tool_families,
            "doctor_healthy": doctor.get("healthy", False),
        }


async def run_rea_analysis_async(apk_path: str, extract_dir: str, config: Dict) -> Dict[str, Any]:
    """Async wrapper for REA analysis"""
    analyzer = REAAnalyzer(config)
    return analyzer.analyze_apk_with_rea(apk_path, extract_dir)


def run_rea_analysis(apk_path: str, extract_dir: str, config: Dict) -> Dict[str, Any]:
    """Synchronous REA analysis entry point"""
    analyzer = REAAnalyzer(config)
    return analyzer.analyze_apk_with_rea(apk_path, extract_dir)


if __name__ == "__main__":
    # Test REA analyzer
    import sys
    config = {
        "rea": {
            "enabled": True,
            "ghidra_path": os.environ.get("GHIDRA_INSTALL_DIR", ""),
        }
    }

    analyzer = REAAnalyzer(config)
    caps = analyzer.get_capabilities()
    print(json.dumps(caps, indent=2))