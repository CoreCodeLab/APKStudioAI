"""
DEX file analyzer with multi-DEX support and individual JADX analysis
"""
import hashlib
import subprocess
from pathlib import Path
from typing import Dict, List, Any, Optional
from .utils import run_command, is_dex_file, sha256_file


class DexAnalyzer:
    def __init__(self, jadx_path: str = "", max_file_mb: int = 100):
        self.jadx_path = jadx_path
        self.max_file_bytes = max_file_mb * 1024 * 1024

    def analyze(self, apk_path: Path, extract_dir: Optional[Path] = None, jadx_output_dir: Optional[Path] = None) -> Dict[str, Any]:
        """Analyze all DEX files in the APK."""
        if extract_dir is None:
            import tempfile
            extract_dir = Path(tempfile.mkdtemp(prefix="apkstudio_dex_"))

        if jadx_output_dir is None:
            import tempfile
            jadx_output_dir = Path(tempfile.mkdtemp(prefix="apkstudio_jadx_"))

        dex_files = []
        dex_results = []

        # Find all DEX files
        for dex_path in extract_dir.rglob("*.dex"):
            if dex_path.is_file():
                dex_info = self._analyze_dex_file(dex_path)
                dex_files.append(dex_info)

        # If no DEX found in extract_dir, check APK directly
        if not dex_files:
            # This would require reading from APK directly
            pass

        # Analyze each DEX with JADX if available
        if self.jadx_path and Path(self.jadx_path).exists():
            for i, dex_info in enumerate(dex_files):
                dex_result = self._analyze_dex_with_jadx(dex_info, jadx_output_dir / f"dex_{i}")
                dex_results.append(dex_result)
        else:
            for i, dex_info in enumerate(dex_files):
                dex_results.append({
                    "dex_info": dex_info,
                    "jadx": {"status": "not configured"},
                    "classes": [],
                    "methods": []
                })

        return {
            "dex_count": len(dex_files),
            "dex_files": dex_files,
            "dex_analysis": dex_results,
            "total_classes": sum(len(d.get("classes", [])) for d in dex_results),
            "total_methods": sum(len(d.get("methods", [])) for d in dex_results)
        }

    def _analyze_dex_file(self, dex_path: Path) -> Dict[str, Any]:
        """Analyze a single DEX file header and structure."""
        info = {
            "path": str(dex_path.relative_to(extract_dir.parent) if (extract_dir := dex_path.parent).parent else dex_path),
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
                # Parse DEX header
                # magic(8) + checksum(4) + signature(20) + file_size(4) + header_size(4) + endian_tag(4)
                # link_size(4) + link_off(4) + map_off(4) + string_ids_size(4) + string_ids_off(4)
                # type_ids_size(4) + type_ids_off(4) + proto_ids_size(4) + proto_ids_off(4)
                # field_ids_size(4) + field_ids_off(4) + method_ids_size(4) + method_ids_off(4)
                # class_defs_size(4) + class_defs_off(4) + data_size(4) + data_off(4)
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

    def _analyze_dex_with_jadx(self, dex_info: Dict[str, Any], output_dir: Path) -> Dict[str, Any]:
        """Run JADX on a single DEX file."""
        result = {
            "dex_info": dex_info,
            "jadx": {"returncode": -1, "output": str(output_dir)},
            "classes": [],
            "methods": [],
            "suspicious_patterns": []
        }

        dex_path = Path(dex_info["path"]) if not Path(dex_info["path"]).is_absolute() else Path(dex_info["path"])
        if not dex_path.exists():
            result["jadx"]["error"] = "DEX file not found"
            return result

        try:
            output_dir.mkdir(parents=True, exist_ok=True)
            cmd = self._build_jadx_cmd(dex_path, output_dir)
            proc_result = run_command(cmd, timeout=600)

            result["jadx"] = {
                "returncode": proc_result["returncode"],
                "stdout": proc_result["stdout"][-10000:],
                "stderr": proc_result["stderr"][-10000:],
                "output": str(output_dir)
            }

            if proc_result["success"] and output_dir.exists():
                result["classes"] = self._extract_classes(output_dir)
                result["methods"] = self._extract_methods(output_dir)
                result["suspicious_patterns"] = self._find_suspicious_patterns(output_dir)

        except Exception as e:
            result["jadx"]["error"] = str(e)

        return result

    def _build_jadx_cmd(self, dex_path: Path, output_dir: Path) -> List[str]:
        """Build JADX command."""
        jadx = self.jadx_path
        if str(jadx).lower().endswith((".bat", ".cmd")):
            return ["cmd.exe", "/c", jadx, "-d", str(output_dir), str(dex_path), "--no-res", "--no-imports"]
        return [jadx, "-d", str(output_dir), str(dex_path), "--no-res", "--no-imports"]

    def _extract_classes(self, jadx_dir: Path) -> List[Dict[str, Any]]:
        """Extract class information from JADX output."""
        classes = []
        for java_file in jadx_dir.rglob("*.java"):
            try:
                if java_file.stat().st_size > 500_000:
                    continue
                content = java_file.read_text(encoding="utf-8", errors="ignore")
                class_info = self._parse_java_file(content, java_file)
                if class_info:
                    classes.append(class_info)
            except Exception:
                pass
        return classes[:500]  # Limit

    def _parse_java_file(self, content: str, file_path: Path) -> Optional[Dict[str, Any]]:
        """Parse a Java file for class info."""
        import re
        class_match = re.search(r'(public\s+|private\s+|protected\s+)?(class|interface|enum)\s+(\w+)', content)
        if not class_match:
            return None

        class_name = class_match.group(3)
        package_match = re.search(r'^package\s+([\w.]+);', content, re.MULTILINE)
        package = package_match.group(1) if package_match else ""

        return {
            "name": class_name,
            "package": package,
            "file": str(file_path),
            "extends": self._extract_extends(content),
            "implements": self._extract_implements(content),
            "methods": self._extract_method_signatures(content),
            "fields": self._extract_fields(content),
            "annotations": self._extract_annotations(content)
        }

    def _extract_extends(self, content: str) -> Optional[str]:
        import re
        match = re.search(r'class\s+\w+\s+extends\s+([\w.]+)', content)
        return match.group(1) if match else None

    def _extract_implements(self, content: str) -> List[str]:
        import re
        match = re.search(r'class\s+\w+(?:\s+extends\s+[\w.]+)?\s+implements\s+([^{]+)', content)
        if match:
            return [i.strip() for i in match.group(1).split(",")]
        return []

    def _extract_method_signatures(self, content: str) -> List[Dict[str, Any]]:
        import re
        methods = []
        # Simple method pattern
        pattern = r'(public|private|protected|static|\s)+\s+[\w<>\[\]]+\s+(\w+)\s*\([^)]*\)\s*(?:throws\s+[\w,\s]+)?\s*\{'
        for match in re.finditer(pattern, content):
            methods.append({
                "name": match.group(2),
                "modifiers": match.group(1).strip()
            })
        return methods[:50]

    def _extract_fields(self, content: str) -> List[Dict[str, Any]]:
        import re
        fields = []
        pattern = r'(public|private|protected|static|final|\s)+\s+[\w<>\[\]]+\s+(\w+)\s*[=;]'
        for match in re.finditer(pattern, content):
            fields.append({
                "name": match.group(2),
                "modifiers": match.group(1).strip()
            })
        return fields[:30]

    def _extract_annotations(self, content: str) -> List[str]:
        import re
        return [m.group(1) for m in re.finditer(r'@(\w+)', content)][:20]

    def _extract_methods(self, jadx_dir: Path) -> List[Dict[str, Any]]:
        """Extract method details from JADX output."""
        methods = []
        for java_file in jadx_dir.rglob("*.java"):
            try:
                if java_file.stat().st_size > 500_000:
                    continue
                content = java_file.read_text(encoding="utf-8", errors="ignore")
                class_name = self._get_class_name(content)
                for method in self._parse_methods_detailed(content, class_name):
                    methods.append(method)
            except Exception:
                pass
        return methods[:1000]

    def _get_class_name(self, content: str) -> str:
        import re
        match = re.search(r'(class|interface|enum)\s+(\w+)', content)
        return match.group(2) if match else "Unknown"

    def _parse_methods_detailed(self, content: str, class_name: str) -> List[Dict[str, Any]]:
        import re
        methods = []
        # More detailed method parsing
        pattern = r'(public|private|protected|static|final|native|synchronized|\s)+\s+([\w<>\[\]]+)\s+(\w+)\s*\(([^)]*)\)\s*(?:throws\s+([\w,\s]+))?\s*\{'
        for match in re.finditer(pattern, content):
            modifiers = match.group(1).strip()
            return_type = match.group(2)
            method_name = match.group(3)
            params = match.group(4)
            throws = match.group(5)

            methods.append({
                "class": class_name,
                "name": method_name,
                "return_type": return_type,
                "parameters": [p.strip() for p in params.split(",") if p.strip()],
                "throws": [t.strip() for t in throws.split(",")] if throws else [],
                "modifiers": modifiers,
                "is_native": "native" in modifiers
            })
        return methods

    def _find_suspicious_patterns(self, jadx_dir: Path) -> List[Dict[str, Any]]:
        """Find suspicious code patterns in decompiled Java."""
        patterns = {
            "reflection": [
                r"Class\.forName", r"\.getMethod\(", r"\.getField\(",
                r"\.newInstance\(", r"Method\.invoke", r"Field\.set"
            ],
            "dynamic_loading": [
                r"DexClassLoader", r"PathClassLoader", r"InMemoryDexClassLoader",
                r"loadClass\(", r"defineClass\("
            ],
            "command_execution": [
                r"Runtime\.getRuntime\(\)\.exec", r"ProcessBuilder",
                r"Runtime\.exec\("
            ],
            "webview": [
                r"addJavascriptInterface", r"setJavaScriptEnabled\(true\)",
                r"WebView", r"loadUrl\(", r"evaluateJavascript"
            ],
            "accessibility": [
                r"AccessibilityService", r"canRetrieveWindowContent",
                r"canPerformGestures", r"onAccessibilityEvent"
            ],
            "media_projection": [
                r"MediaProjection", r"createScreenCaptureIntent",
                r"ImageReader", r"acquireLatestImage"
            ],
            "device_admin": [
                r"DeviceAdminReceiver", r"DevicePolicyManager",
                r"force-lock", r"reset-password", r"wipe-data"
            ],
            "vpn": [
                r"VpnService", r"BIND_VPN_SERVICE", r"addRoute",
                r"establish\(\)"
            ],
            "native": [
                r"System\.loadLibrary", r"System\.load\(",
                r"native\s+\w+"
            ],
            "crypto": [
                r"Cipher\.getInstance", r"MessageDigest\.getInstance",
                r"SecretKeySpec", r"IvParameterSpec"
            ],
            "network": [
                r"HttpURLConnection", r"OkHttpClient", r"WebSocket",
                r"Socket\(", r"ServerSocket\(", r"DatagramSocket"
            ],
            "anti_analysis": [
                r"Build\.TYPE.*emu", r"Build\.FINGERPRINT.*generic",
                r"isDebuggerConnected", r"Debug\.isDebuggerConnected",
                r"Trace\.isTracing"
            ]
        }

        findings = []
        for java_file in jadx_dir.rglob("*.java"):
            try:
                if java_file.stat().st_size > 500_000:
                    continue
                content = java_file.read_text(encoding="utf-8", errors="ignore")
                class_name = self._get_class_name(content)

                for category, pattern_list in patterns.items():
                    for pattern in pattern_list:
                        for match in re.finditer(pattern, content):
                            # Get context
                            start = max(0, match.start() - 100)
                            end = min(len(content), match.end() + 100)
                            context = content[start:end].replace("\n", " ")

                            findings.append({
                                "category": category,
                                "pattern": pattern,
                                "class": class_name,
                                "file": str(java_file),
                                "context": context[:500]
                            })
            except Exception:
                pass

        return findings[:200]