"""
Apktool engine wrapper for resource and manifest decoding
"""
import subprocess
from pathlib import Path
from typing import Dict, List, Any, Optional
from .utils import run_command
from .config_manager import get_config


class ApktoolEngine:
    def __init__(self, config: Dict[str, Any] = None, timeout: int = 300):
        """Initialize with config dict or string path."""
        if isinstance(config, str):
            self.apktool_path = config
        elif isinstance(config, dict):
            self.apktool_path = config.get("apktool", config.get("apktool_path", ""))
        else:
            global_config = get_config()
            tools_config = global_config.get("tools", {})
            self.apktool_path = tools_config.get("apktool_path", tools_config.get("apktool", ""))

        # Get timeout from config
        if isinstance(config, dict) and "timeouts" in config:
            self.timeout = config["timeouts"].get("apktool", timeout)
        else:
            global_config = get_config()
            self.timeout = global_config.get("timeouts", {}).get("apktool", timeout)

        self.available = bool(self.apktool_path and Path(self.apktool_path).exists())

    def decode(self, apk_path: Path, output_dir: Path, force: bool = True) -> Dict[str, Any]:
        """Decode APK resources and manifest."""
        if not self.available:
            return {"success": False, "error": "Apktool not configured", "output_dir": str(output_dir)}

        output_dir.mkdir(parents=True, exist_ok=True)
        cmd = self._build_cmd(apk_path, output_dir, force)

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
            result_dict["manifest"] = self._parse_manifest(output_dir / "AndroidManifest.xml")
            result_dict["resources"] = self._analyze_resources(output_dir / "res")
            result_dict["smali"] = self._analyze_smali(output_dir / "smali")

        return result_dict

    def _build_cmd(self, apk_path: Path, output_dir: Path, force: bool) -> List[str]:
        """Build Apktool command."""
        cmd = ["java", "-jar", self.apktool_path, "d"]
        if force:
            cmd.append("-f")
        cmd.extend(["-o", str(output_dir), str(apk_path)])
        return cmd

    def build(self, decoded_dir: Path, output_apk: Path, use_aapt2: bool = True) -> Dict[str, Any]:
        """Build APK from decoded sources (not used in analysis, but available)."""
        if not self.available:
            return {"success": False, "error": "Apktool not configured"}

        cmd = ["java", "-jar", self.apktool_path, "b"]
        if use_aapt2:
            cmd.append("--use-aapt2")
        cmd.extend(["-o", str(output_apk), str(decoded_dir)])

        return run_command(cmd, timeout=self.timeout)

    def _parse_manifest(self, manifest_path: Path) -> Dict[str, Any]:
        """Parse decoded AndroidManifest.xml."""
        if not manifest_path.exists():
            return {"error": "Manifest not found"}

        try:
            content = manifest_path.read_text(encoding="utf-8", errors="ignore")
            return self._extract_manifest_info(content)
        except Exception as e:
            return {"error": str(e)}

    def _extract_manifest_info(self, xml: str) -> Dict[str, Any]:
        """Extract structured info from manifest XML."""
        import re
        info = {
            "package": None,
            "version_code": None,
            "version_name": None,
            "min_sdk": None,
            "target_sdk": None,
            "max_sdk": None,
            "permissions": [],
            "activities": [],
            "services": [],
            "receivers": [],
            "providers": [],
            "application": {}
        }

        # Package
        pkg = re.search(r'package\s*=\s*["\']([^"\']+)', xml)
        info["package"] = pkg.group(1) if pkg else None

        # Version
        vc = re.search(r'android:versionCode\s*=\s*["\']?(\d+)', xml)
        info["version_code"] = int(vc.group(1)) if vc else None
        vn = re.search(r'android:versionName\s*=\s*["\']([^"\']+)', xml)
        info["version_name"] = vn.group(1) if vn else None

        # SDK
        for attr, key in [
            (r'android:minSdkVersion\s*=\s*["\']?(\d+)', "min_sdk"),
            (r'android:targetSdkVersion\s*=\s*["\']?(\d+)', "target_sdk"),
            (r'android:maxSdkVersion\s*=\s*["\']?(\d+)', "max_sdk"),
        ]:
            m = re.search(attr, xml)
            info[key] = int(m.group(1)) if m else None

        # Permissions
        for perm in re.finditer(r'<uses-permission\s+android:name\s*=\s*["\']([^"\']+)', xml):
            info["permissions"].append(perm.group(1))

        # Application attributes
        app_section = self._extract_section(xml, "<application", "</application>")
        if app_section:
            info["application"]["debuggable"] = 'android:debuggable="true"' in app_section
            info["application"]["allow_backup"] = 'android:allowBackup="true"' in app_section
            info["application"]["label"] = self._extract_attr(app_section, "android:label")
            info["application"]["icon"] = self._extract_attr(app_section, "android:icon")
            info["application"]["theme"] = self._extract_attr(app_section, "android:theme")

        # Components
        info["activities"] = self._parse_components(xml, "activity")
        info["services"] = self._parse_components(xml, "service")
        info["receivers"] = self._parse_components(xml, "receiver")
        info["providers"] = self._parse_providers(xml)

        return info

    def _extract_section(self, xml: str, start: str, end: str) -> str:
        """Extract XML section."""
        s = xml.find(start)
        if s == -1:
            return ""
        e = xml.find(end, s)
        if e == -1:
            return xml[s:]
        return xml[s:e + len(end)]

    def _extract_attr(self, xml: str, attr: str) -> Optional[str]:
        import re
        m = re.search(rf'{attr}\s*=\s*["\']([^"\']+)', xml)
        return m.group(1) if m else None

    def _parse_components(self, xml: str, tag: str) -> List[Dict[str, Any]]:
        """Parse component elements."""
        import re
        components = []
        pattern = rf"<{tag}\s+([^>]*/?>|[^>]*>.*?</{tag}>)"
        for match in re.finditer(pattern, xml, re.DOTALL):
            comp_xml = match.group(0)
            comp = {
                "name": self._extract_attr(comp_xml, "android:name"),
                "exported": self._extract_attr(comp_xml, "android:exported") == "true",
                "enabled": self._extract_attr(comp_xml, "android:enabled") != "false",
                "permission": self._extract_attr(comp_xml, "android:permission"),
                "intent_filters": self._parse_intent_filters(comp_xml)
            }
            components.append(comp)
        return components

    def _parse_providers(self, xml: str) -> List[Dict[str, Any]]:
        """Parse content providers."""
        import re
        providers = []
        pattern = r"<provider\s+([^>]*/?>|[^>]*>.*?</provider>)"
        for match in re.finditer(pattern, xml, re.DOTALL):
            prov_xml = match.group(0)
            prov = {
                "name": self._extract_attr(prov_xml, "android:name"),
                "authorities": self._extract_attr(prov_xml, "android:authorities"),
                "exported": self._extract_attr(prov_xml, "android:exported") == "true",
                "permission": self._extract_attr(prov_xml, "android:permission"),
                "read_permission": self._extract_attr(prov_xml, "android:readPermission"),
                "write_permission": self._extract_attr(prov_xml, "android:writePermission"),
                "grant_uri_permissions": self._extract_attr(prov_xml, "android:grantUriPermissions") == "true"
            }
            providers.append(prov)
        return providers

    def _parse_intent_filters(self, xml: str) -> List[Dict[str, Any]]:
        """Parse intent filters from component XML."""
        import re
        filters = []
        pattern = r"<intent-filter\s*>(.*?)</intent-filter>"
        for match in re.finditer(pattern, xml, re.DOTALL):
            filter_xml = match.group(1)
            filter_data = {"actions": [], "categories": [], "data": []}

            for m in re.finditer(r'<action\s+android:name\s*=\s*["\']([^"\']+)', filter_xml):
                filter_data["actions"].append(m.group(1))
            for m in re.finditer(r'<category\s+android:name\s*=\s*["\']([^"\']+)', filter_xml):
                filter_data["categories"].append(m.group(1))
            for m in re.finditer(r'<data\s+([^>]*/?>)', filter_xml):
                data_attrs = {}
                for attr in ['scheme', 'host', 'port', 'path', 'pathPrefix', 'pathPattern', 'mimeType']:
                    mm = re.search(rf'android:{attr}\s*=\s*["\']([^"\']+)', m.group(1))
                    if mm:
                        data_attrs[attr] = mm.group(1)
                if data_attrs:
                    filter_data["data"].append(data_attrs)

            if any(filter_data.values()):
                filters.append(filter_data)
        return filters

    def _analyze_resources(self, res_dir: Path) -> Dict[str, Any]:
        """Analyze decoded resources."""
        if not res_dir.exists():
            return {"error": "Resources directory not found"}

        resources = {
            "layouts": [],
            "values": [],
            "drawables": [],
            "xml": [],
            "raw": [],
            "strings_count": 0,
            "string_keys": []
        }

        try:
            # Count layouts
            resources["layouts"] = [f.name for f in (res_dir / "layout").glob("*.xml")] if (res_dir / "layout").exists() else []
            resources["values"] = [f.name for f in (res_dir / "values").glob("*.xml")] if (res_dir / "values").exists() else []
            resources["drawables"] = list((res_dir / "drawable").glob("*")) if (res_dir / "drawable").exists() else []
            resources["xml"] = [f.name for f in (res_dir / "xml").glob("*.xml")] if (res_dir / "xml").exists() else []
            resources["raw"] = [f.name for f in (res_dir / "raw").glob("*")] if (res_dir / "raw").exists() else []

            # Extract strings
            strings_file = res_dir / "values" / "strings.xml"
            if strings_file.exists():
                content = strings_file.read_text(encoding="utf-8", errors="ignore")
                import re
                strings = re.findall(r'<string\s+name\s*=\s*["\']([^"\']+)', content)
                resources["strings_count"] = len(strings)
                resources["string_keys"] = strings[:200]

        except Exception as e:
            resources["error"] = str(e)

        return resources

    def _analyze_smali(self, smali_dir: Path) -> Dict[str, Any]:
        """Analyze smali output."""
        if not smali_dir.exists():
            return {"error": "Smali directory not found"}

        smali_info = {
            "classes_count": 0,
            "methods_count": 0,
            "fields_count": 0,
            "packages": set(),
            "suspicious": []
        }

        suspicious_patterns = {
            "reflection": [r"invoke-virtual.*Ljava/lang/reflect/", r"Ljava/lang/Class;->forName"],
            "dynamic_load": [r"Ldalvik/system/DexClassLoader", r"Ldalvik/system/PathClassLoader",
                           r"Ldalvik/system/InMemoryDexClassLoader"],
            "native": [r"\.native\s", r"System\.loadLibrary", r"System\.load"],
            "crypto": [r"Ljavax/crypto/", r"Ljava/security/MessageDigest"],
            "command": [r"Ljava/lang/Runtime;->exec", r"Ljava/lang/ProcessBuilder"],
            "anti_debug": [r"Landroid/os/Debug;->isDebuggerConnected", r"Landroid/os/Build;->TYPE"]
        }

        try:
            for smali_file in smali_dir.rglob("*.smali"):
                if smali_file.stat().st_size > 500_000:
                    continue
                try:
                    content = smali_file.read_text(encoding="utf-8", errors="ignore")
                except Exception:
                    continue

                smali_info["classes_count"] += 1
                smali_info["methods_count"] += content.count(".method")
                smali_info["fields_count"] += content.count(".field")

                # Extract package
                import re
                pkg_match = re.search(r'\.class\s+.*?L([^/]+)/', content)
                if pkg_match:
                    smali_info["packages"].add(pkg_match.group(1))

                # Check suspicious patterns
                for category, patterns in suspicious_patterns.items():
                    for pattern in patterns:
                        if re.search(pattern, content):
                            rel_path = smali_file.relative_to(smali_dir)
                            smali_info["suspicious"].append({
                                "category": category,
                                "file": str(rel_path),
                                "pattern": pattern
                            })
                            break  # One match per category per file

        except Exception as e:
            smali_info["error"] = str(e)

        smali_info["packages"] = list(smali_info["packages"])
        smali_info["suspicious"] = smali_info["suspicious"][:100]
        return smali_info