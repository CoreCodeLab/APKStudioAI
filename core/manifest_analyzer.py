"""
Android Manifest analyzer with binary XML support and Apktool fallback
Uses lxml for robust XML parsing instead of regex.
"""
import re
import json
from pathlib import Path
from typing import Dict, List, Any, Optional, Set
from .utils import run_command, printable_strings, printable_strings_utf16
from .config_manager import get_config
from .logging_setup import get_module_logger

logger = get_module_logger("manifest")

# Try to import lxml, fall back to built-in xml.etree
try:
    from lxml import etree
    HAS_LXML = True
except ImportError:
    import xml.etree.ElementTree as etree
    HAS_LXML = False

# Android namespace
ANDROID_NS = "http://schemas.android.com/apk/res/android"


class ManifestAnalyzer:
    def __init__(self, config: Dict[str, Any] = None, max_file_mb: int = 100):
        """Initialize with config dict or string path."""
        # Get apktool path from config
        if isinstance(config, str):
            self.apktool_path = config
        elif isinstance(config, dict):
            self.apktool_path = config.get("apktool_path", config.get("apktool", ""))
        else:
            # Use global config
            global_config = get_config()
            tools_config = global_config.get("tools", {})
            self.apktool_path = tools_config.get("apktool_path", tools_config.get("apktool", ""))

        # Get max file size from config
        if isinstance(config, dict) and "analysis" in config:
            max_file_mb = config["analysis"].get("max_file_size_mb", max_file_mb)
        else:
            global_config = get_config()
            max_file_mb = global_config.get("analysis", {}).get("max_file_size_mb", max_file_mb)

        self.max_file_bytes = max_file_mb * 1024 * 1024

    def analyze(self, apk_path: Path, extract_dir: Path) -> Dict[str, Any]:
        """Analyze manifest using multiple methods."""
        logger.info("manifest_analysis_started", apk=str(apk_path))

        result = {
            "package": None,
            "version_code": None,
            "version_name": None,
            "min_sdk": None,
            "target_sdk": None,
            "max_sdk": None,
            "activities": [],
            "services": [],
            "receivers": [],
            "providers": [],
            "permissions": [],
            "uses_permissions": [],
            "permission_groups": [],
            "intent_filters": [],
            "exported_components": [],
            "debuggable": False,
            "allow_backup": False,
            "accessibility_services": [],
            "device_admin_receivers": [],
            "vpn_services": [],
            "boot_receivers": [],
            "package_install_receivers": [],
            "raw_xml": "",
            "analysis_method": "binary_xml",
            "warnings": [],
            "errors": []
        }

        # Method 1: Try Apktool for proper XML decoding
        if self.apktool_path and Path(self.apktool_path).exists():
            apktool_result = self._analyze_with_apktool(apk_path, extract_dir)
            if apktool_result:
                result.update(apktool_result)
                result["analysis_method"] = "apktool"
                return result

        # Method 2: Fallback to binary XML parsing
        manifest_path = extract_dir / "AndroidManifest.xml"
        if manifest_path.exists():
            binary_result = self._analyze_binary_xml(manifest_path)
            result.update(binary_result)
            result["analysis_method"] = "binary_xml"
        else:
            result["warnings"].append("AndroidManifest.xml not found in extracted files")
            result["errors"].append("AndroidManifest.xml not found in extracted files")

        return result

    def _analyze_permissions(self, permissions: List[str]) -> Dict[str, Any]:
        """Analyze permissions for risk mapping - used by tests."""
        from core.permission_analyzer import PermissionAnalyzer
        pa = PermissionAnalyzer()
        return pa.analyze(permissions)

    def _analyze_with_apktool(self, apk_path: Path, extract_dir: Path) -> Optional[Dict[str, Any]]:
        """Use Apktool to decode manifest and resources."""
        output_dir = extract_dir / "apktool_out"
        try:
            cmd = ["java", "-jar", self.apktool_path, "d", "-f", "-o", str(output_dir), str(apk_path)]
            result = run_command(cmd, timeout=300)
            if not result["success"]:
                return None

            manifest_file = output_dir / "AndroidManifest.xml"
            if not manifest_file.exists():
                return None

            xml_content = manifest_file.read_text(encoding="utf-8", errors="ignore")
            return self._parse_manifest_xml_lxml(xml_content)
        except Exception as e:
            return None

    def _analyze_binary_xml(self, manifest_path: Path) -> Dict[str, Any]:
        """Parse binary Android XML directly using string extraction."""
        raw = manifest_path.read_bytes()
        strings = set(printable_strings(raw, 4))
        strings.update(printable_strings_utf16(raw, 4))

        # Convert to searchable text
        text = raw.decode("utf-8", errors="ignore")
        text += "\n" + "\n".join(strings)

        return self._parse_manifest_text(text)

    def _parse_manifest_xml_lxml(self, xml: str) -> Dict[str, Any]:
        """Parse decoded XML manifest using lxml/ElementTree."""
        result = {}
        result["raw_xml"] = xml[:50000]

        try:
            # Parse XML with lxml or built-in
            parser = etree.XMLParser(recover=True, remove_comments=True)
            root = etree.fromstring(xml.encode('utf-8'), parser=parser)
        except Exception as e:
            # Fallback to regex parsing if XML parsing fails
            return self._parse_manifest_xml_regex(xml)

        # Package
        pkg = root.get("package")
        if pkg:
            result["package"] = pkg

        # Version
        vc = root.get(f"{{{ANDROID_NS}}}versionCode")
        if vc:
            result["version_code"] = int(vc) if vc.isdigit() else None
        vn = root.get(f"{{{ANDROID_NS}}}versionName")
        if vn:
            result["version_name"] = vn

        # SDK versions from uses-sdk
        uses_sdk = root.find("uses-sdk")
        if uses_sdk is not None:
            min_sdk = uses_sdk.get(f"{{{ANDROID_NS}}}minSdkVersion")
            if min_sdk:
                result["min_sdk"] = int(min_sdk) if min_sdk.isdigit() else None
            target_sdk = uses_sdk.get(f"{{{ANDROID_NS}}}targetSdkVersion")
            if target_sdk:
                result["target_sdk"] = int(target_sdk) if target_sdk.isdigit() else None
            max_sdk = uses_sdk.get(f"{{{ANDROID_NS}}}maxSdkVersion")
            if max_sdk:
                result["max_sdk"] = int(max_sdk) if max_sdk.isdigit() else None

        # Application attributes
        app = root.find("application")
        if app is not None:
            result["debuggable"] = app.get(f"{{{ANDROID_NS}}}debuggable") == "true"
            result["allow_backup"] = app.get(f"{{{ANDROID_NS}}}allowBackup") == "true"

            # Components under application
            result["activities"] = self._parse_components_lxml(app, "activity")
            result["services"] = self._parse_components_lxml(app, "service")
            result["receivers"] = self._parse_components_lxml(app, "receiver")
            result["providers"] = self._parse_providers_lxml(app)

        # Permissions (at root level)
        result["uses_permissions"] = self._parse_permissions_lxml(root, "uses-permission")
        result["permissions"] = self._parse_permissions_lxml(root, "permission")
        result["permission_groups"] = self._parse_permissions_lxml(root, "permission-group")

        # Intent filters (from all components)
        result["intent_filters"] = self._parse_intent_filters_lxml(root)

        # Exported components
        result["exported_components"] = self._find_exported(result)

        # Special components
        result["accessibility_services"] = self._find_accessibility_services(result)
        result["device_admin_receivers"] = self._find_device_admin(result)
        result["vpn_services"] = self._find_vpn_services(result)
        result["boot_receivers"] = self._find_boot_receivers(result)
        result["package_install_receivers"] = self._find_package_install(result)

        logger.info("manifest_xml_parsed",
                   package=result.get("package"),
                   activities=len(result.get("activities", [])),
                   services=len(result.get("services", [])),
                   receivers=len(result.get("receivers", [])),
                   providers=len(result.get("providers", [])),
                   permissions=len(result.get("uses_permissions", [])))

        return result

    def _parse_manifest_xml_regex(self, xml: str) -> Dict[str, Any]:
        """Fallback regex-based parsing (original implementation)."""
        result = {}
        result["raw_xml"] = xml[:50000]

        # Package
        pkg_match = re.search(r'package\s*=\s*["\']([^"\']+)', xml)
        result["package"] = pkg_match.group(1) if pkg_match else None

        # Version
        vc_match = re.search(r'android:versionCode\s*=\s*["\']?(\d+)', xml)
        result["version_code"] = int(vc_match.group(1)) if vc_match else None
        vn_match = re.search(r'android:versionName\s*=\s*["\']([^"\']+)', xml)
        result["version_name"] = vn_match.group(1) if vn_match else None

        # SDK versions
        for attr, key in [
            (r'android:minSdkVersion\s*=\s*["\']?(\d+)', "min_sdk"),
            (r'android:targetSdkVersion\s*=\s*["\']?(\d+)', "target_sdk"),
            (r'android:maxSdkVersion\s*=\s*["\']?(\d+)', "max_sdk"),
        ]:
            m = re.search(attr, xml)
            result[key] = int(m.group(1)) if m else None

        # Application attributes
        app_section = self._extract_section(xml, "<application", "</application>")
        if app_section:
            result["debuggable"] = 'android:debuggable="true"' in app_section
            result["allow_backup"] = 'android:allowBackup="true"' in app_section

        # Components
        result["activities"] = self._parse_components(xml, "activity")
        result["services"] = self._parse_components(xml, "service")
        result["receivers"] = self._parse_components(xml, "receiver")
        result["providers"] = self._parse_providers(xml)

        # Permissions
        result["uses_permissions"] = self._parse_permissions(xml, "uses-permission")
        result["permissions"] = self._parse_permissions(xml, "permission")
        result["permission_groups"] = self._parse_permissions(xml, "permission-group")

        # Intent filters
        result["intent_filters"] = self._parse_intent_filters(xml)

        # Exported components
        result["exported_components"] = self._find_exported(result)

        # Special components
        result["accessibility_services"] = self._find_accessibility_services(result)
        result["device_admin_receivers"] = self._find_device_admin(result)
        result["vpn_services"] = self._find_vpn_services(result)
        result["boot_receivers"] = self._find_boot_receivers(result)
        result["package_install_receivers"] = self._find_package_install(result)

        return result

    def _parse_components_lxml(self, parent: Any, tag: str) -> List[Dict[str, Any]]:
        """Parse component elements (activity, service, receiver) using lxml."""
        components = []
        for elem in parent.findall(tag):
            comp = {"raw": etree.tostring(elem, encoding='unicode')[:5000]}

            # Name
            name = elem.get(f"{{{ANDROID_NS}}}name")
            comp["name"] = name

            # Exported
            exported = elem.get(f"{{{ANDROID_NS}}}exported")
            comp["exported"] = exported == "true" if exported is not None else None

            # Permission
            perm = elem.get(f"{{{ANDROID_NS}}}permission")
            comp["permission"] = perm

            # Enabled
            enabled = elem.get(f"{{{ANDROID_NS}}}enabled")
            comp["enabled"] = enabled != "false" if enabled is not None else True

            # Intent filters
            comp["intent_filters"] = self._parse_intent_filters_lxml(elem)

            components.append(comp)
        return components

    def _parse_providers_lxml(self, app: Any) -> List[Dict[str, Any]]:
        """Parse content providers using lxml."""
        providers = []
        for elem in app.findall("provider"):
            prov = {"raw": etree.tostring(elem, encoding='unicode')[:5000]}

            name = elem.get(f"{{{ANDROID_NS}}}name")
            prov["name"] = name

            authorities = elem.get(f"{{{ANDROID_NS}}}authorities")
            prov["authorities"] = authorities

            exported = elem.get(f"{{{ANDROID_NS}}}exported")
            prov["exported"] = exported == "true" if exported is not None else None

            perm = elem.get(f"{{{ANDROID_NS}}}permission")
            prov["read_permission"] = perm

            write_perm = elem.get(f"{{{ANDROID_NS}}}writePermission")
            prov["write_permission"] = write_perm

            providers.append(prov)
        return providers

    def _parse_permissions_lxml(self, root: Any, tag: str) -> List[Dict[str, Any]]:
        """Parse permission declarations using lxml."""
        perms = []
        for elem in root.findall(tag):
            name = elem.get(f"{{{ANDROID_NS}}}name")
            if name:
                perm = {
                    "name": name,
                    "protection_level": "normal"
                }
                level = elem.get(f"{{{ANDROID_NS}}}protectionLevel")
                if level:
                    perm["protection_level"] = level
                perms.append(perm)
        return perms

    def _parse_intent_filters_lxml(self, root: Any) -> List[Dict[str, Any]]:
        """Parse intent filters using lxml."""
        filters = []
        for elem in root.findall(".//intent-filter"):
            filter_data = {"actions": [], "categories": [], "data": []}

            for action in elem.findall("action"):
                name = action.get(f"{{{ANDROID_NS}}}name")
                if name:
                    filter_data["actions"].append(name)

            for cat in elem.findall("category"):
                name = cat.get(f"{{{ANDROID_NS}}}name")
                if name:
                    filter_data["categories"].append(name)

            for data in elem.findall("data"):
                data_attrs = {}
                for attr in ['scheme', 'host', 'port', 'path', 'pathPrefix', 'pathPattern', 'mimeType']:
                    val = data.get(f"{{{ANDROID_NS}}}{attr}")
                    if val:
                        data_attrs[attr] = val
                if data_attrs:
                    filter_data["data"].append(data_attrs)

            if any(filter_data.values()):
                filters.append(filter_data)
        return filters

    def _parse_manifest_text(self, text: str) -> Dict[str, Any]:
        """Parse manifest from binary XML string extraction."""
        result = {}
        result["raw_xml"] = text[:50000]

        # Helper to strip binary XML prefix chars
        def clean(s):
            return re.sub(r'^[\#\$\%\&\+\"\'\!\<\>\=\*\/\?\@\;\:\,\-\.\d]*', '', s)

        # Extract package name from component class names
        class_pattern = r'([a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+)\.(?:[A-Z][a-zA-Z0-9_]*Activity|[A-Z][a-zA-Z0-9_]*Service|[A-Z][a-zA-Z0-9_]*Receiver|[A-Z][a-zA-Z0-9_]*Provider)'
        class_matches = re.findall(class_pattern, text)
        package_candidates = set()
        for match in class_matches:
            full_class = match[0]
            parts = full_class.split('.')
            if len(parts) >= 2:
                if parts[0] not in ('android', 'androidx', 'java', 'javax'):
                    if len(parts) >= 3:
                        package_candidates.add('.'.join(parts[:3]))
                    elif len(parts) == 2 and parts[0] not in ('com', 'org'):
                        package_candidates.add(full_class)

        # Also check for package attribute in manifest
        pkg_match = re.search(r'package\s*=\s*["\']([^"\']+)', text)
        if pkg_match:
            result["package"] = pkg_match.group(1)
        elif package_candidates:
            result["package"] = sorted(package_candidates)[0]
        else:
            result["package"] = None

        # Extract version - try multiple patterns for binary XML
        for attr, key in [
            (r'android:versionCode\s*=\s*["\']?(\d+)', "version_code"),
            (r'versionCode\s*["\']?\s*[:=]\s*["\']?(\d+)', "version_code"),
            (r'android:versionName\s*=\s*["\']([^"\']+)', "version_name"),
            (r'versionName\s*["\']?\s*[:=]\s*["\']([^"\']+)', "version_name"),
        ]:
            m = re.search(attr, text)
            if m and result.get(key) is None:
                result[key] = int(m.group(1)) if key == "version_code" else m.group(1)

        # Extract SDK versions - handle binary XML prefixes
        for attr, key in [
            (r'android:minSdkVersion\s*=\s*["\']?(\d+)', "min_sdk"),
            (r'android:targetSdkVersion\s*=\s*["\']?(\d+)', "target_sdk"),
            (r'android:maxSdkVersion\s*=\s*["\']?(\d+)', "max_sdk"),
            (r'minSdkVersion\s*["\']?\s*[:=]\s*["\']?(\d+)', "min_sdk"),
            (r'targetSdkVersion\s*["\']?\s*[:=]\s*["\']?(\d+)', "target_sdk"),
            (r'maxSdkVersion\s*["\']?\s*[:=]\s*["\']?(\d+)', "max_sdk"),
        ]:
            m = re.search(attr, text)
            if m and result.get(key) is None:
                result[key] = int(m.group(1))

        # Permissions - handle binary XML prefixes like #android.permission.XXX
        perm_pattern = r"[#\$\%\&\+\"\']?android\.permission\.[A-Z0-9_]+"
        raw_perms = re.findall(perm_pattern, text)
        perms = set(clean(p) for p in raw_perms)
        result["uses_permissions"] = sorted(perms)
        result["permissions"] = []

        # Application attributes
        result["debuggable"] = "debuggable" in text.lower()
        result["allow_backup"] = "allowbackup" in text.lower()

        # Basic component detection - handle prefixes
        result["activities"] = self._find_components_in_strings(text, "Activity")
        result["services"] = self._find_components_in_strings(text, "Service")
        result["receivers"] = self._find_components_in_strings(text, "Receiver")
        result["providers"] = self._find_components_in_strings(text, "Provider")

        # Filter components to only include those from our package
        if result["package"]:
            prefix = result["package"] + "."
            result["activities"] = [c for c in result["activities"] if c.get("name", "").startswith(prefix)]
            result["services"] = [c for c in result["services"] if c.get("name", "").startswith(prefix)]
            result["receivers"] = [c for c in result["receivers"] if c.get("name", "").startswith(prefix)]
            result["providers"] = [c for c in result["providers"] if c.get("name", "").startswith(prefix)]

        # Special components from strings
        result["accessibility_services"] = []
        result["device_admin_receivers"] = []
        result["vpn_services"] = []
        result["boot_receivers"] = []
        result["package_install_receivers"] = []

        # Check for special service types in strings
        if "android.accessibilityservice.AccessibilityService" in text:
            for svc in result["services"]:
                result["accessibility_services"].append({"name": svc.get("name"), "source": "string_table"})
        if "android.app.action.DEVICE_ADMIN_ENABLED" in text:
            for rcv in result["receivers"]:
                result["device_admin_receivers"].append({"name": rcv.get("name"), "source": "string_table"})
        if "android.net.VpnService" in text:
            for svc in result["services"]:
                result["vpn_services"].append({"name": svc.get("name"), "source": "string_table"})
        if "android.intent.action.BOOT_COMPLETED" in text:
            for rcv in result["receivers"]:
                result["boot_receivers"].append({"name": rcv.get("name"), "source": "string_table"})

        result["exported_components"] = []
        result["intent_filters"] = []

        return result

    def _extract_section(self, xml: str, start_tag: str, end_tag: str) -> str:
        """Extract XML section between tags."""
        start = xml.find(start_tag)
        if start == -1:
            return ""
        end = xml.find(end_tag, start)
        if end == -1:
            return xml[start:]
        return xml[start:end + len(end_tag)]

    def _parse_components(self, xml: str, tag: str) -> List[Dict[str, Any]]:
        """Parse component elements (activity, service, receiver) - regex fallback."""
        components = []
        pattern = rf"<{tag}\s+([^>]*/?>|[^>]*>.*?</{tag}>)"
        for match in re.finditer(pattern, xml, re.DOTALL):
            comp_xml = match.group(0)
            comp = {"raw": comp_xml[:5000]}

            name_match = re.search(r'android:name\s*=\s*["\']([^"\']+)', comp_xml)
            comp["name"] = name_match.group(1) if name_match else None

            exported_match = re.search(r'android:exported\s*=\s*["\']?(true|false)', comp_xml)
            comp["exported"] = exported_match.group(1) == "true" if exported_match else None

            perm_match = re.search(r'android:permission\s*=\s*["\']([^"\']+)', comp_xml)
            comp["permission"] = perm_match.group(1) if perm_match else None

            enabled_match = re.search(r'android:enabled\s*=\s*["\']?(true|false)', comp_xml)
            comp["enabled"] = enabled_match.group(1) != "false" if enabled_match else True

            comp["intent_filters"] = self._parse_intent_filters(comp_xml)

            components.append(comp)
        return components

    def _parse_providers(self, xml: str) -> List[Dict[str, Any]]:
        """Parse content providers - regex fallback."""
        providers = []
        pattern = r"<provider\s+([^>]*/?>|[^>]*>.*?</provider>)"
        for match in re.finditer(pattern, xml, re.DOTALL):
            prov_xml = match.group(0)
            prov = {"raw": prov_xml[:5000]}

            name_match = re.search(r'android:name\s*=\s*["\']([^"\']+)', prov_xml)
            prov["name"] = name_match.group(1) if name_match else None

            authorities_match = re.search(r'android:authorities\s*=\s*["\']([^"\']+)', prov_xml)
            prov["authorities"] = authorities_match.group(1) if authorities_match else None

            exported_match = re.search(r'android:exported\s*=\s*["\']?(true|false)', prov_xml)
            prov["exported"] = exported_match.group(1) == "true" if exported_match else None

            permission_match = re.search(r'android:permission\s*=\s*["\']([^"\']+)', prov_xml)
            prov["read_permission"] = permission_match.group(1) if permission_match else None

            write_perm_match = re.search(r'android:writePermission\s*=\s*["\']([^"\']+)', prov_xml)
            prov["write_permission"] = write_perm_match.group(1) if write_perm_match else None

            providers.append(prov)
        return providers

    def _parse_permissions(self, xml: str, tag: str) -> List[Dict[str, Any]]:
        """Parse permission declarations - regex fallback."""
        perms = []
        pattern = rf"<{tag}\s+([^>]*/?>|[^>]*>.*?</{tag}>)"
        for match in re.finditer(pattern, xml, re.DOTALL):
            perm_xml = match.group(0)
            name_match = re.search(r'android:name\s*=\s*["\']([^"\']+)', perm_xml)
            if name_match:
                perm = {
                    "name": name_match.group(1),
                    "protection_level": "normal"
                }
                level_match = re.search(r'android:protectionLevel\s*=\s*["\']([^"\']+)', perm_xml)
                if level_match:
                    perm["protection_level"] = level_match.group(1)
                perms.append(perm)
        return perms

    def _parse_intent_filters(self, xml: str) -> List[Dict[str, Any]]:
        """Parse intent filters - regex fallback."""
        filters = []
        pattern = r"<intent-filter\s*>(.*?)</intent-filter>"
        for match in re.finditer(pattern, xml, re.DOTALL):
            filter_xml = match.group(1)
            filter_data = {"actions": [], "categories": [], "data": []}

            for action in re.finditer(r'<action\s+android:name\s*=\s*["\']([^"\']+)', filter_xml):
                filter_data["actions"].append(action.group(1))
            for cat in re.finditer(r'<category\s+android:name\s*=\s*["\']([^"\']+)', filter_xml):
                filter_data["categories"].append(cat.group(1))
            for data in re.finditer(r'<data\s+([^>]*/?>)', filter_xml):
                data_attrs = {}
                for attr in ['scheme', 'host', 'port', 'path', 'pathPrefix', 'pathPattern', 'mimeType']:
                    m = re.search(rf'android:{attr}\s*=\s*["\']([^"\']+)', data.group(1))
                    if m:
                        data_attrs[attr] = m.group(1)
                if data_attrs:
                    filter_data["data"].append(data_attrs)

            if any(filter_data.values()):
                filters.append(filter_data)
        return filters

    def _find_exported(self, result: Dict) -> List[Dict[str, Any]]:
        """Find all exported components."""
        exported = []
        for comp_type in ["activities", "services", "receivers", "providers"]:
            for comp in result.get(comp_type, []):
                if comp.get("exported") is True:
                    exported.append({
                        "type": comp_type[:-1],  # activity, service, etc.
                        "name": comp.get("name"),
                        "permission": comp.get("permission")
                    })
        return exported

    def _find_accessibility_services(self, result: Dict) -> List[Dict[str, Any]]:
        """Find accessibility service declarations."""
        services = []
        for svc in result.get("services", []):
            for intent in svc.get("intent_filters", []):
                if "android.accessibilityservice.AccessibilityService" in intent.get("actions", []):
                    services.append({"name": svc.get("name"), "intent_filter": intent})
        return services

    def _find_device_admin(self, result: Dict) -> List[Dict[str, Any]]:
        """Find device admin receivers."""
        admins = []
        for rcv in result.get("receivers", []):
            for intent in rcv.get("intent_filters", []):
                if "android.app.action.DEVICE_ADMIN_ENABLED" in intent.get("actions", []):
                    admins.append({"name": rcv.get("name"), "intent_filter": intent})
        return admins

    def _find_vpn_services(self, result: Dict) -> List[Dict[str, Any]]:
        """Find VPN services."""
        vpns = []
        for svc in result.get("services", []):
            for intent in svc.get("intent_filters", []):
                if "android.net.VpnService" in intent.get("actions", []):
                    vpns.append({"name": svc.get("name"), "intent_filter": intent})
        return vpns

    def _find_boot_receivers(self, result: Dict) -> List[Dict[str, Any]]:
        """Find BOOT_COMPLETED receivers."""
        boots = []
        for rcv in result.get("receivers", []):
            for intent in rcv.get("intent_filters", []):
                if "android.intent.action.BOOT_COMPLETED" in intent.get("actions", []):
                    boots.append({"name": rcv.get("name"), "intent_filter": intent})
        return boots

    def _find_package_install(self, result: Dict) -> List[Dict[str, Any]]:
        """Find package install receivers."""
        installs = []
        for rcv in result.get("receivers", []):
            for intent in rcv.get("intent_filters", []):
                actions = intent.get("actions", [])
                if any("PACKAGE" in a and ("INSTALL" in a or "REPLACE" in a) for a in actions):
                    installs.append({"name": rcv.get("name"), "intent_filter": intent})
        return installs

    def _find_components_in_strings(self, text: str, suffix: str) -> List[Dict[str, Any]]:
        """Find component class names in string table."""
        components = []
        # Match class names ending with suffix, allowing prefix chars like quotes, +, <, etc.
        # Class name pattern: package.ClassName (with possible $ for inner classes)
        pattern = rf"([a-z][a-z0-9_]*(\.[a-z0-9_$]+)*\.[A-Z][a-zA-Z0-9_$]*{suffix})"
        for match in re.finditer(pattern, text):
            components.append({"name": match.group(1), "source": "string_table"})
        return components