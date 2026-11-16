"""
Androguard integration for APKStudioAI 2.1
Robust APK/DEX/ARSC parsing with multidex support
"""
import zipfile
import logging
import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple, Set
from collections import defaultdict

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.backends import default_backend
    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False

try:
    from androguard.core.apk import APK, AXMLPrinter
    from androguard.core.dex import DEX
    from androguard.misc import AnalyzeAPK, Analysis
    HAS_ANDROGUARD = True
except ImportError:
    HAS_ANDROGUARD = False
    APK = None
    DEX = None
    AXMLPrinter = None
    AnalyzeAPK = None
    Analysis = None

from .config_manager import get_config
from .utils import calculate_sha256, format_size

logger = logging.getLogger(__name__)


class AndroguardEngine:
    """Wrapper for Androguard APK/DEX/ARSC analysis."""

    def __init__(self, config: Dict = None):
        self.config = config or get_config().get_all()
        analysis_config = self.config.get("analysis", {})
        self.max_dex_size_mb = analysis_config.get("max_dex_size_mb", 50)
        self.max_file_size_mb = analysis_config.get("max_file_size_mb", 100)
        self.max_methods_analyze = analysis_config.get("max_methods_analyze", 2000)

        if not HAS_ANDROGUARD:
            logger.warning("Androguard not available - install with: pip install androguard")

    def analyze_apk(self, apk_path: Path, extract_dir: Path = None) -> Dict[str, Any]:
        """Comprehensive APK analysis using Androguard."""
        if not HAS_ANDROGUARD:
            return {"error": "Androguard not installed", "available": False}

        try:
            # Use Androguard's AnalyzeAPK for full analysis
            apk_obj, dex_list, dx = AnalyzeAPK(str(apk_path))

            result = {
                "available": True,
                "package": apk_obj.get_package(),
                "version_name": apk_obj.get_androidversion_name(),
                "version_code": apk_obj.get_androidversion_code(),
                "min_sdk": apk_obj.get_min_sdk_version(),
                "target_sdk": apk_obj.get_target_sdk_version(),
                "max_sdk": apk_obj.get_max_sdk_version(),
                "manifest": self._parse_manifest(apk_obj),
                "certificates": self._analyze_certificates(apk_obj),
                "permissions": self._extract_permissions(apk_obj),
                "components": self._extract_components(apk_obj),
                "dex_files": self._analyze_dex_files(apk_obj, dex_list),
                "libraries": self._extract_native_libs(apk_obj),
                "resources": self._analyze_resources(apk_obj),
                "apis": self._extract_apis(dx) if dx else [],
                "findings": []
            }

            # Security findings
            self._add_security_findings(apk_obj, result)

            return result

        except Exception as e:
            logger.error(f"Androguard analysis failed: {e}")
            return {"error": str(e), "available": True}

    def _parse_manifest(self, apk_obj: APK) -> Dict[str, Any]:
        """Parse AndroidManifest.xml using Androguard."""
        try:
            axml = apk_obj.get_android_manifest_xml()
            if axml:
                # Get raw XML
                xml_str = axml.toxml() if hasattr(axml, 'toxml') else str(axml)
            else:
                # Fallback to AXMLPrinter
                raw_xml = apk_obj.get_raw_android_manifest()
                if raw_xml:
                    printer = AXMLPrinter(raw_xml)
                    xml_str = printer.get_xml().decode('utf-8', errors='ignore')
                else:
                    xml_str = ""

            return {
                "xml": xml_str[:100000],  # Limit size
                "package": apk_obj.get_package(),
                "version_name": apk_obj.get_androidversion_name(),
                "version_code": apk_obj.get_androidversion_code(),
                "min_sdk": apk_obj.get_min_sdk_version(),
                "target_sdk": apk_obj.get_target_sdk_version(),
                "max_sdk": apk_obj.get_max_sdk_version(),
                "uses_permissions": apk_obj.get_permissions() or [],
                "uses_features": apk_obj.get_features() or [],
                "uses_libraries": apk_obj.get_libraries() or [],
            }
        except Exception as e:
            logger.warning(f"Manifest parsing failed: {e}")
            return {"error": str(e)}

    def _analyze_certificates(self, apk_obj: APK) -> List[Dict[str, Any]]:
        """Analyze APK signing certificates."""
        certs = []
        try:
            # Androguard 4.x uses get_certificates_der_v2/v3/v31
            certs_der = apk_obj.get_certificates_der_v2()
            if not certs_der:
                certs_der = apk_obj.get_certificates_der_v3()
            if not certs_der:
                certs_der = apk_obj.get_certificates_der_v31()

            for cert_der in certs_der:
                if cert_der:
                    if HAS_CRYPTOGRAPHY:
                        try:
                            from cryptography import x509
                            from cryptography.hazmat.primitives import hashes
                            from cryptography.hazmat.backends import default_backend
                            cert = x509.load_der_x509_certificate(cert_der, default_backend())
                            certs.append({
                                "issuer": cert.issuer.rfc4514_string(),
                                "subject": cert.subject.rfc4514_string(),
                                "serial_number": str(cert.serial_number),
                                "sha256": cert.fingerprint(hashes.SHA256()).hex(),
                                "sha1": cert.fingerprint(hashes.SHA1()).hex(),
                                "md5": cert.fingerprint(hashes.MD5()).hex(),
                                "valid_not_before": cert.not_valid_before_utc.isoformat() if hasattr(cert, 'not_valid_before_utc') else str(cert.not_valid_before),
                                "valid_not_after": cert.not_valid_after_utc.isoformat() if hasattr(cert, 'not_valid_after_utc') else str(cert.not_valid_after),
                                "signature_algorithm": cert.signature_algorithm_oid._name if cert.signature_algorithm_oid else "",
                                "public_key_algorithm": cert.public_key().__class__.__name__,
                                "is_self_signed": cert.issuer == cert.subject,
                                "is_expired": cert.not_valid_after_utc < datetime.datetime.now(datetime.timezone.utc) if hasattr(cert, 'not_valid_after_utc') else False,
                                "key_size": cert.public_key().key_size if hasattr(cert.public_key(), 'key_size') else 0,
                            })
                        except Exception:
                            pass
                    # If no cryptography or parsing failed, add basic info
                    if not certs or certs[-1].get("issuer") == "":
                        certs.append({
                            "issuer": "",
                            "subject": "",
                            "serial_number": "",
                            "sha256": "",
                            "sha1": "",
                            "md5": "",
                            "valid_not_before": "",
                            "valid_not_after": "",
                            "signature_algorithm": "",
                            "public_key_algorithm": "",
                            "is_self_signed": False,
                            "is_expired": False,
                            "key_size": 0,
                        })
        except Exception as e:
            logger.warning(f"Certificate analysis failed: {e}")
        return certs

    def _extract_permissions(self, apk_obj: APK) -> List[Dict[str, Any]]:
        """Extract permissions with metadata."""
        permissions = []
        perms = apk_obj.get_permissions() or []
        for perm in perms:
            # Get permission groups and protection levels if available
            perm_details = {
                "name": perm,
                "group": self._get_permission_group(perm),
                "protection_level": self._get_protection_level(perm),
                "description": self._get_permission_description(perm)
            }
            permissions.append(perm_details)
        return permissions

    def _get_permission_group(self, perm: str) -> str:
        """Map permission to group."""
        if perm.startswith("android.permission."):
            base = perm[len("android.permission."):]
            # Common groups
            if "READ_" in base or "WRITE_" in base or "ACCESS_" in base:
                return "storage" if "EXTERNAL" in base or "MEDIA" in base else "location"
            if "CAMERA" in base or "RECORD_AUDIO" in base:
                return "hardware"
            if "INTERNET" in base or "NETWORK" in base or "WIFI" in base or "BLUETOOTH" in base:
                return "network"
            if "SEND_SMS" in base or "RECEIVE_SMS" in base or "READ_SMS" in base:
                return "messaging"
            if "CALL_PHONE" in base or "READ_CONTACTS" in base or "WRITE_CONTACTS" in base:
                return "contacts"
            if "SYSTEM_ALERT_WINDOW" in base or "BIND_ACCESSIBILITY_SERVICE" in base:
                return "overlay"
            if "DEVICE_ADMIN" in base or "BIND_DEVICE_ADMIN" in base:
                return "admin"
            return "other"
        return "custom"

    def _get_protection_level(self, perm: str) -> str:
        """Get protection level for known permissions."""
        dangerous = {
            "READ_CALENDAR", "WRITE_CALENDAR", "CAMERA", "READ_CONTACTS", "WRITE_CONTACTS",
            "GET_ACCOUNTS", "ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION", "RECORD_AUDIO",
            "READ_PHONE_STATE", "READ_PHONE_NUMBERS", "CALL_PHONE", "ANSWER_PHONE_CALLS",
            "READ_CALL_LOG", "WRITE_CALL_LOG", "ADD_VOICEMAIL", "USE_SIP", "PROCESS_OUTGOING_CALLS",
            "BODY_SENSORS", "SEND_SMS", "RECEIVE_SMS", "READ_SMS", "RECEIVE_WAP_PUSH",
            "RECEIVE_MMS", "READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE", "ACCESS_MEDIA_LOCATION",
            "ACCEPT_HANDOVER", "ACCESS_BACKGROUND_LOCATION", "ACTIVITY_RECOGNITION",
            "READ_MEDIA_IMAGES", "READ_MEDIA_VIDEO", "READ_MEDIA_AUDIO"
        }
        if perm in dangerous or perm.replace("android.permission.", "") in dangerous:
            return "dangerous"
        if perm.startswith("android.permission."):
            return "normal"
        return "signature"

    def _get_permission_description(self, perm: str) -> str:
        """Get human-readable description."""
        descriptions = {
            "android.permission.INTERNET": "Allows applications to open network sockets",
            "android.permission.ACCESS_NETWORK_STATE": "Allows applications to access information about networks",
            "android.permission.ACCESS_WIFI_STATE": "Allows applications to access information about Wi-Fi networks",
            "android.permission.CAMERA": "Required to be able to access the camera device",
            "android.permission.RECORD_AUDIO": "Allows an application to record audio",
            "android.permission.READ_CONTACTS": "Allows an application to read the user's contacts data",
            "android.permission.WRITE_CONTACTS": "Allows an application to write the user's contacts data",
            "android.permission.READ_SMS": "Allows an application to read SMS messages",
            "android.permission.RECEIVE_SMS": "Allows an application to receive SMS messages",
            "android.permission.SEND_SMS": "Allows an application to send SMS messages",
            "android.permission.ACCESS_FINE_LOCATION": "Allows an app to access precise location",
            "android.permission.ACCESS_COARSE_LOCATION": "Allows an app to access approximate location",
            "android.permission.READ_EXTERNAL_STORAGE": "Allows an application to read from external storage",
            "android.permission.WRITE_EXTERNAL_STORAGE": "Allows an application to write to external storage",
            "android.permission.SYSTEM_ALERT_WINDOW": "Allows an app to create windows using TYPE_SYSTEM_ALERT",
            "android.permission.BIND_ACCESSIBILITY_SERVICE": "Allows an app to bind to accessibility services",
            "android.permission.REQUEST_INSTALL_PACKAGES": "Allows an application to request installing packages",
            "android.permission.FOREGROUND_SERVICE": "Allows a regular application to use foreground services",
            "android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS": "Allows an app to ask to ignore battery optimizations",
        }
        return descriptions.get(perm, "")

    def _extract_components(self, apk_obj: APK) -> Dict[str, List[Dict[str, Any]]]:
        """Extract all Android components (activities, services, receivers, providers)."""
        components = {
            "activities": [],
            "services": [],
            "receivers": [],
            "providers": [],
        }

        for comp_type in components.keys():
            method_name = f"get_{comp_type}"
            if hasattr(apk_obj, method_name):
                comps = getattr(apk_obj, method_name)() or []
                for comp in comps:
                    comp_data = {
                        "name": comp,
                        "exported": self._is_component_exported(apk_obj, comp, comp_type[:-1]),
                        "permission": self._get_component_permission(apk_obj, comp, comp_type[:-1]),
                        "intent_filters": self._get_intent_filters(apk_obj, comp, comp_type[:-1]),
                    }
                    components[comp_type].append(comp_data)

        return components

    def _is_component_exported(self, apk_obj: APK, comp: str, comp_type: str) -> bool:
        """Check if component is exported."""
        try:
            return apk_obj.is_component_exported(comp_type, comp)
        except Exception:
            return False

    def _get_component_permission(self, apk_obj: APK, comp: str, comp_type: str) -> Optional[str]:
        """Get component permission."""
        try:
            return apk_obj.get_component_permission(comp_type, comp)
        except Exception:
            return None

    def _get_intent_filters(self, apk_obj: APK, comp: str, comp_type: str) -> List[Dict[str, Any]]:
        """Get intent filters for component."""
        try:
            filters = apk_obj.get_intent_filters(comp_type, comp) or {}
            return [
                {"action": action, "category": category, "data": data}
                for action, (category, data) in filters.items()
            ]
        except Exception:
            return []

    def _analyze_dex_files(self, apk_obj: APK, dex_list: List) -> List[Dict[str, Any]]:
        """Analyze all DEX files (multidex support)."""
        dex_files = []
        for i, dex in enumerate(dex_list):
            dex_info = {
                "index": i,
                "classes_count": dex.get_class_count() if hasattr(dex, 'get_class_count') else 0,
                "methods_count": dex.get_method_count() if hasattr(dex, 'get_method_count') else 0,
                "fields_count": dex.get_field_count() if hasattr(dex, 'get_field_count') else 0,
                "sha256": "",
                "size_bytes": 0,
            }
            dex_files.append(dex_info)
        return dex_files

    def _extract_native_libs(self, apk_obj: APK) -> List[Dict[str, Any]]:
        """Extract native library information."""
        libs = []
        try:
            lib_files = apk_obj.get_libraries() or []
            for lib in lib_files:
                libs.append({
                    "name": lib,
                    "architecture": self._guess_arch_from_path(lib)
                })
        except Exception:
            pass
        return libs

    def _guess_arch_from_path(self, path: str) -> str:
        """Guess architecture from library path."""
        if "arm64-v8a" in path:
            return "arm64-v8a"
        elif "armeabi-v7a" in path:
            return "armeabi-v7a"
        elif "x86_64" in path:
            return "x86_64"
        elif "x86" in path:
            return "x86"
        elif "armeabi" in path:
            return "armeabi"
        return "unknown"

    def _analyze_resources(self, apk_obj: APK) -> Dict[str, Any]:
        """Analyze resources (limited to avoid memory issues)."""
        try:
            resources = apk_obj.get_resources()
            if resources:
                return {
                    "package_name": resources.get_package_name(),
                    "strings_count": len(resources.get_strings()) if hasattr(resources, 'get_strings') else 0,
                    "has_resources": True
                }
        except Exception:
            pass
        return {"has_resources": False}

    def _extract_apis(self, dx) -> List[Dict[str, Any]]:
        """Extract API calls from analysis object."""
        apis = []
        if not dx:
            return apis

        try:
            # Get external classes (Android framework APIs)
            external_classes = dx.get_external_classes()
            for ext_class in external_classes:
                if ext_class.name.startswith("Landroid/") or ext_class.name.startswith("Ljava/"):
                    class_name = ext_class.name[1:-1].replace("/", ".")
                    for method in ext_class.get_methods():
                        apis.append({
                            "class": class_name,
                            "method": method.name,
                            "descriptor": method.descriptor,
                            "access_flags": method.access_flags
                        })
        except Exception as e:
            logger.warning(f"API extraction failed: {e}")

        return apis[:5000]  # Limit

    def _add_security_findings(self, apk_obj: APK, result: Dict[str, Any]):
        """Add security-related findings."""
        findings = result.get("findings", [])

        # Debuggable
        if apk_obj.is_debuggable():
            findings.append({
                "severity": "medium",
                "category": "Manifest",
                "title": "Debuggable enabled",
                "evidence": "android:debuggable=true",
                "interpretation": "Application can be debugged in production, exposing sensitive data."
            })

        # Allow backup
        if apk_obj.get_allow_backup():
            findings.append({
                "severity": "low",
                "category": "Manifest",
                "title": "Backup allowed",
                "evidence": "android:allowBackup=true",
                "interpretation": "Application data can be backed up via adb, potentially exposing sensitive data."
            })

        # Network security config
        if apk_obj.get_network_security_config():
            findings.append({
                "severity": "info",
                "category": "Manifest",
                "title": "Network security config present",
                "evidence": f"android:networkSecurityConfig={apk_obj.get_network_security_config()}",
                "interpretation": "Custom network security configuration defined. Review for certificate pinning."
            })

        # Test only
        if apk_obj.get_test_only():
            findings.append({
                "severity": "low",
                "category": "Manifest",
                "title": "Test only application",
                "evidence": "android:testOnly=true",
                "interpretation": "Application is marked as test-only, not for production use."
            })

        # Exported components without permissions
        for comp_type in ["activities", "services", "receivers", "providers"]:
            for comp in result.get("components", {}).get(comp_type, []):
                if comp.get("exported") and not comp.get("permission"):
                    findings.append({
                        "severity": "medium",
                        "category": "Manifest",
                        "title": f"Exported {comp_type[:-1]} without permission",
                        "evidence": comp["name"],
                        "interpretation": f"Exported {comp_type[:-1]} has no permission protection, accessible by any app."
                    })

        # Dangerous permissions
        for perm in result.get("permissions", []):
            if perm.get("protection_level") == "dangerous":
                findings.append({
                    "severity": "high" if perm["group"] in ["location", "contacts", "messaging", "storage"] else "medium",
                    "category": "Permission",
                    "title": f"Dangerous permission: {perm['name']}",
                    "evidence": perm["name"],
                    "interpretation": f"Requires dangerous permission ({perm['group']}): {perm.get('description', '')}"
                })

    def analyze_dex(self, dex_path: Path) -> Dict[str, Any]:
        """Analyze a single DEX file."""
        if not HAS_ANDROGUARD:
            return {"error": "Androguard not installed"}

        try:
            dex = DEX(dex_path.read_bytes())
            return {
                "classes_count": dex.get_class_count() if hasattr(dex, 'get_class_count') else 0,
                "methods_count": dex.get_method_count() if hasattr(dex, 'get_method_count') else 0,
                "fields_count": dex.get_field_count() if hasattr(dex, 'get_field_count') else 0,
                "strings_count": dex.get_string_count() if hasattr(dex, 'get_string_count') else 0,
                "types_count": dex.get_type_count() if hasattr(dex, 'get_type_count') else 0,
                "protos_count": dex.get_proto_count() if hasattr(dex, 'get_proto_count') else 0,
                "sha256": calculate_sha256(dex_path),
                "size_bytes": dex_path.stat().st_size
            }
        except Exception as e:
            return {"error": str(e)}

    def get_call_graph(self, apk_path: Path) -> Dict[str, Any]:
        """Generate call graph from APK."""
        if not HAS_ANDROGUARD:
            return {"error": "Androguard not installed"}

        try:
            apk_obj, dex_list, dx = AnalyzeAPK(str(apk_path))
            if not dx:
                return {"error": "Failed to create analysis object"}

            # Build call graph
            graph = {
                "nodes": [],
                "edges": [],
                "entry_points": []
            }

            # Get all methods
            method_map = {}
            for method in dx.get_methods():
                class_name = method.get_class_name()
                method_name = method.get_name()
                descriptor = method.get_descriptor()
                full_name = f"{class_name}->{method_name}{descriptor}"
                method_map[full_name] = {
                    "class": class_name,
                    "method": method_name,
                    "descriptor": descriptor,
                    "access": method.get_access_flags_string()
                }

            # Build edges from cross-references
            for method in dx.get_methods():
                src = f"{method.get_class_name()}->{method.get_name()}{method.get_descriptor()}"
                for _, callee, _ in method.get_xref_to():
                    dst = f"{callee.class_name}->{callee.name}{callee.descriptor}"
                    if src in method_map and dst in method_map:
                        graph["edges"].append({"source": src, "target": dst})

            graph["nodes"] = list(method_map.values())
            return graph

        except Exception as e:
            return {"error": str(e)}


def get_androguard_engine(config: Dict = None) -> AndroguardEngine:
    """Factory function for AndroguardEngine."""
    return AndroguardEngine(config)