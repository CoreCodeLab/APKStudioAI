"""
Feature Extractor for ML Models
Extracts numerical features from APK analysis results for ML/GNN models.
"""
import json
import hashlib
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field
from collections import Counter
import numpy as np
from ..config_manager import get_config
from ..logging_setup import get_module_logger

logger = get_module_logger("feature_extractor")


@dataclass
class FeatureVector:
    """Container for extracted feature vector."""
    features: np.ndarray
    feature_names: List[str]
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict:
        return {
            "features": self.features.tolist(),
            "feature_names": self.feature_names,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: Dict) -> 'FeatureVector':
        return cls(
            features=np.array(data["features"]),
            feature_names=data["feature_names"],
            metadata=data.get("metadata", {}),
        )


class FeatureExtractor:
    """Extracts features from APK analysis for ML models."""

    # Feature categories and their weights
    FEATURE_CATEGORIES = {
        "manifest": 0.15,
        "permissions": 0.15,
        "api_calls": 0.20,
        "strings": 0.10,
        "network": 0.10,
        "behavior": 0.10,
        "structure": 0.10,
        "advanced_static": 0.10,
    }

    # Dangerous permission list for feature encoding
    DANGEROUS_PERMISSIONS = [
        "android.permission.READ_PHONE_STATE",
        "android.permission.READ_SMS",
        "android.permission.RECEIVE_SMS",
        "android.permission.SEND_SMS",
        "android.permission.READ_CONTACTS",
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.ACCESS_COARSE_LOCATION",
        "android.permission.CAMERA",
        "android.permission.RECORD_AUDIO",
        "android.permission.READ_EXTERNAL_STORAGE",
        "android.permission.WRITE_EXTERNAL_STORAGE",
        "android.permission.SYSTEM_ALERT_WINDOW",
        "android.permission.BIND_ACCESSIBILITY_SERVICE",
        "android.permission.BIND_DEVICE_ADMIN",
        "android.permission.BIND_VPN_SERVICE",
        "android.permission.INTERNET",
        "android.permission.ACCESS_NETWORK_STATE",
    ]

    # Sensitive API categories
    API_CATEGORIES = [
        "device_id", "location", "contacts", "sms", "camera", "audio",
        "network", "crypto", "execution", "dynamic_loading", "reflection",
        "overlay", "accessibility", "device_admin",
    ]

    # Malware family labels for supervised learning
    FAMILY_LABELS = [
        "banking_trojan", "spyware", "rat", "dropper", "ransomware",
        "adware", "sms_trojan", "cryptominer", "root_exploit", "benign",
    ]

    def __init__(self, config: Dict = None):
        self.config = config or get_config().get_all()
        self._permission_index = {p: i for i, p in enumerate(self.DANGEROUS_PERMISSIONS)}
        self._api_category_index = {c: i for i, c in enumerate(self.API_CATEGORIES)}
        self._family_index = {f: i for i, f in enumerate(self.FAMILY_LABELS)}

        # Sensitive API patterns for categorization
        self.api_patterns = {
            "device_id": ["getDeviceId", "getSubscriberId", "getSimSerialNumber", "getImei", "getMeid"],
            "location": ["getLastKnownLocation", "requestLocationUpdates", "getLatitude", "getLongitude"],
            "contacts": ["query", "ContactsContract"],
            "sms": ["sendTextMessage", "sendMultipartTextMessage", "getMessageBody"],
            "camera": ["Camera.open", "takePicture"],
            "audio": ["MediaRecorder", "AudioRecord"],
            "network": ["HttpURLConnection", "OkHttpClient", "WebSocket", "Socket"],
            "crypto": ["Cipher.getInstance", "Cipher.init", "Cipher.doFinal", "MessageDigest"],
            "execution": ["Runtime.exec", "ProcessBuilder", "loadLibrary", "load"],
            "dynamic_loading": ["DexClassLoader", "PathClassLoader", "InMemoryDexClassLoader", "DexFile.loadDex"],
            "reflection": ["Class.forName", "Method.invoke", "Field.set", "Constructor.newInstance"],
            "overlay": ["SYSTEM_ALERT_WINDOW", "addContentView"],
            "accessibility": ["AccessibilityService", "onAccessibilityEvent"],
            "device_admin": ["DevicePolicyManager", "lockNow", "resetPassword", "wipeData"],
        }

    def extract(self, analysis_data: Dict) -> FeatureVector:
        """Extract all features from analysis data."""
        feature_parts = []
        feature_names = []

        # 1. Manifest features
        manifest_feats, manifest_names = self._extract_manifest_features(analysis_data.get("manifest_analysis", {}))
        feature_parts.append(manifest_feats)
        feature_names.extend(manifest_names)

        # 2. Permission features
        perm_feats, perm_names = self._extract_permission_features(analysis_data.get("manifest_analysis", {}))
        feature_parts.append(perm_feats)
        feature_names.extend(perm_names)

        # 3. API call features
        api_feats, api_names = self._extract_api_features(analysis_data.get("dex_analysis", {}))
        feature_parts.append(api_feats)
        feature_names.extend(api_names)

        # 4. String features
        str_feats, str_names = self._extract_string_features(analysis_data.get("string_analysis", {}))
        feature_parts.append(str_feats)
        feature_names.extend(str_names)

        # 5. Network features
        net_feats, net_names = self._extract_network_features(analysis_data.get("network_analysis", {}))
        feature_parts.append(net_feats)
        feature_names.extend(net_names)

        # 6. Behavior features
        beh_feats, beh_names = self._extract_behavior_features(analysis_data.get("behavior_analysis", {}))
        feature_parts.append(beh_feats)
        feature_names.extend(beh_names)

        # 7. Structural features
        struct_feats, struct_names = self._extract_structural_features(analysis_data.get("archive_analysis", {}), analysis_data.get("dex_analysis", {}))
        feature_parts.append(struct_feats)
        feature_names.extend(struct_names)

        # 8. Advanced static features
        adv_feats, adv_names = self._extract_advanced_static_features(analysis_data.get("advanced_static", {}))
        feature_parts.append(adv_feats)
        feature_names.extend(adv_names)

        # Combine all features
        all_features = np.concatenate(feature_parts) if feature_parts else np.array([])

        # Metadata
        metadata = {
            "total_features": len(all_features),
            "categories": {
                "manifest": len(manifest_feats),
                "permissions": len(perm_feats),
                "api_calls": len(api_feats),
                "strings": len(str_feats),
                "network": len(net_feats),
                "behavior": len(beh_feats),
                "structure": len(struct_feats),
                "advanced_static": len(adv_feats),
            },
            "apk_path": analysis_data.get("apk_path", "unknown"),
        }

        return FeatureVector(
            features=all_features.astype(np.float32),
            feature_names=feature_names,
            metadata=metadata,
        )

    def _extract_manifest_features(self, manifest: Dict) -> Tuple[np.ndarray, List[str]]:
        """Extract manifest-level features."""
        features = []
        names = []

        # Boolean flags
        flags = [
            ("debuggable", manifest.get("debuggable", False)),
            ("uses_cleartext_traffic", manifest.get("uses_cleartext_traffic", False)),
            ("allow_backup", manifest.get("allow_backup", True)),
            ("shared_user_id", bool(manifest.get("shared_user_id"))),
        ]

        for name, value in flags:
            features.append(1.0 if value else 0.0)
            names.append(f"manifest_{name}")

        # Component counts
        for comp_type in ["activities", "services", "receivers", "providers"]:
            comps = manifest.get(comp_type, [])
            exported = sum(1 for c in comps if c.get("exported", False))
            unprotected = sum(1 for c in comps if c.get("exported", False) and not c.get("permission"))

            features.extend([
                len(comps),
                exported,
                unprotected,
            ])
            names.extend([
                f"manifest_{comp_type}_count",
                f"manifest_{comp_type}_exported",
                f"manifest_{comp_type}_unprotected",
            ])

        # Version info
        features.extend([
            manifest.get("min_sdk_version", 1) / 33.0,  # Normalized
            manifest.get("target_sdk_version", 33) / 33.0,
            manifest.get("version_code", 1) / 1000.0,  # Normalized
        ])
        names.extend(["manifest_min_sdk_norm", "manifest_target_sdk_norm", "manifest_version_code_norm"])

        return np.array(features, dtype=np.float32), names

    def _extract_permission_features(self, manifest: Dict) -> Tuple[np.ndarray, List[str]]:
        """Extract permission-based features."""
        permissions = manifest.get("permissions", [])
        perm_set = set(permissions)

        features = []
        names = []

        # Binary vector for dangerous permissions
        for perm in self.DANGEROUS_PERMISSIONS:
            features.append(1.0 if perm in perm_set else 0.0)
            names.append(f"perm_{perm.split('.')[-1].lower()}")

        # Aggregate counts
        features.extend([
            len(permissions),
            sum(1 for p in permissions if p in self.DANGEROUS_PERMISSIONS),
        ])
        names.extend(["perm_total_count", "perm_dangerous_count"])

        return np.array(features, dtype=np.float32), names

    def _extract_api_features(self, dex: Dict) -> Tuple[np.ndarray, List[str]]:
        """Extract API call features."""
        api_calls = dex.get("api_calls", [])

        # Count by category
        category_counts = {cat: 0 for cat in self.API_CATEGORIES}

        for call in api_calls:
            call_str = call.get("call", "")
            for category, patterns in self.api_patterns.items():
                if any(p in call_str for p in patterns):
                    category_counts[category] += 1
                    break

        features = []
        names = []

        # Category counts (normalized by total calls)
        total_calls = len(api_calls) if api_calls else 1
        for cat in self.API_CATEGORIES:
            features.append(category_counts[cat] / total_calls)
            names.append(f"api_{cat}_rate")

        # Total calls
        features.append(min(total_calls / 1000.0, 1.0))  # Normalized
        names.append("api_total_calls_norm")

        # Unique classes calling APIs
        unique_classes = len(set(c.get("class", "") for c in api_calls))
        features.append(min(unique_classes / 500.0, 1.0))
        names.append("api_unique_classes_norm")

        return np.array(features, dtype=np.float32), names

    def _extract_string_features(self, strings: Dict) -> Tuple[np.ndarray, List[str]]:
        """Extract string-based features."""
        all_strings = strings.get("all_strings", [])
        decoded = strings.get("decoded_strings", [])
        urls = strings.get("urls", [])
        domains = strings.get("domains", [])
        ips = strings.get("ips", [])
        firebase = strings.get("firebase", [])
        telegram = strings.get("telegram_bots", [])

        features = []
        names = []

        # Counts
        features.extend([
            min(len(all_strings) / 10000.0, 1.0),
            min(len(decoded) / 100.0, 1.0),
            min(len(urls) / 100.0, 1.0),
            min(len(domains) / 50.0, 1.0),
            min(len(ips) / 20.0, 1.0),
            min(len(firebase) / 10.0, 1.0),
            min(len(telegram) / 10.0, 1.0),
        ])
        names.extend([
            "str_total_count_norm", "str_decoded_count_norm", "str_url_count_norm",
            "str_domain_count_norm", "str_ip_count_norm", "str_firebase_count_norm",
            "str_telegram_count_norm",
        ])

        # Suspicious string indicators
        suspicious_keywords = [
            "password", "username", "login", "token", "api_key", "secret",
            "key", "credential", "auth", "c2", "command", "control",
            "encrypt", "decrypt", "payload", "shell", "exec", "root",
        ]

        combined_text = " ".join(all_strings).lower()
        for kw in suspicious_keywords:
            features.append(1.0 if kw in combined_text else 0.0)
            names.append(f"str_suspicious_{kw}")

        # Entropy estimate (average string entropy)
        if all_strings:
            avg_entropy = sum(self._estimate_entropy(s) for s in all_strings) / len(all_strings)
            features.append(avg_entropy / 8.0)  # Normalized to 0-1
        else:
            features.append(0.0)
        names.append("str_avg_entropy_norm")

        return np.array(features, dtype=np.float32), names

    def _estimate_entropy(self, s: str) -> float:
        """Estimate Shannon entropy of string."""
        if not s:
            return 0.0
        counts = Counter(s)
        length = len(s)
        entropy = -sum((c / length) * np.log2(c / length) for c in counts.values())
        return entropy

    def _extract_network_features(self, network: Dict) -> Tuple[np.ndarray, List[str]]:
        """Extract network-related features."""
        urls = network.get("urls", [])
        domains = network.get("domains", [])
        ips = network.get("ips", [])
        certs = network.get("certificates", [])
        c2_config = network.get("c2_config", [])

        features = []
        names = []

        # Counts
        features.extend([
            min(len(urls) / 50.0, 1.0),
            min(len(domains) / 30.0, 1.0),
            min(len(ips) / 20.0, 1.0),
            min(len(certs) / 10.0, 1.0),
            min(len(c2_config) / 10.0, 1.0),
        ])
        names.extend([
            "net_url_count_norm", "net_domain_count_norm", "net_ip_count_norm",
            "net_cert_count_norm", "net_c2_count_norm",
        ])

        # Suspicious TLDs
        suspicious_tlds = [".top", ".xyz", ".ru", ".cn", ".tk", ".ml", ".ga", ".cf"]
        domain_str = " ".join(d.get("domain", "") for d in domains).lower()
        for tld in suspicious_tlds:
            features.append(1.0 if tld in domain_str else 0.0)
            names.append(f"net_suspicious_tld_{tld[1:]}")

        # IP vs domain ratio
        if len(domains) + len(ips) > 0:
            features.append(len(ips) / (len(domains) + len(ips)))
        else:
            features.append(0.0)
        names.append("net_ip_ratio")

        # HTTPS vs HTTP
        http_count = sum(1 for u in urls if u.get("url", "").startswith("http:"))
        https_count = sum(1 for u in urls if u.get("url", "").startswith("https:"))
        if http_count + https_count > 0:
            features.append(https_count / (http_count + https_count))
        else:
            features.append(0.0)
        names.append("net_https_ratio")

        return np.array(features, dtype=np.float32), names

    def _extract_behavior_features(self, behavior: Dict) -> Tuple[np.ndarray, List[str]]:
        """Extract behavioral features."""
        detected = behavior.get("detected_behaviors", [])

        features = []
        names = []

        # Behavior categories
        behavior_categories = [
            "surveillance", "persistence", "anti_emulator", "anti_debugger",
            "exfiltration", "ransomware", "root_exploit", "dropper",
            "c2_communication", "obfuscation", "dynamic_loading",
        ]

        for cat in behavior_categories:
            matches = [d for d in detected if d.get("category") == cat]
            max_conf = max((d.get("confidence", 0) for d in matches), default=0)
            features.append(max_conf / 100.0)
            names.append(f"beh_{cat}_confidence")

        # Total behaviors
        features.append(min(len(detected) / 20.0, 1.0))
        names.append("beh_total_count_norm")

        return np.array(features, dtype=np.float32), names

    def _extract_structural_features(self, archive: Dict, dex: Dict) -> Tuple[np.ndarray, List[str]]:
        """Extract structural features."""
        features = []
        names = []

        # Archive features
        file_size = archive.get("file_size_mb", 0)
        features.append(min(file_size / 100.0, 1.0))
        names.append("struct_file_size_norm")

        native_count = archive.get("native_libs_count", 0)
        features.append(min(native_count / 20.0, 1.0))
        names.append("struct_native_libs_norm")

        native_archs = archive.get("native_architectures", [])
        features.append(len(native_archs) / 5.0)
        names.append("struct_native_archs_norm")

        cert_count = len(archive.get("certificates", []))
        features.append(min(cert_count / 5.0, 1.0))
        names.append("struct_cert_count_norm")

        # DEX features
        dex_count = dex.get("dex_count", 1)
        features.append(min(dex_count / 10.0, 1.0))
        names.append("struct_dex_count_norm")

        total_classes = dex.get("total_classes", 0)
        features.append(min(total_classes / 5000.0, 1.0))
        names.append("struct_total_classes_norm")

        total_methods = dex.get("total_methods", 0)
        features.append(min(total_methods / 50000.0, 1.0))
        names.append("struct_total_methods_norm")

        # File entropy (from archive files)
        files = archive.get("files", [])
        if files:
            avg_entropy = sum(f.get("entropy", 0) for f in files) / len(files)
            features.append(avg_entropy / 8.0)
        else:
            features.append(0.0)
        names.append("struct_avg_entropy_norm")

        return np.array(features, dtype=np.float32), names

    def _extract_advanced_static_features(self, advanced: Dict) -> Tuple[np.ndarray, List[str]]:
        """Extract advanced static analysis features."""
        features = []
        names = []

        # Call graph
        cg = advanced.get("call_graph", {}).get("statistics", {})
        features.extend([
            min(cg.get("nodes", 0) / 5000.0, 1.0),
            min(cg.get("edges", 0) / 20000.0, 1.0),
            min(cg.get("sensitive_apis", 0) / 100.0, 1.0),
            min(cg.get("entry_points", 0) / 100.0, 1.0),
        ])
        names.extend(["adv_cg_nodes_norm", "adv_cg_edges_norm", "adv_cg_sensitive_norm", "adv_cg_entries_norm"])

        # Sensitive paths
        sensitive_paths = advanced.get("call_graph", {}).get("sensitive_paths", [])
        features.append(min(len(sensitive_paths) / 50.0, 1.0))
        names.append("adv_sensitive_paths_norm")

        # Taint
        taint = advanced.get("taint", {}).get("statistics", {})
        features.extend([
            min(taint.get("tainted_methods", 0) / 500.0, 1.0),
            min(taint.get("source_sink_paths", 0) / 50.0, 1.0),
        ])
        names.extend(["adv_taint_methods_norm", "adv_taint_paths_norm"])

        # ICC
        icc = advanced.get("icc", {}).get("statistics", {})
        features.extend([
            min(icc.get("total_icc_edges", 0) / 100.0, 1.0),
            min(icc.get("exported_components", 0) / 50.0, 1.0),
            min(icc.get("unprotected_exported", 0) / 30.0, 1.0),
        ])
        names.extend(["adv_icc_edges_norm", "adv_icc_exported_norm", "adv_icc_unprotected_norm"])

        # Dynamic loading
        dyn_loading = advanced.get("dynamic_loading", {}).get("load_sites", [])
        features.append(min(len(dyn_loading) / 10.0, 1.0))
        names.append("adv_dyn_load_norm")

        # Reflection
        reflection = advanced.get("reflection", {})
        features.extend([
            min(reflection.get("total_reflection_calls", 0) / 50.0, 1.0),
            min(reflection.get("resolved_count", 0) / 50.0, 1.0),
        ])
        names.extend(["adv_refl_total_norm", "adv_refl_resolved_norm"])

        # Obfuscation
        obfu = advanced.get("obfuscation", {})
        features.append(min(obfu.get("risk_score", 0) / 100.0, 1.0))
        names.append("adv_obfu_risk_norm")

        # YARA
        yara = advanced.get("yara", {}).get("matches", [])
        features.append(min(len(yara) / 20.0, 1.0))
        names.append("adv_yara_matches_norm")

        return np.array(features, dtype=np.float32), names

    def extract_batch(self, analysis_list: List[Dict]) -> List[FeatureVector]:
        """Extract features for multiple APKs."""
        return [self.extract(data) for data in analysis_list]

    def get_feature_names(self) -> List[str]:
        """Get all feature names by running extraction on dummy data."""
        dummy = {
            "manifest_analysis": {},
            "dex_analysis": {"api_calls": []},
            "string_analysis": {"all_strings": []},
            "network_analysis": {"urls": [], "domains": []},
            "behavior_analysis": {"detected_behaviors": []},
            "archive_analysis": {"files": []},
            "advanced_static": {},
        }
        fv = self.extract(dummy)
        return fv.feature_names


_feature_extractor_instance = None


def get_feature_extractor(config: Dict = None) -> FeatureExtractor:
    """Get singleton feature extractor instance."""
    global _feature_extractor_instance
    if _feature_extractor_instance is None:
        _feature_extractor_instance = FeatureExtractor(config)
    return _feature_extractor_instance