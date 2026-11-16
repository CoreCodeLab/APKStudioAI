"""
Permission analyzer for APKStudioAI 2.1
Maps permissions to risk levels, MITRE ATT&CK tactics, and malware behaviors
"""
from typing import Dict, List, Any, Set
from pathlib import Path


class PermissionAnalyzer:
    def __init__(self):
        # Permission risk mapping
        self.permission_risk = {
            # Critical - direct access to sensitive data/actions
            "android.permission.SEND_SMS": {"risk": "critical", "category": "communication", "cost": True, "data_exfil": True},
            "android.permission.RECEIVE_SMS": {"risk": "critical", "category": "communication", "data_exfil": True},
            "android.permission.READ_SMS": {"risk": "critical", "category": "communication", "data_exfil": True},
            "android.permission.WRITE_SMS": {"risk": "critical", "category": "communication", "data_exfil": True},
            "android.permission.RECEIVE_MMS": {"risk": "critical", "category": "communication", "data_exfil": True},
            "android.permission.RECEIVE_WAP_PUSH": {"risk": "high", "category": "communication", "data_exfil": True},
            "android.permission.CALL_PHONE": {"risk": "critical", "category": "communication", "cost": True},
            "android.permission.READ_CALL_LOG": {"risk": "high", "category": "communication", "data_exfil": True},
            "android.permission.WRITE_CALL_LOG": {"risk": "high", "category": "communication", "data_exfil": True},
            "android.permission.PROCESS_OUTGOING_CALLS": {"risk": "critical", "category": "communication", "data_exfil": True},

            # Critical - location tracking
            "android.permission.ACCESS_FINE_LOCATION": {"risk": "critical", "category": "location", "tracking": True},
            "android.permission.ACCESS_COARSE_LOCATION": {"risk": "high", "category": "location", "tracking": True},
            "android.permission.ACCESS_BACKGROUND_LOCATION": {"risk": "critical", "category": "location", "tracking": True},

            # Critical - audio/video recording
            "android.permission.RECORD_AUDIO": {"risk": "critical", "category": "recording", "surveillance": True},
            "android.permission.CAMERA": {"risk": "critical", "category": "recording", "surveillance": True},

            # High - personal data
            "android.permission.READ_CONTACTS": {"risk": "high", "category": "personal_data", "data_exfil": True},
            "android.permission.WRITE_CONTACTS": {"risk": "high", "category": "personal_data", "data_exfil": True},
            "android.permission.READ_CALENDAR": {"risk": "high", "category": "personal_data", "data_exfil": True},
            "android.permission.WRITE_CALENDAR": {"risk": "high", "category": "personal_data", "data_exfil": True},
            "android.permission.READ_USER_DICTIONARY": {"risk": "medium", "category": "personal_data"},

            # High - device control
            "android.permission.DEVICE_ADMIN": {"risk": "critical", "category": "device_control", "persistence": True},
            "android.permission.BIND_DEVICE_ADMIN": {"risk": "critical", "category": "device_control", "persistence": True},
            "android.permission.MANAGE_DEVICE_ADMINS": {"risk": "critical", "category": "device_control"},
            "android.permission.WRITE_SECURE_SETTINGS": {"risk": "high", "category": "device_control"},

            # High - overlay/draw over apps
            "android.permission.SYSTEM_ALERT_WINDOW": {"risk": "high", "category": "overlay", "phishing": True},
            "android.permission.ACTION_MANAGE_OVERLAY_PERMISSION": {"risk": "high", "category": "overlay"},

            # High - accessibility
            "android.permission.BIND_ACCESSIBILITY_SERVICE": {"risk": "critical", "category": "accessibility", "surveillance": True, "keylogging": True},
            "android.permission.ACCESSIBILITY_SERVICE": {"risk": "critical", "category": "accessibility"},

            # High - media projection
            "android.permission.MEDIA_PROJECTION": {"risk": "critical", "category": "screen_capture", "surveillance": True},
            "android.permission.MEDIA_PROJECTION_MANAGE": {"risk": "high", "category": "screen_capture"},

            # High - VPN
            "android.permission.BIND_VPN_SERVICE": {"risk": "critical", "category": "network", "traffic_intercept": True},
            "android.permission.CONTROL_VPN": {"risk": "high", "category": "network"},

            # High - package installation
            "android.permission.REQUEST_INSTALL_PACKAGES": {"risk": "high", "category": "installation", "dropper": True},
            "android.permission.INSTALL_PACKAGES": {"risk": "critical", "category": "installation"},
            "android.permission.DELETE_PACKAGES": {"risk": "critical", "category": "installation"},

            # High - system modification
            "android.permission.WRITE_SETTINGS": {"risk": "medium", "category": "system_modification"},
            "android.permission.CHANGE_CONFIGURATION": {"risk": "medium", "category": "system_modification"},
            "android.permission.MODIFY_AUDIO_SETTINGS": {"risk": "medium", "category": "system_modification"},

            # Medium - network
            "android.permission.INTERNET": {"risk": "low", "category": "network", "required_for_c2": True},
            "android.permission.ACCESS_NETWORK_STATE": {"risk": "low", "category": "network"},
            "android.permission.ACCESS_WIFI_STATE": {"risk": "low", "category": "network"},
            "android.permission.CHANGE_WIFI_STATE": {"risk": "medium", "category": "network"},
            "android.permission.CHANGE_NETWORK_STATE": {"risk": "medium", "category": "network"},

            # Medium - storage
            "android.permission.READ_EXTERNAL_STORAGE": {"risk": "medium", "category": "storage", "data_exfil": True},
            "android.permission.WRITE_EXTERNAL_STORAGE": {"risk": "medium", "category": "storage", "data_exfil": True},
            "android.permission.MANAGE_EXTERNAL_STORAGE": {"risk": "high", "category": "storage"},

            # Medium - boot/persistence
            "android.permission.RECEIVE_BOOT_COMPLETED": {"risk": "medium", "category": "persistence", "autostart": True},
            "android.permission.FOREGROUND_SERVICE": {"risk": "medium", "category": "persistence"},

            # Low - info
            "android.permission.VIBRATE": {"risk": "low", "category": "info"},
            "android.permission.WAKE_LOCK": {"risk": "low", "category": "info"},
            "android.permission.FLASHLIGHT": {"risk": "low", "category": "info"},
            "android.permission.BLUETOOTH": {"risk": "low", "category": "info"},
            "android.permission.BLUETOOTH_ADMIN": {"risk": "medium", "category": "info"},
            "android.permission.NFC": {"risk": "low", "category": "info"},

            # Special - signature level
            "android.permission.SIGNATURE": {"risk": "info", "category": "system"},
            "android.permission.SIGNATURE_OR_SYSTEM": {"risk": "info", "category": "system"},
        }

        # Permission groups for analysis
        self.permission_groups = {
            "sms_control": [
                "android.permission.SEND_SMS", "android.permission.RECEIVE_SMS",
                "android.permission.READ_SMS", "android.permission.WRITE_SMS"
            ],
            "call_control": [
                "android.permission.CALL_PHONE", "android.permission.READ_CALL_LOG",
                "android.permission.WRITE_CALL_LOG", "android.permission.PROCESS_OUTGOING_CALLS"
            ],
            "location_tracking": [
                "android.permission.ACCESS_FINE_LOCATION", "android.permission.ACCESS_COARSE_LOCATION",
                "android.permission.ACCESS_BACKGROUND_LOCATION"
            ],
            "surveillance": [
                "android.permission.RECORD_AUDIO", "android.permission.CAMERA",
                "android.permission.BIND_ACCESSIBILITY_SERVICE", "android.permission.MEDIA_PROJECTION"
            ],
            "device_admin": [
                "android.permission.DEVICE_ADMIN", "android.permission.BIND_DEVICE_ADMIN",
                "android.permission.MANAGE_DEVICE_ADMINS"
            ],
            "overlay_phishing": [
                "android.permission.SYSTEM_ALERT_WINDOW", "android.permission.ACTION_MANAGE_OVERLAY_PERMISSION"
            ],
            "network_intercept": [
                "android.permission.BIND_VPN_SERVICE", "android.permission.CONTROL_VPN"
            ],
            "dropper": [
                "android.permission.REQUEST_INSTALL_PACKAGES", "android.permission.INSTALL_PACKAGES",
                "android.permission.DELETE_PACKAGES"
            ],
            "data_exfiltration": [
                "android.permission.READ_EXTERNAL_STORAGE", "android.permission.WRITE_EXTERNAL_STORAGE",
                "android.permission.MANAGE_EXTERNAL_STORAGE", "android.permission.READ_CONTACTS",
                "android.permission.READ_SMS", "android.permission.READ_CALL_LOG"
            ],
            "persistence": [
                "android.permission.RECEIVE_BOOT_COMPLETED", "android.permission.FOREGROUND_SERVICE",
                "android.permission.DEVICE_ADMIN", "android.permission.BIND_DEVICE_ADMIN"
            ]
        }

        # MITRE ATT&CK for Mobile mapping
        self.mitre_mapping = {
            "android.permission.RECEIVE_BOOT_COMPLETED": ["T1547.001"],  # Boot Autostart
            "android.permission.DEVICE_ADMIN": ["T1547.001", "T1556.004"],  # Device Admin
            "android.permission.BIND_ACCESSIBILITY_SERVICE": ["T1056.001", "T1505.003"],  # Keylogging, Accessibility
            "android.permission.RECORD_AUDIO": ["T1505.003"],  # Audio Capture
            "android.permission.CAMERA": ["T1505.003"],  # Screen Capture
            "android.permission.MEDIA_PROJECTION": ["T1505.003"],  # Screen Capture
            "android.permission.ACCESS_FINE_LOCATION": ["T1614.001"],  # Location Tracking
            "android.permission.READ_SMS": ["T1538"],  # SMS Collection
            "android.permission.SEND_SMS": ["T1538"],  # SMS Sending
            "android.permission.READ_CONTACTS": ["T1539"],  # Contact Collection
            "android.permission.CALL_PHONE": ["T1497"],  # Phone Call
            "android.permission.REQUEST_INSTALL_PACKAGES": ["T1505.001"],  # Install Package
            "android.permission.BIND_VPN_SERVICE": ["T1040"],  # Network Sniffing
            "android.permission.SYSTEM_ALERT_WINDOW": ["T1556.004"],  # Overlay Attack
        }

    def analyze(self, permissions: List[str]) -> Dict[str, Any]:
        """Analyze permission list for risk assessment."""
        result = {
            "permissions": permissions,
            "total_count": len(permissions),
            "by_risk": {"critical": [], "high": [], "medium": [], "low": [], "normal": [], "info": []},
            "by_category": {},
            "groups_matched": {},
            "mitre_techniques": [],
            "capabilities": {
                "sms_control": False,
                "call_control": False,
                "location_tracking": False,
                "surveillance": False,
                "device_admin": False,
                "overlay_phishing": False,
                "network_intercept": False,
                "dropper": False,
                "data_exfiltration": False,
                "data_access": False,  # Alias for data_exfiltration
                "persistence": False,
                "cost_fraud": False,
                "keylogging": False,
                "screen_capture": False
            },
            "risk_score": 0
        }

        # Categorize by risk
        for perm in permissions:
            info = self.permission_risk.get(perm, {"risk": "unknown", "category": "unknown"})
            risk = info.get("risk", "unknown")
            category = info.get("category", "unknown")

            if risk in result["by_risk"]:
                result["by_risk"][risk].append({
                    "permission": perm,
                    "category": category,
                    "description": self._get_description(perm),
                    "flags": {k: v for k, v in info.items() if k not in ["risk", "category"]}
                })
            # Also map "low" to "normal" for compatibility
            if risk == "low":
                result["by_risk"]["normal"].append({
                    "permission": perm,
                    "category": category,
                    "description": self._get_description(perm),
                    "flags": {k: v for k, v in info.items() if k not in ["risk", "category"]}
                })

            # Category grouping
            if category not in result["by_category"]:
                result["by_category"][category] = []
            result["by_category"][category].append(perm)

            # MITRE mapping
            if perm in self.mitre_mapping:
                result["mitre_techniques"].extend(self.mitre_mapping[perm])

            # Capability flags
            if info.get("cost"):
                result["capabilities"]["cost_fraud"] = True
            if info.get("tracking"):
                result["capabilities"]["location_tracking"] = True
            if info.get("surveillance"):
                result["capabilities"]["surveillance"] = True
            if info.get("persistence"):
                result["capabilities"]["persistence"] = True
            if info.get("phishing"):
                result["capabilities"]["overlay_phishing"] = True
            if info.get("dropper"):
                result["capabilities"]["dropper"] = True
            if info.get("data_exfil"):
                result["capabilities"]["data_exfiltration"] = True
                result["capabilities"]["data_access"] = True  # Alias
            if info.get("keylogging"):
                result["capabilities"]["keylogging"] = True

        # Check permission groups
        for group_name, group_perms in self.permission_groups.items():
            matched = [p for p in group_perms if p in permissions]
            if matched:
                result["groups_matched"][group_name] = matched
                result["capabilities"][group_name] = True

        # Deduplicate MITRE
        result["mitre_techniques"] = list(set(result["mitre_techniques"]))

        # Calculate risk score (0-100)
        result["risk_score"] = self._calculate_risk_score(result)

        return result

    def _calculate_risk_score(self, result: Dict) -> int:
        """Calculate permission risk score 0-100."""
        weights = {
            "critical": 15,
            "high": 8,
            "medium": 4,
            "low": 1,
            "info": 0,
            "unknown": 2
        }

        score = 0
        for risk_level, perms in result["by_risk"].items():
            score += len(perms) * weights.get(risk_level, 0)

        # Bonus for dangerous combinations
        if result["capabilities"]["sms_control"] and result["capabilities"]["device_admin"]:
            score += 20  # SMS + Admin = RAT
        if result["capabilities"]["surveillance"] and result["capabilities"]["network_intercept"]:
            score += 15  # Spyware combo
        if result["capabilities"]["overlay_phishing"] and result["capabilities"]["keylogging"]:
            score += 15  # Banking trojan combo
        if result["capabilities"]["dropper"] and result["capabilities"]["persistence"]:
            score += 10  # Persistent dropper

        return min(100, score)

    def get_permission_details(self, permission: str) -> Dict[str, Any]:
        """Get detailed info for a single permission."""
        info = self.permission_risk.get(permission, {})
        return {
            "permission": permission,
            "risk": info.get("risk", "unknown"),
            "category": info.get("category", "unknown"),
            "description": self._get_description(permission),
            "mitre": self.mitre_mapping.get(permission, []),
            "flags": {k: v for k, v in info.items() if k not in ["risk", "category"]}
        }

    def _get_description(self, permission: str) -> str:
        """Get human-readable description."""
        descriptions = {
            "android.permission.SEND_SMS": "Send SMS messages (costs money)",
            "android.permission.RECEIVE_SMS": "Receive SMS messages",
            "android.permission.READ_SMS": "Read SMS messages",
            "android.permission.CALL_PHONE": "Make phone calls (costs money)",
            "android.permission.RECORD_AUDIO": "Record audio from microphone",
            "android.permission.CAMERA": "Access camera",
            "android.permission.ACCESS_FINE_LOCATION": "Precise GPS location",
            "android.permission.BIND_ACCESSIBILITY_SERVICE": "Full screen/keylog access (high risk)",
            "android.permission.MEDIA_PROJECTION": "Screen capture/recording",
            "android.permission.BIND_VPN_SERVICE": "Intercept all network traffic",
            "android.permission.REQUEST_INSTALL_PACKAGES": "Install other apps (dropper)",
            "android.permission.SYSTEM_ALERT_WINDOW": "Draw over other apps (phishing)",
            "android.permission.DEVICE_ADMIN": "Device administration (lock, wipe, policy)",
            "android.permission.RECEIVE_BOOT_COMPLETED": "Run at boot (persistence)",
        }
        return descriptions.get(permission, "Custom or less common permission")