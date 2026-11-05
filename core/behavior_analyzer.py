"""
Behavior analyzer for APKStudioAI 2.1
Detects malicious behaviors from static analysis: patterns, APIs, component configurations
Loads rules from analysis/behavior_rules.json
"""
import re
import json
from pathlib import Path
from typing import Dict, List, Any, Set
from .utils import printable_strings, printable_strings_utf16, get_project_root


class BehaviorAnalyzer:
    def __init__(self):
        # Load behavior patterns from JSON file
        self.behavior_patterns = self._load_behavior_rules()

    def _load_behavior_rules(self) -> Dict[str, Any]:
        """Load behavior analysis rules from analysis/behavior_rules.json and merge with built-in"""
        # Start with built-in patterns
        builtin = self._get_builtin_patterns()

        try:
            rules_path = get_project_root() / "analysis" / "behavior_rules.json"
            if rules_path.exists():
                with open(rules_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    # Parse the patterns array and convert to dict by category
                    patterns_list = data.get("rules", {}).get("suspicious_api_usage", {}).get("patterns", [])
                    json_patterns = self._convert_patterns_to_dict(patterns_list)
                    # Merge JSON patterns with built-in (JSON takes precedence for same category)
                    for cat, config in json_patterns.items():
                        if cat in builtin:
                            # Merge patterns, avoid duplicates
                            existing_patterns = set(builtin[cat].get("patterns", []))
                            new_patterns = [p for p in config.get("patterns", []) if p not in existing_patterns]
                            builtin[cat]["patterns"].extend(new_patterns)
                        else:
                            builtin[cat] = config
        except Exception as e:
            print(f"Warning: Could not load behavior_rules.json: {e}")

        return builtin

    def _convert_patterns_to_dict(self, patterns_list: List[Dict]) -> Dict[str, Any]:
        """Convert patterns array from JSON to dict grouped by category."""
        result = {}
        for pattern_obj in patterns_list:
            category = pattern_obj.get("category", "unknown")
            regex_list = pattern_obj.get("regex", [])
            min_matches = 1  # default
            description = pattern_obj.get("description", "")

            if category not in result:
                result[category] = {
                    "patterns": [],
                    "min_matches": min_matches,
                    "description": description
                }
            result[category]["patterns"].extend(regex_list)

        # Set min_matches based on category (could be enhanced from JSON)
        min_matches_map = {
            "spyware": 3, "rat": 4, "trojan": 3, "banker": 3, "dropper": 3,
            "downloader": 3, "screen_capture": 2, "keylogger": 2,
            "accessibility_abuse": 3, "device_admin_abuse": 2, "vpn_abuse": 2,
            "overlay_attack": 2, "sms_stealer": 2, "credential_theft": 3,
            "data_exfiltration": 3, "dynamic_code_loading": 2, "persistence": 2,
            "anti_analysis": 2, "obfuscation": 1, "hidden_payload": 2,
            "command_execution": 2, "native_code": 1, "network": 2,
            "crypto": 2, "sms_stealer": 2, "persistence": 2
        }

        for cat, config in result.items():
            if cat in min_matches_map:
                config["min_matches"] = min_matches_map[cat]

        return result

    def _get_builtin_patterns(self) -> Dict[str, Any]:
        """Fallback built-in patterns if JSON file not available."""
        return {
            "spyware": {
                "patterns": [
                    r"RECORD_AUDIO", r"CAMERA", r"ACCESS_FINE_LOCATION",
                    r"READ_CONTACTS", r"READ_SMS", r"READ_CALL_LOG",
                    r"MediaProjection", r"createScreenCaptureIntent",
                    r"ImageReader", r"acquireLatestImage",
                    r"AccessibilityService", r"canRetrieveWindowContent",
                    r"onAccessibilityEvent", r"getRunningTasks",
                    r"getInstalledApplications", r"PackageManager"
                ],
                "min_matches": 3,
                "description": "Surveillance capabilities: audio, video, location, contacts, messages",
                "category": "spyware",
                "severity": "high"
            },
            "rat": {
                "patterns": [
                    r"Socket", r"ServerSocket", r"DatagramSocket",
                    r"HttpURLConnection", r"OkHttpClient", r"WebSocket",
                    r"Runtime\.exec", r"ProcessBuilder", r"Command",
                    r"Shell", r"su\s", r"chmod", r"chown",
                    r"DexClassLoader", r"PathClassLoader", r"InMemoryDexClassLoader",
                    r"loadClass", r"defineClass", r"Class\.forName",
                    r"Method\.invoke", r"Field\.set", r"Constructor\.newInstance"
                ],
                "min_matches": 4,
                "description": "Remote Access Tool: command execution, C2 communication, dynamic loading",
                "category": "rat",
                "severity": "critical"
            },
            "trojan": {
                "patterns": [
                    r"SYSTEM_ALERT_WINDOW", r"addView", r"WindowManager",
                    r"TYPE_SYSTEM_ALERT", r"TYPE_APPLICATION_OVERLAY",
                    r"REQUEST_INSTALL_PACKAGES", r"PackageInstaller",
                    r"INSTALL_PACKAGES", r"DELETE_PACKAGES",
                    r"DEVICE_ADMIN", r"DeviceAdminReceiver",
                    r"force-lock", r"reset-password", r"wipe-data",
                    r"BIND_ACCESSIBILITY_SERVICE", r"performGesture",
                    r"dispatchGesture", r"click", r"scroll"
                ],
                "min_matches": 3,
                "description": "Trojan: overlay attacks, package installation, device admin abuse, accessibility abuse",
                "category": "trojan",
                "severity": "high"
            },
            "banker": {
                "patterns": [
                    r"SYSTEM_ALERT_WINDOW", r"AccessibilityService",
                    r"getPackageName", r"getRunningTasks",
                    r"WebView", r"loadUrl", r"evaluateJavascript",
                    r"addJavascriptInterface", r"setJavaScriptEnabled",
                    r"onPageFinished", r"onReceivedError",
                    r"SharedPreferences", r"Editor", r"commit",
                    r"Keystore", r"KeyStore", r"SecretKey",
                    r"Cipher", r"AES", r"RSA", r"encrypt", r"decrypt"
                ],
                "min_matches": 3,
                "description": "Banking trojan: overlay, accessibility, WebView injection, crypto",
                "category": "banker",
                "severity": "critical"
            },
            "dropper": {
                "patterns": [
                    r"REQUEST_INSTALL_PACKAGES", r"PackageInstaller",
                    r"INSTALL_PACKAGES", r"DELETE_PACKAGES",
                    r"DownloadManager", r"DownloadManager\.Request",
                    r"HttpURLConnection", r"OkHttpClient", r"InputStream",
                    r"FileOutputStream", r"write\(", r"flush\(",
                    r"Runtime\.exec", r"ProcessBuilder", r"pm install",
                    r"DexClassLoader", r"PathClassLoader", r"loadDex",
                    r"assets/", r"raw/", r"getAssets", r"openRawResource"
                ],
                "min_matches": 3,
                "description": "Dropper: downloads and installs additional payloads",
                "category": "dropper",
                "severity": "high"
            },
            "downloader": {
                "patterns": [
                    r"DownloadManager", r"HttpURLConnection", r"OkHttpClient",
                    r"WebSocket", r"Socket", r"GET", r"POST",
                    r"InputStream", r"FileOutputStream", r"write\(",
                    r"DexClassLoader", r"PathClassLoader", r"InMemoryDexClassLoader",
                    r"loadClass", r"defineClass", r"Class\.forName"
                ],
                "min_matches": 3,
                "description": "Downloader: fetches and loads additional code",
                "category": "downloader",
                "severity": "high"
            },
            "screen_capture": {
                "patterns": [
                    r"MediaProjection", r"createScreenCaptureIntent",
                    r"ImageReader", r"acquireLatestImage",
                    r"Surface", r"Canvas", r"Bitmap",
                    r"onScreenShot", r"screenshot",
                    r"BIND_ACCESSIBILITY_SERVICE", r"getWindows",
                    r"getRootInActiveWindow", r"getSource"
                ],
                "min_matches": 2,
                "description": "Screen capture capabilities",
                "category": "screen_capture",
                "severity": "high"
            },
            "keylogging": {
                "patterns": [
                    r"BIND_ACCESSIBILITY_SERVICE", r"AccessibilityEvent",
                    r"TYPE_VIEW_TEXT_CHANGED", r"TYPE_VIEW_CLICKED",
                    r"TYPE_VIEW_FOCUSED", r"getText", r"getContentDescription",
                    r"onAccessibilityEvent", r"dispatchEvent",
                    r"InputMethodService", r"onKeyDown", r"onKeyUp",
                    r"KeyEvent", r"KEYCODE"
                ],
                "min_matches": 2,
                "description": "Keylogging via accessibility or input method",
                "category": "keylogger",
                "severity": "high"
            },
            "accessibility_abuse": {
                "patterns": [
                    r"BIND_ACCESSIBILITY_SERVICE", r"AccessibilityService",
                    r"canRetrieveWindowContent", r"canPerformGestures",
                    r"FLAG_REQUEST_TOUCH_EXPLORATION_MODE",
                    r"FLAG_REQUEST_FILTER_KEY_EVENTS",
                    r"FLAG_REPORT_VIEW_IDS", r"FLAG_RETRIEVE_INTERACTIVE_WINDOWS",
                    r"performGesture", r"dispatchGesture", r"click",
                    r"scrollForward", r"scrollBackward", r"setText"
                ],
                "min_matches": 3,
                "description": "Accessibility service abuse for automation/overlay",
                "category": "accessibility_abuse",
                "severity": "high"
            },
            "device_admin_abuse": {
                "patterns": [
                    r"DeviceAdminReceiver", r"DevicePolicyManager",
                    r"BIND_DEVICE_ADMIN", r"DEVICE_ADMIN",
                    r"force-lock", r"reset-password", r"wipe-data",
                    r"watch-login", r"setPasswordQuality",
                    r"setPasswordMinimumLength", r"lockNow",
                    r"wipeData", r"setMaximumFailedPasswordsForWipe"
                ],
                "min_matches": 2,
                "description": "Device admin abuse for lock/wipe/policy control",
                "category": "device_admin_abuse",
                "severity": "critical"
            },
            "vpn_abuse": {
                "patterns": [
                    r"VpnService", r"BIND_VPN_SERVICE", r"establish\(",
                    r"addRoute", r"addAddress", r"addDnsServer",
                    r"protect\(", r"Socket", r"DatagramSocket",
                    r"HttpURLConnection", r"OkHttpClient"
                ],
                "min_matches": 2,
                "description": "VPN service abuse for traffic interception",
                "category": "vpn_abuse",
                "severity": "high"
            },
            "overlay_attack": {
                "patterns": [
                    r"SYSTEM_ALERT_WINDOW", r"WindowManager",
                    r"TYPE_SYSTEM_ALERT", r"TYPE_APPLICATION_OVERLAY",
                    r"addView", r"updateViewLayout", r"removeView",
                    r"LayoutParams", r"FLAG_NOT_FOCUSABLE",
                    r"FLAG_NOT_TOUCH_MODAL", r"FLAG_WATCH_OUTSIDE_TOUCH"
                ],
                "min_matches": 2,
                "description": "Overlay attack for phishing/credential theft",
                "category": "overlay_attack",
                "severity": "high"
            },
            "sms_abuse": {
                "patterns": [
                    r"SEND_SMS", r"RECEIVE_SMS", r"READ_SMS", r"WRITE_SMS",
                    r"SmsManager", r"sendTextMessage", r"sendMultipartTextMessage",
                    r"onReceive", r"SMS_RECEIVED", r"abortBroadcast",
                    r"PDU", r"getMessageBody", r"getOriginatingAddress"
                ],
                "min_matches": 2,
                "description": "SMS interception, sending, or manipulation",
                "category": "sms_stealer",
                "severity": "high"
            },
            "credential_theft": {
                "patterns": [
                    r"AccountManager", r"getAccounts", r"getAuthToken",
                    r"SharedPreferences", r"getString", r"PASSWORD",
                    r"USERNAME", r"LOGIN", r"CREDENTIAL",
                    r"WebView", r"loadUrl", r"evaluateJavascript",
                    r"addJavascriptInterface", r"onPageFinished",
                    r"BIND_ACCESSIBILITY_SERVICE", r"getText",
                    r"TYPE_VIEW_TEXT_CHANGED", r"TYPE_WINDOW_CONTENT_CHANGED"
                ],
                "min_matches": 3,
                "description": "Credential theft via account manager, WebView, or accessibility",
                "category": "credential_theft",
                "severity": "critical"
            },
            "data_exfiltration": {
                "patterns": [
                    r"READ_EXTERNAL_STORAGE", r"WRITE_EXTERNAL_STORAGE",
                    r"MANAGE_EXTERNAL_STORAGE", r"READ_CONTACTS",
                    r"READ_SMS", r"READ_CALL_LOG", r"READ_CALENDAR",
                    r"HttpURLConnection", r"OkHttpClient", r"WebSocket",
                    r"Socket", r"OutputStream", r"write\(",
                    r"FileOutputStream", r"InputStream", r"read\(",
                    r"Firebase", r"DatabaseReference", r"setValue",
                    r"Telegram", r"bot", r"api\.telegram\.org"
                ],
                "min_matches": 3,
                "description": "Data collection and exfiltration",
                "category": "data_exfiltration",
                "severity": "high"
            },
            "dynamic_code_loading": {
                "patterns": [
                    r"DexClassLoader", r"PathClassLoader", r"InMemoryDexClassLoader",
                    r"loadClass", r"defineClass", r"Class\.forName",
                    r"Method\.invoke", r"Field\.set", r"Constructor\.newInstance",
                    r"DexFile", r"loadDex", r"defineClass",
                    r"assets/", r"raw/", r"getAssets", r"openRawResource",
                    r"DownloadManager", r"FileOutputStream", r"write\("
                ],
                "min_matches": 2,
                "description": "Dynamic code loading (DexClassLoader, reflection)",
                "category": "dynamic_code_loading",
                "severity": "high"
            },
            "persistence": {
                "patterns": [
                    r"RECEIVE_BOOT_COMPLETED", r"BOOT_COMPLETED",
                    r"QUICKBOOT_POWERON", r"RECEIVE_BOOT_COMPLETED",
                    r"FOREGROUND_SERVICE", r"startForeground",
                    r"DeviceAdminReceiver", r"BIND_DEVICE_ADMIN",
                    r"AccessibilityService", r"BIND_ACCESSIBILITY_SERVICE",
                    r"JobScheduler", r"WorkManager", r"AlarmManager",
                    r"setExact", r"setRepeating", r"setInexactRepeating"
                ],
                "min_matches": 2,
                "description": "Persistence mechanisms: boot, foreground service, admin, accessibility",
                "category": "persistence",
                "severity": "high"
            },
            "anti_analysis": {
                "patterns": [
                    r"Build\.TYPE", r"Build\.FINGERPRINT", r"Build\.MODEL",
                    r"Build\.MANUFACTURER", r"Build\.BRAND", r"Build\.DEVICE",
                    r"Build\.PRODUCT", r"goldfish", r"generic", r"emulator",
                    r"isDebuggerConnected", r"Debug\.isDebuggerConnected",
                    r"Trace\.isTracing", r"TracerPid", r"ptrace",
                    r"Xposed", r"Frida", r"Substrate", r"Cydia",
                    r"SU", r"Superuser", r"Magisk", r"root",
                    r"checkSignature", r"getPackageInfo", r"SIGNATURE",
                    r"GET_SIGNATURES", r"GET_PERMISSIONS"
                ],
                "min_matches": 2,
                "description": "Anti-analysis: emulator detection, debugger detection, root detection, signature verification",
                "category": "anti_analysis",
                "severity": "medium"
            },
            "obfuscation": {
                "patterns": [
                    r"ProGuard", r"proguard", r"DexGuard", r"dexguard",
                    r"a/b/c", r"\.a\.", r"\.b\.", r"\.c\.",
                    r"Class\.\w{1,2}", r"Method\.\w{1,2}", r"Field\.\w{1,2}",
                    r"StringEncryption", r"ControlFlow", r"Reflection",
                    r"ArithmeticObfuscation", r"ControlFlowObfuscation"
                ],
                "min_matches": 1,
                "description": "Code obfuscation indicators",
                "category": "obfuscation",
                "severity": "medium"
            },
            "hidden_payload": {
                "patterns": [
                    r"assets/", r"raw/", r"res/raw/",
                    r"getAssets", r"openRawResource", r"InputStream",
                    r"DexFile", r"loadDex", r"defineClass",
                    r"Base64", r"decode", r"decodeBase64",
                    r"XOR", r"AES", r"Cipher", r"SecretKeySpec",
                    r"IvParameterSpec", r"encryption", r"decryption"
                ],
                "min_matches": 2,
                "description": "Hidden/encrypted payload in assets or resources",
                "category": "hidden_payload",
                "severity": "high"
            }
        }

    def analyze(self, findings: List[Dict], strings: List[str],
                manifest_data: Dict, java_classes: List[Dict] = None,
                native_libs: List[Dict] = None) -> Dict[str, Any]:
        """Analyze all collected data for behavior patterns."""
        # Combine all text sources
        all_text = " ".join(strings)
        all_text += " " + " ".join(str(f.get("evidence", "")) for f in findings)
        all_text += " " + manifest_data.get("raw_xml", "")

        if java_classes:
            for cls in java_classes:
                all_text += " " + cls.get("name", "")
                for method in cls.get("methods", []):
                    all_text += " " + method.get("name", "")

        if native_libs:
            for lib in native_libs:
                all_text += " " + " ".join(lib.get("interesting_strings", []))

        results = {
            "detected_behaviors": [],
            "behavior_scores": {},
            "indicators": [],
            "malware_categories": []
        }

        # Check each behavior category
        for category, config in self.behavior_patterns.items():
            # Handle both old format (list of patterns) and new format (dict with patterns key)
            if isinstance(config, dict):
                patterns = config.get("patterns", [])
                min_matches = config.get("min_matches", 1)
                description = config.get("description", "")
            else:
                patterns = config
                min_matches = 1
                description = ""

            matches = self._check_patterns(all_text, patterns)
            if len(matches) >= min_matches:
                confidence = min(100, (len(matches) / max(min_matches, 1)) * 50 + 30)
                results["detected_behaviors"].append({
                    "category": category,
                    "description": description,
                    "matches": matches[:20],
                    "match_count": len(matches),
                    "confidence": confidence,
                    "min_required": min_matches
                })
                results["behavior_scores"][category] = confidence

        # Map to malware categories
        results["malware_categories"] = self._map_to_malware_categories(results["detected_behaviors"])

        # Extract specific indicators
        results["indicators"] = self._extract_indicators(all_text, findings, manifest_data)

        # Also check permission abuse combinations from rules
        permission_abuse = self._load_permission_abuse_rules()
        results["permission_abuse"] = self._check_permission_abuse(manifest_data, permission_abuse)

        return results

    def _load_permission_abuse_rules(self) -> List[Dict]:
        """Load permission abuse rules from behavior_rules.json"""
        try:
            rules_path = get_project_root() / "analysis" / "behavior_rules.json"
            if rules_path.exists():
                with open(rules_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    return data.get("rules", {}).get("permission_abuse", {}).get("combinations", [])
        except Exception:
            pass
        return []

    def _check_permission_abuse(self, manifest_data: Dict, combinations: List[Dict]) -> List[Dict]:
        """Check for dangerous permission combinations."""
        results = []
        permissions = set(manifest_data.get("permissions", []))

        for combo in combinations:
            required_perms = set(combo.get("permissions", []))
            if required_perms.issubset(permissions):
                results.append({
                    "name": combo.get("name", "Unknown"),
                    "category": combo.get("category", "unknown"),
                    "severity": combo.get("severity", "medium"),
                    "description": combo.get("description", ""),
                    "matched_permissions": list(required_perms)
                })

        return results

    def _check_patterns(self, text: str, patterns: List[str]) -> List[Dict[str, Any]]:
        """Check for pattern matches in text."""
        matches = []
        for pattern in patterns:
            for match in re.finditer(pattern, text, re.IGNORECASE):
                start = max(0, match.start() - 50)
                end = min(len(text), match.end() + 50)
                context = text[start:end].replace("\n", " ")
                matches.append({
                    "pattern": pattern,
                    "match": match.group(),
                    "context": context[:200]
                })
        return matches

    def _map_to_malware_categories(self, behaviors: List[Dict]) -> List[Dict[str, Any]]:
        """Map detected behaviors to malware categories."""
        mapping = {
            "spyware": ["spyware", "data_exfiltration", "screen_capture", "keylogging"],
            "rat": ["rat", "dynamic_code_loading", "persistence", "anti_analysis"],
            "trojan": ["trojan", "overlay_attack", "device_admin_abuse", "accessibility_abuse"],
            "banker": ["banker", "overlay_attack", "accessibility_abuse", "credential_theft"],
            "dropper": ["dropper", "downloader", "dynamic_code_loading", "persistence"],
            "downloader": ["downloader", "dynamic_code_loading", "persistence"],
            "screen_capture": ["screen_capture", "spyware"],
            "keylogger": ["keylogging", "accessibility_abuse", "spyware"],
            "sms_stealer": ["sms_abuse", "spyware"],
            "ransomware": ["device_admin_abuse", "overlay_attack", "persistence", "anti_analysis"],
            "adware": ["overlay_attack", "persistence", "dynamic_code_loading"],
            "crypto_miner": ["persistence", "anti_analysis", "network_intercept"]
        }

        detected = set()
        for behavior in behaviors:
            cat = behavior["category"]
            if cat in mapping:
                for mcat in mapping[cat]:
                    detected.add(mcat)

        return [{"category": cat, "confidence": "high" if len([b for b in behaviors if cat in mapping.get(b["category"], [])]) > 1 else "medium"} for cat in detected]

    def _extract_indicators(self, text: str, findings: List[Dict], manifest_data: Dict) -> List[Dict[str, Any]]:
        """Extract specific behavioral indicators."""
        indicators = []

        # Exported components without permission
        for comp_type in ["activities", "services", "receivers", "providers"]:
            for comp in manifest_data.get(comp_type, []):
                if comp.get("exported") is True and not comp.get("permission"):
                    indicators.append({
                        "type": "exported_component",
                        "component": f"{comp_type[:-1]}:{comp.get('name')}",
                        "severity": "medium",
                        "description": f"Exported {comp_type[:-1]} without permission protection"
                    })

        # Debuggable
        if manifest_data.get("debuggable"):
            indicators.append({
                "type": "debuggable",
                "severity": "low",
                "description": "Application is debuggable"
            })

        # Allow backup
        if manifest_data.get("allow_backup"):
            indicators.append({
                "type": "allow_backup",
                "severity": "low",
                "description": "Application allows backup (data extraction)"
            })

        # Native code
        if "System.loadLibrary" in text or "System.load(" in text:
            indicators.append({
                "type": "native_code",
                "severity": "info",
                "description": "Application loads native libraries"
            })

        # Reflection
        if any(p in text for p in ["Class.forName", "Method.invoke", "Field.set"]):
            indicators.append({
                "type": "reflection",
                "severity": "medium",
                "description": "Heavy reflection usage detected"
            })

        # Dynamic loading
        if any(p in text for p in ["DexClassLoader", "PathClassLoader", "InMemoryDexClassLoader"]):
            indicators.append({
                "type": "dynamic_loading",
                "severity": "high",
                "description": "Dynamic code loading capability"
            })

        return indicators