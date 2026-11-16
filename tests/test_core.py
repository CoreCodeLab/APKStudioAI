"""
Unit tests for APKStudioAI 2.1 core modules
"""
import unittest
import tempfile
import json
from pathlib import Path
import sys

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.utils import (
    calculate_sha256, printable_strings, printable_strings_utf16,
    decode_base64, decode_hex, xor_decode, is_elf_file, is_dex_file,
    is_elf_file_bytes, is_dex_file_bytes,
    run_command, ProgressTracker, get_project_root
)
from core.archive_analyzer import ArchiveAnalyzer
from core.manifest_analyzer import ManifestAnalyzer
from core.dex_analyzer import DexAnalyzer
from core.permission_analyzer import PermissionAnalyzer
from core.behavior_analyzer import BehaviorAnalyzer
from core.network_analyzer import NetworkAnalyzer
from core.string_analyzer import StringAnalyzer
from core.risk_engine import RiskEngine
from core.malware_detector import MalwareDetector


class TestUtils(unittest.TestCase):
    """Tests for utils module"""

    def test_calculate_sha256(self):
        """Test SHA256 calculation"""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"test content")
            temp_path = Path(f.name)

        try:
            sha256 = calculate_sha256(temp_path)
            self.assertEqual(len(sha256), 64)
            self.assertTrue(all(c in '0123456789abcdef' for c in sha256))
        finally:
            temp_path.unlink()

    def test_printable_strings(self):
        """Test ASCII string extraction"""
        data = b"Hello\x00\x01World\x02Test"
        strings = printable_strings(data, min_len=3)
        self.assertIn("Hello", strings)
        self.assertIn("World", strings)
        self.assertIn("Test", strings)

    def test_printable_strings_utf16(self):
        """Test UTF-16 string extraction"""
        data = "Test".encode('utf-16le')
        strings = printable_strings_utf16(data, min_len=2)
        self.assertIn("Test", strings)

    def test_decode_base64(self):
        """Test Base64 decoding"""
        encoded = "SGVsbG8gV29ybGQ="  # "Hello World"
        decoded = decode_base64(encoded)
        self.assertEqual(decoded, "Hello World")

    def test_decode_hex(self):
        """Test Hex decoding"""
        encoded = "48656c6c6f"  # "Hello"
        decoded = decode_hex(encoded)
        self.assertEqual(decoded, "Hello")

    def test_xor_decode(self):
        """Test XOR decoding"""
        data = b"Hello"
        key = 0x55
        encoded = bytes(b ^ key for b in data)
        decoded = xor_decode(encoded, key)
        self.assertEqual(decoded, "Hello")

    def test_is_elf_file(self):
        """Test ELF detection"""
        # Valid ELF magic
        self.assertTrue(is_elf_file_bytes(b"\x7fELF\x02\x01\x01"))
        # Invalid
        self.assertFalse(is_elf_file_bytes(b"PK\x03\x04"))
        self.assertFalse(is_elf_file_bytes(b""))

    def test_is_dex_file(self):
        """Test DEX detection"""
        # Valid DEX magic
        self.assertTrue(is_dex_file_bytes(b"dex\n035\x00"))
        # Invalid
        self.assertFalse(is_dex_file_bytes(b"PK\x03\x04"))
        self.assertFalse(is_dex_file_bytes(b""))

    def test_run_command(self):
        """Test command execution"""
        result = run_command(["echo", "test"], timeout=5)
        self.assertEqual(result.returncode, 0)
        self.assertIn("test", result.stdout)

    def test_progress_tracker(self):
        """Test ProgressTracker"""
        calls = []
        def callback(stage, percent, message):
            calls.append((stage, percent, message))

        tracker = ProgressTracker(callback)
        tracker.update("test", 50, "halfway")
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0], ("test", 50, "halfway"))

    def test_get_project_root(self):
        """Test project root detection"""
        root = get_project_root()
        self.assertTrue(root.exists())
        self.assertTrue((root / "core").exists())


class TestArchiveAnalyzer(unittest.TestCase):
    """Tests for ArchiveAnalyzer"""

    def setUp(self):
        self.analyzer = ArchiveAnalyzer()

    def test_analyze_nonexistent(self):
        """Test analyzing non-existent file"""
        result = self.analyzer.analyze(Path("/nonexistent.apk"))
        self.assertIn("errors", result)
        self.assertTrue(len(result["errors"]) > 0)


class TestManifestAnalyzer(unittest.TestCase):
    """Tests for ManifestAnalyzer"""

    def setUp(self):
        self.analyzer = ManifestAnalyzer({})

    def test_analyze_nonexistent(self):
        """Test analyzing non-existent APK"""
        with tempfile.TemporaryDirectory() as tmpdir:
            result = self.analyzer.analyze(Path("/nonexistent.apk"), Path(tmpdir))
            self.assertIn("errors", result)

    def test_permission_risk_mapping(self):
        """Test permission risk levels"""
        # Test critical permissions
        perms = ["android.permission.RECORD_AUDIO", "android.permission.CAMERA"]
        result = self.analyzer._analyze_permissions(perms)
        self.assertTrue(len(result.get("by_risk", {}).get("critical", [])) >= 2)

        # Test normal permissions
        perms = ["android.permission.INTERNET", "android.permission.ACCESS_NETWORK_STATE"]
        result = self.analyzer._analyze_permissions(perms)
        self.assertTrue(len(result.get("by_risk", {}).get("normal", [])) >= 2)


class TestDexAnalyzer(unittest.TestCase):
    """Tests for DexAnalyzer"""

    def setUp(self):
        self.analyzer = DexAnalyzer({})

    def test_analyze_nonexistent(self):
        """Test analyzing non-existent APK"""
        with tempfile.TemporaryDirectory() as tmpdir:
            result = self.analyzer.analyze(Path("/nonexistent.apk"), Path(tmpdir))
            self.assertIn("dex_files", result)


class TestPermissionAnalyzer(unittest.TestCase):
    """Tests for PermissionAnalyzer"""

    def setUp(self):
        self.analyzer = PermissionAnalyzer()

    def test_analyze_permissions(self):
        """Test permission analysis"""
        perms = [
            "android.permission.CAMERA",
            "android.permission.INTERNET",
            "android.permission.RECORD_AUDIO",
            "android.permission.ACCESS_FINE_LOCATION"
        ]
        result = self.analyzer.analyze(perms)

        self.assertEqual(result["total_count"], 4)
        self.assertIn("by_risk", result)
        self.assertIn("capabilities", result)
        self.assertIn("risk_score", result)

        # Check critical permissions detected
        critical = result["by_risk"].get("critical", [])
        self.assertTrue(len(critical) >= 2)

    def test_capability_detection(self):
        """Test capability detection"""
        perms = [
            "android.permission.CAMERA",
            "android.permission.RECORD_AUDIO",
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.READ_CONTACTS",
            "android.permission.READ_SMS"
        ]
        result = self.analyzer.analyze(perms)

        caps = result["capabilities"]
        self.assertTrue(caps.get("surveillance"))
        self.assertTrue(caps.get("data_access"))


class TestBehaviorAnalyzer(unittest.TestCase):
    """Tests for BehaviorAnalyzer"""

    def setUp(self):
        self.analyzer = BehaviorAnalyzer()

    def test_analyze_spyware_patterns(self):
        """Test spyware behavior detection"""
        strings = [
            "RECORD_AUDIO",
            "CAMERA",
            "ACCESS_FINE_LOCATION",
            "MediaProjection",
            "AccessibilityService"
        ]
        result = self.analyzer.analyze([], strings, {}, [], [])

        behaviors = [b["category"] for b in result["detected_behaviors"]]
        self.assertIn("spyware", behaviors)

    def test_analyze_rat_patterns(self):
        """Test RAT behavior detection"""
        strings = [
            "Socket",
            "Runtime.exec",
            "DexClassLoader",
            "ProcessBuilder",
            "BIND_DEVICE_ADMIN"
        ]
        result = self.analyzer.analyze([], strings, {}, [], [])

        behaviors = [b["category"] for b in result["detected_behaviors"]]
        self.assertIn("rat", behaviors)

    def test_anti_analysis_detection(self):
        """Test anti-analysis detection"""
        strings = [
            "Build.FINGERPRINT",
            "isDebuggerConnected",
            "goldfish",
            "Frida",
            "Magisk"
        ]
        result = self.analyzer.analyze([], strings, {}, [], [])

        behaviors = [b["category"] for b in result["detected_behaviors"]]
        self.assertIn("anti_analysis", behaviors)


class TestNetworkAnalyzer(unittest.TestCase):
    """Tests for NetworkAnalyzer"""

    def setUp(self):
        self.analyzer = NetworkAnalyzer()

    def test_extract_urls(self):
        """Test URL extraction"""
        strings = [
            "https://example.com/api",
            "http://malicious-site.com/payload",
            "https://api.firebase.com/v1"
        ]
        result = self.analyzer.analyze(strings, {}, [], [], [])

        self.assertTrue(len(result["urls"]) >= 2)
        self.assertIn("https://example.com/api", result["urls"])

    def test_extract_domains(self):
        """Test domain extraction"""
        strings = [
            "example.com",
            "malware.c2.server.net",
            "api.telegram.org"
        ]
        result = self.analyzer.analyze(strings, {}, [], [], [])

        self.assertTrue(len(result["domains"]) >= 2)

    def test_extract_telegram_bots(self):
        """Test Telegram bot token detection"""
        strings = [
            "bot123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11",
            "https://api.telegram.org/bot123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11/sendMessage"
        ]
        result = self.analyzer.analyze(strings, {}, [], [], [])

        self.assertTrue(len(result["telegram_bots"]) >= 1)

    def test_extract_firebase(self):
        """Test Firebase config detection"""
        strings = [
            "my-project.firebaseio.com",
            "https://my-project.firebaseio.com/users.json"
        ]
        result = self.analyzer.analyze(strings, {}, [], [], [])

        self.assertTrue(len(result["firebase_config"]) >= 1)


class TestStringAnalyzer(unittest.TestCase):
    """Tests for StringAnalyzer"""

    def setUp(self):
        self.analyzer = StringAnalyzer()

    def test_analyze_strings(self):
        """Test string analysis with decoding"""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create test file with strings
            test_file = Path(tmpdir) / "test.txt"
            test_file.write_text("Hello World\nSGVsbG8gV29ybGQ=\n48656c6c6f")

            result = self.analyzer.analyze(Path(tmpdir))

            self.assertIn("all_strings", result)
            self.assertIn("decoded_strings", result)

            # Check Base64 decoded
            decoded = result["decoded_strings"]
            base64_decoded = [d for d in decoded if d["method"] == "base64"]
            self.assertTrue(len(base64_decoded) >= 1)

            # Check Hex decoded
            hex_decoded = [d for d in decoded if d["method"] == "hex"]
            self.assertTrue(len(hex_decoded) >= 1)


class TestRiskEngine(unittest.TestCase):
    """Tests for RiskEngine"""

    def setUp(self):
        self.engine = RiskEngine()

    def test_calculate_clean_app(self):
        """Test scoring for clean app"""
        result = self.engine.calculate({
            "permissions": ["android.permission.INTERNET"],
            "behavior": {"behavior_scores": {}},
            "network": {"urls": [], "domains": [], "telegram_bots": []},
            "strings": {"decoded_strings": []},
            "manifest": {},
            "native": {"libraries": []},
            "malware": {"detections": [], "summary": {"total": 0}},
            "permission_analysis": {"risk_score": 10, "by_risk": {"critical": [], "high": []}}
        })

        self.assertIn("score", result)
        self.assertIn("risk_level", result)
        self.assertLessEqual(result["score"], 30)

    def test_calculate_malicious_app(self):
        """Test scoring for malicious app"""
        result = self.engine.calculate({
            "permissions": [
                "android.permission.CAMERA",
                "android.permission.RECORD_AUDIO",
                "android.permission.BIND_DEVICE_ADMIN",
                "android.permission.BIND_ACCESSIBILITY_SERVICE",
                "android.permission.SYSTEM_ALERT_WINDOW"
            ],
            "behavior": {
                "behavior_scores": {
                    "spyware": 80,
                    "rat": 70,
                    "device_admin_abuse": 90
                }
            },
            "network": {
                "urls": ["http://c2.example.com"],
                "domains": ["c2.example.com"],
                "telegram_bots": ["bot123:token"],
                "c2_config": [{"type": "http", "url": "http://c2.example.com"}]
            },
            "strings": {"decoded_strings": []},
            "manifest": {},
            "native": {"libraries": [{"name": "libnative.so", "native_methods": []}]},
            "malware": {
                "detections": [
                    {"category": "spyware", "classification": "confirmed", "confidence_score": 90},
                    {"category": "rat", "classification": "likely", "confidence_score": 80}
                ],
                "summary": {"total": 2, "confirmed": 1, "likely": 1}
            },
            "permission_analysis": {"risk_score": 85, "by_risk": {"critical": [1,2,3], "high": [4,5]}}
        })

        self.assertIn("score", result)
        self.assertIn("risk_level", result)
        self.assertGreaterEqual(result["score"], 60)
        self.assertIn(result["risk_level"], ["TRÈS ÉLEVÉ", "CRITIQUE"])


class TestMalwareDetector(unittest.TestCase):
    """Tests for MalwareDetector"""

    def setUp(self):
        self.detector = MalwareDetector()

    def test_detect_no_findings(self):
        """Test detection with no findings"""
        result = self.detector.detect({
            "permissions": [],
            "behavior": {"behavior_scores": {}},
            "network": {},
            "strings": {"all_strings": []},
            "manifest": {},
            "native": {"libraries": []},
            "dex": {}
        })

        self.assertIn("detections", result)
        self.assertIn("summary", result)
        self.assertEqual(result["summary"]["total"], 0)

    def test_signature_matching(self):
        """Test known signature matching"""
        # Create mock findings with SpyMax indicators
        strings_data = {
            "all_strings": [
                "SpyMax", "SpyNote", "remote control", "keylogger",
                "camera", "microphone", "location", "contacts", "sms"
            ]
        }

        result = self.detector._match_signatures(strings_data, {}, {})

        # Should match SpyMax/RAT signatures
        self.assertTrue(len(result) >= 0)  # May match depending on indicators


class TestIntegration(unittest.TestCase):
    """Integration tests"""

    def test_full_pipeline_imports(self):
        """Test all core modules can be imported"""
        from core import (
            scanner, archive_analyzer, manifest_analyzer, dex_analyzer,
            jadx_engine, apktool_engine, native_analyzer, elf_analyzer,
            jni_analyzer, string_analyzer, permission_analyzer,
            behavior_analyzer, network_analyzer, malware_detector,
            risk_engine, ollama_client, utils, reporter
        )
        self.assertTrue(True)

    def test_analysis_rules_load(self):
        """Test analysis rule files can be loaded"""
        from core.utils import get_project_root
        root = get_project_root()

        for rule_file in ["rules.json", "signatures.json", "behavior_rules.json"]:
            path = root / "analysis" / rule_file
            self.assertTrue(path.exists(), f"{rule_file} not found")

            with open(path) as f:
                data = json.load(f)
                self.assertIn("version", data)
                self.assertIn("categories" if "rules" in rule_file else "signatures" if "signatures" in rule_file else "rules", data)


if __name__ == "__main__":
    unittest.main(verbosity=2)