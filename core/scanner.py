"""
Main scanner orchestrator for APKStudioAI 2.1
Coordinates all analyzers: archive, manifest, DEX, Java, native, JNI, strings, permissions, behavior, network, malware, risk
"""
import os
import json
import hashlib
import shutil
import tempfile
import threading
import time
from pathlib import Path
from typing import Dict, List, Any, Optional, Callable
from datetime import datetime

from .archive_analyzer import ArchiveAnalyzer
from .manifest_analyzer import ManifestAnalyzer
from .dex_analyzer import DexAnalyzer
from .jadx_engine import JadxEngine
from .apktool_engine import ApktoolEngine
from .native_analyzer import NativeAnalyzer
from .string_analyzer import StringAnalyzer
from .permission_analyzer import PermissionAnalyzer
from .behavior_analyzer import BehaviorAnalyzer
from .network_analyzer import NetworkAnalyzer
from .malware_detector import MalwareDetector
from .risk_engine import RiskEngine
from .ollama_client import OllamaClient
from .utils import run_command, calculate_sha256, safe_extract_zip, ProgressTracker


class APKScanner:
    def __init__(self, config: Dict[str, Any] = None, progress_callback: Callable = None):
        self.config = config or {}
        self.progress_callback = progress_callback
        self.tracker = ProgressTracker(progress_callback)

        # Initialize analyzers
        self.archive_analyzer = ArchiveAnalyzer()
        self.manifest_analyzer = ManifestAnalyzer(self.config.get("tools", {}))
        self.dex_analyzer = DexAnalyzer(self.config.get("tools", {}))
        self.jadx_engine = JadxEngine(self.config.get("tools", {}))
        self.apktool_engine = ApktoolEngine(self.config.get("tools", {}))
        self.native_analyzer = NativeAnalyzer()
        self.string_analyzer = StringAnalyzer()
        self.permission_analyzer = PermissionAnalyzer()
        self.behavior_analyzer = BehaviorAnalyzer()
        self.network_analyzer = NetworkAnalyzer()
        self.malware_detector = MalwareDetector()
        self.risk_engine = RiskEngine()
        self.ollama_client = OllamaClient(self.config.get("ollama", {}))

        # State
        self.extract_dir = None
        self.apk_path = None
        self.cancelled = False

    def _update_progress(self, stage: str, percent: int, message: str = ""):
        """Update progress via callback."""
        if self.progress_callback:
            self.progress_callback(stage, percent, message)
        self.tracker.update(stage, percent, message)

    def scan(self, apk_path: str, no_ai: bool = False) -> Dict[str, Any]:
        """Perform complete APK scan."""
        self.apk_path = Path(apk_path)
        self.cancelled = False

        if no_ai:
            self.ollama_client.no_ai_mode = True

        # Initialize result structure
        result = {
            "apk_path": str(self.apk_path),
            "scan_time": datetime.now().isoformat(),
            "sha256": "",
            "manifest": {},
            "permissions": [],
            "dex": {},
            "java": {},
            "smali": {},
            "native": {},
            "jni": {},
            "strings": {},
            "behavior": {},
            "network": {},
            "malware": {},
            "risk": {},
            "ai_analysis": {},
            "errors": [],
            "warnings": []
        }

        try:
            # Stage 1: Archive analysis & SHA256
            self._update_progress("archive", 5, "Analyzing APK archive...")
            result["sha256"] = calculate_sha256(self.apk_path)
            archive_result = self.archive_analyzer.analyze(self.apk_path)
            result["archive"] = archive_result
            if archive_result.get("errors"):
                result["errors"].extend(archive_result["errors"])
            if archive_result.get("warnings"):
                result["warnings"].extend(archive_result["warnings"])

            if self.cancelled:
                return result

            # Stage 2: Extract APK
            self._update_progress("extract", 10, "Extracting APK...")
            self.extract_dir = self._extract_apk()
            if not self.extract_dir:
                result["errors"].append("Failed to extract APK")
                return result

            if self.cancelled:
                return result

            # Stage 3: Manifest analysis
            self._update_progress("manifest", 20, "Analyzing AndroidManifest.xml...")
            manifest_result = self.manifest_analyzer.analyze(self.apk_path, self.extract_dir)
            result["manifest"] = manifest_result
            result["permissions"] = manifest_result.get("permissions", [])

            if self.cancelled:
                return result

            # Stage 4: DEX analysis
            self._update_progress("dex", 30, "Analyzing DEX files...")
            dex_result = self.dex_analyzer.analyze(self.apk_path, self.extract_dir)
            result["dex"] = dex_result

            if self.cancelled:
                return result

            # Stage 5: Java decompilation (JADX)
            self._update_progress("jadx", 40, "Decompiling with JADX...")
            jadx_result = self.jadx_engine.decompile(self.apk_path, self.extract_dir)
            result["java"] = jadx_result

            if self.cancelled:
                return result

            # Stage 6: Smali analysis (Apktool)
            self._update_progress("smali", 50, "Analyzing Smali with Apktool...")
            apktool_result = self.apktool_engine.decode(self.apk_path, self.extract_dir)
            result["smali"] = apktool_result

            if self.cancelled:
                return result

            # Stage 7: Native library analysis
            self._update_progress("native", 60, "Analyzing native libraries...")
            native_result = self.native_analyzer.analyze(self.extract_dir)
            result["native"] = native_result

            if self.cancelled:
                return result

            # Stage 8: JNI analysis
            self._update_progress("jni", 65, "Analyzing JNI...")
            jni_result = self._analyze_jni(native_result, jadx_result)
            result["jni"] = jni_result

            if self.cancelled:
                return result

            # Stage 9: String analysis
            self._update_progress("strings", 70, "Analyzing strings...")
            strings_result = self.string_analyzer.analyze(self.extract_dir)
            result["strings"] = strings_result

            if self.cancelled:
                return result

            # Stage 10: Permission analysis
            self._update_progress("permissions", 75, "Analyzing permissions...")
            perm_result = self.permission_analyzer.analyze(result["permissions"])
            result["permission_analysis"] = perm_result

            if self.cancelled:
                return result

            # Stage 11: Behavior analysis
            self._update_progress("behavior", 80, "Analyzing behaviors...")
            behavior_result = self.behavior_analyzer.analyze(
                result.get("raw_findings", []),
                strings_result.get("all_strings", []),
                manifest_result,
                jadx_result.get("classes", []),
                native_result.get("libraries", [])
            )
            result["behavior"] = behavior_result

            if self.cancelled:
                return result

            # Stage 12: Network analysis
            self._update_progress("network", 85, "Analyzing network IOCs...")
            network_result = self.network_analyzer.analyze(
                strings_result.get("all_strings", []),
                manifest_result,
                jadx_result.get("classes", []),
                native_result.get("libraries", []),
                strings_result.get("decoded_strings", [])
            )
            result["network"] = network_result

            if self.cancelled:
                return result

            # Stage 13: Malware detection
            self._update_progress("malware", 90, "Running malware detection...")
            malware_result = self.malware_detector.detect({
                "permissions": result["permissions"],
                "behavior": behavior_result,
                "network": network_result,
                "strings": strings_result,
                "manifest": manifest_result,
                "native": native_result,
                "dex": dex_result,
                "raw_findings": result.get("raw_findings", [])
            })
            result["malware"] = malware_result

            if self.cancelled:
                return result

            # Stage 14: Risk scoring
            self._update_progress("risk", 95, "Calculating risk score...")
            risk_result = self.risk_engine.calculate({
                "permissions": result["permissions"],
                "behavior": behavior_result,
                "network": network_result,
                "strings": strings_result,
                "manifest": manifest_result,
                "native": native_result,
                "malware": malware_result,
                "permission_analysis": perm_result
            })
            result["risk"] = risk_result

            if self.cancelled:
                return result

            # Stage 15: AI Analysis
            self._update_progress("ai", 98, "Running AI analysis...")
            ai_result = self.ollama_client.analyze(result)
            result["ai_analysis"] = ai_result

            self._update_progress("complete", 100, "Scan complete!")

        except Exception as e:
            result["errors"].append(f"Scan error: {str(e)}")
            import traceback
            result["errors"].append(traceback.format_exc())
        finally:
            # Cleanup
            if self.extract_dir and self.extract_dir.exists():
                try:
                    shutil.rmtree(self.extract_dir)
                except Exception:
                    pass

        return result

    def _extract_apk(self) -> Optional[Path]:
        """Extract APK to temporary directory."""
        try:
            temp_dir = Path(tempfile.mkdtemp(prefix="apkstudio_"))
            success = safe_extract_zip(self.apk_path, temp_dir)
            if success:
                return temp_dir
            else:
                shutil.rmtree(temp_dir, ignore_errors=True)
                return None
        except Exception:
            return None

    def _analyze_jni(self, native_result: Dict, jadx_result: Dict) -> Dict[str, Any]:
        """Analyze JNI for all native libraries."""
        jni_results = []
        java_classes = jadx_result.get("classes", [])

        for lib in native_result.get("libraries", []):
            lib_path = Path(lib.get("path", ""))
            if lib_path.exists():
                # Import JNIAnalyzer here to avoid circular imports
                from .jni_analyzer import JNIAnalyzer
                jni_analyzer = JNIAnalyzer()
                jni_result = jni_analyzer.analyze(lib_path, java_classes)
                jni_results.append(jni_result)

        return {"libraries": jni_results}

    def cancel(self):
        """Cancel ongoing scan."""
        self.cancelled = True

    def batch_scan(self, directory: str, no_ai: bool = False) -> List[Dict[str, Any]]:
        """Scan all APKs in a directory."""
        results = []
        apk_files = list(Path(directory).rglob("*.apk"))

        for i, apk_file in enumerate(apk_files):
            self._update_progress("batch", int((i / len(apk_files)) * 100),
                                  f"Scanning {apk_file.name} ({i+1}/{len(apk_files)})")
            result = self.scan(str(apk_file), no_ai=no_ai)
            results.append(result)

        return results


def main():
    """CLI entry point."""
    import argparse
    parser = argparse.ArgumentParser(description="APKStudioAI 2.1 - Android Malware Analyzer")
    parser.add_argument("apk", nargs="?", help="Path to APK file")
    parser.add_argument("--batch", help="Batch scan directory")
    parser.add_argument("--no-ai", action="store_true", help="Disable AI analysis")
    parser.add_argument("--json", action="store_true", help="Output JSON")
    parser.add_argument("--output", help="Output file path")
    parser.add_argument("--config", help="Config file path")

    args = parser.parse_args()

    # Load config
    config = {}
    if args.config and Path(args.config).exists():
        with open(args.config) as f:
            config = json.load(f)

    # Progress callback
    def progress(stage, percent, message):
        print(f"[{percent:3d}%] {stage}: {message}")

    scanner = APKScanner(config, progress_callback=progress)

    if args.batch:
        results = scanner.batch_scan(args.batch, no_ai=args.no_ai)
        output_data = {"batch_results": results}
    elif args.apk:
        result = scanner.scan(args.apk, no_ai=args.no_ai)
        output_data = result
    else:
        parser.print_help()
        return

    # Output
    if args.json:
        output = json.dumps(output_data, indent=2, default=str)
    else:
        output = format_text_output(output_data)

    if args.output:
        with open(args.output, "w") as f:
            f.write(output)
        print(f"Results saved to {args.output}")
    else:
        print(output)


def format_text_output(data: Dict) -> str:
    """Format results as text."""
    lines = []
    lines.append("=" * 60)
    lines.append("APKStudioAI 2.1 - Analysis Report")
    lines.append("=" * 60)
    lines.append(f"APK: {data.get('apk_path', 'N/A')}")
    lines.append(f"SHA256: {data.get('sha256', 'N/A')}")
    lines.append(f"Scan Time: {data.get('scan_time', 'N/A')}")
    lines.append("")

    # Risk
    risk = data.get("risk", {})
    lines.append(f"RISK SCORE: {risk.get('score', 0)}/100 ({risk.get('risk_level', 'UNKNOWN')})")
    lines.append(f"Summary: {risk.get('summary', {}).get('description', 'N/A')}")
    lines.append("")

    # Malware
    malware = data.get("malware", {})
    detections = malware.get("detections", [])
    if detections:
        lines.append("MALWARE DETECTIONS:")
        for det in detections[:5]:
            lines.append(f"  - {det['category'].upper()}: {det['classification']} ({det['confidence_score']}%)")
    else:
        lines.append("MALWARE DETECTIONS: None")
    lines.append("")

    # Permissions
    perm = data.get("permission_analysis", {})
    lines.append(f"PERMISSIONS: {perm.get('total_count', 0)} total")
    for level in ["critical", "high", "medium", "low"]:
        count = len(perm.get("by_risk", {}).get(level, []))
        if count:
            lines.append(f"  {level.capitalize()}: {count}")
    lines.append("")

    # Network
    net = data.get("network", {})
    lines.append(f"NETWORK IOCs: {len(net.get('urls', []))} URLs, {len(net.get('domains', []))} domains")
    if net.get("telegram_bots"):
        lines.append(f"  Telegram bots: {len(net['telegram_bots'])}")
    if net.get("c2_config"):
        lines.append(f"  C2 configs: {len(net['c2_config'])}")
    lines.append("")

    # Native
    native = data.get("native", {})
    lines.append(f"NATIVE LIBS: {len(native.get('libraries', []))}")
    for lib in native.get("libraries", [])[:3]:
        lines.append(f"  - {lib.get('name', 'unknown')}: {len(lib.get('native_methods', []))} JNI methods")
    lines.append("")

    # AI Analysis
    ai = data.get("ai_analysis", {})
    if ai.get("success"):
        analysis = ai.get("analysis", {})
        lines.append("AI ANALYSIS:")
        lines.append(f"  Category: {analysis.get('malware_category', 'unknown')}")
        lines.append(f"  Confidence: {analysis.get('confidence', 0)}%")
        lines.append(f"  Risk: {analysis.get('risk_level', 'UNKNOWN')}")
        lines.append(f"  Summary: {analysis.get('summary', 'N/A')}")
    else:
        lines.append(f"AI ANALYSIS: {ai.get('error', 'Not available')}")

    return "\n".join(lines)


if __name__ == "__main__":
    main()