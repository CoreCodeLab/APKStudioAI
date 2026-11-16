"""
APKiD integration for APKStudioAI 2.1
Packer, obfuscator, and compiler detection
Uses APKiD 3.x programmatic API
"""
import json
import logging
import tempfile
import os
from pathlib import Path
from typing import Dict, List, Any, Optional, Set

logger = logging.getLogger(__name__)

try:
    from apkid.apkid import Scanner, RulesManager, Options
    import yara
    HAS_APKID = True
except ImportError:
    HAS_APKID = False
    Scanner = None
    RulesManager = None
    Options = None
    yara = None


class APKiDEngine:
    """Wrapper for APKiD 3.x packer/obfuscator detection."""

    def __init__(self, config: Dict = None):
        self.config = config
        self.available = HAS_APKID
        self._scanner = None
        self._rules_manager = None

    def _get_scanner(self):
        """Get or create APKiD scanner."""
        if self._scanner is None and self.available:
            try:
                self._rules_manager = RulesManager(include_trackers=True)
                yara_rules = self._rules_manager.load()  # Load compiled yara rules
                options = Options(json=True, timeout=30, include_trackers=True)
                self._scanner = Scanner(yara_rules, options)
            except Exception as e:
                logger.warning(f"Failed to initialize APKiD scanner: {e}")
                self.available = False
        return self._scanner

    def analyze(self, apk_path: Path) -> Dict[str, Any]:
        """Run APKiD analysis on APK or DEX file."""
        if not self.available:
            return {"error": "APKiD not available", "available": False}

        scanner = self._get_scanner()
        if not scanner:
            return {"error": "Failed to initialize APKiD scanner", "available": True}

        try:
            # Scan the file - returns Dict[str, List[yara.Match]]
            results = scanner.scan_file(str(apk_path))
            return self._normalize_results(results, str(apk_path))

        except Exception as e:
            logger.error(f"APKiD analysis failed: {e}")
            return {"error": str(e), "available": True}

    def analyze_dex(self, dex_path: Path) -> Dict[str, Any]:
        """Analyze a single DEX file."""
        return self.analyze(dex_path)

    def analyze_bytes(self, data: bytes, filename: str = "sample.dex") -> Dict[str, Any]:
        """Analyze DEX/APK bytes directly."""
        if not self.available:
            return {"error": "APKiD not available", "available": False}

        scanner = self._get_scanner()
        if not scanner:
            return {"error": "Failed to initialize APKiD scanner", "available": True}

        try:
            # Create a temporary file for scanning
            with tempfile.NamedTemporaryFile(suffix='.dex', delete=False) as tmp:
                tmp.write(data)
                tmp_path = tmp.name

            try:
                results = scanner.scan_file(tmp_path)
                return self._normalize_results(results, filename)
            finally:
                os.unlink(tmp_path)

        except Exception as e:
            logger.error(f"APKiD bytes analysis failed: {e}")
            return {"error": str(e), "available": True}

    def _normalize_results(self, data: Dict[str, List], file_path: str) -> Dict[str, Any]:
        """Normalize APKiD results into structured format.
        APKiD 3.x returns Dict[str, List[yara.Match]] where key is file path
        """
        result = {
            "available": True,
            "packers": [],
            "obfuscators": [],
            "compilers": [],
            "anti_analysis": [],
            "suspicious_indicators": [],
            "files_analyzed": 0,
            "raw_matches": []
        }

        # data is Dict[str, List[yara.Match]] where keys are file paths (for zip entries)
        result["files_analyzed"] = len(data)

        for fp, matches in data.items():
            for match in matches:
                # yara.Match has: rule, namespace, tags, meta, strings
                rule_name = match.rule
                meta = match.meta if hasattr(match, 'meta') else {}

                match_info = {
                    "file": fp,
                    "rule": rule_name,
                    "description": meta.get("description", ""),
                    "category": meta.get("category", ""),
                    "confidence": meta.get("confidence", "unknown")
                }
                result["raw_matches"].append(match_info)

                # Categorize by category from meta
                category = meta.get("category", "").lower()
                rule_lower = rule_name.lower()

                if "packer" in category or "packer" in rule_lower:
                    result["packers"].append(match_info)
                elif "obfuscator" in category or "obfuscator" in rule_lower:
                    result["obfuscators"].append(match_info)
                elif "compiler" in category or "compiler" in rule_lower:
                    result["compilers"].append(match_info)
                elif "anti" in category or "anti" in rule_lower or "debug" in rule_lower or "emulator" in rule_lower:
                    result["anti_analysis"].append(match_info)
                else:
                    result["suspicious_indicators"].append(match_info)

        # Deduplicate
        for key in ["packers", "obfuscators", "compilers", "anti_analysis", "suspicious_indicators"]:
            seen: Set[str] = set()
            unique = []
            for item in result[key]:
                key_str = f"{item['file']}:{item['rule']}"
                if key_str not in seen:
                    seen.add(key_str)
                    unique.append(item)
            result[key] = unique

        # Summary
        result["summary"] = {
            "packers_found": len(result["packers"]),
            "obfuscators_found": len(result["obfuscators"]),
            "compilers_found": len(result["compilers"]),
            "anti_analysis_found": len(result["anti_analysis"]),
            "suspicious_indicators": len(result["suspicious_indicators"]),
            "is_packed": len(result["packers"]) > 0,
            "is_obfuscated": len(result["obfuscators"]) > 0,
            "has_anti_analysis": len(result["anti_analysis"]) > 0
        }

        return result


def get_apkid_engine(config: Dict = None) -> APKiDEngine:
    """Factory function for APKiDEngine."""
    return APKiDEngine(config)