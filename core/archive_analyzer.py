"""
Deep APK archive analysis for APKStudioAI 2.1
Detects: nested archives, hidden DEX, PNG append, encrypted entries, suspicious paths
"""
import zipfile
import re
import tempfile
import shutil
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from .utils import (
    printable_strings, printable_strings_utf16, sha256_file,
    safe_name, is_dex_file, format_size, safe_extract_zip
)
from .config_manager import get_config


class ArchiveAnalyzer:
    def __init__(self, max_extract_mb: int = 500, max_file_mb: int = 100, config: Dict = None):
        # Use config if provided, otherwise use parameters, otherwise use global config
        if config:
            analysis_config = config.get("analysis", {})
            self.max_extract_mb = analysis_config.get("max_total_extract_mb", max_extract_mb)
            self.max_file_mb = analysis_config.get("max_file_size_mb", max_file_mb)
        else:
            global_config = get_config()
            analysis_config = global_config.get("analysis", {})
            self.max_extract_mb = analysis_config.get("max_total_extract_mb", max_extract_mb)
            self.max_file_mb = analysis_config.get("max_file_size_mb", max_file_mb)

        self.max_total_bytes = self.max_extract_mb * 1024 * 1024
        self.max_file_bytes = self.max_file_mb * 1024 * 1024

    def analyze(self, apk_path: Path, extract_dir: Optional[Path] = None) -> Dict[str, Any]:
        """Perform complete archive analysis."""
        temp_dir_created = False
        if extract_dir is None:
            extract_dir = Path(tempfile.mkdtemp(prefix="apkstudio_archive_"))
            temp_dir_created = True

        findings = []
        inventory = {
            "dex": [], "native": [], "xml": [], "assets": [],
            "resources": [], "certificates": [], "other": []
        }
        manifest_bytes = b""
        encrypted_entries = []
        suspicious_paths = []
        nested_archives = []
        hidden_dex = []
        png_appended = []

        try:
            # First, use consolidated safe extraction
            extract_result = safe_extract_zip(
                apk_path, extract_dir,
                max_total_mb=self.max_extract_mb,
                max_file_mb=self.max_file_mb
            )

            if not extract_result["success"]:
                findings.append(self._make_finding(
                    "critical", "Archive", "Failed to extract APK",
                    extract_result["errors"][0] if extract_result["errors"] else "Unknown error",
                    "APK extraction failed."
                ))
                return {
                    "package": None,
                    "manifest_raw": "",
                    "manifest_strings": [],
                    "inventory": inventory,
                    "findings": findings,
                    "encrypted_entries": encrypted_entries,
                    "suspicious_paths": suspicious_paths,
                    "nested_archives": nested_archives,
                    "hidden_dex": hidden_dex,
                    "png_appended": png_appended,
                    "extracted_bytes": 0,
                    "sha256": "",
                    "errors": extract_result["errors"]
                }

            # Add extraction errors as findings
            for err in extract_result["errors"]:
                findings.append(self._make_finding(
                    "info", "Extraction", "Extraction warning",
                    err,
                    "File may be encrypted, corrupted, or use unsupported compression."
                ))

            # Now analyze the extracted files and the ZIP structure
            try:
                with zipfile.ZipFile(apk_path) as zf:
                    # Test ZIP integrity
                    try:
                        bad = zf.testzip()
                        if bad:
                            findings.append(self._make_finding(
                                "medium", "Archive", "Encrypted or corrupted ZIP entry",
                                f"testzip() flagged: {bad}",
                                "Entry may be encrypted, compressed with unsupported method, or damaged. "
                                "Analysis continues on readable entries."
                            ))
                            encrypted_entries.append(bad)
                    except Exception as exc:
                        findings.append(self._make_finding(
                            "info", "Archive", "Partial ZIP verification",
                            str(exc),
                            "ZIP structure has issues but analysis continues on accessible entries."
                        ))

                    # Analyze each entry
                    for info in zf.infolist():
                        name = info.filename
                        if info.is_dir():
                            continue

                        low = name.lower()
                        size = info.file_size

                        # Categorize
                        if name == "AndroidManifest.xml":
                            try:
                                manifest_bytes = zf.read(info)
                            except Exception:
                                pass
                        elif low.endswith(".dex"):
                            inventory["dex"].append({"name": name, "size": size, "crc32": info.CRC})
                        elif low.endswith(".so"):
                            inventory["native"].append({"name": name, "size": size, "crc32": info.CRC})
                        elif low.endswith(".xml"):
                            inventory["xml"].append({"name": name, "size": size, "crc32": info.CRC})
                        elif name.startswith("assets/"):
                            inventory["assets"].append({"name": name, "size": size, "crc32": info.CRC})
                        elif name.startswith("res/") or name.startswith("resources.arsc"):
                            inventory["resources"].append({"name": name, "size": size, "crc32": info.CRC})
                        elif low.endswith((".rsa", ".dsa", ".ec", ".sf", ".mf")):
                            inventory["certificates"].append({"name": name, "size": size, "crc32": info.CRC})
                        else:
                            inventory["other"].append({"name": name, "size": size, "crc32": info.CRC})

                        # Detect suspicious paths (path traversal, absolute, etc.)
                        if self._is_suspicious_path(name):
                            suspicious_paths.append(name)
                            findings.append(self._make_finding(
                                "high", "Archive", "Suspicious ZIP entry path",
                                name,
                                "Path contains traversal sequences or unusual patterns. "
                                "Could indicate ZIP slip attempt or obfuscation."
                            ))

                        # Detect nested archives
                        if low.endswith((".zip", ".jar", ".apk", ".aar")) and name != apk_path.name:
                            nested_archives.append(name)
                            findings.append(self._make_finding(
                                "medium", "Archive", "Nested archive detected",
                                name,
                                "APK contains another archive. May hide additional DEX or resources."
                            ))

                        # Detect hidden DEX (non-standard names)
                        if self._is_hidden_dex(name, low):
                            hidden_dex.append(name)
                            findings.append(self._make_finding(
                                "medium", "Archive", "Potential hidden DEX file",
                                name,
                                "DEX file with non-standard naming. May be loaded dynamically via DexClassLoader."
                            ))

                        # Check for PNG with appended data in extracted files
                        if low.endswith(".png"):
                            target = extract_dir / name
                            if target.exists() and self._has_appended_data(target):
                                png_appended.append(name)
                                findings.append(self._make_finding(
                                    "medium", "Archive", "PNG with appended data",
                                    name,
                                    "PNG file contains extra bytes after IEND chunk. May hide payload."
                                ))

            except Exception as e:
                findings.append(self._make_finding(
                    "critical", "Archive", "Failed to open APK file",
                    str(e),
                    "APK file not found or not a valid ZIP archive."
                ))
                return {
                    "package": None,
                    "manifest_raw": "",
                    "manifest_strings": [],
                    "inventory": inventory,
                    "findings": findings,
                    "encrypted_entries": encrypted_entries,
                    "suspicious_paths": suspicious_paths,
                    "nested_archives": nested_archives,
                    "hidden_dex": hidden_dex,
                    "png_appended": png_appended,
                    "extracted_bytes": extract_result["extracted_bytes"],
                    "sha256": "",
                    "errors": [str(e)]
                }

            # Analyze manifest
            manifest_text, manifest_strings = self._analyze_manifest(manifest_bytes)

            return {
                "package": self._extract_package(manifest_text),
                "manifest_raw": manifest_text[:50000],
                "manifest_strings": manifest_strings[:1000],
                "inventory": inventory,
                "findings": findings,
                "encrypted_entries": encrypted_entries,
                "suspicious_paths": suspicious_paths,
                "nested_archives": nested_archives,
                "hidden_dex": hidden_dex,
                "png_appended": png_appended,
                "extracted_bytes": extract_result["extracted_bytes"],
                "sha256": sha256_file(apk_path)
            }
        except Exception as e:
            # Handle case where APK file doesn't exist or can't be opened
            findings.append(self._make_finding(
                "critical", "Archive", "Failed to open APK file",
                str(e),
                "APK file not found or not a valid ZIP archive."
            ))
            return {
                "package": None,
                "manifest_raw": "",
                "manifest_strings": [],
                "inventory": inventory,
                "findings": findings,
                "encrypted_entries": encrypted_entries,
                "suspicious_paths": suspicious_paths,
                "nested_archives": nested_archives,
                "hidden_dex": hidden_dex,
                "png_appended": png_appended,
                "extracted_bytes": 0,
                "sha256": "",
                "errors": [str(e)]
            }
        finally:
            # Clean up temp directory if we created it
            if temp_dir_created and extract_dir.exists():
                try:
                    shutil.rmtree(extract_dir, ignore_errors=True)
                except Exception:
                    pass

    def _make_finding(self, severity: str, category: str, title: str,
                      evidence: str, interpretation: str) -> Dict[str, Any]:
        return {
            "severity": severity,
            "category": category,
            "title": title,
            "evidence": evidence,
            "interpretation": interpretation
        }

    def _is_suspicious_path(self, name: str) -> bool:
        """Detect path traversal and suspicious patterns."""
        # Path traversal
        if ".." in name or name.startswith("/") or name.startswith("\\"):
            return True
        # Absolute paths
        if re.match(r"^[A-Za-z]:[\\/]", name):
            return True
        # Null bytes
        if "\x00" in name:
            return True
        # Very long paths
        if len(name) > 260:
            return True
        return False

    def _is_hidden_dex(self, name: str, low: str) -> bool:
        """Detect DEX files with non-standard names."""
        standard_dex = {"classes.dex", "classes2.dex", "classes3.dex"}
        if low.endswith(".dex") and name not in standard_dex:
            return True
        # DEX with different extension but DEX magic
        return False  # Would need to read file to confirm

    def _has_appended_data(self, png_path: Path) -> bool:
        """Check if PNG has data after IEND chunk."""
        try:
            with open(png_path, "rb") as f:
                data = f.read()
            # Find IEND chunk (0x00 0x00 0x00 0x00 0x49 0x45 0x4E 0x44 0xAE 0x42 0x60 0x82)
            iend_pos = data.find(b"IEND")
            if iend_pos > 0:
                # IEND chunk is 12 bytes: length(4) + type(4) + CRC(4)
                after_iend = iend_pos + 12
                if after_iend < len(data):
                    return True
        except Exception:
            pass
        return False

    def _analyze_manifest(self, manifest_bytes: bytes) -> Tuple[str, List[str]]:
        """Extract strings from binary XML manifest."""
        if not manifest_bytes:
            return "", []

        # Try UTF-8
        text = manifest_bytes.decode("utf-8", errors="ignore")

        # Extract UTF-16LE strings
        strings = set(printable_strings(manifest_bytes, 4))
        strings.update(printable_strings_utf16(manifest_bytes, 4))

        return text, sorted(strings)

    def _extract_package(self, manifest_text: str) -> Optional[str]:
        """Extract package name from manifest text."""
        import re
        match = re.search(r'package\s*=\s*["\']([^"\']+)', manifest_text)
        return match.group(1) if match else None