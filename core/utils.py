"""
Enhanced utilities for APKStudioAI 2.1
"""
import hashlib
import re
import json
import os
import base64
import binascii
from pathlib import Path
from typing import List, Dict, Any, Optional, Set, Tuple
from datetime import datetime


def calculate_sha256(path: Path, chunk_size: int = 1024 * 1024) -> str:
    """Calculate SHA256 hash of a file."""
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(chunk_size):
            digest.update(chunk)
    return digest.hexdigest()


# Alias for backwards compatibility
sha256_file = calculate_sha256


def safe_name(value: str) -> str:
    """Sanitize a string for use as a filename."""
    return re.sub(r"[^A-Za-z0-9._-]+", "_", value).strip("._") or "apk"


def printable_strings(data: bytes, min_len: int = 5) -> List[str]:
    """Extract printable ASCII strings from binary data."""
    found = []
    current = bytearray()
    for byte in data:
        if 32 <= byte <= 126:
            current.append(byte)
        else:
            if len(current) >= min_len:
                found.append(current.decode("ascii", errors="ignore"))
            current.clear()
    if len(current) >= min_len:
        found.append(current.decode("ascii", errors="ignore"))
    return found


def printable_strings_utf16(data: bytes, min_len: int = 5) -> List[str]:
    """Extract printable UTF-16LE strings from binary data."""
    found = []
    # Look for UTF-16LE patterns (ASCII char followed by null byte)
    pattern = rb"(?:[\x20-\x7e]\x00){" + str(min_len).encode() + rb",}"
    for match in re.finditer(pattern, data):
        try:
            decoded = match.group().decode("utf-16le", errors="ignore")
            if len(decoded) >= min_len:
                found.append(decoded)
        except Exception:
            pass
    return found


def decode_base64(data: str) -> str:
    """Try to decode base64 string. Returns decoded string or empty string on failure."""
    try:
        # Add padding if needed
        padding = 4 - (len(data) % 4) if len(data) % 4 else 0
        padded = data + ("=" * padding)
        decoded = base64.b64decode(padded, validate=True).decode("utf-8", errors="ignore")
        return decoded
    except Exception:
        return ""


def decode_hex(data: str) -> str:
    """Try to decode hex string. Returns decoded string or empty string on failure."""
    try:
        decoded = bytes.fromhex(data).decode("utf-8", errors="ignore")
        return decoded
    except Exception:
        return ""


def xor_decode(data: bytes | str, key: int = 0x55) -> str:
    """Try simple XOR decode. Returns decoded string or empty string on failure."""
    try:
        if isinstance(data, bytes):
            data = data.decode('latin-1')
        decoded = "".join(chr(ord(c) ^ key) for c in data)
        # Check if result looks like printable text
        if all(32 <= ord(c) <= 126 or c in '\n\r\t' for c in decoded):
            return decoded
        return ""
    except Exception:
        return ""


# Alias for backwards compatibility
decode_xor = xor_decode


def try_decode_string(encoded: str) -> Dict[str, Any]:
    """Try multiple decoding methods on a string. Returns dict with results."""
    results = {"original": encoded, "decoded": []}

    # Try base64
    decoded = decode_base64(encoded)
    if decoded and decoded != encoded:
        results["decoded"].append({"method": "base64", "result": decoded})

    # Try hex
    decoded = decode_hex(encoded)
    if decoded and decoded != encoded:
        results["decoded"].append({"method": "hex", "result": decoded})

    # Try common XOR keys
    for key in [0x55, 0xAA, 0xFF, 0x00, 0x33, 0xCC]:
        decoded = decode_xor(encoded, key)
        if decoded and decoded != encoded:
            results["decoded"].append({"method": f"xor_0x{key:02X}", "result": decoded})

    return results


def load_json(path: Path, default: Any = None) -> Any:
    """Load JSON file with error handling."""
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default


def save_json(path: Path, data: Any) -> bool:
    """Save JSON file with error handling."""
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        return True
    except Exception:
        return False


def format_size(size_bytes: int) -> str:
    """Format bytes as human-readable string."""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size_bytes < 1024:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.1f} TB"


def truncate(text: str, max_len: int = 5000) -> str:
    """Truncate text with indicator."""
    if len(text) <= max_len:
        return text
    return text[:max_len] + f"\n... [truncated, {len(text)} total chars]"


def run_command(cmd: List[str], timeout: int = 300, cwd: Optional[Path] = None):
    """Run command with timeout and return structured result."""
    import subprocess
    import sys
    from types import SimpleNamespace
    try:
        # On Windows, shell builtins like 'echo' need shell=True
        use_shell = sys.platform == "win32" and cmd[0].lower() in ("echo", "type", "dir", "cd")
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=str(cwd) if cwd else None,
            errors="replace",
            shell=use_shell
        )
        return SimpleNamespace(
            returncode=result.returncode,
            stdout=result.stdout,
            stderr=result.stderr,
            success=result.returncode == 0
        )
    except subprocess.TimeoutExpired:
        return SimpleNamespace(returncode=-1, stdout="", stderr="TIMEOUT", success=False)
    except Exception as e:
        return SimpleNamespace(returncode=-1, stdout="", stderr=str(e), success=False)


class ProgressTracker:
    """Thread-safe progress tracking for long operations."""

    def __init__(self, callback=None):
        self._progress = 0
        self._status = "Starting..."
        self._cancelled = False
        self._lock = __import__("threading").Lock()
        self._callback = callback

    def update(self, stage: str = "", progress: int = 0, status: str = ""):
        with self._lock:
            if progress:
                self._progress = max(0, min(100, progress))
            if status:
                self._status = status
            if self._callback:
                self._callback(stage, self._progress, self._status)

    def get(self) -> Tuple[int, str]:
        with self._lock:
            return self._progress, self._status

    def cancel(self):
        with self._lock:
            self._cancelled = True

    def is_cancelled(self) -> bool:
        with self._lock:
            return self._cancelled


def is_elf_file(path: Path) -> bool:
    """Check if file is ELF format."""
    try:
        with open(path, "rb") as f:
            magic = f.read(4)
        return magic == b"\x7fELF"
    except Exception:
        return False


def is_dex_file(path: Path) -> bool:
    """Check if file is DEX format."""
    try:
        with open(path, "rb") as f:
            magic = f.read(8)
        return magic.startswith(b"dex\n")
    except Exception:
        return False


def get_architecture_from_elf(path: Path) -> Optional[str]:
    """Extract architecture from ELF file."""
    try:
        with open(path, "rb") as f:
            f.seek(0x12)  # e_machine offset in ELF header
            machine = int.from_bytes(f.read(2), "little")

        arch_map = {
            0x03: "x86",
            0x28: "ARM",
            0x3E: "x86_64",
            0xB7: "AArch64",
            0x2A: "SPARC",
        }
        return arch_map.get(machine, f"unknown(0x{machine:04X})")
    except Exception:
        return None


def get_project_root() -> Path:
    """Get the project root directory."""
    # Try to find the project root by looking for core directory
    current = Path(__file__).resolve()
    while current != current.parent:
        if (current / "core").exists() and (current / "core" / "utils.py").exists():
            return current
        current = current.parent
    # Fallback to parent of core
    return Path(__file__).resolve().parent.parent


# Overloaded versions for bytes input (used by tests)
def is_elf_file(data: bytes) -> bool:
    """Check if data is ELF format."""
    return data[:4] == b"\x7fELF"


def is_dex_file(data: bytes) -> bool:
    """Check if data is DEX format."""
    return data[:8].startswith(b"dex\n")


def safe_extract_zip(zip_path: Path, extract_dir: Path, max_total_mb: int = 500, max_file_mb: int = 100) -> Dict[str, Any]:
    """
    Safely extract a ZIP file with ZIP slip protection and size limits.

    Args:
        zip_path: Path to the ZIP file
        extract_dir: Directory to extract to
        max_total_mb: Maximum total extraction size in MB
        max_file_mb: Maximum individual file size in MB

    Returns:
        Dict with 'success' bool, 'extracted_files' list, 'errors' list, 'extracted_bytes' int
    """
    import zipfile
    max_total_bytes = max_total_mb * 1024 * 1024
    max_file_bytes = max_file_mb * 1024 * 1024
    total_extracted = 0
    extracted_files = []
    errors = []

    try:
        with zipfile.ZipFile(zip_path) as zf:
            for info in zf.infolist():
                if info.is_dir():
                    continue

                name = info.filename
                size = info.file_size

                # Skip if file too large
                if size > max_file_bytes:
                    errors.append(f"File {name} exceeds max file size ({format_size(size)} > {format_size(max_file_bytes)})")
                    continue

                # Skip if total would exceed limit
                if total_extracted + size > max_total_bytes:
                    errors.append(f"Total extraction size would exceed limit")
                    continue

                # ZIP slip protection
                target = (extract_dir / name).resolve()
                if extract_dir.resolve() not in target.parents and target != extract_dir.resolve():
                    errors.append(f"ZIP slip blocked: {name}")
                    continue

                try:
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with zf.open(info) as src, open(target, "wb") as dst:
                        while True:
                            chunk = src.read(1024 * 1024)
                            if not chunk:
                                break
                            dst.write(chunk)
                    total_extracted += size
                    extracted_files.append(str(target.relative_to(extract_dir)))
                except Exception as e:
                    errors.append(f"Failed to extract {name}: {e}")

        return {
            "success": True,
            "extracted_files": extracted_files,
            "errors": errors,
            "extracted_bytes": total_extracted
        }
    except Exception as e:
        return {
            "success": False,
            "extracted_files": extracted_files,
            "errors": [str(e)],
            "extracted_bytes": total_extracted
        }