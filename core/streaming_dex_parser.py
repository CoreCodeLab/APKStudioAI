"""
Streaming DEX Parser for APKStudioAI 2.1
Memory-efficient parsing of large DEX files using incremental reading.
Supports multidex and parallel processing.
"""
import struct
import hashlib
import logging
from pathlib import Path
from typing import Dict, List, Any, Optional, Generator, Iterator, Set, Tuple
from collections import defaultdict
from dataclasses import dataclass, field
from .utils import calculate_sha256, is_dex_file_bytes, format_size
from .logging_setup import get_module_logger

logger = get_module_logger("dex_streaming")


@dataclass
class DEXHeader:
    """Parsed DEX header information."""
    magic: str = ""
    checksum: int = 0
    signature: bytes = b""
    file_size: int = 0
    header_size: int = 0
    endian_tag: int = 0
    link_size: int = 0
    link_off: int = 0
    map_off: int = 0
    string_ids_size: int = 0
    string_ids_off: int = 0
    type_ids_size: int = 0
    type_ids_off: int = 0
    proto_ids_size: int = 0
    proto_ids_off: int = 0
    field_ids_size: int = 0
    field_ids_off: int = 0
    method_ids_size: int = 0
    method_ids_off: int = 0
    class_defs_size: int = 0
    class_defs_off: int = 0
    data_size: int = 0
    data_off: int = 0
    valid: bool = False


@dataclass
class DEXStringId:
    """String ID entry."""
    string_data_off: int = 0


@dataclass
class DEXTypeId:
    """Type ID entry."""
    descriptor_idx: int = 0


@dataclass
class DEXProtoId:
    """Proto ID entry."""
    shorty_idx: int = 0
    return_type_idx: int = 0
    parameters_off: int = 0


@dataclass
class DEXFieldId:
    """Field ID entry."""
    class_idx: int = 0
    type_idx: int = 0
    name_idx: int = 0


@dataclass
class DEXMethodId:
    """Method ID entry."""
    class_idx: int = 0
    proto_idx: int = 0
    name_idx: int = 0


@dataclass
class DEXClassDef:
    """Class definition entry."""
    class_idx: int = 0
    access_flags: int = 0
    superclass_idx: int = 0
    interfaces_off: int = 0
    source_file_idx: int = 0
    annotations_off: int = 0
    class_data_off: int = 0
    static_values_off: int = 0


@dataclass
class StreamingDEXResult:
    """Result of streaming DEX analysis."""
    header: DEXHeader = field(default_factory=DEXHeader)
    classes: List[Dict[str, Any]] = field(default_factory=list)
    methods: List[Dict[str, Any]] = field(default_factory=list)
    strings: List[str] = field(default_factory=list)
    string_count: int = 0
    type_count: int = 0
    method_count: int = 0
    field_count: int = 0
    class_count: int = 0
    api_calls: List[Dict[str, Any]] = field(default_factory=list)
    suspicious_patterns: List[Dict[str, Any]] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    sha256: str = ""
    size_bytes: int = 0


class StreamingDEXParser:
    """
    Memory-efficient DEX parser that streams through the file without loading
    entire file into memory. Supports large DEX files and multidex APKs.
    """

    # DEX format constants
    DEX_MAGIC = b"dex\n"
    ENDIAN_CONSTANT = 0x12345678
    REVERSE_ENDIAN_CONSTANT = 0x78563412

    # LEB128 constants
    LEB128_MAX_SHIFT = 35  # Prevent infinite loops

    # Access flags
    ACC_PUBLIC = 0x0001
    ACC_PRIVATE = 0x0002
    ACC_PROTECTED = 0x0004
    ACC_STATIC = 0x0008
    ACC_FINAL = 0x0010
    ACC_SYNCHRONIZED = 0x0020
    ACC_VOLATILE = 0x0040
    ACC_TRANSIENT = 0x0080
    ACC_NATIVE = 0x0100
    ACC_INTERFACE = 0x0200
    ACC_ABSTRACT = 0x0400
    ACC_STRICT = 0x0800
    ACC_SYNTHETIC = 0x1000
    ACC_ANNOTATION = 0x2000
    ACC_ENUM = 0x4000
    ACC_CONSTRUCTOR = 0x10000
    ACC_DECLARED_SYNCHRONIZED = 0x20000

    # Sensitive API patterns for detection
    SENSITIVE_API_PATTERNS = {
        "telephony": [
            "sendTextMessage", "sendMultipartTextMessage", "getDeviceId", "getSubscriberId",
            "getLine1Number", "getSimSerialNumber", "getNetworkOperator", "getNetworkOperatorName"
        ],
        "location": [
            "getLastKnownLocation", "requestLocationUpdates", "getLatitude", "getLongitude",
            "getAccuracy", "getAltitude", "getBearing", "getSpeed"
        ],
        "contacts": [
            "query", "insert", "update", "delete", "openInputStream", "ContactsContract"
        ],
        "sms": [
            "SmsManager", "sendTextMessage", "sendMultipartTextMessage", "getInbox",
            "getAllMessagesFromPhone", "getConversationList", "getThreads"
        ],
        "camera": [
            "Camera", "takePicture", "startPreview", "setPreviewCallback", "MediaRecorder"
        ],
        "audio": [
            "AudioRecord", "startRecording", "read", "MediaRecorder", "setAudioSource"
        ],
        "network": [
            "HttpURLConnection", "HttpsURLConnection", "Socket", "SSLSocket",
            "HttpClient", "execute", "getResponseCode", "connect", "DefaultHttpClient"
        ],
        "crypto": [
            "Cipher", "MessageDigest", "SecretKeySpec", "IvParameterSpec",
            "KeyGenerator", "SecureRandom", "getInstance", "init", "doFinal"
        ],
        "execution": [
            "Runtime", "exec", "ProcessBuilder", "start", "loadLibrary", "System.load",
            "System.loadLibrary", "DexClassLoader", "PathClassLoader", "loadClass"
        ],
        "storage": [
            "getExternalStorageDirectory", "getExternalFilesDir", "getCacheDir",
            "openFileOutput", "openFileInput", "FileOutputStream", "FileInputStream"
        ],
        "admin": [
            "DevicePolicyManager", "setPasswordQuality", "setPasswordMinimumLength",
            "lockNow", "wipeData", "resetPassword"
        ],
        "accessibility": [
            "AccessibilityService", "onAccessibilityEvent", "performGlobalAction",
            "AccessibilityNodeInfo", "findAccessibilityNodeInfosByText"
        ],
        "overlay": [
            "SYSTEM_ALERT_WINDOW", "TYPE_SYSTEM_ALERT", "WindowManager.LayoutParams",
            "addView", "updateViewLayout"
        ]
    }

    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.max_methods = self.config.get("analysis", {}).get("max_methods_analyze", 2000)
        self.max_classes = self.config.get("analysis", {}).get("max_classes_analyze", 500)
        self.max_bytecode_strings = self.config.get("analysis", {}).get("max_bytecode_strings", 5000)

    def parse_dex_streaming(self, dex_path: Path, max_classes: int = None,
                            max_methods: int = None) -> StreamingDEXResult:
        """
        Parse DEX file using streaming approach.

        Args:
            dex_path: Path to DEX file
            max_classes: Maximum classes to analyze (default from config)
            max_methods: Maximum methods to analyze (default from config)

        Returns:
            StreamingDEXResult with analysis data
        """
        max_classes = max_classes or self.max_classes
        max_methods = max_methods or self.max_methods

        logger.info("streaming_dex_parse_started", dex_path=str(dex_path))

        result = StreamingDEXResult()
        result.sha256 = calculate_sha256(dex_path)
        result.size_bytes = dex_path.stat().st_size

        try:
            with open(dex_path, "rb") as f:
                # Read and parse header
                header_data = f.read(112)
                if len(header_data) < 112:
                    result.errors.append("DEX file too small for header")
                    return result

                result.header = self._parse_header(header_data)
                if not result.header.valid:
                    result.errors.append("Invalid DEX header")
                    return result

                # Read string IDs
                string_ids = self._read_string_ids(f, result.header)

                # Read type IDs
                type_ids = self._read_type_ids(f, result.header)

                # Read proto IDs
                proto_ids = self._read_proto_ids(f, result.header)

                # Read field IDs
                field_ids = self._read_field_ids(f, result.header)

                # Read method IDs
                method_ids = self._read_method_ids(f, result.header)

                # Read class definitions
                class_defs = self._read_class_defs(f, result.header)

                # Resolve strings
                strings = self._resolve_strings(f, result.header, string_ids)
                result.strings = strings[:self.max_bytecode_strings]
                result.string_count = len(strings)

                # Analyze classes
                result.classes, result.methods = self._analyze_classes_streaming(
                    f, result.header, class_defs, string_ids, type_ids,
                    proto_ids, field_ids, method_ids, strings,
                    max_classes, max_methods
                )
                result.class_count = len(result.classes)
                result.method_count = len(result.methods)

                # Detect API calls and suspicious patterns
                result.api_calls = self._detect_api_calls(result.methods, result.strings)
                result.suspicious_patterns = self._detect_suspicious_patterns(
                    result.classes, result.methods, result.strings, result.api_calls
                )

                logger.info("streaming_dex_parse_completed",
                           dex_path=str(dex_path),
                           classes=result.class_count,
                           methods=result.method_count,
                           strings=result.string_count,
                           api_calls=len(result.api_calls))

        except Exception as e:
            logger.error("streaming_dex_parse_failed", dex_path=str(dex_path), error=str(e))
            result.errors.append(f"Parse failed: {str(e)}")

        return result

    def parse_multidex(self, apk_path: Path, extract_dir: Path) -> List[StreamingDEXResult]:
        """
        Parse all DEX files in a multidex APK.

        Args:
            apk_path: Path to APK file
            extract_dir: Extracted APK directory

        Returns:
            List of StreamingDEXResult for each DEX file
        """
        results = []

        # Find all DEX files
        dex_files = list(extract_dir.rglob("classes*.dex"))
        dex_files.sort(key=lambda x: x.name)  # classes.dex, classes2.dex, etc.

        logger.info("multidex_parse_started", apk=str(apk_path), dex_count=len(dex_files))

        for i, dex_file in enumerate(dex_files):
            logger.info("multidex_parsing_dex", index=i, dex_file=str(dex_file))
            result = self.parse_dex_streaming(dex_file)
            results.append(result)

        return results

    def _parse_header(self, data: bytes) -> DEXHeader:
        """Parse DEX header (112 bytes)."""
        header = DEXHeader()
        try:
            # Unpack header fields
            # magic(8) + checksum(4) + signature(20) + file_size(4) + header_size(4) + endian_tag(4)
            # link_size(4) + link_off(4) + map_off(4) + string_ids_size(4) + string_ids_off(4)
            # type_ids_size(4) + type_ids_off(4) + proto_ids_size(4) + proto_ids_off(4)
            # field_ids_size(4) + field_ids_off(4) + method_ids_size(4) + method_ids_off(4)
            # class_defs_size(4) + class_defs_off(4) + data_size(4) + data_off(4)
            values = struct.unpack("<8sII20sIIIIIIIIIIIIIIII", data[:112])

            header.magic = values[0].decode("ascii", errors="ignore")
            header.checksum = values[1]
            header.signature = values[2]
            header.file_size = values[3]
            header.header_size = values[4]
            header.endian_tag = values[5]
            header.link_size = values[6]
            header.link_off = values[7]
            header.map_off = values[8]
            header.string_ids_size = values[9]
            header.string_ids_off = values[10]
            header.type_ids_size = values[11]
            header.type_ids_off = values[12]
            header.proto_ids_size = values[13]
            header.proto_ids_off = values[14]
            header.field_ids_size = values[15]
            header.field_ids_off = values[16]
            header.method_ids_size = values[17]
            header.method_ids_off = values[18]
            header.class_defs_size = values[19]
            header.class_defs_off = values[20]
            header.data_size = values[21]
            header.data_off = values[22]

            # Validate
            header.valid = (
                header.magic.startswith("dex") and
                header.header_size == 112 and
                header.endian_tag in (self.ENDIAN_CONSTANT, self.REVERSE_ENDIAN_CONSTANT)
            )

        except Exception as e:
            logger.warning("header_parse_failed", error=str(e))

        return header

    def _read_section(self, f, offset: int, count: int, entry_size: int) -> bytes:
        """Read a section from the file."""
        f.seek(offset)
        return f.read(count * entry_size)

    def _read_string_ids(self, f, header: DEXHeader) -> List[DEXStringId]:
        """Read string ID section."""
        if header.string_ids_size == 0 or header.string_ids_off == 0:
            return []

        data = self._read_section(f, header.string_ids_off, header.string_ids_size, 4)
        string_ids = []
        for i in range(header.string_ids_size):
            sid = DEXStringId()
            sid.string_data_off = struct.unpack("<I", data[i*4:(i+1)*4])[0]
            string_ids.append(sid)
        return string_ids

    def _read_type_ids(self, f, header: DEXHeader) -> List[DEXTypeId]:
        """Read type ID section."""
        if header.type_ids_size == 0 or header.type_ids_off == 0:
            return []

        data = self._read_section(f, header.type_ids_off, header.type_ids_size, 4)
        type_ids = []
        for i in range(header.type_ids_size):
            tid = DEXTypeId()
            tid.descriptor_idx = struct.unpack("<I", data[i*4:(i+1)*4])[0]
            type_ids.append(tid)
        return type_ids

    def _read_proto_ids(self, f, header: DEXHeader) -> List[DEXProtoId]:
        """Read proto ID section."""
        if header.proto_ids_size == 0 or header.proto_ids_off == 0:
            return []

        data = self._read_section(f, header.proto_ids_off, header.proto_ids_size, 12)
        proto_ids = []
        for i in range(header.proto_ids_size):
            pid = DEXProtoId()
            pid.shorty_idx = struct.unpack("<I", data[i*12:i*12+4])[0]
            pid.return_type_idx = struct.unpack("<I", data[i*12+4:i*12+8])[0]
            pid.parameters_off = struct.unpack("<I", data[i*12+8:i*12+12])[0]
            proto_ids.append(pid)
        return proto_ids

    def _read_field_ids(self, f, header: DEXHeader) -> List[DEXFieldId]:
        """Read field ID section."""
        if header.field_ids_size == 0 or header.field_ids_off == 0:
            return []

        data = self._read_section(f, header.field_ids_off, header.field_ids_size, 8)
        field_ids = []
        for i in range(header.field_ids_size):
            fid = DEXFieldId()
            fid.class_idx = struct.unpack("<H", data[i*8:i*8+2])[0]
            fid.type_idx = struct.unpack("<H", data[i*8+2:i*8+4])[0]
            fid.name_idx = struct.unpack("<I", data[i*8+4:i*8+8])[0]
            field_ids.append(fid)
        return field_ids

    def _read_method_ids(self, f, header: DEXHeader) -> List[DEXMethodId]:
        """Read method ID section."""
        if header.method_ids_size == 0 or header.method_ids_off == 0:
            return []

        data = self._read_section(f, header.method_ids_off, header.method_ids_size, 8)
        method_ids = []
        for i in range(header.method_ids_size):
            mid = DEXMethodId()
            mid.class_idx = struct.unpack("<H", data[i*8:i*8+2])[0]
            mid.proto_idx = struct.unpack("<H", data[i*8+2:i*8+4])[0]
            mid.name_idx = struct.unpack("<I", data[i*8+4:i*8+8])[0]
            method_ids.append(mid)
        return method_ids

    def _read_class_defs(self, f, header: DEXHeader) -> List[DEXClassDef]:
        """Read class definitions section."""
        if header.class_defs_size == 0 or header.class_defs_off == 0:
            return []

        data = self._read_section(f, header.class_defs_off, header.class_defs_size, 32)
        class_defs = []
        for i in range(header.class_defs_size):
            cdef = DEXClassDef()
            offset = i * 32
            cdef.class_idx = struct.unpack("<I", data[offset:offset+4])[0]
            cdef.access_flags = struct.unpack("<I", data[offset+4:offset+8])[0]
            cdef.superclass_idx = struct.unpack("<I", data[offset+8:offset+12])[0]
            cdef.interfaces_off = struct.unpack("<I", data[offset+12:offset+16])[0]
            cdef.source_file_idx = struct.unpack("<I", data[offset+16:offset+20])[0]
            cdef.annotations_off = struct.unpack("<I", data[offset+20:offset+24])[0]
            cdef.class_data_off = struct.unpack("<I", data[offset+24:offset+28])[0]
            cdef.static_values_off = struct.unpack("<I", data[offset+28:offset+32])[0]
            class_defs.append(cdef)
        return class_defs

    def _read_uleb128(self, data: bytes, offset: int) -> Tuple[int, int]:
        """Read unsigned LEB128 from data. Returns (value, new_offset)."""
        result = 0
        shift = 0
        while shift < self.LEB128_MAX_SHIFT:
            if offset >= len(data):
                break
            byte = data[offset]
            offset += 1
            result |= (byte & 0x7F) << shift
            if not (byte & 0x80):
                break
            shift += 7
        return result, offset

    def _read_sleb128(self, data: bytes, offset: int) -> Tuple[int, int]:
        """Read signed LEB128 from data. Returns (value, new_offset)."""
        result = 0
        shift = 0
        size = 0
        while shift < self.LEB128_MAX_SHIFT:
            if offset >= len(data):
                break
            byte = data[offset]
            offset += 1
            result |= (byte & 0x7F) << shift
            size += 7
            if not (byte & 0x80):
                break
            shift += 7
        # Sign extend if needed
        if (shift < 32) and (byte & 0x40):
            result |= (~0) << shift
        return result, offset

    def _read_string_data(self, f, offset: int) -> str:
        """Read a string from the string data section."""
        f.seek(offset)
        # Read ULEB128 length
        length_bytes = b""
        for _ in range(5):  # Max 5 bytes for ULEB128
            byte = f.read(1)
            if not byte:
                break
            length_bytes += byte
            if byte[0] & 0x80 == 0:
                break

        length, _ = self._read_uleb128(length_bytes, 0)

        # Read string data
        if length > 10000:  # Sanity check
            return ""
        string_data = f.read(length)
        try:
            return string_data.decode("utf-8", errors="ignore")
        except Exception:
            return ""

    def _resolve_strings(self, f, header: DEXHeader, string_ids: List[DEXStringId]) -> List[str]:
        """Resolve all string IDs to actual strings."""
        strings = []
        for sid in string_ids:
            if sid.string_data_off >= header.data_off:
                # String is in data section
                try:
                    string = self._read_string_data(f, sid.string_data_off)
                    strings.append(string)
                except Exception:
                    strings.append("")
            else:
                strings.append("")
        return strings

    def _analyze_classes_streaming(self, f, header: DEXHeader, class_defs: List[DEXClassDef],
                                    string_ids: List[DEXStringId], type_ids: List[DEXTypeId],
                                    proto_ids: List[DEXProtoId], field_ids: List[DEXFieldId],
                                    method_ids: List[DEXMethodId], strings: List[str],
                                    max_classes: int, max_methods: int) -> Tuple[List[Dict], List[Dict]]:
        """Analyze class definitions streaming through class data."""
        classes = []
        methods = []
        method_count = 0

        for i, cdef in enumerate(class_defs):
            if i >= max_classes:
                break

            if cdef.class_data_off == 0:
                continue

            f.seek(cdef.class_data_off)
            class_data = f.read(1024 * 1024)  # Read up to 1MB of class data

            class_info = self._parse_class_data(
                class_data, i, cdef, string_ids, type_ids, strings
            )

            # Parse methods
            class_methods = self._parse_class_methods(
                class_data, class_info, method_ids, proto_ids, field_ids,
                string_ids, type_ids, strings, max_methods - method_count
            )
            class_info["methods"] = class_methods
            methods.extend(class_methods)
            method_count += len(class_methods)

            classes.append(class_info)

            if method_count >= max_methods:
                break

        return classes, methods

    def _parse_class_data(self, data: bytes, class_idx: int, cdef: DEXClassDef,
                          string_ids: List[DEXStringId], type_ids: List[DEXTypeId],
                          strings: List[str]) -> Dict[str, Any]:
        """Parse class data section."""
        offset = 0

        # Read class data header
        static_fields_size, offset = self._read_uleb128(data, offset)
        instance_fields_size, offset = self._read_uleb128(data, offset)
        direct_methods_size, offset = self._read_uleb128(data, offset)
        virtual_methods_size, offset = self._read_uleb128(data, offset)

        # Get class name
        class_name = ""
        if cdef.class_idx < len(type_ids):
            type_id = type_ids[cdef.class_idx]
            if type_id.descriptor_idx < len(string_ids):
                string_id = string_ids[type_id.descriptor_idx]
                if string_id.string_data_off < len(strings):
                    class_name = strings[string_id.string_data_off]

        # Get superclass name
        superclass_name = ""
        if cdef.superclass_idx != 0xFFFFFFFF and cdef.superclass_idx < len(type_ids):
            type_id = type_ids[cdef.superclass_idx]
            if type_id.descriptor_idx < len(string_ids):
                string_id = string_ids[type_id.descriptor_idx]
                if string_id.string_data_off < len(strings):
                    superclass_name = strings[string_id.string_data_off]

        # Get source file
        source_file = ""
        if cdef.source_file_idx != 0xFFFFFFFF and cdef.source_file_idx < len(string_ids):
            string_id = string_ids[cdef.source_file_idx]
            if string_id.string_data_off < len(strings):
                source_file = strings[string_id.string_data_off]

        return {
            "index": class_idx,
            "name": class_name,
            "superclass": superclass_name,
            "source_file": source_file,
            "access_flags": cdef.access_flags,
            "access_flags_str": self._format_access_flags(cdef.access_flags),
            "static_fields": static_fields_size,
            "instance_fields": instance_fields_size,
            "direct_methods": direct_methods_size,
            "virtual_methods": virtual_methods_size,
            "interfaces_off": cdef.interfaces_off,
            "annotations_off": cdef.annotations_off,
            "static_values_off": cdef.static_values_off
        }

    def _parse_class_methods(self, data: bytes, class_info: Dict,
                             method_ids: List[DEXMethodId], proto_ids: List[DEXProtoId],
                             field_ids: List[DEXFieldId], string_ids: List[DEXStringId],
                             type_ids: List[DEXTypeId], strings: List[str],
                             remaining_methods: int) -> List[Dict[str, Any]]:
        """Parse method data from class."""
        methods = []
        offset = 0

        # Skip static fields
        for _ in range(class_info["static_fields"]):
            field_idx_diff, offset = self._read_uleb128(data, offset)
            access_flags, offset = self._read_uleb128(data, offset)

        # Skip instance fields
        for _ in range(class_info["instance_fields"]):
            field_idx_diff, offset = self._read_uleb128(data, offset)
            access_flags, offset = self._read_uleb128(data, offset)

        # Parse direct methods
        method_idx = 0
        for _ in range(class_info["direct_methods"]):
            if len(methods) >= remaining_methods:
                break
            method_idx_diff, offset = self._read_uleb128(data, offset)
            method_idx += method_idx_diff
            access_flags, offset = self._read_uleb128(data, offset)
            code_off, offset = self._read_uleb128(data, offset)

            if method_idx < len(method_ids):
                method_info = self._parse_method(
                    method_idx, method_ids, proto_ids, field_ids,
                    string_ids, type_ids, strings, class_info["name"],
                    access_flags, code_off, f
                )
                methods.append(method_info)

        # Parse virtual methods
        for _ in range(class_info["virtual_methods"]):
            if len(methods) >= remaining_methods:
                break
            method_idx_diff, offset = self._read_uleb128(data, offset)
            method_idx += method_idx_diff
            access_flags, offset = self._read_uleb128(data, offset)
            code_off, offset = self._read_uleb128(data, offset)

            if method_idx < len(method_ids):
                method_info = self._parse_method(
                    method_idx, method_ids, proto_ids, field_ids,
                    string_ids, type_ids, strings, class_info["name"],
                    access_flags, code_off, f
                )
                methods.append(method_info)

        return methods

    def _parse_method(self, method_idx: int, method_ids: List[DEXMethodId],
                      proto_ids: List[DEXProtoId], field_ids: List[DEXFieldId],
                      string_ids: List[DEXStringId], type_ids: List[DEXTypeId],
                      strings: List[str], class_name: str,
                      access_flags: int, code_off: int, f) -> Dict[str, Any]:
        """Parse a single method."""
        mid = method_ids[method_idx]

        # Get method name
        method_name = ""
        if mid.name_idx < len(string_ids):
            sid = string_ids[mid.name_idx]
            if sid.string_data_off < len(strings):
                method_name = strings[sid.string_data_off]

        # Get class name (from method's class_idx)
        class_name_full = class_name
        if mid.class_idx < len(type_ids):
            tid = type_ids[mid.class_idx]
            if tid.descriptor_idx < len(string_ids):
                sid = string_ids[tid.descriptor_idx]
                if sid.string_data_off < len(strings):
                    class_name_full = strings[sid.string_data_off]

        # Get prototype
        proto = proto_ids[mid.proto_idx] if mid.proto_idx < len(proto_ids) else None
        return_type = ""
        if proto and proto.return_type_idx < len(type_ids):
            tid = type_ids[proto.return_type_idx]
            if tid.descriptor_idx < len(string_ids):
                sid = string_ids[tid.descriptor_idx]
                if sid.string_data_off < len(strings):
                    return_type = strings[sid.string_data_off]

        # Get shorty
        shorty = ""
        if proto and proto.shorty_idx < len(string_ids):
            sid = string_ids[proto.shorty_idx]
            if sid.string_data_off < len(strings):
                shorty = strings[sid.string_data_off]

        method_info = {
            "class": class_name_full,
            "name": method_name,
            "return_type": return_type,
            "shorty": shorty,
            "access_flags": access_flags,
            "access_flags_str": self._format_access_flags(access_flags),
            "code_off": code_off,
            "code": [],
            "strings_referenced": [],
            "api_calls": []
        }

        # Parse code if available
        if code_off > 0:
            f.seek(code_off)
            code_data = f.read(64 * 1024)  # Read up to 64KB of code
            method_info["code"], method_info["strings_referenced"] = self._parse_method_code(
                code_data, string_ids, type_ids, proto_ids, method_ids, field_ids, strings
            )

        return method_info

    def _parse_method_code(self, code_data: bytes,
                          string_ids: List[DEXStringId], type_ids: List[DEXTypeId],
                          proto_ids: List[DEXProtoId], method_ids: List[DEXMethodId],
                          field_ids: List[DEXFieldId], strings: List[str]) -> Tuple[List[Dict], List[str]]:
        """Parse method bytecode."""
        if len(code_data) < 16:
            return [], []

        offset = 0

        # Parse code header
        registers_size = struct.unpack("<H", code_data[offset:offset+2])[0]
        offset += 2
        ins_size = struct.unpack("<H", code_data[offset:offset+2])[0]
        offset += 2
        outs_size = struct.unpack("<H", code_data[offset:offset+2])[0]
        offset += 2
        tries_size = struct.unpack("<H", code_data[offset:offset+2])[0]
        offset += 2
        debug_info_off = struct.unpack("<I", code_data[offset:offset+4])[0]
        offset += 4
        insns_size = struct.unpack("<I", code_data[offset:offset+4])[0]
        offset += 4

        insns_data = code_data[offset:offset + insns_size * 2]
        code = []
        strings_referenced = []

        # Parse instructions
        i = 0
        while i < len(insns_data) - 1:
            opcode = insns_data[i]
            i += 1

            # Get instruction format and operands
            insn = {"opcode": opcode, "mnemonic": "unknown"}
            # Simplified - just track string and type references
            if opcode in (0x1a, 0x1b):  # const-string, const-string/jumbo
                if i + 3 < len(insns_data):
                    string_idx = struct.unpack("<H", insns_data[i:i+2])[0] if opcode == 0x1a else struct.unpack("<I", insns_data[i:i+4])[0]
                    i += 2 if opcode == 0x1a else 4
                    if string_idx < len(string_ids):
                        sid = string_ids[string_idx]
                        if sid.string_data_off < len(strings):
                            string_val = strings[sid.string_data_off]
                            strings_referenced.append(string_val)
                            insn["string"] = string_val
                            insn["string_idx"] = string_idx
            elif opcode == 0x1c:  # const-class
                if i + 1 < len(insns_data):
                    type_idx = struct.unpack("<H", insns_data[i:i+2])[0]
                    i += 2
                    if type_idx < len(type_ids):
                        tid = type_ids[type_idx]
                        if tid.descriptor_idx < len(string_ids):
                            sid = string_ids[tid.descriptor_idx]
                            if sid.string_data_off < len(strings):
                                type_name = strings[sid.string_data_off]
                                insn["type"] = type_name
                                insn["type_idx"] = type_idx
            elif opcode in (0x22, 0x23):  # new-instance, new-array
                if i + 1 < len(insns_data):
                    type_idx = struct.unpack("<H", insns_data[i:i+2])[0]
                    i += 2
                    if type_idx < len(type_ids):
                        tid = type_ids[type_idx]
                        if tid.descriptor_idx < len(string_ids):
                            sid = string_ids[tid.descriptor_idx]
                            if sid.string_data_off < len(strings):
                                type_name = strings[sid.string_data_off]
                                insn["type"] = type_name
            elif opcode in (0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73):  # invoke-*
                if i + 3 < len(insns_data):
                    method_idx = struct.unpack("<H", insns_data[i:i+2])[0]
                    i += 4  # skip method_idx + registers
                    if method_idx < len(method_ids):
                        mid = method_ids[method_idx]
                        # Get method name
                        method_name = ""
                        if mid.name_idx < len(string_ids):
                            sid = string_ids[mid.name_idx]
                            if sid.string_data_off < len(strings):
                                method_name = strings[sid.string_data_off]
                        # Get class name
                        class_name = ""
                        if mid.class_idx < len(type_ids):
                            tid = type_ids[mid.class_idx]
                            if tid.descriptor_idx < len(string_ids):
                                sid = string_strings[tid.descriptor_idx]
                                if sid.string_data_off < len(strings):
                                    class_name = strings[sid.string_data_off]
                        insn["invoke"] = f"{class_name}->{method_name}"
                        insn["method_idx"] = method_idx
            else:
                # Skip operands for other instructions (simplified)
                i += 1  # Minimum 1 byte per instruction

            code.append(insn)

        return code, strings_referenced

    def _format_access_flags(self, flags: int) -> str:
        """Format access flags as string."""
        parts = []
        flag_map = {
            self.ACC_PUBLIC: "public", self.ACC_PRIVATE: "private",
            self.ACC_PROTECTED: "protected", self.ACC_STATIC: "static",
            self.ACC_FINAL: "final", self.ACC_SYNCHRONIZED: "synchronized",
            self.ACC_VOLATILE: "volatile", self.ACC_TRANSIENT: "transient",
            self.ACC_NATIVE: "native", self.ACC_INTERFACE: "interface",
            self.ACC_ABSTRACT: "abstract", self.ACC_STRICT: "strict",
            self.ACC_SYNTHETIC: "synthetic", self.ACC_ANNOTATION: "annotation",
            self.ACC_ENUM: "enum", self.ACC_CONSTRUCTOR: "constructor",
        }
        for flag, name in flag_map.items():
            if flags & flag:
                parts.append(name)
        return " ".join(parts)

    def _detect_api_calls(self, methods: List[Dict], strings: List[str]) -> List[Dict[str, Any]]:
        """Detect sensitive API calls from methods and strings."""
        api_calls = []

        # From method invocations
        for method in methods:
            for insn in method.get("code", []):
                if "invoke" in insn:
                    invoke_str = insn["invoke"]
                    for category, patterns in self.SENSITIVE_API_PATTERNS.items():
                        for pattern in patterns:
                            if pattern.lower() in invoke_str.lower():
                                api_calls.append({
                                    "category": category,
                                    "pattern": pattern,
                                    "method": f"{method['class']}->{method['name']}",
                                    "call": invoke_str,
                                    "confidence": "high"
                                })

        # From referenced strings
        for method in methods:
            for string in method.get("strings_referenced", []):
                for category, patterns in self.SENSITIVE_API_PATTERNS.items():
                    for pattern in patterns:
                        if pattern.lower() in string.lower():
                            api_calls.append({
                                "category": category,
                                "pattern": pattern,
                                "method": f"{method['class']}->{method['name']}",
                                "call": string,
                                "confidence": "medium"
                            })

        return api_calls

    def _detect_suspicious_patterns(self, classes: List[Dict], methods: List[Dict],
                                    strings: List[str], api_calls: List[Dict]) -> List[Dict[str, Any]]:
        """Detect suspicious patterns in the DEX."""
        patterns = []

        # Check for dynamic code loading
        for method in methods:
            for insn in method.get("code", []):
                if "invoke" in insn:
                    invoke = insn["invoke"].lower()
                    if any(x in invoke for x in ["dexclassloader", "pathclassloader", "loadclass", "defineclass"]):
                        patterns.append({
                            "type": "dynamic_code_loading",
                            "severity": "high",
                            "method": f"{method['class']}->{method['name']}",
                            "evidence": invoke
                        })

        # Check for reflection
        for method in methods:
            for insn in method.get("code", []):
                if "invoke" in insn:
                    invoke = insn["invoke"].lower()
                    if any(x in invoke for x in ["class.forname", "method.invoke", "field.set", "constructor.newinstance"]):
                        patterns.append({
                            "type": "reflection",
                            "severity": "medium",
                            "method": f"{method['class']}->{method['name']}",
                            "evidence": invoke
                        })

        # Check for native methods
        for method in methods:
            if "native" in method.get("access_flags_str", "").lower():
                patterns.append({
                    "type": "native_method",
                    "severity": "medium",
                    "method": f"{method['class']}->{method['name']}",
                    "evidence": "Native method declaration"
                })

        # Check for obfuscation indicators
        short_names = sum(1 for c in classes if len(c.get("name", "").split("/")[-1]) <= 2)
        if short_names > len(classes) * 0.3:
            patterns.append({
                "type": "obfuscation",
                "severity": "medium",
                "evidence": f"{short_names}/{len(classes)} classes have very short names"
            })

        # Check for crypto constants in strings
        crypto_indicators = ["AES", "RSA", "DES", "ECB", "CBC", "PKCS5Padding", "PKCS7Padding",
                            "BouncyCastle", "SpongyCastle", "SecretKeySpec", "IvParameterSpec"]
        for s in strings:
            for indicator in crypto_indicators:
                if indicator in s:
                    patterns.append({
                        "type": "crypto_usage",
                        "severity": "low",
                        "evidence": s[:200]
                    })
                    break

        return patterns


def get_streaming_dex_parser(config: Dict[str, Any] = None) -> StreamingDEXParser:
    """Factory function for StreamingDEXParser."""
    return StreamingDEXParser(config)