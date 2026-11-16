"""
DEX Bytecode-level Analyzer for APKStudioAI 2.1
Provides deep analysis of DEX bytecode without external dependencies.
Parses DEX file format directly to extract:
- Class definitions with full hierarchy
- Method bytecode instructions
- String references from bytecode
- Field references
- Annotation data
- Control flow analysis
- API call graph extraction
"""
import struct
import hashlib
import re
from pathlib import Path
from typing import Dict, List, Any, Optional, Set, Tuple
from collections import defaultdict
from .utils import printable_strings_streaming
from .config_manager import get_config


class DEXBytecodeAnalyzer:
    """
    Analyzes DEX bytecode directly from the binary format.
    No external dependencies required - pure Python implementation.
    """

    # DEX format constants
    DEX_MAGIC = b"dex\n"
    ENDIAN_CONSTANT = 0x12345678
    REVERSE_ENDIAN_CONSTANT = 0x78563412

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

    # DEX opcodes (subset for analysis)
    OPCODES = {
        0x00: "nop", 0x01: "move", 0x02: "move/from16", 0x03: "move/16",
        0x04: "move-wide", 0x05: "move-wide/from16", 0x06: "move-wide/16",
        0x07: "move-object", 0x08: "move-object/from16", 0x09: "move-object/16",
        0x0a: "move-result", 0x0b: "move-result-wide", 0x0c: "move-result-object",
        0x0d: "move-exception", 0x0e: "return-void", 0x0f: "return",
        0x10: "return-wide", 0x11: "return-object", 0x12: "const/4", 0x13: "const/16",
        0x14: "const", 0x15: "const/high16", 0x16: "const-wide/16", 0x17: "const-wide/32",
        0x18: "const-wide", 0x19: "const-wide/high16", 0x1a: "const-string",
        0x1b: "const-string/jumbo", 0x1c: "const-class", 0x1d: "monitor-enter",
        0x1e: "monitor-exit", 0x1f: "check-cast", 0x20: "instance-of",
        0x21: "array-length", 0x22: "new-instance", 0x23: "new-array",
        0x24: "filled-new-array", 0x25: "filled-new-array/range",
        0x26: "fill-array-data", 0x27: "throw", 0x28: "goto",
        0x29: "goto/16", 0x2a: "goto/32", 0x2b: "packed-switch",
        0x2c: "sparse-switch", 0x2d: "cmpl-float", 0x2e: "cmpg-float",
        0x2f: "cmpl-double", 0x30: "cmpg-double", 0x31: "cmp-long",
        0x32: "if-eq", 0x33: "if-ne", 0x34: "if-lt", 0x35: "if-ge",
        0x36: "if-gt", 0x37: "if-le", 0x38: "if-eqz", 0x39: "if-nez",
        0x3a: "if-ltz", 0x3b: "if-gez", 0x3c: "if-gtz", 0x3d: "if-lez",
        0x3e: "unused-3e", 0x3f: "unused-3f", 0x40: "unused-40", 0x41: "unused-41",
        0x42: "unused-42", 0x43: "unused-43", 0x44: "unused-44", 0x45: "unused-45",
        0x46: "unused-46", 0x47: "unused-47", 0x48: "unused-48", 0x49: "unused-49",
        0x4a: "unused-4a", 0x4b: "unused-4b", 0x4c: "unused-4c", 0x4d: "unused-4d",
        0x4e: "unused-4e", 0x4f: "unused-4f", 0x50: "unused-50", 0x51: "unused-51",
        0x52: "unused-52", 0x53: "unused-53", 0x54: "unused-54", 0x55: "unused-55",
        0x56: "unused-56", 0x57: "unused-57", 0x58: "unused-58", 0x59: "unused-59",
        0x5a: "unused-5a", 0x5b: "unused-5b", 0x5c: "unused-5c", 0x5d: "unused-5d",
        0x5e: "unused-5e", 0x5f: "unused-5f", 0x60: "unused-60", 0x61: "unused-61",
        0x62: "unused-62", 0x63: "unused-63", 0x64: "unused-64", 0x65: "unused-65",
        0x66: "unused-66", 0x67: "unused-67", 0x68: "unused-68", 0x69: "unused-69",
        0x6e: "invoke-virtual", 0x6f: "invoke-super", 0x70: "invoke-direct",
        0x71: "invoke-static", 0x72: "invoke-interface", 0x73: "unused-73",
        0x74: "invoke-virtual/range", 0x75: "invoke-super/range",
        0x76: "invoke-direct/range", 0x77: "invoke-static/range",
        0x78: "invoke-interface/range", 0x79: "unused-79", 0x7a: "unused-7a",
        0x7b: "neg-int", 0x7c: "not-int", 0x7d: "neg-long", 0x7e: "not-long",
        0x7f: "neg-float", 0x80: "neg-double", 0x81: "int-to-long",
        0x82: "int-to-float", 0x83: "int-to-double", 0x84: "long-to-int",
        0x85: "long-to-float", 0x86: "long-to-double", 0x87: "float-to-int",
        0x88: "float-to-long", 0x89: "float-to-double", 0x8a: "double-to-int",
        0x8b: "double-to-long", 0x8c: "double-to-float", 0x8d: "int-to-byte",
        0x8e: "int-to-char", 0x8f: "int-to-short", 0x90: "add-int",
        0x91: "add-int/2addr", 0x92: "add-int/lit16", 0x93: "add-int/lit8",
        0x94: "rsub-int", 0x95: "rsub-int/2addr", 0x96: "rsub-int/lit16",
        0x97: "rsub-int/lit8", 0x98: "mul-int", 0x99: "mul-int/2addr",
        0x9a: "mul-int/lit16", 0x9b: "mul-int/lit8", 0x9c: "div-int",
        0x9d: "div-int/2addr", 0x9e: "div-int/lit16", 0x9f: "div-int/lit8",
        0xa0: "rem-int", 0xa1: "rem-int/2addr", 0xa2: "rem-int/lit16",
        0xa3: "rem-int/lit8", 0xa4: "and-int", 0xa5: "and-int/2addr",
        0xa6: "and-int/lit16", 0xa7: "and-int/lit8", 0xa8: "or-int",
        0xa9: "or-int/2addr", 0xaa: "or-int/lit16", 0xab: "or-int/lit8",
        0xac: "xor-int", 0xad: "xor-int/2addr", 0xae: "xor-int/lit16",
        0xaf: "xor-int/lit8", 0xb0: "shl-int", 0xb1: "shl-int/2addr",
        0xb2: "shl-int/lit16", 0xb3: "shl-int/lit8", 0xb4: "shr-int",
        0xb5: "shr-int/2addr", 0xb6: "shr-int/lit16", 0xb7: "shr-int/lit8",
        0xb8: "ushr-int", 0xb9: "ushr-int/2addr", 0xba: "ushr-int/lit16",
        0xbb: "ushr-int/lit8", 0xbc: "add-long", 0xbd: "add-long/2addr",
        0xbe: "sub-long", 0xbf: "sub-long/2addr", 0xc0: "mul-long",
        0xc1: "mul-long/2addr", 0xc2: "div-long", 0xc3: "div-long/2addr",
        0xc4: "rem-long", 0xc5: "rem-long/2addr", 0xc6: "and-long",
        0xc7: "and-long/2addr", 0xc8: "or-long", 0xc9: "or-long/2addr",
        0xca: "xor-long", 0xcb: "xor-long/2addr", 0xcc: "shl-long",
        0xcd: "shl-long/2addr", 0xce: "shr-long", 0xcf: "shr-long/2addr",
        0xd0: "ushr-long", 0xd1: "ushr-long/2addr", 0xd2: "add-float",
        0xd3: "add-float/2addr", 0xd4: "sub-float", 0xd5: "sub-float/2addr",
        0xd6: "mul-float", 0xd7: "mul-float/2addr", 0xd8: "div-float",
        0xd9: "div-float/2addr", 0xda: "rem-float", 0xdb: "rem-float/2addr",
        0xdc: "add-double", 0xdd: "add-double/2addr", 0xde: "sub-double",
        0xdf: "sub-double/2addr", 0xe0: "mul-double", 0xe1: "mul-double/2addr",
        0xe2: "div-double", 0xe3: "div-double/2addr", 0xe4: "rem-double",
        0xe5: "rem-double/2addr", 0xe6: "cmpl-float", 0xe7: "cmpg-float",
        0xe8: "cmpl-double", 0xe9: "cmpg-double", 0xea: "cmp-long",
    }

    def __init__(self, config: Dict = None):
        global_config = get_config(config)
        analysis_config = global_config.get("analysis", {})
        self.max_file_size_mb = analysis_config.get("max_dex_size_mb", 50)
        self.max_file_bytes = self.max_file_size_mb * 1024 * 1024
        self.max_methods = analysis_config.get("max_methods_analyze", 2000)
        self.max_strings = analysis_config.get("max_bytecode_strings", 5000)
        self.max_instructions = analysis_config.get("max_instructions_per_method", 5000)
        self.max_classes = analysis_config.get("max_classes_analyze", 500)

    def analyze(self, dex_path: Path) -> Dict[str, Any]:
        """Analyze a single DEX file at bytecode level."""
        if dex_path.stat().st_size > self.max_file_bytes:
            return {"error": f"DEX file too large ({dex_path.stat().st_size / 1024 / 1024:.1f}MB > {self.max_file_size_mb}MB)"}

        result = {
            "path": str(dex_path),
            "sha256": hashlib.sha256(dex_path.read_bytes()).hexdigest(),
            "header": {},
            "classes": [],
            "methods": [],
            "strings": [],
            "method_references": [],
            "field_references": [],
            "class_references": [],
            "api_calls": [],
            "control_flow": {},
            "suspicious_patterns": [],
            "statistics": {}
        }

        try:
            with open(dex_path, "rb") as f:
                data = f.read()

            # Parse header
            header = self._parse_header(data)
            result["header"] = header

            if not header.get("valid"):
                result["error"] = "Invalid DEX header"
                return result

            # Determine endianness from header
            endian_tag = header.get("endian_tag", "0x12345678")
            self._is_little_endian = endian_tag in ("0x12345678", "0x78563412")
            self._struct_endian = "<" if self._is_little_endian else ">"

            # Parse string table
            strings = self._parse_string_table(data, header)
            result["strings"] = strings[:self.max_strings]

            # Parse type table
            types = self._parse_type_table(data, header, strings)

            # Parse proto table
            protos = self._parse_proto_table(data, header, strings, types)

            # Parse field table
            fields = self._parse_field_table(data, header, strings, types)

            # Parse method table
            methods = self._parse_method_table(data, header, strings, types, protos)

            # Parse class defs
            classes = self._parse_class_defs(data, header, strings, types, fields, methods)

            result["classes"] = classes
            result["methods"] = methods[:self.max_methods]
            result["field_references"] = fields
            result["method_references"] = methods

            # Analyze bytecode for each method
            self._analyze_method_bytecode(data, header, result, classes, types, methods, fields, protos, strings)

            # Compute statistics
            result["statistics"] = self._compute_statistics(result)

        except Exception as e:
            result["error"] = str(e)

        return result

    def _parse_header(self, data: bytes) -> Dict[str, Any]:
        """Parse DEX file header (112-124 bytes depending on version)."""
        if len(data) < 112 or not data.startswith(self.DEX_MAGIC):
            return {"valid": False}

        try:
            # DEX header structure (all little-endian)
            # magic(8) + checksum(4) + signature(20) = 32 bytes
            # Then 23 uint32 values:
            # file_size[4] + header_size[4] + endian_tag[4] +
            # link_size[4] + link_off[4] + map_off[4] +
            # string_ids_size[4] + string_ids_off[4] +
            # type_ids_size[4] + type_ids_off[4] +
            # proto_ids_size[4] + proto_ids_off[4] +
            # field_ids_size[4] + field_ids_off[4] +
            # method_ids_size[4] + method_ids_off[4] +
            # class_defs_size[4] + class_defs_off[4] +
            # data_size[4] + data_off[4]
            # Total: 32 + 23*4 = 124 bytes for full header

            # Try parsing full 124-byte header first
            header_fmt = "<8sI20s" + "I"*23
            header_size = struct.calcsize(header_fmt)

            if len(data) >= header_size:
                values = struct.unpack(header_fmt, data[:header_size])
            else:
                # Fallback to 112-byte header (older DEX format)
                header_fmt = "<8sI20s" + "I"*20
                header_size = struct.calcsize(header_fmt)
                values = struct.unpack(header_fmt, data[:header_size])
                # Pad missing values
                values = values + (0, 0, 0)

            return {
                "valid": True,
                "magic": values[0].decode("ascii", errors="ignore"),
                "checksum": values[1],
                "signature": values[2].hex(),
                "file_size": values[3],
                "header_size": values[4],
                "endian_tag": hex(values[5]),
                "link_size": values[6],
                "link_off": values[7],
                "map_off": values[8],
                "string_ids_size": values[9],
                "string_ids_off": values[10],
                "type_ids_size": values[11],
                "type_ids_off": values[12],
                "proto_ids_size": values[13],
                "proto_ids_off": values[14],
                "field_ids_size": values[15],
                "field_ids_off": values[16],
                "method_ids_size": values[17],
                "method_ids_off": values[18],
                "class_defs_size": values[19],
                "class_defs_off": values[20],
                "data_size": values[21],
                "data_off": values[22]
            }
        except Exception as e:
            return {"valid": False, "error": str(e)}

    def _read_uleb128(self, data: bytes, offset: int) -> Tuple[int, int]:
        """Read unsigned LEB128 value."""
        result = 0
        shift = 0
        max_shift = 63  # Prevent infinite loops
        while offset < len(data) and shift <= max_shift:
            byte = data[offset]
            offset += 1
            result |= (byte & 0x7f) << shift
            if byte & 0x80 == 0:
                break
            shift += 7
        return result, offset

    def _parse_string_table(self, data: bytes, header: Dict) -> List[str]:
        """Parse string_id table and string_data."""
        strings = []
        string_ids_off = header["string_ids_off"]
        string_ids_size = header["string_ids_size"]

        # First get all string_data offsets
        string_data_offsets = []
        for i in range(min(string_ids_size, self.max_strings)):
            off = string_ids_off + i * 4
            if off + 4 <= len(data):
                string_data_off = struct.unpack(f"{self._struct_endian}I", data[off:off+4])[0]
                string_data_offsets.append(string_data_off)

        # Now read each string
        for string_data_off in string_data_offsets:
            if string_data_off >= len(data):
                strings.append("")
                continue

            # Read ULEB128 length
            length, offset = self._read_uleb128(data, string_data_off)

            # Read UTF-8 string
            if offset + length <= len(data):
                string_bytes = data[offset:offset+length]
                try:
                    strings.append(string_bytes.decode("utf-8", errors="replace"))
                except:
                    strings.append("")
            else:
                strings.append("")

        return strings

    def _parse_type_table(self, data: bytes, header: Dict, strings: List[str]) -> List[str]:
        """Parse type_id table."""
        types = []
        type_ids_off = header["type_ids_off"]
        type_ids_size = header["type_ids_size"]

        for i in range(type_ids_size):
            off = type_ids_off + i * 4
            if off + 4 <= len(data):
                string_idx = struct.unpack(f"{self._struct_endian}I", data[off:off+4])[0]
                if string_idx < len(strings):
                    types.append(strings[string_idx])
                else:
                    types.append(f"type_{string_idx}")
            else:
                types.append(f"type_{i}")

        return types

    def _parse_proto_table(self, data: bytes, header: Dict, strings: List[str], types: List[str]) -> List[Dict]:
        """Parse proto_id table."""
        protos = []
        proto_ids_off = header["proto_ids_off"]
        proto_ids_size = header["proto_ids_size"]

        for i in range(proto_ids_size):
            off = proto_ids_off + i * 12
            if off + 12 <= len(data):
                shorty_idx, return_type_idx, parameters_off = struct.unpack(f"{self._struct_endian}III", data[off:off+12])
                proto = {
                    "shorty": strings[shorty_idx] if shorty_idx < len(strings) else f"shorty_{shorty_idx}",
                    "return_type": types[return_type_idx] if return_type_idx < len(types) else f"type_{return_type_idx}",
                    "parameters": []
                }

                if parameters_off > 0 and parameters_off < len(data):
                    # Parse type_list
                    size = struct.unpack(f"{self._struct_endian}I", data[parameters_off:parameters_off+4])[0]
                    for j in range(size):
                        param_off = parameters_off + 4 + j * 2
                        if param_off + 2 <= len(data):
                            type_idx = struct.unpack(f"{self._struct_endian}H", data[param_off:param_off+2])[0]
                            proto["parameters"].append(types[type_idx] if type_idx < len(types) else f"type_{type_idx}")

                protos.append(proto)
            else:
                protos.append({"shorty": "", "return_type": "", "parameters": []})

        return protos

    def _parse_field_table(self, data: bytes, header: Dict, strings: List[str], types: List[str]) -> List[Dict]:
        """Parse field_id table."""
        fields = []
        field_ids_off = header["field_ids_off"]
        field_ids_size = header["field_ids_size"]

        for i in range(field_ids_size):
            off = field_ids_off + i * 8
            if off + 8 <= len(data):
                class_idx, type_idx, name_idx = struct.unpack(f"{self._struct_endian}HH I", data[off:off+8])
                fields.append({
                    "class": types[class_idx] if class_idx < len(types) else f"class_{class_idx}",
                    "type": types[type_idx] if type_idx < len(types) else f"type_{type_idx}",
                    "name": strings[name_idx] if name_idx < len(strings) else f"name_{name_idx}"
                })
            else:
                fields.append({"class": "", "type": "", "name": ""})

        return fields

    def _parse_method_table(self, data: bytes, header: Dict, strings: List[str], types: List[str], protos: List[Dict]) -> List[Dict]:
        """Parse method_id table."""
        methods = []
        method_ids_off = header["method_ids_off"]
        method_ids_size = header["method_ids_size"]

        for i in range(method_ids_size):
            off = method_ids_off + i * 8
            if off + 8 <= len(data):
                class_idx, proto_idx, name_idx = struct.unpack(f"{self._struct_endian}HH I", data[off:off+8])
                proto = protos[proto_idx] if proto_idx < len(protos) else {}
                methods.append({
                    "class": types[class_idx] if class_idx < len(types) else f"class_{class_idx}",
                    "proto": proto,
                    "name": strings[name_idx] if name_idx < len(strings) else f"name_{name_idx}"
                })
            else:
                methods.append({"class": "", "proto": {}, "name": ""})

        return methods

    def _parse_class_defs(self, data: bytes, header: Dict, strings: List[str], types: List[str],
                          fields: List[Dict], methods: List[Dict]) -> List[Dict]:
        """Parse class_def table."""
        classes = []
        class_defs_off = header["class_defs_off"]
        class_defs_size = header["class_defs_size"]

        for i in range(min(class_defs_size, self.max_classes)):
            off = class_defs_off + i * 32
            if off + 32 <= len(data):
                # class_def is 32 bytes: class_idx[4], access_flags[2], superclass_idx[2], interfaces_off[4],
                # source_file_idx[4], annotations_off[4], class_data_off[4], static_values_off[4] = 28 bytes + 4 padding
                (class_idx, access_flags, superclass_idx, interfaces_off,
                 source_file_idx, annotations_off, class_data_off, static_values_off) = struct.unpack(f"{self._struct_endian}IHHI IIII", data[off:off+28])

                class_info = {
                    "class": types[class_idx] if class_idx < len(types) else f"class_{class_idx}",
                    "access_flags": access_flags,
                    "access_flags_str": self._decode_access_flags(access_flags),
                    "superclass": types[superclass_idx] if superclass_idx != 0xFFFFFFFF and superclass_idx < len(types) else None,
                    "source_file": strings[source_file_idx] if source_file_idx != 0xFFFFFFFF and source_file_idx < len(strings) else None,
                    "interfaces": [],
                    "static_fields": [],
                    "instance_fields": [],
                    "direct_methods": [],
                    "virtual_methods": []
                }

                # Parse interfaces
                if interfaces_off > 0 and interfaces_off + 4 <= len(data):
                    size = struct.unpack(f"{self._struct_endian}I", data[interfaces_off:interfaces_off+4])[0]
                    # Validate size is reasonable (max 1000 interfaces per class)
                    if size <= 1000 and interfaces_off + 4 + size * 2 <= len(data):
                        for j in range(size):
                            iface_off = interfaces_off + 4 + j * 2
                            if iface_off + 2 <= len(data):
                                iface_idx = struct.unpack(f"{self._struct_endian}H", data[iface_off:iface_off+2])[0]
                                class_info["interfaces"].append(types[iface_idx] if iface_idx < len(types) else f"iface_{iface_idx}")

                # Parse class_data (fields and methods)
                if class_data_off > 0 and class_data_off < len(data):
                    class_data = self._parse_class_data(data, class_data_off, fields, methods, strings)
                    class_info.update(class_data)

                classes.append(class_info)

        return classes

    def _parse_class_data(self, data: bytes, offset: int, fields: List[Dict], methods: List[Dict], strings: List[str]) -> Dict:
        """Parse class_data_item (encoded with ULEB128)."""
        # header: static_fields_size, instance_fields_size, direct_methods_size, virtual_methods_size
        static_fields_size, offset = self._read_uleb128(data, offset)
        instance_fields_size, offset = self._read_uleb128(data, offset)
        direct_methods_size, offset = self._read_uleb128(data, offset)
        virtual_methods_size, offset = self._read_uleb128(data, offset)

        result = {
            "static_fields": [],
            "instance_fields": [],
            "direct_methods": [],
            "virtual_methods": []
        }

        # Limits per class
        max_fields_per_class = 100
        max_methods_per_class = 50

        # Parse fields (using encoded indices)
        field_idx = 0
        for _ in range(min(static_fields_size, max_fields_per_class)):
            field_idx, offset = self._read_encoded_field(data, offset, field_idx)
            if field_idx < len(fields):
                result["static_fields"].append(fields[field_idx])

        for _ in range(min(instance_fields_size, max_fields_per_class)):
            field_idx, offset = self._read_encoded_field(data, offset, field_idx)
            if field_idx < len(fields):
                result["instance_fields"].append(fields[field_idx])

        # Parse methods
        method_idx = 0
        for _ in range(min(direct_methods_size, max_methods_per_class)):
            method_idx, method_data, offset = self._read_encoded_method(data, offset, method_idx)
            if method_idx < len(methods):
                m = methods[method_idx].copy()
                m.update(method_data)
                result["direct_methods"].append(m)

        for _ in range(min(virtual_methods_size, max_methods_per_class)):
            method_idx, method_data, offset = self._read_encoded_method(data, offset, method_idx)
            if method_idx < len(methods):
                m = methods[method_idx].copy()
                m.update(method_data)
                result["virtual_methods"].append(m)

        return result

    def _read_encoded_field(self, data: bytes, offset: int, last_idx: int) -> Tuple[int, int]:
        """Read encoded field (index_diff, access_flags)."""
        index_diff, offset = self._read_uleb128(data, offset)
        access_flags, offset = self._read_uleb128(data, offset)
        return last_idx + index_diff, offset

    def _read_encoded_method(self, data: bytes, offset: int, last_idx: int) -> Tuple[int, Dict, int]:
        """Read encoded method (index_diff, access_flags, code_off)."""
        index_diff, offset = self._read_uleb128(data, offset)
        access_flags, offset = self._read_uleb128(data, offset)
        code_off, offset = self._read_uleb128(data, offset)
        new_idx = last_idx + index_diff

        method_data = {
            "access_flags": access_flags,
            "access_flags_str": self._decode_access_flags(access_flags),
            "code_off": code_off,
            "is_native": bool(access_flags & self.ACC_NATIVE),
            "is_abstract": bool(access_flags & self.ACC_ABSTRACT)
        }

        return new_idx, method_data, offset

    def _analyze_method_bytecode(self, data: bytes, header: Dict, result: Dict,
                                  classes: List[Dict], types: List[str], methods: List[Dict],
                                  fields: List[Dict], protos: List[Dict], strings: List[str]):
        """Analyze bytecode for all methods."""
        # Build lookup maps
        type_to_class = {c["class"]: c for c in classes}
        method_by_class = defaultdict(list)
        for m in methods:
            method_by_class[m["class"]].append(m)

        # Suspicious API patterns
        suspicious_apis = {
            "reflection": [
                "java.lang.Class.forName",
                "java.lang.Class.getMethod",
                "java.lang.Class.getField",
                "java.lang.reflect.Method.invoke",
                "java.lang.reflect.Field.set",
                "java.lang.reflect.Constructor.newInstance"
            ],
            "dynamic_loading": [
                "dalvik.system.DexClassLoader",
                "dalvik.system.PathClassLoader",
                "dalvik.system.InMemoryDexClassLoader",
                "java.lang.ClassLoader.loadClass",
                "java.lang.ClassLoader.defineClass"
            ],
            "command_execution": [
                "java.lang.Runtime.exec",
                "java.lang.ProcessBuilder.start",
                "java.lang.ProcessBuilder.command"
            ],
            "webview": [
                "android.webkit.WebView.addJavascriptInterface",
                "android.webkit.WebSettings.setJavaScriptEnabled",
                "android.webkit.WebView.loadUrl",
                "android.webkit.WebView.evaluateJavascript"
            ],
            "accessibility": [
                "android.accessibilityservice.AccessibilityService",
                "android.view.accessibility.AccessibilityEvent"
            ],
            "media_projection": [
                "android.media.projection.MediaProjection",
                "android.media.projection.MediaProjectionManager.createScreenCaptureIntent"
            ],
            "device_admin": [
                "android.app.admin.DeviceAdminReceiver",
                "android.app.admin.DevicePolicyManager",
                "android.app.admin.DevicePolicyManager.wipeData",
                "android.app.admin.DevicePolicyManager.resetPassword"
            ],
            "vpn": [
                "android.net.VpnService",
                "android.net.VpnService.Builder",
                "android.net.VpnService.protect"
            ],
            "native": [
                "java.lang.System.loadLibrary",
                "java.lang.System.load",
                "java.lang.Runtime.loadLibrary"
            ],
            "crypto": [
                "javax.crypto.Cipher.getInstance",
                "java.security.MessageDigest.getInstance",
                "javax.crypto.spec.SecretKeySpec",
                "javax.crypto.spec.IvParameterSpec"
            ],
            "network": [
                "java.net.URL.openConnection",
                "java.net.HttpURLConnection",
                "okhttp3.OkHttpClient",
                "java.net.Socket",
                "java.net.ServerSocket",
                "java.net.DatagramSocket"
            ],
            "anti_analysis": [
                "android.os.Build.TYPE",
                "android.os.Build.FINGERPRINT",
                "android.os.Debug.isDebuggerConnected",
                "android.os.Debug.waitingForDebugger"
            ],
            "sms": [
                "android.telephony.SmsManager.sendTextMessage",
                "android.telephony.SmsManager.sendMultipartTextMessage"
            ],
            "contacts": [
                "android.provider.ContactsContract",
                "android.content.ContentResolver.query"
            ],
            "location": [
                "android.location.LocationManager.requestLocationUpdates",
                "android.location.LocationManager.getLastKnownLocation"
            ]
        }

        api_calls = []
        suspicious_findings = []
        methods_analyzed = 0
        max_methods_to_analyze = self.max_methods

        for class_info in classes:
            class_name = class_info["class"]

            # Analyze direct methods
            for method in class_info.get("direct_methods", []) + class_info.get("virtual_methods", []):
                if methods_analyzed >= max_methods_to_analyze:
                    break
                if method.get("is_native") or method.get("is_abstract"):
                    continue

                code_off = method.get("code_off", 0)
                if code_off == 0:
                    continue

                # Parse code_item
                bytecode_analysis = self._parse_code_item(data, code_off, types, methods, fields, strings)

                if bytecode_analysis:
                    method["bytecode"] = bytecode_analysis

                    # Check for suspicious API calls
                    for call in bytecode_analysis.get("method_calls", []):
                        for category, patterns in suspicious_apis.items():
                            for pattern in patterns:
                                if pattern in call:
                                    suspicious_findings.append({
                                        "category": category,
                                        "pattern": pattern,
                                        "class": class_name,
                                        "method": method.get("name", ""),
                                        "call": call
                                    })
                                    break

                    # Collect all API calls
                    for call in bytecode_analysis.get("method_calls", []):
                        api_calls.append({
                            "class": class_name,
                            "method": method.get("name", ""),
                            "call": call
                        })
                    methods_analyzed += 1

            if methods_analyzed >= max_methods_to_analyze:
                break

        result["api_calls"] = api_calls[:2000]
        result["suspicious_patterns"] = suspicious_findings[:200]

    def _parse_code_item(self, data: bytes, offset: int, types: List[str],
                         methods: List[Dict], fields: List[Dict], strings: List[str]) -> Optional[Dict]:
        """Parse code_item structure and extract bytecode instructions."""
        if offset >= len(data):
            return None

        try:
            # code_item header
            # registers_size[2], ins_size[2], outs_size[2], tries_size[2],
            # debug_info_off[4], insns_size[4]
            header_fmt = "<HHHHII"
            header_size = struct.calcsize(header_fmt)

            if offset + header_size > len(data):
                return None

            (registers_size, ins_size, outs_size, tries_size,
             debug_info_off, insns_size) = struct.unpack(f"{self._struct_endian}HHHHII", data[offset:offset+header_size])

            offset += header_size

            # Read instructions
            insns_data = data[offset:offset + insns_size * 2]

            # Parse instructions
            instructions = []
            method_calls = []
            string_refs = []
            field_refs = []
            type_refs = []

            pc = 0
            i = 0
            instruction_count = 0
            while i < len(insns_data) and instruction_count < self.max_instructions:
                if i >= len(insns_data):
                    break

                opcode = insns_data[i]
                op_name = self.OPCODES.get(opcode, f"unknown_{opcode:02x}")

                instr = {"pc": pc, "opcode": opcode, "name": op_name}

                # Parse based on instruction format (simplified)
                # This is a basic parser - full implementation would need all formats
                if op_name in ["const-string", "const-string/jumbo"]:
                    # format 21c: opcode, A, string_idx
                    if i + 4 <= len(insns_data):
                        string_idx = struct.unpack(f"{self._struct_endian}H", insns_data[i+2:i+4])[0]
                        if string_idx < len(strings):
                            ref = strings[string_idx]
                            instr["string_ref"] = ref
                            string_refs.append(ref)

                elif op_name in ["const-class"]:
                    # format 21c
                    if i + 4 <= len(insns_data):
                        type_idx = struct.unpack(f"{self._struct_endian}H", insns_data[i+2:i+4])[0]
                        if type_idx < len(types):
                            ref = types[type_idx]
                            instr["type_ref"] = ref
                            type_refs.append(ref)

                elif op_name in ["invoke-virtual", "invoke-super", "invoke-direct",
                                "invoke-static", "invoke-interface"]:
                    # format 35c: opcode, A, G, method_idx
                    if i + 6 <= len(insns_data):
                        method_idx = struct.unpack(f"{self._struct_endian}H", insns_data[i+4:i+6])[0]
                        if method_idx < len(methods):
                            m = methods[method_idx]
                            call_str = f"{m['class']}.{m['name']}{m['proto'].get('shorty', '')}"
                            instr["method_call"] = call_str
                            method_calls.append(call_str)

                elif op_name in ["invoke-virtual/range", "invoke-super/range",
                                "invoke-direct/range", "invoke-static/range",
                                "invoke-interface/range"]:
                    # format 3rc
                    if i + 6 <= len(insns_data):
                        method_idx = struct.unpack(f"{self._struct_endian}H", insns_data[i+4:i+6])[0]
                        if method_idx < len(methods):
                            m = methods[method_idx]
                            call_str = f"{m['class']}.{m['name']}{m['proto'].get('shorty', '')}"
                            instr["method_call"] = call_str
                            method_calls.append(call_str)

                elif op_name in ["new-instance", "check-cast", "instance-of", "new-array"]:
                    # format 21c or 22c
                    if i + 4 <= len(insns_data):
                        type_idx = struct.unpack(f"{self._struct_endian}H", insns_data[i+2:i+4])[0]
                        if type_idx < len(types):
                            ref = types[type_idx]
                            instr["type_ref"] = ref
                            type_refs.append(ref)

                elif op_name in ["iget", "iput", "sget", "sput",
                                "iget-wide", "iput-wide", "sget-wide", "sput-wide",
                                "iget-object", "iput-object", "sget-object", "sput-object",
                                "iget-boolean", "iput-boolean", "sget-boolean", "sput-boolean",
                                "iget-byte", "iput-byte", "sget-byte", "sput-byte",
                                "iget-char", "iput-char", "sget-char", "sput-char",
                                "iget-short", "iput-short", "sget-short", "sput-short"]:
                    # format 22c
                    if i + 6 <= len(insns_data):
                        field_idx = struct.unpack(f"{self._struct_endian}H", insns_data[i+4:i+6])[0]
                        if field_idx < len(fields):
                            f = fields[field_idx]
                            ref = f"{f['class']}.{f['name']}:{f['type']}"
                            instr["field_ref"] = ref
                            field_refs.append(ref)

                instructions.append(instr)
                pc += 1
                instruction_count += 1
                i += 2  # Each instruction is at least 2 bytes (16-bit aligned)

            return {
                "registers_size": registers_size,
                "ins_size": ins_size,
                "outs_size": outs_size,
                "instruction_count": len(instructions),
                "instructions": instructions[:500],  # Limit
                "method_calls": list(set(method_calls)),
                "string_references": list(set(string_refs)),
                "field_references": list(set(field_refs)),
                "type_references": list(set(type_refs))
            }

        except Exception as e:
            return {"error": str(e), "instruction_count": 0}

    def _decode_access_flags(self, flags: int) -> List[str]:
        """Decode access flags to human-readable strings."""
        result = []
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
                result.append(name)
        return result

    def _compute_statistics(self, result: Dict) -> Dict[str, Any]:
        """Compute analysis statistics."""
        stats = {
            "total_classes": len(result.get("classes", [])),
            "total_methods": len(result.get("methods", [])),
            "total_strings": len(result.get("strings", [])),
            "total_api_calls": len(result.get("api_calls", [])),
            "suspicious_patterns": len(result.get("suspicious_patterns", [])),
            "native_methods": 0,
            "abstract_methods": 0,
            "public_classes": 0,
            "interfaces": 0,
            "enums": 0
        }

        for cls in result.get("classes", []):
            flags = cls.get("access_flags_str", [])
            if "public" in flags:
                stats["public_classes"] += 1
            if "interface" in flags:
                stats["interfaces"] += 1
            if "enum" in flags:
                stats["enums"] += 1

        for method in result.get("methods", []):
            if method.get("is_native"):
                stats["native_methods"] += 1
            if method.get("is_abstract"):
                stats["abstract_methods"] += 1

        return stats


def analyze_dex_bytecode(dex_path: Path, config: Dict = None) -> Dict[str, Any]:
    """Convenience function to analyze a DEX file at bytecode level."""
    analyzer = DEXBytecodeAnalyzer(config)
    return analyzer.analyze(dex_path)