"""
Deep JNI Analyzer for APKStudioAI 2.1
Locates JNI_OnLoad, RegisterNatives, JNINativeMethod tables
Maps ELF virtual addresses to file offsets, identifies native functions
Uses pyelftools + Capstone (no external readelf/objdump dependency)
"""
import struct
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from .utils import is_elf_file
from .elf_analyzer import ELFAnalyzer


class JNIAnalyzer:
    def __init__(self):
        self.elf_analyzer = ELFAnalyzer()

    def analyze(self, so_path: Path, java_classes: List[Dict] = None) -> Dict[str, Any]:
        """Perform deep JNI analysis on a native library."""
        result = {
            "library": so_path.name,
            "jni_onload": {"found": False, "address": None, "offset": None, "disassembly": []},
            "register_natives_calls": [],
            "native_methods": [],
            "class_mappings": [],
            "unresolved_tables": [],
            "cross_references": [],
            "limitations": []
        }

        if not is_elf_file(so_path):
            result["limitations"].append("Not a valid ELF file")
            return result

        # Get ELF info (includes Capstone disassembly capability)
        elf_info = self.elf_analyzer.analyze(so_path)

        if "error" in elf_info:
            result["limitations"].append(f"ELF analysis error: {elf_info['error']}")
            return result

        # 1. Find JNI_OnLoad
        result["jni_onload"] = self._analyze_jni_onload(so_path, elf_info)

        # 2. Find RegisterNatives calls (using relocations + Capstone disassembly)
        result["register_natives_calls"] = self._find_register_natives_calls(so_path, elf_info)

        # 3. Extract JNINativeMethod tables (struct parsing + Capstone analysis)
        result["native_methods"] = self._extract_native_methods(so_path, elf_info)

        # 4. Map to Java classes
        if java_classes:
            result["class_mappings"] = self._map_to_java_classes(result["native_methods"], java_classes)

        # 5. Cross-references (using Capstone disassembly)
        result["cross_references"] = self._find_cross_references(so_path, elf_info)

        return result

    def _analyze_jni_onload(self, so_path: Path, elf_info: Dict) -> Dict[str, Any]:
        """Analyze JNI_OnLoad function with Capstone disassembly."""
        jni_info = {
            "found": False,
            "address": None,
            "offset": None,
            "disassembly": [],
            "register_natives_calls": []
        }

        # Check exports for JNI_OnLoad
        for exp in elf_info.get("exports", []):
            if exp.get("name") == "JNI_OnLoad":
                jni_info["found"] = True
                jni_info["address"] = exp.get("value") if "value" in exp else exp.get("address")
                jni_info["offset"] = self._vaddr_to_offset(elf_info, jni_info["address"])
                break

        if not jni_info["found"]:
            # Search in symbols
            for sym in elf_info.get("symbols", []):
                if sym.get("name") == "JNI_OnLoad":
                    jni_info["found"] = True
                    jni_info["address"] = sym.get("value")
                    jni_info["offset"] = self._vaddr_to_offset(elf_info, sym.get("value"))
                    break

        if jni_info["found"] and jni_info["offset"]:
            # Disassemble JNI_OnLoad using Capstone
            disasm = self.elf_analyzer.disassemble_at_offset(so_path, jni_info["offset"], max_instructions=200)
            if disasm and isinstance(disasm, list):
                jni_info["disassembly"] = disasm
                # Analyze disassembly for RegisterNatives calls
                jni_info["register_natives_calls"] = self._analyze_disassembly_for_reg_natives(disasm, so_path, elf_info)

        return jni_info

    def _find_register_natives_calls(self, so_path: Path, elf_info: Dict) -> List[Dict[str, Any]]:
        """Find all calls to RegisterNatives using relocations and disassembly."""
        calls = []

        # Check imports for RegisterNatives
        for imp in elf_info.get("imports", []):
            if "RegisterNatives" in imp.get("name", ""):
                calls.append({
                    "type": "import",
                    "function": imp.get("name"),
                    "library": imp.get("library", "libjvm.so")
                })

        # Search for RegisterNatives in relocations
        for rel in elf_info.get("relocations", []):
            if "RegisterNatives" in rel.get("symbol", ""):
                calls.append({
                    "type": "relocation",
                    "offset": rel.get("offset"),
                    "symbol": rel.get("symbol"),
                    "addend": rel.get("addend", 0)
                })

        # Search in code sections using Capstone disassembly
        # Disassemble each code section and look for calls to RegisterNatives
        for sec_name, sec_data in elf_info.get("section_data", {}).items():
            vaddr = sec_data.get("vaddr", 0)
            if isinstance(vaddr, str):
                vaddr = int(vaddr, 16)
            offset = sec_data.get("offset", 0)

            disasm = self.elf_analyzer.disassemble_at_offset(so_path, offset, max_instructions=500)
            if disasm and isinstance(disasm, list):
                for insn in disasm:
                    if "RegisterNatives" in insn.get("op_str", "") or \
                       (insn.get("mnemonic") in ("bl", "call", "blx") and
                        self._is_register_natives_target(insn, elf_info)):
                        calls.append({
                            "type": "code_reference",
                            "address": insn.get("address"),
                            "instruction": f"{insn.get('mnemonic')} {insn.get('op_str')}",
                            "section": sec_name
                        })

        return calls[:50]

    def _is_register_natives_target(self, insn: Dict, elf_info: Dict) -> bool:
        """Check if instruction targets RegisterNatives."""
        op_str = insn.get("op_str", "")
        # Check if operand contains RegisterNatives address
        for imp in elf_info.get("imports", []):
            if "RegisterNatives" in imp.get("name", ""):
                imp_addr = imp.get("value") if "value" in imp else imp.get("address")
                if imp_addr and imp_addr in op_str:
                    return True
        return False

    def _analyze_disassembly_for_reg_natives(self, disasm: List[Dict], so_path: Path, elf_info: Dict) -> List[Dict]:
        """Analyze JNI_OnLoad disassembly for RegisterNatives calls and method tables."""
        calls = []
        for i, insn in enumerate(disasm):
            mnemonic = insn.get("mnemonic", "")
            op_str = insn.get("op_str", "")

            # Look for call/bl to RegisterNatives
            if mnemonic in ("bl", "call", "blx") and "RegisterNatives" in op_str:
                # Look backwards for method table setup (adrp/ldr on ARM64, lea/mov on x86)
                table_addr = self._find_method_table_before_call(disasm, i, elf_info)
                calls.append({
                    "address": insn.get("address"),
                    "instruction": f"{mnemonic} {op_str}",
                    "method_table_address": table_addr
                })
        return calls

    def _find_method_table_before_call(self, disasm: List[Dict], call_index: int, elf_info: Dict) -> Optional[str]:
        """Look for method table address loaded before RegisterNatives call."""
        # Search backwards for address loads
        for i in range(max(0, call_index - 20), call_index):
            insn = disasm[i]
            mnemonic = insn.get("mnemonic", "")
            op_str = insn.get("op_str", "")

            # ARM64: adrp + ldr, x86: lea/mov
            if mnemonic in ("adrp", "ldr", "lea", "mov") and ("x0" in op_str or "x1" in op_str or "rdi" in op_str or "rsi" in op_str):
                # This might be loading the method table pointer
                # Extract address from operand
                import re
                addr_match = re.search(r'0x[0-9a-f]+', op_str)
                if addr_match:
                    return addr_match.group(0)
        return None

    def _extract_native_methods(self, so_path: Path, elf_info: Dict) -> List[Dict[str, Any]]:
        """Extract JNINativeMethod tables from the binary using struct parsing."""
        methods = []

        # Strategy 1: Use ELF analyzer's struct-based JNINativeMethod table finder
        tables = self.elf_analyzer.find_jni_native_method_tables(so_path)
        for table in tables:
            methods.append({
                "class_name": self._extract_class_from_method_name(table.get("name", "")),
                "method_name": table.get("name", ""),
                "signature": table.get("signature", ""),
                "native_function": table.get("function", ""),
                "address": table.get("function_address", ""),
                "table_address": table.get("table_address", ""),
                "table_offset": table.get("table_offset", ""),
                "source": "jni_table"
            })

        # Strategy 2: Analyze JNI_OnLoad for RegisterNatives with method tables
        jni_onload = None
        for exp in elf_info.get("exports", []):
            if exp.get("name") == "JNI_OnLoad":
                jni_onload = exp.get("value") if "value" in exp else exp.get("address")
                break

        if jni_onload:
            methods.extend(self._analyze_jni_onload_body(so_path, elf_info, jni_onload))

        # Strategy 3: Export-based - find all Java_* functions
        methods.extend(self._find_java_native_exports(elf_info))

        # Deduplicate
        seen = set()
        unique = []
        for m in methods:
            key = (m.get("class_name"), m.get("method_name"), m.get("signature"))
            if key not in seen:
                seen.add(key)
                unique.append(m)

        return unique[:200]

    def _analyze_jni_onload_body(self, so_path: Path, elf_info: Dict, jni_onload_addr: int) -> List[Dict]:
        """Analyze JNI_OnLoad function body for RegisterNatives calls using Capstone."""
        methods = []

        # Disassemble JNI_OnLoad using Capstone
        offset = self._vaddr_to_offset(elf_info, jni_onload_addr)
        if not offset:
            return methods

        disasm = self.elf_analyzer.disassemble_at_offset(so_path, offset, max_instructions=300)
        if not disasm or not isinstance(disasm, list):
            return methods

        # Look for RegisterNatives call and trace method table
        for i, insn in enumerate(disasm):
            mnemonic = insn.get("mnemonic", "")
            op_str = insn.get("op_str", "")

            if mnemonic in ("bl", "call", "blx") and "RegisterNatives" in op_str:
                # Found RegisterNatives call - trace back for method table
                table_info = self._trace_register_natives_args(disasm, i, so_path, elf_info)
                if table_info:
                    methods.extend(table_info)

        return methods

    def _trace_register_natives_args(self, disasm: List[Dict], call_index: int,
                                      so_path: Path, elf_info: Dict) -> List[Dict]:
        """Trace RegisterNatives arguments to find method table."""
        methods = []

        # RegisterNatives signature: jint RegisterNatives(JNIEnv* env, jclass clazz,
        #                                                const JNINativeMethod* methods, jint nMethods)
        # On ARM64: x0=env, x1=clazz, x2=methods, x3=nMethods
        # On x86_64: rdi=env, rsi=clazz, rdx=methods, rcx=nMethods

        # Look backwards for x2/rdx (methods pointer) and x3/rcx (nMethods)
        methods_ptr = None
        nmethods = None

        for i in range(max(0, call_index - 30), call_index):
            insn = disasm[i]
            mnemonic = insn.get("mnemonic", "")
            op_str = insn.get("op_str", "")

            # ARM64: mov x2, <addr> or ldr x2, [xN] or adrp+add
            # x86_64: mov rdx, <addr> or lea rdx, [rip+...]
            if "x2" in op_str or "rdx" in op_str:
                import re
                addr_match = re.search(r'0x[0-9a-f]+', op_str)
                if addr_match:
                    methods_ptr = int(addr_match.group(0), 16)

            if "x3" in op_str or "rcx" in op_str or "ecx" in op_str:
                import re
                val_match = re.search(r'#?(\d+)', op_str)
                if val_match:
                    nmethods = int(val_match.group(1))

        if methods_ptr and nmethods and nmethods > 0 and nmethods < 500:
            # Read method table from memory
            methods.extend(self._read_jni_method_table(so_path, elf_info, methods_ptr, nmethods))

        return methods

    def _read_jni_method_table(self, so_path: Path, elf_info: Dict, table_vaddr: int, count: int) -> List[Dict]:
        """Read JNINativeMethod table from virtual address."""
        methods = []

        # Convert virtual address to file offset
        file_offset = self._vaddr_to_offset(elf_info, table_vaddr)
        if not file_offset:
            return methods

        try:
            data = so_path.read_bytes()
            if file_offset + count * 24 > len(data):  # 24 bytes per entry (3*8 for 64-bit)
                # Try 32-bit: 12 bytes per entry
                if file_offset + count * 12 > len(data):
                    return methods
                entry_size = 12
                ptr_size = 4
            else:
                entry_size = 24
                ptr_size = 8

            endian = '<' if elf_info.get("header", {}).get("endianness") == "little" else '>'
            ptr_fmt = 'Q' if ptr_size == 8 else 'I'

            # Build string and function maps
            str_map = self._build_string_map(elf_info, so_path)
            func_map = self._build_function_map(elf_info)

            for i in range(count):
                entry_offset = file_offset + i * entry_size
                if entry_offset + entry_size > len(data):
                    break

                entry_data = data[entry_offset:entry_offset + entry_size]

                try:
                    name_ptr = struct.unpack(f"{endian}{ptr_fmt}", entry_data[0:ptr_size])[0]
                    sig_ptr = struct.unpack(f"{endian}{ptr_fmt}", entry_data[ptr_size:2*ptr_size])[0]
                    fn_ptr = struct.unpack(f"{endian}{ptr_fmt}", entry_data[2*ptr_size:3*ptr_size])[0]

                    name_str = self._resolve_string(name_ptr, str_map, so_path, elf_info)
                    sig_str = self._resolve_string(sig_ptr, str_map, so_path, elf_info)
                    fn_name = func_map.get(fn_ptr, f"sub_{fn_ptr:x}")

                    if name_str and sig_str:
                        methods.append({
                            "class_name": self._extract_class_from_method_name(name_str),
                            "method_name": name_str,
                            "signature": sig_str,
                            "native_function": fn_name,
                            "address": hex(fn_ptr),
                            "table_index": i,
                            "source": "jni_table_parsed"
                        })
                except Exception:
                    continue

        except Exception:
            pass

        return methods

    def _build_string_map(self, elf_info: Dict, so_path: Path) -> Dict[int, str]:
        """Build map of string pointer addresses to string values."""
        str_map = {}

        for sec_name, sec_data in elf_info.get("section_data", {}).items():
            if sec_name in (".rodata", ".data", ".dynstr", ".strtab", ".data.rel.ro"):
                data = sec_data.get("data", b"")
                vaddr = sec_data.get("vaddr", 0)
                if isinstance(vaddr, str):
                    vaddr = int(vaddr, 16)

                pos = 0
                while pos < len(data):
                    if data[pos] != 0:
                        start = pos
                        while pos < len(data) and data[pos] != 0:
                            pos += 1
                        if pos > start:
                            try:
                                s = data[start:pos].decode("utf-8", errors="ignore")
                                if len(s) >= 2:
                                    str_map[vaddr + start] = s
                            except Exception:
                                pass
                    pos += 1

        return str_map

    def _build_function_map(self, elf_info: Dict) -> Dict[int, str]:
        """Build map of function addresses to names from symbols."""
        func_map = {}
        for sym in elf_info.get("symbols", []):
            if sym.get("name") and sym.get("type") == "STT_FUNC":
                try:
                    val = sym.get("value")
                    if isinstance(val, str):
                        val = int(val, 16)
                    func_map[val] = sym.get("name")
                except Exception:
                    pass
        return func_map

    def _resolve_string(self, ptr: int, str_map: Dict, so_path: Path, elf_info: Dict) -> Optional[str]:
        """Resolve string pointer to actual string."""
        if ptr in str_map:
            return str_map[ptr]

        # Try reading directly from file
        file_offset = self._vaddr_to_offset(elf_info, ptr)
        if file_offset:
            try:
                data = so_path.read_bytes()
                s_data = data[file_offset:file_offset+256]
                end = s_data.find(b'\x00')
                if end > 0:
                    return s_data[:end].decode("utf-8", errors="ignore")
            except Exception:
                pass
        return None

    def _find_native_method_tables(self, so_path: Path, elf_info: Dict) -> List[Dict[str, Any]]:
        """Search for JNINativeMethod structures in data sections (legacy fallback)."""
        methods = []

        try:
            data = so_path.read_bytes()

            for exp in elf_info.get("exports", []):
                name = exp.get("name", "")
                if name.startswith("Java_"):
                    parts = name[5:].split("_")
                    if len(parts) >= 3:
                        class_name = "/".join(parts[:-1]).replace("_", "/")
                        method_name = parts[-1]
                        methods.append({
                            "class_name": class_name,
                            "method_name": method_name,
                            "signature": "unknown",
                            "native_function": name,
                            "address": exp.get("address"),
                            "source": "export"
                        })

        except Exception:
            pass

        return methods

    def _find_java_native_exports(self, elf_info: Dict) -> List[Dict[str, Any]]:
        """Find all Java_* exported functions with proper JNI name parsing."""
        methods = []

        for exp in elf_info.get("exports", []):
            name = exp.get("name", "")
            if name.startswith("Java_"):
                # Parse JNI mangled name properly
                class_name, method_name = self._parse_jni_export_name(name[5:])
                methods.append({
                    "class_name": class_name,
                    "method_name": method_name,
                    "signature": "unknown",
                    "native_function": name,
                    "address": exp.get("address"),
                    "source": "export"
                })

        return methods

    def _parse_jni_export_name(self, mangled: str) -> Tuple[str, str]:
        """Parse JNI mangled export name to class and method.

        JNI mangling rules:
        - Java_package_class_method
        - '_' -> '_1'
        - ';' -> '_2'
        - '[' -> '_3'
        - '/' in package becomes '_'
        """
        parts = mangled.split("_")
        if len(parts) < 2:
            return "", ""

        # Last part is method name
        method_name = parts[-1]
        # Everything before is class (with package)
        class_parts = parts[:-1]

        # Reconstruct class name with proper unmangling
        class_str = "_".join(class_parts)
        # Unmangle: _1 -> _, _2 -> ;, _3 -> [
        class_str = class_str.replace("_1", "_").replace("_2", ";").replace("_3", "[")
        # Convert package separators
        class_str = class_str.replace("_", "/")

        return class_str, method_name

    def _extract_class_from_method_name(self, name: str) -> str:
        """Extract class name from method name if it follows Java_ pattern."""
        if name.startswith("Java_"):
            class_name, _ = self._parse_jni_export_name(name[5:])
            return class_name
        return ""

    def _map_to_java_classes(self, native_methods: List[Dict], java_classes: List[Dict]) -> List[Dict]:
        """Map native methods to Java class declarations."""
        mappings = []

        # Build lookup from Java classes
        java_native_methods = {}
        for cls in java_classes:
            for method in cls.get("methods", []):
                if method.get("is_native"):
                    key = (cls.get("package", "").replace(".", "/") + "/" + cls.get("name", ""), method.get("name"))
                    java_native_methods[key] = {
                        "class": cls.get("name"),
                        "package": cls.get("package"),
                        "method": method.get("name"),
                        "signature": method.get("signature", "unknown"),
                        "modifiers": method.get("modifiers", "")
                    }

        # Match native methods
        for nm in native_methods:
            class_name = nm.get("class_name", "")
            method_name = nm.get("method_name", "")

            # Try exact match
            key = (class_name, method_name)
            if key in java_native_methods:
                mappings.append({
                    "native": nm,
                    "java": java_native_methods[key],
                    "match": "exact"
                })
            else:
                # Try fuzzy match
                for jkey, jval in java_native_methods.items():
                    if jkey[1] == method_name and jkey[0].endswith(class_name.split("/")[-1]):
                        mappings.append({
                            "native": nm,
                            "java": jval,
                            "match": "fuzzy"
                        })
                        break

        return mappings

    def _find_cross_references(self, so_path: Path, elf_info: Dict) -> List[Dict[str, Any]]:
        """Find cross-references between native functions using Capstone."""
        xrefs = []

        # Disassemble all code sections
        for sec_name, sec_data in elf_info.get("section_data", {}).items():
            offset = sec_data.get("offset", 0)
            disasm = self.elf_analyzer.disassemble_at_offset(so_path, offset, max_instructions=1000)

            if disasm and isinstance(disasm, list):
                current_func = None
                for insn in disasm:
                    # Function labels are typically addresses
                    addr = insn.get("address")
                    mnemonic = insn.get("mnemonic", "")
                    op_str = insn.get("op_str", "")

                    # Heuristic: function entry (simplified)
                    # In real scenario, we'd use symbol table

                    # Call instructions
                    if mnemonic in ("bl", "call", "blx", "bx", "blr", "jr"):
                        import re
                        target_match = re.search(r'0x[0-9a-f]+', op_str)
                        if target_match:
                            xrefs.append({
                                "from_address": addr,
                                "to_address": target_match.group(0),
                                "instruction": f"{mnemonic} {op_str}",
                                "section": sec_name
                            })

        return xrefs[:200]

    def _vaddr_to_offset(self, elf_info: Dict, vaddr) -> Optional[int]:
        """Convert virtual address to file offset."""
        if vaddr is None:
            return None

        try:
            if isinstance(vaddr, str):
                vaddr = int(vaddr, 16)
        except Exception:
            return None

        # Search segments
        for seg in elf_info.get("segments", []):
            vaddr_start = int(seg.get("vaddr", "0"), 16)
            vaddr_end = vaddr_start + seg.get("memsz", 0)
            offset = seg.get("offset", 0)

            if vaddr_start <= vaddr < vaddr_end:
                return offset + (vaddr - vaddr_start)

        # Search sections
        for sec in elf_info.get("sections", []):
            vaddr_start = int(sec.get("addr", "0"), 16)
            vaddr_end = vaddr_start + sec.get("size", 0)
            offset = sec.get("offset", 0)

            if vaddr_start <= vaddr < vaddr_end:
                return offset + (vaddr - vaddr_start)

        return None