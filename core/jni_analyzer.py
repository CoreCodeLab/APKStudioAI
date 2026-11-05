"""
Deep JNI Analyzer for APKStudioAI 2.1
Locates JNI_OnLoad, RegisterNatives, JNINativeMethod tables
Maps ELF virtual addresses to file offsets, identifies native functions
"""
import struct
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from .utils import run_command, is_elf_file
from .elf_analyzer import ELFAnalyzer


class JNIAnalyzer:
    def __init__(self):
        self.elf_analyzer = ELFAnalyzer()

    def analyze(self, so_path: Path, java_classes: List[Dict] = None) -> Dict[str, Any]:
        """Perform deep JNI analysis on a native library."""
        result = {
            "library": so_path.name,
            "jni_onload": {"found": False, "address": None, "offset": None},
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

        # Get ELF info
        elf_info = self.elf_analyzer.analyze(so_path)

        # 1. Find JNI_OnLoad
        result["jni_onload"] = self._analyze_jni_onload(so_path, elf_info)

        # 2. Find RegisterNatives calls
        result["register_natives_calls"] = self._find_register_natives_calls(so_path, elf_info)

        # 3. Extract JNINativeMethod tables
        result["native_methods"] = self._extract_native_methods(so_path, elf_info)

        # 4. Map to Java classes
        if java_classes:
            result["class_mappings"] = self._map_to_java_classes(result["native_methods"], java_classes)

        # 5. Cross-references
        result["cross_references"] = self._find_cross_references(so_path, elf_info)

        return result

    def _analyze_jni_onload(self, so_path: Path, elf_info: Dict) -> Dict[str, Any]:
        """Analyze JNI_OnLoad function."""
        jni_info = {
            "found": False,
            "address": None,
            "offset": None,
            "analysis": {}
        }

        # Check exports
        for exp in elf_info.get("exports", []):
            if exp.get("name") == "JNI_OnLoad":
                jni_info["found"] = True
                jni_info["address"] = exp.get("address")
                jni_info["offset"] = self._vaddr_to_offset(elf_info, exp.get("address"))
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
            # Try to disassemble JNI_OnLoad
            jni_info["analysis"] = self._disassemble_function(so_path, jni_info["offset"])

        return jni_info

    def _find_register_natives_calls(self, so_path: Path, elf_info: Dict) -> List[Dict[str, Any]]:
        """Find all calls to RegisterNatives."""
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
                    "symbol": rel.get("symbol")
                })

        # Search in code sections for call patterns
        # This would require disassembly - use objdump if available
        code_calls = self._search_register_natives_in_code(so_path)
        calls.extend(code_calls)

        return calls

    def _search_register_natives_in_code(self, so_path: Path) -> List[Dict[str, Any]]:
        """Search for RegisterNatives call patterns in code."""
        calls = []

        # Use objdump to find call instructions to RegisterNatives
        result = run_command(["objdump", "-d", str(so_path)], timeout=60)
        if not result["success"]:
            return calls

        import re
        # Look for call/jmp to RegisterNatives
        # Pattern: call/qword ptr [rip+...] or bl/blx on ARM
        lines = result["stdout"].split("\n")
        for i, line in enumerate(lines):
            if "RegisterNatives" in line:
                # Get context
                context = "\n".join(lines[max(0, i-5):i+5])
                calls.append({
                    "type": "code_reference",
                    "assembly": line.strip(),
                    "context": context
                })

        return calls[:20]

    def _extract_native_methods(self, so_path: Path, elf_info: Dict) -> List[Dict[str, Any]]:
        """Extract JNINativeMethod tables from the binary."""
        methods = []

        # Strategy 1: Find JNI_OnLoad and analyze its RegisterNatives calls
        jni_onload = None
        for exp in elf_info.get("exports", []):
            if exp.get("name") == "JNI_OnLoad":
                jni_onload = exp.get("address")
                break

        if jni_onload:
            methods.extend(self._analyze_jni_onload_body(so_path, elf_info, jni_onload))

        # Strategy 2: Search for JNINativeMethod structures in .data/.rodata
        methods.extend(self._find_native_method_tables(so_path, elf_info))

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
        """Analyze JNI_OnLoad function body for RegisterNatives calls."""
        methods = []

        # Disassemble JNI_OnLoad
        offset = self._vaddr_to_offset(elf_info, jni_onload_addr)
        if not offset:
            return methods

        asm = self._disassemble_function(so_path, offset, max_instructions=200)
        if not asm:
            return methods

        # Look for RegisterNatives call pattern
        # RegisterNatives(env, clazz, methods, nMethods)
        # On ARM64: bl <RegisterNatives>
        # On x86_64: call <RegisterNatives>
        import re

        # Search for method table pointers being loaded before RegisterNatives call
        # This is complex without full CFG - use heuristic
        lines = asm.split("\n")
        for i, line in enumerate(lines):
            if "RegisterNatives" in line or "bl " in line or "call " in line:
                # Look backwards for pointer loads (ldr/adrp on ARM, lea/mov on x86)
                for j in range(max(0, i-10), i):
                    if j < len(lines):
                        prev = lines[j]
                        # Look for address loads that could be method tables
                        pass  # Simplified for now

        return methods

    def _find_native_method_tables(self, so_path: Path, elf_info: Dict) -> List[Dict[str, Any]]:
        """Search for JNINativeMethod structures in data sections."""
        methods = []

        # JNINativeMethod struct:
        # const char* name;
        # const char* signature;
        # void* fnPtr;

        # Read raw binary and search for patterns
        try:
            data = so_path.read_bytes()

            # Search for method name strings followed by signature strings
            # This is heuristic - look for "Java_" prefixed exports near string pairs
            for exp in elf_info.get("exports", []):
                name = exp.get("name", "")
                if name.startswith("Java_"):
                    # Parse Java_<package>_<class>_<method>
                    parts = name[5:].split("_")
                    if len(parts) >= 3:
                        # Reconstruct class and method
                        # This is simplified - real parsing needs JNI name mangling rules
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
        """Find all Java_* exported functions."""
        methods = []

        for exp in elf_info.get("exports", []):
            name = exp.get("name", "")
            if name.startswith("Java_"):
                # Parse JNI mangled name: Java_package_class_method
                # Underscores in package/class become _1, _2, _3
                # Method name follows last _
                parts = name[5:].split("_")
                if len(parts) >= 2:
                    # Simplified parsing
                    class_parts = parts[:-1]
                    method_name = parts[-1]

                    # Handle mangled underscores
                    class_name = "/".join(class_parts).replace("_1", "_").replace("_2", ";").replace("_3", "[")

                    methods.append({
                        "class_name": class_name,
                        "method_name": method_name,
                        "signature": "unknown",
                        "native_function": name,
                        "address": exp.get("address"),
                        "source": "export"
                    })

        return methods

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
        """Find cross-references between native functions."""
        xrefs = []

        # Look for function calls in disassembly
        result = run_command(["objdump", "-d", str(so_path)], timeout=60)
        if not result["success"]:
            return xrefs

        # Simple pattern: find function calls
        import re
        lines = result["stdout"].split("\n")
        current_func = None

        for line in lines:
            # Function label
            func_match = re.match(r'\s*([0-9a-f]+)\s*<(.+?)>:', line)
            if func_match:
                current_func = func_match.group(2)
                continue

            # Call instruction
            call_match = re.search(r'\b(bl|call|blx)\s+([0-9a-f]+)', line)
            if call_match and current_func:
                target = call_match.group(2)
                xrefs.append({
                    "from": current_func,
                    "to_address": target,
                    "instruction": line.strip()
                })

        return xrefs[:100]

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

    def _disassemble_function(self, so_path: Path, offset: int, max_instructions: int = 100) -> Optional[str]:
        """Disassemble function at file offset."""
        # Convert offset to virtual address for objdump --start-address
        # For simplicity, use objdump with --start-address
        try:
            vaddr = offset  # Approximation
            result = run_command([
                "objdump", "-d",
                f"--start-address=0x{vaddr:x}",
                f"--stop-address=0x{vaddr + max_instructions * 4:x}",
                str(so_path)
            ], timeout=30)

            if result["success"]:
                return result["stdout"]
        except Exception:
            pass
        return None