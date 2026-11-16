"""
ELF binary analyzer using pyelftools with Capstone disassembly
No external tool dependencies (readelf/objdump not required)
"""
import struct
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple, Union
from .utils import run_command, is_elf_file


class ELFAnalyzer:
    def __init__(self):
        self.has_elftools = self._check_elftools()
        self.has_capstone = self._check_capstone()
        self.capstone_arch = None
        self.capstone_mode = None

    def _check_elftools(self) -> bool:
        try:
            import elftools
            return True
        except ImportError:
            return False

    def _check_capstone(self) -> bool:
        try:
            import capstone
            return True
        except ImportError:
            return False

    def _init_capstone(self, elf_header: Dict) -> bool:
        """Initialize Capstone disassembler based on ELF architecture."""
        if not self.has_capstone:
            return False

        try:
            import capstone
            machine = elf_header.get("machine", "0x0")
            if isinstance(machine, str):
                machine = int(machine, 16) if machine.startswith("0x") else int(machine)

            elf_class = elf_header.get("class", "")
            endianness = elf_header.get("endianness", "little")

            # Map ELF machine to Capstone architecture
            if machine == 0xB7:  # AArch64 (ARM64)
                self.capstone_arch = capstone.CS_ARCH_ARM64
                self.capstone_mode = capstone.CS_MODE_ARM
            elif machine == 0x28:  # ARM (32-bit)
                self.capstone_arch = capstone.CS_ARCH_ARM
                self.capstone_mode = capstone.CS_MODE_ARM
            elif machine == 0x3E:  # x86_64
                self.capstone_arch = capstone.CS_ARCH_X86
                self.capstone_mode = capstone.CS_MODE_64
            elif machine == 0x03:  # x86 (32-bit)
                self.capstone_arch = capstone.CS_ARCH_X86
                self.capstone_mode = capstone.CS_MODE_32
            else:
                return False

            # Endianness
            if endianness == "big":
                self.capstone_mode |= capstone.CS_MODE_BIG_ENDIAN
            else:
                self.capstone_mode |= capstone.CS_MODE_LITTLE_ENDIAN

            return True
        except Exception:
            return False

    def analyze(self, elf_path: Path) -> Dict[str, Any]:
        """Analyze ELF binary using pyelftools only."""
        if not self.has_elftools:
            return {"error": "pyelftools not available. Install with: pip install pyelftools"}

        return self._analyze_with_elftools(elf_path)

    def _analyze_with_elftools(self, elf_path: Path) -> Dict[str, Any]:
        """Analyze using pyelftools."""
        from elftools.elf.elffile import ELFFile
        from elftools.elf.sections import SymbolTableSection, Section
        from elftools.elf.dynamic import DynamicSection
        from elftools.elf.relocation import RelocationSection

        result = {
            "header": {},
            "sections": [],
            "segments": [],
            "symbols": [],
            "imports": [],
            "exports": [],
            "dynamic": [],
            "relocations": [],
            "notes": [],
            "jni_onload_offset": None,
            "register_natives_offset": None,
            "strings": [],
            "section_data": {},  # Store section data for disassembly
            "capstone_available": self.has_capstone
        }

        try:
            with open(elf_path, "rb") as f:
                elf = ELFFile(f)

                # Header
                result["header"] = {
                    "class": elf.elfclass,
                    "endianness": "little" if elf.little_endian else "big",
                    "machine": hex(elf.header["e_machine"]),
                    "type": hex(elf.header["e_type"]),
                    "entry": hex(elf.header["e_entry"]),
                    "phoff": elf.header["e_phoff"],
                    "shoff": elf.header["e_shoff"],
                    "flags": hex(elf.header["e_flags"])
                }

                # Initialize Capstone if available
                self._init_capstone(result["header"])

                # Sections
                for section in elf.iter_sections():
                    sec_info = {
                        "name": section.name,
                        "type": hex(section["sh_type"]),
                        "flags": hex(section["sh_flags"]),
                        "addr": hex(section["sh_addr"]),
                        "offset": section["sh_offset"],
                        "size": section["sh_size"],
                        "entsize": section["sh_entsize"]
                    }
                    result["sections"].append(sec_info)

                    # Store section data for disassembly (code sections only)
                    if section["sh_type"] == "SHT_PROGBITS" and (section["sh_flags"] & 0x4):  # SHF_EXECINSTR
                        try:
                            f.seek(section["sh_offset"])
                            result["section_data"][section.name] = {
                                "data": f.read(section["sh_size"]),
                                "vaddr": section["sh_addr"],
                                "offset": section["sh_offset"],
                                "size": section["sh_size"]
                            }
                        except Exception:
                            pass

                    # Symbol table
                    if isinstance(section, SymbolTableSection):
                        for symbol in section.iter_symbols():
                            if symbol.name:
                                sym_info = {
                                    "name": symbol.name,
                                    "value": hex(symbol["st_value"]),
                                    "size": symbol["st_size"],
                                    "bind": symbol["st_info"]["bind"],
                                    "type": symbol["st_info"]["type"],
                                    "section": symbol["st_shndx"]
                                }
                                result["symbols"].append(sym_info)

                                # Categorize as import/export
                                if symbol["st_shndx"] == "SHN_UNDEF":
                                    result["imports"].append(sym_info)
                                elif symbol["st_info"]["bind"] in ("STB_GLOBAL", "STB_WEAK"):
                                    result["exports"].append(sym_info)

                                # Check for JNI_OnLoad
                                if symbol.name == "JNI_OnLoad":
                                    result["jni_onload_offset"] = symbol["st_value"]

                                # Check for RegisterNatives
                                if "RegisterNatives" in symbol.name:
                                    result["register_natives_offset"] = symbol["st_value"]

                # Segments
                for segment in elf.iter_segments():
                    seg_info = {
                        "type": hex(segment["p_type"]),
                        "flags": hex(segment["p_flags"]),
                        "offset": segment["p_offset"],
                        "vaddr": hex(segment["p_vaddr"]),
                        "paddr": hex(segment["p_paddr"]),
                        "filesz": segment["p_filesz"],
                        "memsz": segment["p_memsz"]
                    }
                    result["segments"].append(seg_info)

                # Dynamic section
                dynamic = elf.get_section_by_name(".dynamic")
                if dynamic and isinstance(dynamic, DynamicSection):
                    for tag in dynamic.iter_tags():
                        result["dynamic"].append({
                            "tag": tag.entry.d_tag,
                            "value": hex(tag.entry.d_val)
                        })

                # Relocations
                for section in elf.iter_sections():
                    if isinstance(section, RelocationSection):
                        for reloc in section.iter_relocations():
                            result["relocations"].append({
                                "offset": hex(reloc["r_offset"]),
                                "type": hex(reloc["r_info_type"]),
                                "symbol": reloc.symbol.name if reloc.symbol else None,
                                "addend": reloc["r_addend"] if hasattr(reloc, "r_addend") else 0
                            })

                # Notes
                for section in elf.iter_sections():
                    if section["sh_type"] == "SHT_NOTE":
                        for note in section.iter_notes():
                            result["notes"].append({
                                "name": note.name,
                                "type": note.type,
                                "desc": note.desc.hex() if isinstance(note.desc, bytes) else str(note.desc)
                            })

                # Extract strings from .rodata, .data, .dynstr sections
                result["strings"] = self._extract_strings(elf)

        except Exception as e:
            result["error"] = f"elftools error: {e}"

        return result

    def _extract_strings(self, elf) -> List[str]:
        """Extract strings from string sections."""
        strings = []
        string_sections = [".dynstr", ".strtab", ".rodata", ".data"]

        for section_name in string_sections:
            section = elf.get_section_by_name(section_name)
            if section:
                try:
                    data = section.data()
                    # Simple string extraction
                    current = bytearray()
                    for byte in data:
                        if 32 <= byte <= 126:
                            current.append(byte)
                        else:
                            if len(current) >= 4:
                                strings.append(current.decode("ascii", errors="ignore"))
                            current.clear()
                    if len(current) >= 4:
                        strings.append(current.decode("ascii", errors="ignore"))
                except Exception:
                    pass

        return list(set(strings))[:500]  # Deduplicate and limit

    def disassemble_function(self, elf_path: Path, address: int, max_instructions: int = 100) -> Optional[List[Dict]]:
        """Disassemble function at virtual address using Capstone."""
        if not self.has_capstone or not self.capstone_arch:
            return None

        try:
            import capstone
            md = capstone.Cs(self.capstone_arch, self.capstone_mode)
            md.detail = True

            # Read ELF to get section data at address
            with open(elf_path, "rb") as f:
                from elftools.elf.elffile import ELFFile
                elf = ELFFile(f)

                # Find section containing address
                code_data = None
                code_vaddr = 0
                code_offset = 0

                for section in elf.iter_sections():
                    if section["sh_type"] == "SHT_PROGBITS" and (section["sh_flags"] & 0x4):
                        vaddr = section["sh_addr"]
                        size = section["sh_size"]
                        if vaddr <= address < vaddr + size:
                            f.seek(section["sh_offset"])
                            code_data = f.read(size)
                            code_vaddr = vaddr
                            code_offset = section["sh_offset"]
                            break

                if not code_data:
                    return None

                # Calculate offset within section
                offset_in_section = address - code_vaddr
                if offset_in_section < 0 or offset_in_section >= len(code_data):
                    return None

                # Disassemble
                instructions = []
                for insn in md.disasm(code_data[offset_in_section:], address, count=max_instructions):
                    insn_info = {
                        "address": hex(insn.address),
                        "mnemonic": insn.mnemonic,
                        "op_str": insn.op_str,
                        "bytes": insn.bytes.hex(),
                        "size": insn.size
                    }

                    # Add detail info for ARM64/x86
                    if hasattr(insn, 'detail') and insn.detail:
                        if self.capstone_arch == capstone.CS_ARCH_ARM64:
                            insn_info["groups"] = [g for g in insn.detail.groups]
                        elif self.capstone_arch == capstone.CS_ARCH_X86:
                            insn_info["prefix"] = [p for p in insn.detail.prefix] if insn.detail.prefix else []

                    instructions.append(insn_info)

                    # Stop at return instructions
                    if insn.mnemonic in ('ret', 'blr', 'bx', 'jr', 'br'):
                        break

                return instructions

        except Exception as e:
            return {"error": f"Disassembly error: {e}"}

    def disassemble_at_offset(self, elf_path: Path, file_offset: int, max_instructions: int = 100) -> Optional[List[Dict]]:
        """Disassemble at file offset using Capstone."""
        if not self.has_capstone or not self.capstone_arch:
            return None

        try:
            import capstone
            md = capstone.Cs(self.capstone_arch, self.capstone_mode)
            md.detail = True

            # Find virtual address for this file offset
            with open(elf_path, "rb") as f:
                from elftools.elf.elffile import ELFFile
                elf = ELFFile(f)

                vaddr = None
                code_data = None

                for section in elf.iter_sections():
                    if section["sh_type"] == "SHT_PROGBITS" and (section["sh_flags"] & 0x4):
                        if section["sh_offset"] <= file_offset < section["sh_offset"] + section["sh_size"]:
                            f.seek(section["sh_offset"])
                            code_data = f.read(section["sh_size"])
                            vaddr = section["sh_addr"] + (file_offset - section["sh_offset"])
                            break

                if not code_data or vaddr is None:
                    return None

                offset_in_section = file_offset - section["sh_offset"]
                instructions = []
                for insn in md.disasm(code_data[offset_in_section:], vaddr, count=max_instructions):
                    insn_info = {
                        "address": hex(insn.address),
                        "mnemonic": insn.mnemonic,
                        "op_str": insn.op_str,
                        "bytes": insn.bytes.hex(),
                        "size": insn.size
                    }
                    instructions.append(insn_info)

                    if insn.mnemonic in ('ret', 'blr', 'bx', 'jr', 'br'):
                        break

                return instructions

        except Exception as e:
            return {"error": f"Disassembly error: {e}"}

    def find_jni_native_method_tables(self, elf_path: Path) -> List[Dict[str, Any]]:
        """Find JNINativeMethod tables in ELF binary using struct parsing."""
        tables = []

        if not self.has_elftools:
            return tables

        try:
            with open(elf_path, "rb") as f:
                from elftools.elf.elffile import ELFFile
                elf = ELFFile(f)

                # Determine architecture for struct packing
                is_64bit = elf.elfclass == 64
                is_little = elf.little_endian
                endian = '<' if is_little else '>'
                ptr_size = 8 if is_64bit else 4

                # JNINativeMethod struct:
                # const char* name;      // pointer
                # const char* signature; // pointer
                # void* fnPtr;           // pointer
                # Total: 3 * ptr_size bytes

                struct_format = f"{endian}{3*ptr_size}s"  # We'll parse manually

                # Search in .data, .rodata, .bss sections
                for section in elf.iter_sections():
                    if section.name in (".data", ".rodata", ".bss", ".data.rel.ro", ".got"):
                        try:
                            f.seek(section["sh_offset"])
                            data = f.read(section["sh_size"])

                            # Scan for potential JNINativeMethod tables
                            # Look for sequences of valid string pointers followed by function pointers
                            found = self._scan_for_jni_tables(
                                data, section["sh_addr"], section["sh_offset"],
                                is_64bit, is_little, elf, f
                            )
                            tables.extend(found)
                        except Exception:
                            pass

                # Also search near RegisterNatives relocations
                for section in elf.iter_sections():
                    from elftools.elf.relocation import RelocationSection
                    if isinstance(section, RelocationSection):
                        for reloc in section.iter_relocations():
                            if reloc.symbol and "RegisterNatives" in reloc.symbol.name:
                                # Look for tables near this relocation
                                pass  # Handled by scanner above

        except Exception:
            pass

        return tables[:50]  # Limit

    def _scan_for_jni_tables(self, data: bytes, section_vaddr: int, section_offset: int,
                              is_64bit: bool, is_little: bool, elf, f) -> List[Dict]:
        """Scan section data for JNINativeMethod table patterns."""
        tables = []
        ptr_size = 8 if is_64bit else 4
        struct_size = 3 * ptr_size
        endian = '<' if is_little else '>'

        # We need to resolve string pointers to actual strings
        # Build a map of string addresses to string values
        str_map = self._build_string_map(elf, f, is_64bit, is_little)

        # Also build a map of function addresses to names
        func_map = self._build_function_map(elf)

        # Scan for potential tables
        for i in range(0, len(data) - struct_size + 1, ptr_size):
            try:
                # Parse potential JNINativeMethod entry
                name_ptr = struct.unpack(f"{endian}{'Q' if is_64bit else 'I'}",
                                          data[i:i+ptr_size])[0]
                sig_ptr = struct.unpack(f"{endian}{'Q' if is_64bit else 'I'}",
                                         data[i+ptr_size:i+2*ptr_size])[0]
                fn_ptr = struct.unpack(f"{endian}{'Q' if is_64bit else 'I'}",
                                        data[i+2*ptr_size:i+3*ptr_size])[0]

                # Check if pointers are plausible (within ELF address space)
                if not self._is_valid_pointer(name_ptr, elf) or \
                   not self._is_valid_pointer(sig_ptr, elf) or \
                   not self._is_valid_pointer(fn_ptr, elf):
                    continue

                # Resolve strings
                name_str = self._resolve_string(name_ptr, str_map, elf, f, is_64bit, is_little)
                sig_str = self._resolve_string(sig_ptr, str_map, elf, f, is_64bit, is_little)
                fn_name = func_map.get(fn_ptr, f"sub_{fn_ptr:x}")

                # Heuristic: valid JNI method name and signature
                if name_str and sig_str and self._looks_like_jni_signature(sig_str):
                    tables.append({
                        "name": name_str,
                        "signature": sig_str,
                        "function": fn_name,
                        "function_address": hex(fn_ptr),
                        "table_address": hex(section_vaddr + i),
                        "table_offset": section_offset + i,
                        "section": "unknown"  # Will be filled by caller
                    })
            except Exception:
                continue

        return tables

    def _build_string_map(self, elf, f, is_64bit: bool, is_little: bool) -> Dict[int, str]:
        """Build map of string pointer addresses to string values."""
        str_map = {}
        endian = '<' if is_little else '>'
        ptr_format = 'Q' if is_64bit else 'I'

        for section in elf.iter_sections():
            if section.name in (".rodata", ".data", ".dynstr", ".strtab", ".data.rel.ro"):
                try:
                    f.seek(section["sh_offset"])
                    data = f.read(section["sh_size"])

                    # Extract null-terminated strings
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
                                        str_map[section["sh_addr"] + start] = s
                                except Exception:
                                    pass
                        pos += 1
                except Exception:
                    pass

        return str_map

    def _build_function_map(self, elf) -> Dict[int, str]:
        """Build map of function addresses to names from symbols."""
        func_map = {}
        for section in elf.iter_sections():
            from elftools.elf.sections import SymbolTableSection
            if isinstance(section, SymbolTableSection):
                for symbol in section.iter_symbols():
                    if symbol.name and symbol["st_info"]["type"] == "STT_FUNC":
                        func_map[symbol["st_value"]] = symbol.name
        return func_map

    def _is_valid_pointer(self, ptr: int, elf) -> bool:
        """Check if pointer is within ELF address space."""
        if ptr == 0:
            return False
        # Check if in any loadable segment
        for segment in elf.iter_segments():
            if segment["p_type"] == "PT_LOAD":
                vaddr = segment["p_vaddr"]
                memsz = segment["p_memsz"]
                if vaddr <= ptr < vaddr + memsz:
                    return True
        return False

    def _resolve_string(self, ptr: int, str_map: Dict, elf, f, is_64bit: bool, is_little: bool) -> Optional[str]:
        """Resolve string pointer to actual string."""
        if ptr in str_map:
            return str_map[ptr]

        # Try reading directly from memory
        try:
            endian = '<' if is_little else '>'
            # Find segment containing pointer
            for segment in elf.iter_segments():
                if segment["p_type"] == "PT_LOAD":
                    vaddr = segment["p_vaddr"]
                    offset = segment["p_offset"]
                    memsz = segment["p_memsz"]
                    if vaddr <= ptr < vaddr + memsz:
                        file_off = offset + (ptr - vaddr)
                        f.seek(file_off)
                        data = f.read(256)
                        # Find null terminator
                        end = data.find(b'\x00')
                        if end > 0:
                            return data[:end].decode("utf-8", errors="ignore")
        except Exception:
            pass
        return None

    def _looks_like_jni_signature(self, sig: str) -> bool:
        """Check if string looks like a JNI signature."""
        if not sig or len(sig) < 3:
            return False
        # JNI signatures: (args)return_type
        # Primitive types: B C D F I J S Z V
        # Object: Lclass/name;
        # Array: [type
        if sig[0] != '(':
            return False
        if ')' not in sig:
            return False
        return True