"""
ELF binary analyzer using pyelftools with readelf/objdump fallback
"""
import subprocess
import os
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from .utils import run_command


class ELFAnalyzer:
    def __init__(self):
        self.has_elftools = self._check_elftools()
        self.has_readelf = self._check_tool("readelf")
        self.has_objdump = self._check_tool("objdump")

    def _check_elftools(self) -> bool:
        try:
            import elftools
            return True
        except ImportError:
            return False

    def _check_tool(self, tool: str) -> bool:
        try:
            subprocess.run([tool, "--version"], capture_output=True, timeout=5)
            return True
        except Exception:
            return False

    def analyze(self, elf_path: Path) -> Dict[str, Any]:
        """Analyze ELF binary."""
        if self.has_elftools:
            return self._analyze_with_elftools(elf_path)
        elif self.has_readelf:
            return self._analyze_with_readelf(elf_path)
        else:
            return {"error": "No ELF analysis tools available (need pyelftools or readelf)"}

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
            "register_natives_offset": None
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
                                "symbol": reloc.symbol.name if reloc.symbol else None
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

        except Exception as e:
            result["error"] = f"elftools error: {e}"

        return result

    def _analyze_with_readelf(self, elf_path: Path) -> Dict[str, Any]:
        """Analyze using readelf command."""
        result = {
            "header": {},
            "sections": [],
            "symbols": [],
            "imports": [],
            "exports": [],
            "dynamic": [],
            "relocations": [],
            "jni_onload_offset": None,
            "register_natives_offset": None
        }

        # Header
        hdr_result = run_command(["readelf", "-h", str(elf_path)], timeout=30)
        if hdr_result["success"]:
            result["header"] = self._parse_readelf_header(hdr_result["stdout"])

        # Sections
        sec_result = run_command(["readelf", "-S", str(elf_path)], timeout=30)
        if sec_result["success"]:
            result["sections"] = self._parse_readelf_sections(sec_result["stdout"])

        # Symbols
        sym_result = run_command(["readelf", "-s", str(elf_path)], timeout=30)
        if sym_result["success"]:
            symbols, imports, exports, jni_onload, reg_natives = self._parse_readelf_symbols(sym_result["stdout"])
            result["symbols"] = symbols
            result["imports"] = imports
            result["exports"] = exports
            result["jni_onload_offset"] = jni_onload
            result["register_natives_offset"] = reg_natives

        # Dynamic
        dyn_result = run_command(["readelf", "-d", str(elf_path)], timeout=30)
        if dyn_result["success"]:
            result["dynamic"] = self._parse_readelf_dynamic(dyn_result["stdout"])

        # Relocations
        rel_result = run_command(["readelf", "-r", str(elf_path)], timeout=30)
        if rel_result["success"]:
            result["relocations"] = self._parse_readelf_relocations(rel_result["stdout"])

        return result

    def _parse_readelf_header(self, output: str) -> Dict[str, Any]:
        """Parse readelf -h output."""
        import re
        header = {}
        patterns = {
            "class": r"Class:\s+(\S+)",
            "endianness": r"Data:\s+(\S+)",
            "machine": r"Machine:\s+(\S+)",
            "type": r"Type:\s+(\S+)",
            "entry": r"Entry point address:\s+(\S+)",
            "phoff": r"Start of program headers:\s+(\d+)",
            "shoff": r"Start of section headers:\s+(\d+)",
            "flags": r"Flags:\s+(\S+)"
        }
        for key, pattern in patterns.items():
            m = re.search(pattern, output)
            if m:
                header[key] = m.group(1)
        return header

    def _parse_readelf_sections(self, output: str) -> List[Dict[str, Any]]:
        """Parse readelf -S output."""
        import re
        sections = []
        # Format: [Nr] Name Type Addr Off Size ES Flg Lk Inf Al
        lines = output.split("\n")
        for line in lines:
            m = re.match(r'\s*\[\s*\d+\]\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)', line)
            if m:
                sections.append({
                    "name": m.group(1),
                    "type": m.group(2),
                    "addr": m.group(3),
                    "offset": m.group(4),
                    "size": m.group(5),
                    "entsize": m.group(6),
                    "flags": m.group(7),
                    "link": m.group(8),
                    "info": m.group(9),
                    "align": m.group(10)
                })
        return sections

    def _parse_readelf_symbols(self, output: str) -> Tuple[List, List, List, Optional[int], Optional[int]]:
        """Parse readelf -s output."""
        import re
        symbols = []
        imports = []
        exports = []
        jni_onload = None
        reg_natives = None

        # Format: Num: Value Size Type Bind Vis Ndx Name
        lines = output.split("\n")
        for line in lines:
            m = re.match(r'\s*\d+:\s+(\S+)\s+(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)', line)
            if m:
                sym = {
                    "name": m.group(7),
                    "value": m.group(1),
                    "size": int(m.group(2)),
                    "type": m.group(3),
                    "bind": m.group(4),
                    "vis": m.group(5),
                    "ndx": m.group(6)
                }
                symbols.append(sym)

                if sym["name"]:
                    if sym["ndx"] == "UND":
                        imports.append(sym)
                    elif sym["bind"] in ("GLOBAL", "WEAK"):
                        exports.append(sym)

                    if sym["name"] == "JNI_OnLoad":
                        try:
                            jni_onload = int(sym["value"], 16)
                        except Exception:
                            pass
                    if "RegisterNatives" in sym["name"]:
                        try:
                            reg_natives = int(sym["value"], 16)
                        except Exception:
                            pass

        return symbols, imports, exports, jni_onload, reg_natives

    def _parse_readelf_dynamic(self, output: str) -> List[Dict[str, Any]]:
        """Parse readelf -d output."""
        import re
        dynamic = []
        for line in output.split("\n"):
            m = re.match(r'\s*0x([0-9a-f]+)\s+\((\w+)\)\s+(.*)', line)
            if m:
                dynamic.append({
                    "tag": m.group(2),
                    "value": m.group(3)
                })
        return dynamic

    def _parse_readelf_relocations(self, output: str) -> List[Dict[str, Any]]:
        """Parse readelf -r output."""
        import re
        relocations = []
        for line in output.split("\n"):
            m = re.match(r'\s*(\S+)\s+(\S+)\s+(\S+)\s+(.*)', line)
            if m and m.group(1) != "Offset":
                relocations.append({
                    "offset": m.group(1),
                    "type": m.group(2),
                    "symbol": m.group(4).strip()
                })
        return relocations