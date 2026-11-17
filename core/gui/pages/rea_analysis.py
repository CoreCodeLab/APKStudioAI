"""
REA (Reverse Engineering Assistant) Analysis Page
Displays enhanced reverse engineering results from REA/Ghidra integration
"""
import customtkinter as ctk
from typing import Dict, Any
from ..main_window import BasePage, register_page


@register_page("rea_analysis", "REA Analysis", "🔧")
class REAAnalysisPage(BasePage):
    """Page for displaying REA enhanced reverse engineering analysis results"""

    def __init__(self, parent, app, **kwargs):
        super().__init__(parent, app, **kwargs)
        self._build_ui()

    def _build_ui(self):
        """Build the REA analysis page UI"""
        # Configure grid
        self.grid_rowconfigure(1, weight=1)
        self.grid_columnconfigure(0, weight=1)

        # Header
        header_frame = ctk.CTkFrame(self, corner_radius=8)
        header_frame.grid(row=0, column=0, sticky="ew", padx=15, pady=15)
        header_frame.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(
            header_frame,
            text="🔧 REA Enhanced Reverse Engineering",
            font=ctk.CTkFont(size=20, weight="bold")
        ).grid(row=0, column=0, padx=15, pady=15, sticky="w")

        # Status label
        self.status_label = ctk.CTkLabel(
            header_frame,
            text="No analysis data",
            font=ctk.CTkFont(size=12),
            text_color=("gray50", "gray70")
        )
        self.status_label.grid(row=0, column=1, padx=15, pady=15, sticky="e")

        # Main content area with tabs
        self.tabview = ctk.CTkTabview(self, corner_radius=8)
        self.tabview.grid(row=1, column=0, sticky="nsew", padx=15, pady=(0, 15))

        # Create tabs
        self.tab_native_libs = self.tabview.add("Native Libraries")
        self.tab_patterns = self.tabview.add("Suspicious Patterns")
        self.tab_ghidra = self.tabview.add("Ghidra Analysis")
        self.tab_xrefs = self.tabview.add("Cross References")
        self.tab_decompiler = self.tabview.add("Decompiler")

        # Configure tab grids
        for tab in [self.tab_native_libs, self.tab_patterns, self.tab_ghidra,
                    self.tab_xrefs, self.tab_decompiler]:
            tab.grid_rowconfigure(0, weight=1)
            tab.grid_columnconfigure(0, weight=1)

        # Native Libraries tab - use CTkTextbox for proper theming
        self.native_libs_text = ctk.CTkTextbox(
            self.tab_native_libs,
            wrap="word",
            font=ctk.CTkFont(family="Consolas", size=11),
            corner_radius=6
        )
        self.native_libs_text.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)

        # Patterns tab
        self.patterns_text = ctk.CTkTextbox(
            self.tab_patterns,
            wrap="word",
            font=ctk.CTkFont(family="Consolas", size=11),
            corner_radius=6
        )
        self.patterns_text.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)

        # Ghidra Analysis tab
        self.ghidra_text = ctk.CTkTextbox(
            self.tab_ghidra,
            wrap="word",
            font=ctk.CTkFont(family="Consolas", size=11),
            corner_radius=6
        )
        self.ghidra_text.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)

        # Cross References tab
        self.xrefs_text = ctk.CTkTextbox(
            self.tab_xrefs,
            wrap="word",
            font=ctk.CTkFont(family="Consolas", size=11),
            corner_radius=6
        )
        self.xrefs_text.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)

        # Decompiler tab
        self.decompiler_text = ctk.CTkTextbox(
            self.tab_decompiler,
            wrap="word",
            font=ctk.CTkFont(family="Consolas", size=11),
            corner_radius=6
        )
        self.decompiler_text.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)

    def _refresh_ui(self):
        """Refresh UI with current analysis results"""
        if not self.analysis_results:
            self.status_label.configure(text="No analysis data")
            self._clear_all_tabs()
            return

        rea = self.analysis_results.get("rea", {})
        if not rea.get("enabled"):
            self.status_label.configure(text="REA analysis not enabled or not available")
            self._clear_all_tabs()
            if rea.get("error"):
                self.status_label.configure(text=f"REA error: {rea['error']}")
            return

        native_libs = rea.get("native_libraries", [])
        patterns = rea.get("patterns", [])
        ghidra_analysis = rea.get("ghidra_analysis", {})
        xrefs = rea.get("cross_references", {})
        decompiler = rea.get("decompiler_results", {})

        self.status_label.configure(
            text=f"REA Analysis Complete: {len(native_libs)} libs, {len(patterns)} patterns"
        )

        # Update Native Libraries tab
        self._update_native_libs_tab(native_libs)

        # Update Patterns tab
        self._update_patterns_tab(patterns)

        # Update Ghidra Analysis tab
        self._update_ghidra_tab(ghidra_analysis)

        # Update Cross References tab
        self._update_xrefs_tab(xrefs)

        # Update Decompiler tab
        self._update_decompiler_tab(decompiler)

    def _clear_all_tabs(self):
        """Clear all tab contents"""
        for text_widget in [self.native_libs_text, self.patterns_text,
                            self.ghidra_text, self.xrefs_text, self.decompiler_text]:
            text_widget.delete("1.0", "end")

    def _update_native_libs_tab(self, native_libs):
        """Update native libraries tab"""
        self.native_libs_text.delete("1.0", "end")
        if not native_libs:
            self.native_libs_text.insert("end", "No native libraries found in APK")
            return

        for lib in native_libs:
            self.native_libs_text.insert("end", f"Library: {lib.get('name', 'unknown')}\n")
            self.native_libs_text.insert("end", f"  Path: {lib.get('path', 'N/A')}\n")
            self.native_libs_text.insert("end", f"  Architecture: {lib.get('arch', 'unknown')}\n")
            self.native_libs_text.insert("end", f"  Size: {lib.get('size', 0)} bytes\n")
            self.native_libs_text.insert("end", "\n")

    def _update_patterns_tab(self, patterns):
        """Update suspicious patterns tab"""
        self.patterns_text.delete("1.0", "end")
        if not patterns:
            self.patterns_text.insert("end", "No suspicious patterns detected")
            return

        # Group by severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        sorted_patterns = sorted(patterns, key=lambda p: severity_order.get(p.get("severity", "low"), 4))

        for p in sorted_patterns:
            severity = p.get("severity", "unknown").upper()
            self.patterns_text.insert("end", f"[{severity}] {p.get('pattern', 'unknown')}\n")
            self.patterns_text.insert("end", f"  Type: {p.get('type', 'unknown')}\n")
            self.patterns_text.insert("end", f"  Description: {p.get('description', 'N/A')}\n")
            self.patterns_text.insert("end", f"  Matches: {p.get('matches', 0)}\n")
            offsets = p.get("offsets", [])
            if offsets:
                self.patterns_text.insert("end", f"  Offsets: {', '.join(offsets[:20])}\n")
                if len(offsets) > 20:
                    self.patterns_text.insert("end", f"  ... and {len(offsets) - 20} more\n")
            self.patterns_text.insert("end", "\n")

    def _update_ghidra_tab(self, ghidra_analysis):
        """Update Ghidra analysis tab"""
        self.ghidra_text.delete("1.0", "end")
        if not ghidra_analysis:
            self.ghidra_text.insert("end", "No Ghidra analysis results available")
            return

        for lib_name, analysis in ghidra_analysis.items():
            self.ghidra_text.insert("end", f"Library: {lib_name}\n")
            if analysis.get("success"):
                self.ghidra_text.insert("end", "  Status: Success\n")
                stdout = analysis.get("stdout", "")
                if stdout:
                    self.ghidra_text.insert("end", f"  Output:\n{stdout[:5000]}\n")
            elif analysis.get("error"):
                self.ghidra_text.insert("end", f"  Error: {analysis['error']}\n")
                stderr = analysis.get("stderr", "")
                if stderr:
                    self.ghidra_text.insert("end", f"  Details:\n{stderr[:5000]}\n")
            self.ghidra_text.insert("end", "\n")

    def _update_xrefs_tab(self, xrefs):
        """Update cross references tab"""
        self.xrefs_text.delete("1.0", "end")
        if not xrefs:
            self.xrefs_text.insert("end", "No cross-reference data available")
            return

        for lib_name, xref_data in xrefs.items():
            self.xrefs_text.insert("end", f"Library: {lib_name}\n")
            xref_list = xref_data.get("xrefs", [])
            if xref_list:
                for xref in xref_list[:50]:
                    self.xrefs_text.insert("end", f"  {xref}\n")
                if len(xref_list) > 50:
                    self.xrefs_text.insert("end", f"  ... and {len(xref_list) - 50} more\n")
            else:
                note = xref_data.get("note", "No cross-references found")
                self.xrefs_text.insert("end", f"  {note}\n")
            self.xrefs_text.insert("end", "\n")

    def _update_decompiler_tab(self, decompiler):
        """Update decompiler tab"""
        self.decompiler_text.delete("1.0", "end")
        if not decompiler:
            self.decompiler_text.insert("end", "No decompiler results available")
            return

        for lib_name, decomp_data in decompiler.items():
            self.decompiler_text.insert("end", f"Library: {lib_name}\n")
            functions = decomp_data.get("functions", [])
            if functions:
                for func in functions[:20]:
                    self.decompiler_text.insert("end", f"  {func}\n")
                if len(functions) > 20:
                    self.decompiler_text.insert("end", f"  ... and {len(functions) - 20} more\n")
            else:
                note = decomp_data.get("note", "No decompiler output available")
                self.decompiler_text.insert("end", f"  {note}\n")
            self.decompiler_text.insert("end", "\n")