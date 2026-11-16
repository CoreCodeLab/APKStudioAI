"""
Advanced Static Analysis Page for APKSTUDIOAI 2.1
ICC, Obfuscation, Reflection, Dynamic Loading, FlowDroid.
"""
import customtkinter as ctk
from typing import Dict, Any
from ..main_window import BasePage, register_page


@register_page("advanced_static", "Advanced Static", "🔬")
class AdvancedStaticPage(BasePage):
    """Advanced static analysis page."""

    def _build_ui(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        header = ctk.CTkFrame(self, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew", padx=20, pady=20)

        ctk.CTkLabel(header, text="Advanced Static Analysis", font=ctk.CTkFont(size=28, weight="bold")).pack(anchor="w")

        # Analyzer tabs
        self.tabview = ctk.CTkTabview(self)
        self.tabview.grid(row=1, column=0, sticky="nsew", padx=20, pady=(0, 20))

        tabs = ["ICC", "Obfuscation", "Reflection", "Dynamic Loading", "FlowDroid", "YARA"]
        for tab in tabs:
            self.tabview.add(tab)
            self.tabview.tab(tab).grid_columnconfigure(0, weight=1)
            self.tabview.tab(tab).grid_rowconfigure(0, weight=1)

        self.tab_frames = {tab: ctk.CTkScrollableFrame(self.tabview.tab(tab)) for tab in tabs}
        for tab, frame in self.tab_frames.items():
            frame.grid(row=0, column=0, sticky="nsew")

    def _refresh_ui(self):
        if not self.analysis_results:
            return

        adv = self.analysis_results.get("advanced_static", {})

        # ICC
        self._build_icc_tab(self.tab_frames["ICC"], adv.get("icc", {}))
        # Obfuscation
        self._build_obfuscation_tab(self.tab_frames["Obfuscation"], adv.get("obfuscation", {}))
        # Reflection
        self._build_reflection_tab(self.tab_frames["Reflection"], adv.get("reflection", {}))
        # Dynamic Loading
        self._build_dynload_tab(self.tab_frames["Dynamic Loading"], adv.get("dynamic_loading", {}))
        # FlowDroid
        self._build_flowdroid_tab(self.tab_frames["FlowDroid"], adv.get("flowdroid", {}))
        # YARA
        self._build_yara_tab(self.tab_frames["YARA"], adv.get("yara", {}))

    def _build_icc_tab(self, frame, data):
        for w in frame.winfo_children():
            w.destroy()

        flows = data.get("flows", [])
        ctk.CTkLabel(frame, text=f"ICC Flows: {len(flows)}", font=ctk.CTkFont(size=14, weight="bold")).pack(
            anchor="w", padx=15, pady=15)

        for i, flow in enumerate(flows[:50]):
            row = ctk.CTkFrame(frame, fg_color=("gray95", "gray10") if i % 2 == 0 else ("gray90", "gray15"))
            row.pack(fill="x", padx=15, pady=2)
            ctk.CTkLabel(row, text=f"{flow.get('source', '?')} -> {flow.get('target', '?')}",
                        anchor="w").pack(side="left", padx=10)
            ctk.CTkLabel(row, text=flow.get('action', '?')).pack(side="left", padx=10)

    def _build_obfuscation_tab(self, frame, data):
        for w in frame.winfo_children():
            w.destroy()

        indicators = data.get("indicators", [])
        packer = data.get("packer", "Unknown")
        score = data.get("obfuscation_score", 0)

        ctk.CTkLabel(frame, text=f"Packer: {packer}", font=ctk.CTkFont(size=14, weight="bold")).pack(
            anchor="w", padx=15, pady=10)
        ctk.CTkLabel(frame, text=f"Obfuscation Score: {score:.1f}/100",
                    text_color="#e74c3c" if score > 70 else "#f39c12" if score > 30 else "#2ecc71").pack(
            anchor="w", padx=15, pady=5)

        ctk.CTkLabel(frame, text="Indicators:", font=ctk.CTkFont(size=12, weight="bold")).pack(
            anchor="w", padx=15, pady=(15, 5))
        for ind in indicators[:20]:
            ctk.CTkLabel(frame, text=f"  • {ind}", text_color=("gray50", "gray70")).pack(
                anchor="w", padx=25, pady=2)

    def _build_reflection_tab(self, frame, data):
        for w in frame.winfo_children():
            w.destroy()

        calls = data.get("calls", [])
        ctk.CTkLabel(frame, text=f"Reflection Calls: {len(calls)}", font=ctk.CTkFont(size=14, weight="bold")).pack(
            anchor="w", padx=15, pady=15)

        for i, call in enumerate(calls[:50]):
            row = ctk.CTkFrame(frame, fg_color=("gray95", "gray10") if i % 2 == 0 else ("gray90", "gray15"))
            row.pack(fill="x", padx=15, pady=2)
            ctk.CTkLabel(row, text=call.get("class", "?"), width=200, anchor="w").pack(side="left", padx=10)
            ctk.CTkLabel(row, text=call.get("method", "?")).pack(side="left", padx=10)

    def _build_dynload_tab(self, frame, data):
        for w in frame.winfo_children():
            w.destroy()

        loaders = data.get("loaders", [])
        ctk.CTkLabel(frame, text=f"Dynamic Loaders: {len(loaders)}", font=ctk.CTkFont(size=14, weight="bold")).pack(
            anchor="w", padx=15, pady=15)

        for i, loader in enumerate(loaders[:50]):
            row = ctk.CTkFrame(frame, fg_color=("gray95", "gray10") if i % 2 == 0 else ("gray90", "gray15"))
            row.pack(fill="x", padx=15, pady=2)
            ctk.CTkLabel(row, text=loader.get("class", "?"), width=250, anchor="w").pack(side="left", padx=10)
            ctk.CTkLabel(row, text=loader.get("method", "?")).pack(side="left", padx=10)

    def _build_flowdroid_tab(self, frame, data):
        for w in frame.winfo_children():
            w.destroy()

        if not data.get("available", False):
            ctk.CTkLabel(frame, text="FlowDroid not available", text_color=("gray50", "gray70")).pack(pady=50)
            return

        taint = data.get("taint_flows", [])
        ctk.CTkLabel(frame, text=f"Taint Flows: {len(taint)}", font=ctk.CTkFont(size=14, weight="bold")).pack(
            anchor="w", padx=15, pady=15)

        for i, flow in enumerate(taint[:30]):
            row = ctk.CTkFrame(frame, fg_color=("gray95", "gray10") if i % 2 == 0 else ("gray90", "gray15"))
            row.pack(fill="x", padx=15, pady=2)
            ctk.CTkLabel(row, text=f"{flow.get('source', '?')} -> {flow.get('sink', '?')}",
                        anchor="w").pack(side="left", padx=10)

    def _build_yara_tab(self, frame, data):
        for w in frame.winfo_children():
            w.destroy()

        matches = data.get("matches", [])
        ctk.CTkLabel(frame, text=f"YARA Matches: {len(matches)}", font=ctk.CTkFont(size=14, weight="bold")).pack(
            anchor="w", padx=15, pady=15)

        for i, match in enumerate(matches):
            row = ctk.CTkFrame(frame, fg_color=("gray95", "gray10") if i % 2 == 0 else ("gray90", "gray15"))
            row.pack(fill="x", padx=15, pady=2)
            ctk.CTkLabel(row, text=match.get("rule", "?"), font=ctk.CTkFont(size=11, weight="bold"),
                        text_color="#e74c3c").pack(side="left", padx=10)
            ctk.CTkLabel(row, text=match.get("namespace", "?")).pack(side="left", padx=10)
            ctk.CTkLabel(row, text=match.get("tags", "?")).pack(side="left", padx=10)