"""
Correlation Page for APKSTUDIOAI 2.1
Static-to-dynamic correlation analysis results.
"""
import customtkinter as ctk
from typing import Dict, Any
from ..main_window import BasePage, register_page


@register_page("correlation", "Correlation", "🔗")
class CorrelationPage(BasePage):
    """Static-to-dynamic correlation analysis page."""

    def _build_ui(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        header = ctk.CTkFrame(self, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew", padx=20, pady=20)

        ctk.CTkLabel(header, text="Static-Dynamic Correlation", font=ctk.CTkFont(size=28, weight="bold")).pack(anchor="w")

        # Summary stats
        stats_frame = ctk.CTkFrame(self)
        stats_frame.grid(row=1, column=0, sticky="ew", padx=20, pady=(0, 20))
        stats_frame.grid_columnconfigure((0, 1, 2, 3), weight=1)

        self.stat_labels = {}
        for i, (key, title) in enumerate([("total", "Total Correlations"), ("confirmed", "Confirmed"),
                                           ("missed_static", "Missed by Static"), ("missed_dynamic", "Missed by Dynamic")]):
            frame = ctk.CTkFrame(stats_frame)
            frame.grid(row=0, column=i, padx=10, pady=10, sticky="ew")
            ctk.CTkLabel(frame, text=title, font=ctk.CTkFont(size=11)).pack(pady=(10, 0))
            label = ctk.CTkLabel(frame, text="0", font=ctk.CTkFont(size=18, weight="bold"))
            label.pack(pady=(0, 10))
            self.stat_labels[key] = label

        # Correlation details tabs
        self.tabview = ctk.CTkTabview(self)
        self.tabview.grid(row=2, column=0, sticky="nsew", padx=20, pady=(0, 20))

        for tab in ["Confirmed", "Static Only", "Dynamic Only", "Discrepancies"]:
            self.tabview.add(tab)
            self.tabview.tab(tab).grid_columnconfigure(0, weight=1)
            self.tabview.tab(tab).grid_rowconfigure(0, weight=1)

        self.tab_frames = {tab: ctk.CTkScrollableFrame(self.tabview.tab(tab))
                          for tab in ["Confirmed", "Static Only", "Dynamic Only", "Discrepancies"]}
        for tab, frame in self.tab_frames.items():
            frame.grid(row=0, column=0, sticky="nsew")

    def _refresh_ui(self):
        if not self.analysis_results:
            return

        corr = self.analysis_results.get("correlation", {})

        # Stats
        confirmed = corr.get("confirmed", [])
        static_only = corr.get("static_only", [])
        dynamic_only = corr.get("dynamic_only", [])
        discrepancies = corr.get("discrepancies", [])

        self.stat_labels["total"].configure(text=str(len(confirmed) + len(static_only) + len(dynamic_only)))
        self.stat_labels["confirmed"].configure(text=str(len(confirmed)), text_color="#2ecc71")
        self.stat_labels["missed_static"].configure(text=str(len(static_only)), text_color="#f39c12")
        self.stat_labels["missed_dynamic"].configure(text=str(len(dynamic_only)), text_color="#e74c3c")

        # Tabs
        self._build_confirmed_tab(self.tab_frames["Confirmed"], confirmed)
        self._build_static_only_tab(self.tab_frames["Static Only"], static_only)
        self._build_dynamic_only_tab(self.tab_frames["Dynamic Only"], dynamic_only)
        self._build_discrepancies_tab(self.tab_frames["Discrepancies"], discrepancies)

    def _build_confirmed_tab(self, frame, data):
        for w in frame.winfo_children():
            w.destroy()

        for i, item in enumerate(data[:50]):
            row = ctk.CTkFrame(frame, fg_color=("gray95", "gray10") if i % 2 == 0 else ("gray90", "gray15"))
            row.pack(fill="x", padx=15, pady=2)
            ctk.CTkLabel(row, text=item.get("finding", "?"), font=ctk.CTkFont(size=11, weight="bold"),
                        text_color="#2ecc71", anchor="w").pack(side="left", padx=10, fill="x", expand=True)
            ctk.CTkLabel(row, text=f"Type: {item.get('type', '?')}").pack(side="left", padx=10)
            ctk.CTkLabel(row, text=item.get("evidence", "?")[:100]).pack(side="left", padx=10)

    def _build_static_only_tab(self, frame, data):
        for w in frame.winfo_children():
            w.destroy()

        ctk.CTkLabel(frame, text="Findings detected statically but not observed at runtime",
                    text_color=("gray50", "gray70")).pack(anchor="w", padx=15, pady=15)

        for i, item in enumerate(data[:50]):
            row = ctk.CTkFrame(frame, fg_color=("gray95", "gray10") if i % 2 == 0 else ("gray90", "gray15"))
            row.pack(fill="x", padx=15, pady=2)
            ctk.CTkLabel(row, text=item.get("finding", "?"), text_color="#f39c12", anchor="w").pack(
                side="left", padx=10, fill="x", expand=True)
            ctk.CTkLabel(row, text=item.get("reason", "Not triggered")).pack(side="left", padx=10)

    def _build_dynamic_only_tab(self, frame, data):
        for w in frame.winfo_children():
            w.destroy()

        ctk.CTkLabel(frame, text="Behavior observed at runtime but not found in static analysis",
                    text_color=("gray50", "gray70")).pack(anchor="w", padx=15, pady=15)

        for i, item in enumerate(data[:50]):
            row = ctk.CTkFrame(frame, fg_color=("gray95", "gray10") if i % 2 == 0 else ("gray90", "gray15"))
            row.pack(fill="x", padx=15, pady=2)
            ctk.CTkLabel(row, text=item.get("finding", "?"), text_color="#e74c3c", anchor="w").pack(
                side="left", padx=10, fill="x", expand=True)
            ctk.CTkLabel(row, text=item.get("reason", "Dynamic only")).pack(side="left", padx=10)

    def _build_discrepancies_tab(self, frame, data):
        for w in frame.winfo_children():
            w.destroy()

        ctk.CTkLabel(frame, text="Conflicting results between static and dynamic analysis",
                    text_color=("gray50", "gray70")).pack(anchor="w", padx=15, pady=15)

        for i, item in enumerate(data[:50]):
            row = ctk.CTkFrame(frame, fg_color=("gray95", "gray10") if i % 2 == 0 else ("gray90", "gray15"))
            row.pack(fill="x", padx=15, pady=2)
            ctk.CTkLabel(row, text=item.get("finding", "?"), text_color="#e74c3c", anchor="w").pack(
                side="left", padx=10, fill="x", expand=True)
            ctk.CTkLabel(row, text=f"Static: {item.get('static', '?')}").pack(side="left", padx=10)
            ctk.CTkLabel(row, text=f"Dynamic: {item.get('dynamic', '?')}").pack(side="left", padx=10)