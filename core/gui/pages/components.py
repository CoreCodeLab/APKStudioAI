"""
Components Page for APKSTUDIOAI 2.1
App component analysis with ICC and attack surface.
"""
import customtkinter as ctk
from typing import Dict, Any
from ..main_window import BasePage, register_page


@register_page("components", "Components", "🧩")
class ComponentsPage(BasePage):
    """App components analysis page."""

    def _build_ui(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        header = ctk.CTkFrame(self, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew", padx=20, pady=20)

        ctk.CTkLabel(header, text="Component Analysis", font=ctk.CTkFont(size=28, weight="bold")).pack(anchor="w")

        # Attack surface
        surface_frame = ctk.CTkFrame(self)
        surface_frame.grid(row=1, column=0, sticky="ew", padx=20, pady=(0, 20))
        surface_frame.grid_columnconfigure((0, 1, 2, 3), weight=1)

        self.surface_labels = {}
        for i, (key, title) in enumerate([("exported", "Exported"), ("total", "Total Components"),
                                           ("icc", "ICC Paths"), ("risk", "Attack Surface")]):
            frame = ctk.CTkFrame(surface_frame)
            frame.grid(row=0, column=i, padx=10, pady=10, sticky="ew")
            ctk.CTkLabel(frame, text=title, font=ctk.CTkFont(size=11)).pack(pady=(10, 0))
            label = ctk.CTkLabel(frame, text="0", font=ctk.CTkFont(size=18, weight="bold"))
            label.pack(pady=(0, 10))
            self.surface_labels[key] = label

        # Component details tabs
        self.tabview = ctk.CTkTabview(self)
        self.tabview.grid(row=2, column=0, sticky="nsew", padx=20, pady=(0, 20))

        for tab in ["Activities", "Services", "Receivers", "Providers", "ICC Flows"]:
            self.tabview.add(tab)
            self.tabview.tab(tab).grid_columnconfigure(0, weight=1)
            self.tabview.tab(tab).grid_rowconfigure(0, weight=1)

        self.tab_frames = {tab: ctk.CTkScrollableFrame(self.tabview.tab(tab))
                          for tab in ["Activities", "Services", "Receivers", "Providers", "ICC Flows"]}
        for tab, frame in self.tab_frames.items():
            frame.grid(row=0, column=0, sticky="nsew")

    def _refresh_ui(self):
        if not self.analysis_results:
            return

        manifest = self.analysis_results.get("manifest", {})
        advanced = self.analysis_results.get("advanced_static", {})

        # Attack surface
        exported = sum(1 for c in manifest.get("activities", []) + manifest.get("services", []) +
                      manifest.get("receivers", []) + manifest.get("providers", [])
                      if c.get("exported"))
        total = (len(manifest.get("activities", [])) + len(manifest.get("services", [])) +
                len(manifest.get("receivers", [])) + len(manifest.get("providers", [])))
        icc = advanced.get("icc", {}).get("total_flows", 0)

        self.surface_labels["exported"].configure(text=str(exported), text_color="#e74c3c" if exported > 5 else "#2ecc71")
        self.surface_labels["total"].configure(text=str(total))
        self.surface_labels["icc"].configure(text=str(icc))
        self.surface_labels["risk"].configure(text="HIGH" if exported > 10 else "MEDIUM" if exported > 5 else "LOW",
                                             text_color="#e74c3c" if exported > 10 else "#f39c12" if exported > 5 else "#2ecc71")

        # Components
        comps = {
            "Activities": manifest.get("activities", []),
            "Services": manifest.get("services", []),
            "Receivers": manifest.get("receivers", []),
            "Providers": manifest.get("providers", []),
        }

        for tab_name, items in comps.items():
            frame = self.tab_frames[tab_name]
            for w in frame.winfo_children():
                w.destroy()

            for i, comp in enumerate(items):
                row = ctk.CTkFrame(frame, fg_color=("gray95", "gray10") if i % 2 == 0 else ("gray90", "gray15"))
                row.grid(row=i, column=0, sticky="ew", pady=2)
                row.grid_columnconfigure(1, weight=1)

                ctk.CTkLabel(row, text=comp.get("name", "Unknown"), font=ctk.CTkFont(size=11, weight="bold")).grid(
                    row=0, column=0, padx=10, pady=5, sticky="w")

                attrs = []
                if comp.get("exported"):
                    attrs.append("📤 Exported")
                if comp.get("permission"):
                    attrs.append(f"🔐 {comp['permission']}")
                if comp.get("intent_filters"):
                    attrs.append(f"🎯 {len(comp['intent_filters'])} filters")
                ctk.CTkLabel(row, text=" | ".join(attrs), text_color=("gray50", "gray70")).grid(
                    row=0, column=1, padx=10, pady=5, sticky="w")

        # ICC Flows
        icc_frame = self.tab_frames["ICC Flows"]
        for w in icc_frame.winfo_children():
            w.destroy()

        icc_data = advanced.get("icc", {})
        for i, flow in enumerate(icc_data.get("flows", [])[:50]):
            row = ctk.CTkFrame(icc_frame, fg_color=("gray95", "gray10") if i % 2 == 0 else ("gray90", "gray15"))
            row.grid(row=i, column=0, sticky="ew", pady=2)
            row.grid_columnconfigure(1, weight=1)

            ctk.CTkLabel(row, text=f"{flow.get('source', '?')} -> {flow.get('target', '?')}",
                        font=ctk.CTkFont(size=11), anchor="w").grid(row=0, column=0, padx=10, pady=3, sticky="w")
            ctk.CTkLabel(row, text=f"Action: {flow.get('action', '?')}", text_color=("gray50", "gray70")).grid(
                row=0, column=1, padx=10, pady=3, sticky="w")