"""
IOC Graph Page for APKStudioAI 2.1
Interactive IOC relationship graph visualization.
"""
import customtkinter as ctk
from typing import Dict, Any
from ..main_window import BasePage, register_page


@register_page("ioc_graph", "IOC Graph", "🕸️")
class IOCGraphPage(BasePage):
    """IOC relationship graph page."""

    def _build_ui(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        header = ctk.CTkFrame(self, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew", padx=20, pady=20)
        header.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(header, text="IOC Graph", font=ctk.CTkFont(size=28, weight="bold")).grid(
            row=0, column=0, sticky="w")

        # Controls
        controls = ctk.CTkFrame(header, fg_color="transparent")
        controls.grid(row=0, column=1, sticky="e")

        ctk.CTkButton(controls, text="Export Graph", width=120,
                     command=self._export_graph).pack(side="left", padx=5)
        ctk.CTkButton(controls, text="Refresh", width=80,
                     command=self._refresh_ui).pack(side="left", padx=5)

        # Stats
        stats_frame = ctk.CTkFrame(self)
        stats_frame.grid(row=1, column=0, sticky="ew", padx=20, pady=(0, 20))
        stats_frame.grid_columnconfigure((0, 1, 2, 3, 4), weight=1)

        self.stat_labels = {}
        for i, (key, title) in enumerate([
            ("nodes", "IOCs"), ("edges", "Relationships"),
            ("clusters", "Clusters"), ("central", "Top Hub"),
            ("density", "Density")
        ]):
            frame = ctk.CTkFrame(stats_frame, fg_color="transparent")
            frame.grid(row=0, column=i, sticky="nsew")
            ctk.CTkLabel(frame, text=title, font=ctk.CTkFont(size=11)).pack()
            label = ctk.CTkLabel(frame, text="0", font=ctk.CTkFont(size=18, weight="bold"))
            label.pack()
            self.stat_labels[key] = label

        # Graph view placeholder
        self.graph_frame = ctk.CTkFrame(self)
        self.graph_frame.grid(row=2, column=0, sticky="nsew", padx=20, pady=(0, 20))
        self.graph_frame.grid_rowconfigure(0, weight=1)
        self.graph_frame.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(self.graph_frame, text="Graph Visualization (Cytoscape.js integration pending)",
                    font=ctk.CTkFont(size=16), text_color=("gray50", "gray70")).grid(
            row=0, column=0, sticky="nsew")

        # IOC List
        list_frame = ctk.CTkFrame(self)
        list_frame.grid(row=3, column=0, sticky="nsew", padx=20, pady=(0, 20))
        list_frame.grid_rowconfigure(1, weight=1)
        list_frame.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(list_frame, text="IOC Nodes", font=ctk.CTkFont(size=16, weight="bold")).grid(
            row=0, column=0, sticky="w", padx=15, pady=15)

        self.ioc_list = ctk.CTkScrollableFrame(list_frame)
        self.ioc_list.grid(row=1, column=0, sticky="nsew", padx=15, pady=(0, 15))

    def _export_graph(self):
        if not self.analysis_results:
            return
        from tkinter import filedialog
        path = filedialog.asksaveasfilename(defaultextension=".json",
                                           filetypes=[("JSON", "*.json"), ("GEXF", "*.gexf"), ("GraphML", "*.graphml")])
        if path:
            # Would export from ioc_graph
            pass

    def _refresh_ui(self):
        if not self.analysis_results:
            return

        # Get stats from analysis
        ioc_stats = self.analysis_results.get("ioc_graph", {}).get("stats", {})

        self.stat_labels["nodes"].configure(text=str(ioc_stats.get("total_iocs", 0)))
        self.stat_labels["edges"].configure(text=str(ioc_stats.get("total_relationships", 0)))
        self.stat_labels["clusters"].configure(text=str(ioc_stats.get("clusters", 0)))
        self.stat_labels["density"].configure(text=f"{ioc_stats.get('avg_degree', 0):.1f}")

        central = ioc_stats.get("central_iocs", [])
        if central:
            self.stat_labels["central"].configure(text=central[0][0].value[:20])

        # IOC list
        for w in self.ioc_list.winfo_children():
            w.destroy()

        # Would populate from actual graph data
        ctk.CTkLabel(self.ioc_list, text="IOC list populated from graph data",
                    text_color=("gray50", "gray70")).pack(pady=20)