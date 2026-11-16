"""
Threat Intelligence Page for APKStudioAI 2.1
IOC feeds, VirusTotal, URLhaus, and threat actor attribution.
"""
import customtkinter as ctk
from typing import Dict, Any
from ..main_window import BasePage, register_page


@register_page("threat_intel", "Threat Intel", "🛡️")
class ThreatIntelPage(BasePage):
    """Threat intelligence page."""

    def _build_ui(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        header = ctk.CTkFrame(self, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew", padx=20, pady=20)
        header.grid_columnconfigure(2, weight=1)

        ctk.CTkLabel(header, text="Threat Intelligence", font=ctk.CTkFont(size=28, weight="bold")).grid(
            row=0, column=0, sticky="w"
        )

        # Query controls
        controls = ctk.CTkFrame(header, fg_color="transparent")
        controls.grid(row=0, column=2, sticky="e")

        self.query_type = ctk.StringVar(value="hash")
        ctk.CTkOptionMenu(controls, values=["hash", "domain", "ip", "url"],
                         variable=self.query_type, width=100).pack(side="left", padx=5)

        self.query_entry = ctk.CTkEntry(controls, placeholder_text="Enter IOC...", width=250)
        self.query_entry.pack(side="left", padx=5)

        ctk.CTkButton(controls, text="Query Feeds", width=100,
                     command=self._query_feeds).pack(side="left", padx=5)

        # Results tabs
        self.tabview = ctk.CTkTabview(self)
        self.tabview.grid(row=1, column=0, sticky="nsew", padx=20, pady=(0, 20))

        tabs = ["VirusTotal", "URLhaus", "MalwareBazaar", "ThreatFox", "AlienVault OTX", "Summary"]
        for tab in tabs:
            self.tabview.add(tab)
            self.tabview.tab(tab).grid_columnconfigure(0, weight=1)
            self.tabview.tab(tab).grid_rowconfigure(0, weight=1)

        self.tab_frames = {tab: ctk.CTkScrollableFrame(self.tabview.tab(tab))
                          for tab in tabs}
        for tab, frame in self.tab_frames.items():
            frame.grid(row=0, column=0, sticky="nsew")

    def _query_feeds(self):
        query = self.query_entry.get().strip()
        if not query:
            return

        qtype = self.query_type.get()

        # Show loading
        for frame in self.tab_frames.values():
            for w in frame.winfo_children():
                w.destroy()
            ctk.CTkLabel(frame, text="Querying feeds...", text_color=("gray50", "gray70")).pack(pady=20)

        def worker():
            try:
                from core.threat_intel.feed_integrations import get_feed_integrations
                feeds = get_feed_integrations()

                results = {}
                if qtype == "hash":
                    results = {"VirusTotal": feeds.check_hash(query),
                               "URLhaus": feeds._check_urlhaus_hash(query),
                               "MalwareBazaar": feeds._check_abuse_ch_hash(query),
                               "ThreatFox": feeds._check_threatfox_hash(query)}
                elif qtype == "domain":
                    results = {"VirusTotal": feeds.check_domain(query),
                               "URLhaus": feeds._check_urlhaus_domain(query),
                               "ThreatFox": feeds._check_threatfox_domain(query)}
                elif qtype == "ip":
                    results = {"VirusTotal": feeds.check_ip(query),
                               "URLhaus": feeds._check_urlhaus_ip(query),
                               "ThreatFox": feeds._check_threatfox_ip(query)}
                elif qtype == "url":
                    results = {"VirusTotal": feeds.check_url(query),
                               "URLhaus": feeds._check_urlhaus_url(query)}

                self.after(0, lambda: self._display_results(results, qtype))
            except Exception as e:
                self.after(0, lambda: self._display_error(str(e)))

        import threading
        threading.Thread(target=worker, daemon=True).start()

    def _display_results(self, results: Dict, qtype: str):
        source_map = {
            "VirusTotal": "VirusTotal",
            "URLhaus": "URLhaus",
            "MalwareBazaar": "MalwareBazaar",
            "ThreatFox": "ThreatFox",
        }

        all_indicators = []

        for source_name, result_list in results.items():
            frame = self.tab_frames.get(source_map.get(source_name, source_name))
            if not frame:
                continue

            for w in frame.winfo_children():
                w.destroy()

            if not result_list:
                ctk.CTkLabel(frame, text="No results", text_color=("gray50", "gray70")).pack(pady=20)
                continue

            for result in result_list:
                if not result.found:
                    ctk.CTkLabel(frame, text=f"Not found ({result.error or 'unknown'})",
                                text_color=("gray50", "gray70")).pack(pady=10)
                    continue

                for indicator in result.indicators:
                    all_indicators.append((source_name, indicator))
                    self._add_indicator_card(frame, source_name, indicator)

        # Summary tab
        self._build_summary(self.tab_frames["Summary"], all_indicators)

    def _display_error(self, error: str):
        for frame in self.tab_frames.values():
            for w in frame.winfo_children():
                w.destroy()
            ctk.CTkLabel(frame, text=f"Error: {error}", text_color="#e74c3c").pack(pady=20)

    def _add_indicator_card(self, parent, source: str, indicator):
        card = ctk.CTkFrame(parent, fg_color=("gray95", "gray10"))
        card.pack(fill="x", padx=10, pady=5)
        card.grid_columnconfigure(1, weight=1)

        # Source badge
        ctk.CTkLabel(card, text=source, font=ctk.CTkFont(size=10, weight="bold"),
                    fg_color=("#3d8bcf", "#1f6aa5"), text_color="white",
                    corner_radius=4, width=100).grid(row=0, column=0, padx=10, pady=10)

        # Details
        details = ctk.CTkFrame(card, fg_color="transparent")
        details.grid(row=0, column=1, sticky="ew", padx=10, pady=10)
        details.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(details, text=f"{indicator.indicator_type}: {indicator.value}",
                    font=ctk.CTkFont(size=12, weight="bold"), anchor="w").grid(row=0, column=0, sticky="w")

        tags = " • ".join([f"{t}" for t in indicator.tags])
        if indicator.malware_families:
            tags += " • " + " • ".join(indicator.malware_families)
        ctk.CTkLabel(details, text=tags, font=ctk.CTkFont(size=10),
                    text_color=("gray50", "gray70"), anchor="w").grid(row=1, column=0, sticky="w")

        # Confidence/Severity
        conf_color = "#e74c3c" if indicator.confidence > 0.8 else "#f39c12" if indicator.confidence > 0.5 else "#3498db"
        ctk.CTkLabel(details, text=f"Confidence: {indicator.confidence:.0%} • Severity: {indicator.severity}",
                    font=ctk.CTkFont(size=10), text_color=conf_color, anchor="w").grid(row=2, column=0, sticky="w")

    def _build_summary(self, parent, indicators):
        for w in parent.winfo_children():
            w.destroy()

        if not indicators:
            ctk.CTkLabel(parent, text="No indicators found", text_color=("gray50", "gray70")).pack(pady=20)
            return

        # Group by source
        by_source = {}
        for source, ind in indicators:
            if source not in by_source:
                by_source[source] = []
            by_source[source].append(ind)

        for source, inds in by_source.items():
            section = ctk.CTkFrame(parent)
            section.pack(fill="x", padx=10, pady=10)

            ctk.CTkLabel(section, text=f"{source} ({len(inds)} indicators)",
                        font=ctk.CTkFont(size=14, weight="bold")).pack(anchor="w", padx=15, pady=10)

            for ind in inds[:5]:
                row = ctk.CTkFrame(section, fg_color="transparent")
                row.pack(fill="x", padx=15, pady=2)
                ctk.CTkLabel(row, text=f"  {ind.indicator_type}: {ind.value[:60]}",
                            anchor="w").pack(side="left")
                ctk.CTkLabel(row, text=f"  {ind.severity} ({ind.confidence:.0%})",
                            text_color="#e74c3c" if ind.severity == "critical" else "#f39c12").pack(side="right")

    def _refresh_ui(self):
        # Auto-query if we have analysis results with IOCs
        if self.analysis_results and not self.query_entry.get():
            file_hash = self.analysis_results.get("file_hashes", {}).get("sha256", "")
            if file_hash:
                self.query_entry.insert(0, file_hash)
                self._query_feeds()