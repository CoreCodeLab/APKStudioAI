"""
Timeline Page for APKSTUDIOAI 2.1
Temporal analysis of events and behaviors.
"""
import customtkinter as ctk
from typing import Dict, Any
from ..main_window import BasePage, register_page


@register_page("timeline", "Timeline", "📅")
class TimelinePage(BasePage):
    """Timeline analysis page."""

    def _build_ui(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        header = ctk.CTkFrame(self, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew", padx=20, pady=20)

        ctk.CTkLabel(header, text="Timeline", font=ctk.CTkFont(size=28, weight="bold")).pack(anchor="w")

        # Timeline view
        self.timeline_frame = ctk.CTkScrollableFrame(self)
        self.timeline_frame.grid(row=1, column=0, sticky="nsew", padx=20, pady=(0, 20))
        self.timeline_frame.grid_columnconfigure(0, weight=1)

        # Legend
        legend_frame = ctk.CTkFrame(self, height=50)
        legend_frame.grid(row=2, column=0, sticky="ew", padx=20, pady=(0, 20))
        legend_frame.grid_propagate(False)

        legend_items = [
            ("Static Finding", "#3498db"),
            ("Dynamic Event", "#e67e22"),
            ("Network Activity", "#2ecc71"),
            ("Critical Alert", "#e74c3c"),
        ]
        for label, color in legend_items:
            item = ctk.CTkFrame(legend_frame, fg_color="transparent")
            item.pack(side="left", padx=20, pady=10)
            ctk.CTkFrame(item, width=20, height=20, fg_color=color).pack(side="left", padx=5)
            ctk.CTkLabel(item, text=label).pack(side="left")

    def _refresh_ui(self):
        if not self.analysis_results:
            return

        for w in self.timeline_frame.winfo_children():
            w.destroy()

        # Collect all timestamped events
        events = []

        # Static findings (use analysis start time as reference)
        base_time = 0
        for analyzer in ["manifest", "strings", "network", "behavior", "dex", "advanced_static"]:
            data = self.analysis_results.get(analyzer, {})
            for f in data.get("findings", []):
                events.append({
                    "time": base_time,
                    "type": "static",
                    "source": analyzer,
                    "title": f.get("description", f.get("type", "Finding")),
                    "severity": f.get("severity", "low"),
                })

        # Dynamic events
        dynamic = self.analysis_results.get("dynamic", {})
        for event in dynamic.get("events", []):
            events.append({
                "time": event.get("timestamp", 0),
                "type": "dynamic",
                "source": event.get("source", "unknown"),
                "title": event.get("event_type", "Event"),
                "severity": event.get("severity", "info"),
            })

        # Network flows
        for flow in dynamic.get("http_flows", []):
            events.append({
                "time": flow.get("timestamp", 0),
                "type": "network",
                "source": "mitmproxy",
                "title": f"{flow.get('method', '')} {flow.get('url', '')[:50]}",
                "severity": "info",
            })

        # Sort by time
        events.sort(key=lambda x: x.get("time", 0))

        # Display
        for i, event in enumerate(events[:200]):
            self._add_timeline_event(i, event)

    def _add_timeline_event(self, idx: int, event: Dict):
        row = ctk.CTkFrame(self.timeline_frame, fg_color=("gray95", "gray10") if idx % 2 == 0 else ("gray90", "gray15"))
        row.grid(row=idx, column=0, sticky="ew", pady=2)
        row.grid_columnconfigure(1, weight=1)

        # Time
        ts = event.get("time", 0)
        time_str = f"T+{ts:.0f}s" if ts else "N/A"
        ctk.CTkLabel(row, text=time_str, width=80, font=ctk.CTkFont(size=10)).grid(
            row=0, column=0, padx=10, pady=5)

        # Event content
        content = ctk.CTkFrame(row, fg_color="transparent")
        content.grid(row=0, column=1, sticky="ew", padx=10, pady=5)
        content.grid_columnconfigure(0, weight=1)

        # Type badge
        type_colors = {"static": "#3498db", "dynamic": "#e67e22", "network": "#2ecc71"}
        badge = ctk.CTkLabel(content, text=event["type"].upper(), font=ctk.CTkFont(size=9, weight="bold"),
                            text_color="white", fg_color=type_colors.get(event["type"], "#95a5a6"),
                            corner_radius=3, width=70)
        badge.grid(row=0, column=0, padx=(0, 10))

        ctk.CTkLabel(content, text=event["title"], font=ctk.CTkFont(size=11, weight="bold"), anchor="w").grid(
            row=0, column=1, sticky="w")

        details = f"Source: {event['source']} • Severity: {event['severity']}"
        ctk.CTkLabel(content, text=details, font=ctk.CTkFont(size=9),
                    text_color=("gray50", "gray70"), anchor="w").grid(row=1, column=1, sticky="w")