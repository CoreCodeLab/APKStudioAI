"""
Dynamic Analysis Page for APKStudioAI 2.1
Runtime behavior, Frida events, and dynamic findings.
"""
import customtkinter as ctk
from typing import Dict, Any
from ..main_window import BasePage, register_page


@register_page("dynamic_analysis", "Dynamic Analysis", "⚡")
class DynamicAnalysisPage(BasePage):
    """Dynamic analysis results page."""

    def _build_ui(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        # Header
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew", padx=20, pady=20)
        header.grid_columnconfigure(2, weight=1)

        ctk.CTkLabel(header, text="Dynamic Analysis", font=ctk.CTkFont(size=28, weight="bold")).grid(
            row=0, column=0, sticky="w"
        )

        # Event type filter
        self.event_type_var = ctk.StringVar(value="all")
        self.event_type_menu = ctk.CTkOptionMenu(
            header,
            values=["all", "network", "file_io", "crypto", "reflection", "dynamic_loading", "anti_analysis", "ipc"],
            variable=self.event_type_var,
            command=self._filter_events,
            width=180
        )
        self.event_type_menu.grid(row=0, column=1, padx=10)

        # Source filter
        self.source_var = ctk.StringVar(value="all")
        self.source_menu = ctk.CTkOptionMenu(
            header,
            values=["all", "frida", "mitmproxy", "system", "logcat"],
            variable=self.source_var,
            command=self._filter_events,
            width=140
        )
        self.source_menu.grid(row=0, column=2, padx=10, sticky="e")

        # Events table
        self.table_frame = ctk.CTkScrollableFrame(self)
        self.table_frame.grid(row=1, column=0, sticky="nsew", padx=20, pady=(0, 20))
        self.table_frame.grid_columnconfigure(0, weight=1)

        self._create_table_header()

        # Timeline chart placeholder
        self.timeline_frame = ctk.CTkFrame(self, height=200)
        self.timeline_frame.grid(row=2, column=0, sticky="ew", padx=20, pady=(0, 20))
        self.timeline_frame.grid_propagate(False)

        ctk.CTkLabel(self.timeline_frame, text="Event Timeline (coming soon)",
                    font=ctk.CTkFont(size=14), text_color=("gray50", "gray70")).pack(expand=True)

    def _create_table_header(self):
        header_row = ctk.CTkFrame(self.table_frame, fg_color=("gray85", "gray20"))
        header_row.grid(row=0, column=0, sticky="ew")
        header_row.grid_columnconfigure((0, 1, 2, 3, 4, 5), weight=1)

        headers = ["Time", "Type", "Source", "Severity", "Package", "Details"]
        for i, h in enumerate(headers):
            ctk.CTkLabel(header_row, text=h, font=ctk.CTkFont(size=12, weight="bold"),
                        anchor="w").grid(row=0, column=i, padx=10, pady=8, sticky="w")

    def _filter_events(self, _=None):
        self._refresh_ui()

    def _refresh_ui(self):
        if not self.analysis_results:
            return

        # Clear rows
        for widget in self.table_frame.winfo_children()[1:]:
            widget.destroy()

        dynamic = self.analysis_results.get("dynamic", {})
        events = dynamic.get("events", [])

        # Apply filters
        event_filter = self.event_type_var.get()
        source_filter = self.source_var.get()

        if event_filter != "all":
            events = [e for e in events if e.get("event_type") == event_filter]
        if source_filter != "all":
            events = [e for e in events if e.get("source") == source_filter]

        # Sort by timestamp
        events.sort(key=lambda x: x.get("timestamp", 0), reverse=True)

        # Limit to 1000 events
        events = events[:1000]

        for i, event in enumerate(events):
            self._add_event_row(i + 1, event)

    def _add_event_row(self, row_idx: int, event: Dict):
        row = ctk.CTkFrame(self.table_frame, fg_color=("gray95", "gray10") if row_idx % 2 == 0 else ("gray90", "gray15"))
        row.grid(row=row_idx, column=0, sticky="ew")
        row.grid_columnconfigure((0, 1, 2, 3, 4, 5), weight=1)

        # Time
        ts = event.get("timestamp", 0)
        time_str = f"{ts:.0f}" if ts else "N/A"
        ctk.CTkLabel(row, text=time_str, anchor="w").grid(row=0, column=0, padx=10, pady=5, sticky="w")

        # Type
        ctk.CTkLabel(row, text=event.get("event_type", "unknown"), anchor="w").grid(
            row=0, column=1, padx=10, pady=5, sticky="w")

        # Source
        ctk.CTkLabel(row, text=event.get("source", "unknown"), anchor="w").grid(
            row=0, column=2, padx=10, pady=5, sticky="w")

        # Severity
        severity = event.get("severity", "info")
        colors = {"critical": "#e74c3c", "high": "#e67e22", "warning": "#f39c12", "info": "#3498db"}
        badge = ctk.CTkLabel(row, text=severity.upper(), font=ctk.CTkFont(size=10, weight="bold"),
                            text_color="white", fg_color=colors.get(severity, "#3498db"), corner_radius=4, width=70)
        badge.grid(row=0, column=3, padx=10, pady=5)

        # Package
        ctk.CTkLabel(row, text=event.get("package", "N/A"), anchor="w").grid(
            row=0, column=4, padx=10, pady=5, sticky="w")

        # Details
        data = event.get("data", {})
        details = str(data)[:100] + "..." if len(str(data)) > 100 else str(data)
        ctk.CTkLabel(row, text=details, anchor="w").grid(row=0, column=5, padx=10, pady=5, sticky="w")