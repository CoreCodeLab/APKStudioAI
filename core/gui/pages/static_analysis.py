"""
Static Analysis Page for APKStudioAI 2.1
Detailed static analysis results with filtering.
"""
import customtkinter as ctk
from typing import Dict, Any
from ..main_window import BasePage, register_page


@register_page("static_analysis", "Static Analysis", "🔍")
class StaticAnalysisPage(BasePage):
    """Static analysis results page."""

    def _build_ui(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        # Header with filters
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew", padx=20, pady=20)
        header.grid_columnconfigure(2, weight=1)

        ctk.CTkLabel(header, text="Static Analysis", font=ctk.CTkFont(size=28, weight="bold")).grid(
            row=0, column=0, sticky="w"
        )

        # Analyzer filter
        self.analyzer_var = ctk.StringVar(value="all")
        self.analyzer_menu = ctk.CTkOptionMenu(
            header,
            values=["all", "manifest", "strings", "network", "behavior", "dex", "advanced_static"],
            variable=self.analyzer_var,
            command=self._filter_results,
            width=180
        )
        self.analyzer_menu.grid(row=0, column=1, padx=10)

        # Severity filter
        self.severity_var = ctk.StringVar(value="all")
        self.severity_menu = ctk.CTkOptionMenu(
            header,
            values=["all", "critical", "high", "medium", "low"],
            variable=self.severity_var,
            command=self._filter_results,
            width=140
        )
        self.severity_menu.grid(row=0, column=2, padx=10, sticky="e")

        # Results table
        self.table_frame = ctk.CTkScrollableFrame(self)
        self.table_frame.grid(row=1, column=0, sticky="nsew", padx=20, pady=(0, 20))
        self.table_frame.grid_columnconfigure(0, weight=1)

        # Table headers
        self._create_table_header()

        # Summary at bottom
        self.summary_frame = ctk.CTkFrame(self, height=80)
        self.summary_frame.grid(row=2, column=0, sticky="ew", padx=20, pady=(0, 20))
        self.summary_frame.grid_propagate(False)
        self.summary_frame.grid_columnconfigure((0, 1, 2, 3), weight=1)

        self.summary_labels = {}
        for i, (key, title) in enumerate([
            ("total", "Total Findings"),
            ("critical", "Critical"),
            ("high", "High"),
            ("medium", "Medium"),
        ]):
            frame = ctk.CTkFrame(self.summary_frame, fg_color="transparent")
            frame.grid(row=0, column=i, sticky="nsew")
            ctk.CTkLabel(frame, text=title, font=ctk.CTkFont(size=11)).pack()
            label = ctk.CTkLabel(frame, text="0", font=ctk.CTkFont(size=20, weight="bold"))
            label.pack()
            self.summary_labels[key] = label

    def _create_table_header(self):
        """Create table header row."""
        header_row = ctk.CTkFrame(self.table_frame, fg_color=("gray85", "gray20"))
        header_row.grid(row=0, column=0, sticky="ew")
        header_row.grid_columnconfigure((0, 1, 2, 3, 4), weight=1)

        headers = ["Severity", "Analyzer", "Type", "Description", "Location"]
        for i, h in enumerate(headers):
            ctk.CTkLabel(
                header_row,
                text=h,
                font=ctk.CTkFont(size=12, weight="bold"),
                anchor="w"
            ).grid(row=0, column=i, padx=10, pady=8, sticky="w")

    def _filter_results(self, _=None):
        """Filter and refresh results."""
        self._refresh_ui()

    def _refresh_ui(self):
        if not self.analysis_results:
            return

        # Clear existing rows (keep header)
        for widget in self.table_frame.winfo_children()[1:]:
            widget.destroy()

        # Collect findings
        all_findings = []
        analyzer_filter = self.analyzer_var.get()
        severity_filter = self.severity_var.get()

        analyzers = ["manifest", "strings", "network", "behavior", "dex", "advanced_static"]
        if analyzer_filter != "all":
            analyzers = [analyzer_filter]

        for analyzer in analyzers:
            data = self.analysis_results.get(analyzer, {})
            for finding in data.get("findings", []):
                finding["analyzer"] = analyzer
                all_findings.append(finding)

        # Apply severity filter
        if severity_filter != "all":
            all_findings = [f for f in all_findings if f.get("severity", "low") == severity_filter]

        # Sort by severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        all_findings.sort(key=lambda x: severity_order.get(x.get("severity", "low"), 3))

        # Update summary
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in all_findings:
            counts[f.get("severity", "low")] = counts.get(f.get("severity", "low"), 0) + 1

        self.summary_labels["total"].configure(text=str(len(all_findings)))
        self.summary_labels["critical"].configure(text=str(counts["critical"]), text_color="#e74c3c")
        self.summary_labels["high"].configure(text=str(counts["high"]), text_color="#e67e22")
        self.summary_labels["medium"].configure(text=str(counts["medium"]), text_color="#f39c12")

        # Populate table
        for i, finding in enumerate(all_findings):
            self._add_finding_row(i + 1, finding)  # +1 for header

    def _add_finding_row(self, row_idx: int, finding: Dict):
        """Add a finding row to the table."""
        row = ctk.CTkFrame(self.table_frame, fg_color=("gray95", "gray10") if row_idx % 2 == 0 else ("gray90", "gray15"))
        row.grid(row=row_idx, column=0, sticky="ew")
        row.grid_columnconfigure((0, 1, 2, 3, 4), weight=1)

        severity = finding.get("severity", "low")
        severity_colors = {
            "critical": "#e74c3c",
            "high": "#e67e22",
            "medium": "#f39c12",
            "low": "#3498db",
        }
        color = severity_colors.get(severity, "#3498db")

        # Severity badge
        badge = ctk.CTkLabel(
            row,
            text=severity.upper(),
            font=ctk.CTkFont(size=10, weight="bold"),
            text_color="white",
            fg_color=color,
            corner_radius=4,
            width=70
        )
        badge.grid(row=0, column=0, padx=10, pady=5)

        # Analyzer
        ctk.CTkLabel(row, text=finding.get("analyzer", "").replace("_", " ").title(),
                    anchor="w").grid(row=0, column=1, padx=10, pady=5, sticky="w")

        # Type
        ctk.CTkLabel(row, text=finding.get("type", "unknown"), anchor="w").grid(
            row=0, column=2, padx=10, pady=5, sticky="w")

        # Description
        desc = finding.get("description", "No description")
        if len(desc) > 80:
            desc = desc[:77] + "..."
        ctk.CTkLabel(row, text=desc, anchor="w").grid(row=0, column=3, padx=10, pady=5, sticky="w")

        # Location
        loc = finding.get("location", {})
        loc_str = ""
        if loc.get("class"):
            loc_str += loc["class"]
        if loc.get("method"):
            loc_str += f" -> {loc['method']}"
        ctk.CTkLabel(row, text=loc_str or "N/A", anchor="w").grid(
            row=0, column=4, padx=10, pady=5, sticky="w")