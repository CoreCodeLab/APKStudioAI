"""
Dashboard Page for APKStudioAI 2.1
Overview with risk score, key findings, and quick actions.
"""
import customtkinter as ctk
import tkinter as tk
from typing import Dict, Any
from ..main_window import BasePage, register_page


@register_page("dashboard", "Dashboard", "🏠")
class DashboardPage(BasePage):
    """Main dashboard page."""

    def _build_ui(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        # Header
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew", padx=20, pady=20)
        header.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(
            header,
            text="Dashboard",
            font=ctk.CTkFont(size=28, weight="bold")
        ).grid(row=0, column=0, sticky="w")

        # Quick stats row
        self.stats_frame = ctk.CTkFrame(self)
        self.stats_frame.grid(row=1, column=0, sticky="ew", padx=20, pady=(0, 20))
        self.stats_frame.grid_columnconfigure((0, 1, 2, 3), weight=1)

        self.stat_cards = {}
        for i, (key, title, color) in enumerate([
            ("risk_score", "Risk Score", "#e74c3c"),
            ("findings", "Total Findings", "#3498db"),
            ("malware_prob", "Malware Probability", "#f39c12"),
            ("confidence", "Confidence", "#2ecc71"),
        ]):
            card = self._create_stat_card(self.stats_frame, title, "—", color)
            card.grid(row=0, column=i, padx=10, pady=10, sticky="ew")
            self.stat_cards[key] = card

        # Main content area
        content = ctk.CTkFrame(self)
        content.grid(row=2, column=0, sticky="nsew", padx=20, pady=(0, 20))
        content.grid_columnconfigure((0, 1), weight=1)
        content.grid_rowconfigure(0, weight=1)

        # Left: Key Findings
        left_frame = ctk.CTkFrame(content)
        left_frame.grid(row=0, column=0, sticky="nsew", padx=(0, 10))
        left_frame.grid_rowconfigure(1, weight=1)
        left_frame.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(left_frame, text="Key Findings", font=ctk.CTkFont(size=16, weight="bold")).grid(
            row=0, column=0, sticky="w", padx=15, pady=15
        )

        self.findings_list = ctk.CTkScrollableFrame(left_frame)
        self.findings_list.grid(row=1, column=0, sticky="nsew", padx=15, pady=(0, 15))
        self.findings_list.grid_columnconfigure(0, weight=1)

        # Right: Risk Breakdown
        right_frame = ctk.CTkFrame(content)
        right_frame.grid(row=0, column=1, sticky="nsew", padx=(10, 0))
        right_frame.grid_rowconfigure(1, weight=1)
        right_frame.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(right_frame, text="Risk Breakdown", font=ctk.CTkFont(size=16, weight="bold")).grid(
            row=0, column=0, sticky="w", padx=15, pady=15
        )

        self.risk_chart_frame = ctk.CTkFrame(right_frame)
        self.risk_chart_frame.grid(row=1, column=0, sticky="nsew", padx=15, pady=(0, 15))
        self.risk_chart_frame.grid_columnconfigure(0, weight=1)

        # Quick actions
        actions_frame = ctk.CTkFrame(self)
        actions_frame.grid(row=3, column=0, sticky="ew", padx=20, pady=(0, 20))
        actions_frame.grid_columnconfigure((0, 1, 2, 3), weight=1)

        actions = [
            ("New Analysis", "📁", self.app._new_analysis),
            ("View Report", "📊", lambda: self.app._switch_page("reporting")),
            ("Settings", "⚙️", lambda: self.app._switch_page("settings")),
            ("Export", "💾", self.app._export_report),
        ]

        for i, (text, icon, cmd) in enumerate(actions):
            btn = ctk.CTkButton(
                actions_frame,
                text=f"{icon} {text}",
                height=40,
                command=cmd,
                font=ctk.CTkFont(size=13)
            )
            btn.grid(row=0, column=i, padx=5, pady=10, sticky="ew")

    def _create_stat_card(self, parent, title: str, value: str, color: str) -> ctk.CTkFrame:
        """Create a statistic card."""
        card = ctk.CTkFrame(parent, fg_color=("gray90", "gray15"))
        card.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            card,
            text=title,
            font=ctk.CTkFont(size=12),
            text_color=("gray50", "gray70")
        ).grid(row=0, column=0, pady=(15, 5))

        value_label = ctk.CTkLabel(
            card,
            text=value,
            font=ctk.CTkFont(size=32, weight="bold"),
            text_color=color
        )
        value_label.grid(row=1, column=0, pady=(0, 15))

        card.value_label = value_label
        return card

    def _refresh_ui(self):
        if not self.analysis_results:
            return

        # Update stat cards
        risk = self.analysis_results.get("risk_score", 0)
        self.stat_cards["risk_score"].value_label.configure(
            text=f"{risk}/100",
            text_color="#e74c3c" if risk > 70 else "#f39c12" if risk > 40 else "#2ecc71"
        )

        findings = self.analysis_results.get("findings_count", 0)
        self.stat_cards["findings"].value_label.configure(text=str(findings))

        ml_prob = self.analysis_results.get("ml_probability", 0)
        self.stat_cards["malware_prob"].value_label.configure(text=f"{ml_prob:.1%}")

        confidence = self.analysis_results.get("confidence", 0)
        self.stat_cards["confidence"].value_label.configure(text=f"{confidence:.1%}")

        # Update findings list
        for widget in self.findings_list.winfo_children():
            widget.destroy()

        top_findings = self.analysis_results.get("top_findings", [])[:5]
        if not top_findings:
            # Generate from analysis results
            top_findings = self._extract_top_findings()

        for i, finding in enumerate(top_findings):
            self._add_finding_row(self.findings_list, i, finding)

        # Update risk breakdown
        for widget in self.risk_chart_frame.winfo_children():
            widget.destroy()

        self._build_risk_breakdown()

    def _extract_top_findings(self) -> list:
        """Extract top findings from analysis results."""
        findings = []
        for analyzer in ["manifest", "strings", "network", "behavior", "dex", "advanced_static"]:
            data = self.analysis_results.get(analyzer, {})
            for f in data.get("findings", [])[:3]:
                f["analyzer"] = analyzer
                findings.append(f)

        # Sort by severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        findings.sort(key=lambda x: severity_order.get(x.get("severity", "low"), 3))
        return findings[:5]

    def _add_finding_row(self, parent, index: int, finding: Dict):
        """Add a finding row to the list."""
        row = ctk.CTkFrame(parent, fg_color=("gray95", "gray10"))
        row.grid(row=index, column=0, sticky="ew", pady=2)
        row.grid_columnconfigure(1, weight=1)

        severity = finding.get("severity", "low")
        severity_colors = {
            "critical": "#e74c3c",
            "high": "#e67e22",
            "medium": "#f39c12",
            "low": "#3498db",
        }
        color = severity_colors.get(severity, "#3498db")

        # Severity indicator
        indicator = ctk.CTkFrame(row, width=8, fg_color=color)
        indicator.grid(row=0, column=0, sticky="ns", padx=(10, 0), pady=10)

        # Finding info
        info_frame = ctk.CTkFrame(row, fg_color="transparent")
        info_frame.grid(row=0, column=1, sticky="ew", padx=10, pady=5)
        info_frame.grid_columnconfigure(0, weight=1)

        title = finding.get("description", finding.get("type", "Unknown"))
        ctk.CTkLabel(
            info_frame,
            text=title,
            font=ctk.CTkFont(size=12, weight="bold"),
            anchor="w"
        ).grid(row=0, column=0, sticky="w")

        details = f"{finding.get('analyzer', '').replace('_', ' ').title()} • {severity.upper()}"
        ctk.CTkLabel(
            info_frame,
            text=details,
            font=ctk.CTkFont(size=10),
            text_color=("gray50", "gray70"),
            anchor="w"
        ).grid(row=1, column=0, sticky="w")

    def _build_risk_breakdown(self):
        """Build risk breakdown visualization."""
        categories = {
            "Manifest": self.analysis_results.get("manifest", {}).get("risk", 0),
            "Network": self.analysis_results.get("network", {}).get("risk", 0),
            "Behavior": self.analysis_results.get("behavior", {}).get("risk", 0),
            "Code": self.analysis_results.get("dex", {}).get("risk", 0),
            "Advanced": self.analysis_results.get("advanced_static", {}).get("risk", 0),
            "Dynamic": self.analysis_results.get("dynamic", {}).get("risk", 0),
        }

        for i, (cat, score) in enumerate(categories.items()):
            row_frame = ctk.CTkFrame(self.risk_chart_frame, fg_color="transparent")
            row_frame.grid(row=i, column=0, sticky="ew", pady=5)
            row_frame.grid_columnconfigure(1, weight=1)

            ctk.CTkLabel(row_frame, text=cat, width=100, anchor="w").grid(row=0, column=0)

            progress = ctk.CTkProgressBar(row_frame)
            progress.grid(row=0, column=1, sticky="ew", padx=10)
            progress.set(score / 100)

            color = "#e74c3c" if score > 70 else "#f39c12" if score > 40 else "#2ecc71"
            progress.configure(progress_color=color)

            ctk.CTkLabel(row_frame, text=f"{score}/100", width=60).grid(row=0, column=2)