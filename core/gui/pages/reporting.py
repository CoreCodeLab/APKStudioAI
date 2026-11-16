"""
Reporting Page for APKSTUDIOAI 2.1
Report generation and export (JSON, HTML, PDF, STIX, MISP).
"""
import customtkinter as ctk
from typing import Dict, Any
from ..main_window import BasePage, register_page


@register_page("reporting", "Reporting", "📊")
class ReportingPage(BasePage):
    """Report generation and export page."""

    def _build_ui(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        header = ctk.CTkFrame(self, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew", padx=20, pady=20)

        ctk.CTkLabel(header, text="Report Generation", font=ctk.CTkFont(size=28, weight="bold")).pack(anchor="w")

        # Report options
        options_frame = ctk.CTkFrame(self)
        options_frame.grid(row=1, column=0, sticky="ew", padx=20, pady=(0, 20))
        options_frame.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(options_frame, text="Report Format", font=ctk.CTkFont(size=14, weight="bold")).pack(
            anchor="w", padx=15, pady=15)

        self.format_var = ctk.StringVar(value="json")
        format_frame = ctk.CTkFrame(options_frame, fg_color="transparent")
        format_frame.pack(fill="x", padx=15, pady=(0, 15))

        formats = [
            ("json", "JSON", "Complete structured data"),
            ("html", "HTML", "Interactive web report"),
            ("pdf", "PDF", "Print-ready document"),
            ("stix", "STIX 2.1", "Threat intelligence standard"),
            ("misp", "MISP", "Malware Information Sharing"),
        ]

        for fmt, title, desc in formats:
            row = ctk.CTkFrame(format_frame)
            row.pack(fill="x", pady=3, padx=5)
            ctk.CTkRadioButton(row, text="", variable=self.format_var, value=fmt).pack(side="left", padx=10)
            ctk.CTkLabel(row, text=title, font=ctk.CTkFont(size=12, weight="bold"), width=100).pack(side="left")
            ctk.CTkLabel(row, text=desc, text_color=("gray50", "gray70")).pack(side="left", padx=10)

        # Sections to include
        ctk.CTkLabel(options_frame, text="Sections to Include", font=ctk.CTkFont(size=14, weight="bold")).pack(
            anchor="w", padx=15, pady=(15, 5))

        sections_frame = ctk.CTkFrame(options_frame, fg_color="transparent")
        sections_frame.pack(fill="x", padx=15, pady=(0, 15))

        self.section_vars = {}
        sections = [
            ("summary", "Executive Summary"),
            ("static", "Static Analysis"),
            ("dynamic", "Dynamic Analysis"),
            ("network", "Network Analysis"),
            ("ml", "ML Classification"),
            ("mitre", "MITRE ATT&CK Mapping"),
            ("families", "Malware Families"),
            ("ioc", "IOC Graph"),
            ("evidence", "Evidence & Artifacts"),
            ("recommendations", "Recommendations"),
        ]

        for i, (key, title) in enumerate(sections):
            var = ctk.BooleanVar(value=True)
            self.section_vars[key] = var
            row = i // 2
            col = i % 2
            ctk.CTkCheckBox(sections_frame, text=title, variable=var).grid(row=row, column=col, sticky="w", padx=10, pady=5)

        # Actions
        action_frame = ctk.CTkFrame(options_frame, fg_color="transparent")
        action_frame.pack(fill="x", padx=15, pady=15)

        ctk.CTkButton(action_frame, text="Generate Report", command=self._generate_report,
                     font=ctk.CTkFont(size=14, weight="bold"), height=40).pack(side="left", padx=5)
        ctk.CTkButton(action_frame, text="Preview", command=self._preview_report,
                     height=40).pack(side="left", padx=5)

        # Preview area
        self.preview_frame = ctk.CTkFrame(self)
        self.preview_frame.grid(row=2, column=0, sticky="nsew", padx=20, pady=(0, 20))
        self.preview_frame.grid_columnconfigure(0, weight=1)
        self.preview_frame.grid_rowconfigure(0, weight=1)

        self.preview_text = ctk.CTkTextbox(self.preview_frame, font=ctk.CTkFont(family="Consolas", size=11))
        self.preview_text.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)

    def _generate_report(self):
        """Generate and export report."""
        if not self.analysis_results:
            return

        from tkinter import filedialog, messagebox
        import json
        from pathlib import Path

        fmt = self.format_var.get()
        ext = {"json": ".json", "html": ".html", "pdf": ".pdf", "stix": ".json", "misp": ".json"}[fmt]

        file_path = filedialog.asksaveasfilename(
            title="Save Report",
            defaultextension=ext,
            filetypes=[(fmt.upper(), f"*{ext}"), ("All Files", "*.*")]
        )

        if not file_path:
            return

        try:
            sections = [k for k, v in self.section_vars.items() if v.get()]
            report_data = self._build_report(sections)

            if fmt == "json":
                with open(file_path, "w") as f:
                    json.dump(report_data, f, indent=2, default=str)
            elif fmt == "html":
                html = self._build_html_report(report_data)
                with open(file_path, "w") as f:
                    f.write(html)
            elif fmt == "stix":
                stix = self._build_stix_report(report_data)
                with open(file_path, "w") as f:
                    json.dump(stix, f, indent=2)
            elif fmt == "misp":
                misp = self._build_misp_report(report_data)
                with open(file_path, "w") as f:
                    json.dump(misp, f, indent=2)
            elif fmt == "pdf":
                messagebox.showinfo("PDF Export", "PDF export requires additional dependencies. Use HTML for now.")

            messagebox.showinfo("Success", f"Report saved to {file_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate report: {e}")

    def _preview_report(self):
        """Preview report in the text area."""
        if not self.analysis_results:
            return

        sections = [k for k, v in self.section_vars.items() if v.get()]
        report_data = self._build_report(sections)
        fmt = self.format_var.get()

        self.preview_text.delete("1.0", "end")

        if fmt == "json":
            import json
            self.preview_text.insert("1.0", json.dumps(report_data, indent=2, default=str)[:50000])
        elif fmt == "html":
            self.preview_text.insert("1.0", self._build_html_report(report_data)[:50000])
        elif fmt == "stix":
            import json
            self.preview_text.insert("1.0", json.dumps(self._build_stix_report(report_data), indent=2)[:50000])
        elif fmt == "misp":
            import json
            self.preview_text.insert("1.0", json.dumps(self._build_misp_report(report_data), indent=2)[:50000])

    def _build_report(self, sections: list) -> Dict:
        """Build report data from analysis results."""
        r = self.analysis_results
        report = {"metadata": r.get("metadata", {})}

        if "summary" in sections:
            report["summary"] = {
                "risk_score": r.get("risk_score", 0),
                "classification": r.get("classification", "Unknown"),
                "family": r.get("family", "Unknown"),
                "total_findings": sum(len(v) for v in r.get("findings", {}).values() if isinstance(v, list)),
            }

        if "static" in sections:
            report["static_analysis"] = r.get("static", {})

        if "dynamic" in sections:
            report["dynamic_analysis"] = r.get("dynamic", {})

        if "network" in sections:
            report["network_analysis"] = r.get("network", {})

        if "ml" in sections:
            report["ml_classification"] = r.get("ml", {})

        if "mitre" in sections:
            report["mitre_attack"] = r.get("mitre", {})

        if "families" in sections:
            report["malware_families"] = r.get("families", {})

        if "ioc" in sections:
            report["ioc_graph"] = r.get("ioc_graph", {})

        if "evidence" in sections:
            report["evidence"] = r.get("evidence", {})

        if "recommendations" in sections:
            report["recommendations"] = self._generate_recommendations(r)

        return report

    def _generate_recommendations(self, r: Dict) -> list:
        """Generate actionable recommendations."""
        recs = []
        risk = r.get("risk_score", 0)

        if risk >= 70:
            recs.append({"priority": "CRITICAL", "action": "Immediate isolation and forensic analysis required"})
        elif risk >= 40:
            recs.append({"priority": "HIGH", "action": "Quarantine and deep analysis recommended"})

        if r.get("dynamic", {}).get("network_connections"):
            recs.append({"priority": "HIGH", "action": "Block C2 IPs/domains at network perimeter"})

        if r.get("mitre", {}).get("techniques"):
            recs.append({"priority": "MEDIUM", "action": f"Update detection rules for {len(r['mitre']['techniques'])} ATT&CK techniques"})

        if r.get("families", {}).get("attributed"):
            recs.append({"priority": "MEDIUM", "action": f"Threat intel enrichment for family: {r['families']['attributed']}"})

        return recs

    def _build_html_report(self, data: Dict) -> str:
        """Build HTML report."""
        import json
        return f"""
<!DOCTYPE html>
<html>
<head>
    <title>APKStudioAI Analysis Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }}
        .container {{ max-width: 1000px; margin: 0 auto; background: white; padding: 40px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        h1 {{ color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }}
        h2 {{ color: #34495e; margin-top: 30px; }}
        .meta {{ color: #7f8c8d; font-size: 14px; }}
        .risk {{ display: inline-block; padding: 8px 20px; border-radius: 20px; font-weight: bold; }}
        .risk.critical {{ background: #e74c3c; color: white; }}
        .risk.high {{ background: #e67e22; color: white; }}
        .risk.medium {{ background: #f39c12; color: white; }}
        .risk.low {{ background: #2ecc71; color: white; }}
        pre {{ background: #2c3e50; color: #ecf0f1; padding: 20px; border-radius: 5px; overflow-x: auto; }}
        .section {{ margin-bottom: 30px; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>APKStudioAI 2.1 Analysis Report</h1>
        <p class="meta">Package: {data.get('metadata', {}).get('package', 'Unknown')}<br>
        Generated: {data.get('metadata', {}).get('timestamp', 'Unknown')}</p>

        <div class="section">
            <h2>Executive Summary</h2>
            <p>Risk Score: <span class="risk {'critical' if data.get('summary', {}).get('risk_score', 0) >= 70 else 'high' if data.get('summary', {}).get('risk_score', 0) >= 40 else 'medium' if data.get('summary', {}).get('risk_score', 0) >= 20 else 'low'}">{data.get('summary', {}).get('risk_score', 0)}/100</span></p>
            <p>Classification: {data.get('summary', {}).get('classification', 'Unknown')}</p>
            <p>Family: {data.get('summary', {}).get('family', 'Unknown')}</p>
        </div>

        <div class="section">
            <h2>Full Data (JSON)</h2>
            <pre>{json.dumps(data, indent=2, default=str)}</pre>
        </div>
    </div>
</body>
</html>
"""

    def _build_stix_report(self, data: Dict) -> Dict:
        """Build STIX 2.1 report."""
        return {
            "type": "report",
            "spec_version": "2.1",
            "id": f"report--{data.get('metadata', {}).get('sha256', 'unknown')[:32]}",
            "labels": ["malware", "analysis"],
            "name": f"APKStudioAI Analysis: {data.get('metadata', {}).get('package', 'Unknown')}",
            "description": f"Risk Score: {data.get('summary', {}).get('risk_score', 0)}/100",
            "published": data.get('metadata', {}).get('timestamp', ''),
            "object_refs": [],
        }

    def _build_misp_report(self, data: Dict) -> Dict:
        """Build MISP event."""
        return {
            "Event": {
                "info": f"APKStudioAI Analysis: {data.get('metadata', {}).get('package', 'Unknown')}",
                "analysis": 2,
                "threat_level_id": "1" if data.get('summary', {}).get('risk_score', 0) >= 70 else "2",
                "published": True,
                "Attribute": self._extract_iocs(data),
            }
        }

    def _extract_iocs(self, data: Dict) -> list:
        """Extract IOCs for MISP."""
        iocs = []
        # Extract from various sections
        for ip in data.get("network", {}).get("ips", []):
            iocs.append({"type": "ip-dst", "value": ip, "category": "Network activity"})
        for domain in data.get("network", {}).get("domains", []):
            iocs.append({"type": "domain", "value": domain, "category": "Network activity"})
        for url in data.get("network", {}).get("urls", []):
            iocs.append({"type": "url", "value": url, "category": "Network activity"})
        return iocs