"""
Network Analysis Page for APKStudioAI 2.1
HTTP/HTTPS traffic, C2 detection, and network IOCs.
"""
import customtkinter as ctk
from typing import Dict, Any
from ..main_window import BasePage, register_page


@register_page("network_analysis", "Network Analysis", "🌐")
class NetworkAnalysisPage(BasePage):
    """Network analysis results page."""

    def _build_ui(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        header = ctk.CTkFrame(self, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew", padx=20, pady=20)
        header.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(header, text="Network Analysis", font=ctk.CTkFont(size=28, weight="bold")).grid(
            row=0, column=0, sticky="w"
        )

        # Traffic analysis frame
        traffic_frame = ctk.CTkFrame(self)
        traffic_frame.grid(row=1, column=0, sticky="nsew", padx=20, pady=(0, 20))
        traffic_frame.grid_columnconfigure((0, 1), weight=1)
        traffic_frame.grid_rowconfigure(1, weight=1)

        # Left: HTTP Flows
        left = ctk.CTkFrame(traffic_frame)
        left.grid(row=0, column=0, rowspan=2, sticky="nsew", padx=(0, 10))
        left.grid_rowconfigure(1, weight=1)
        left.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(left, text="HTTP Flows", font=ctk.CTkFont(size=16, weight="bold")).grid(
            row=0, column=0, sticky="w", padx=15, pady=15)

        self.flows_frame = ctk.CTkScrollableFrame(left)
        self.flows_frame.grid(row=1, column=0, sticky="nsew", padx=15, pady=(0, 15))

        # Right: Analysis Summary
        right = ctk.CTkFrame(traffic_frame)
        right.grid(row=0, column=1, sticky="nsew", padx=(10, 0))
        right.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(right, text="Traffic Analysis", font=ctk.CTkFont(size=16, weight="bold")).grid(
            row=0, column=0, sticky="w", padx=15, pady=15)

        self.analysis_frame = ctk.CTkFrame(right)
        self.analysis_frame.grid(row=1, column=0, sticky="ew", padx=15, pady=(0, 15))

        # IOCs section
        ioc_frame = ctk.CTkFrame(traffic_frame)
        ioc_frame.grid(row=1, column=1, sticky="nsew", padx=(10, 0))
        ioc_frame.grid_rowconfigure(1, weight=1)
        ioc_frame.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(ioc_frame, text="Network IOCs", font=ctk.CTkFont(size=16, weight="bold")).grid(
            row=0, column=0, sticky="w", padx=15, pady=15)

        self.iocs_frame = ctk.CTkScrollableFrame(ioc_frame)
        self.iocs_frame.grid(row=1, column=0, sticky="nsew", padx=15, pady=(0, 15))

    def _refresh_ui(self):
        if not self.analysis_results:
            return

        # HTTP Flows
        for w in self.flows_frame.winfo_children():
            w.destroy()

        dynamic = self.analysis_results.get("dynamic", {})
        flows = dynamic.get("http_flows", [])
        network = self.analysis_results.get("network", {})

        for i, flow in enumerate(flows[:50]):
            self._add_flow_row(i, flow)

        # Traffic Analysis
        for w in self.analysis_frame.winfo_children():
            w.destroy()

        analysis = dynamic.get("traffic_analysis", {})
        if not analysis and flows:
            from core.dynamic.mitmproxy_integration import get_mitmproxy_integration
            mitm = get_mitmproxy_integration()
            analysis = mitm.analyze_traffic(flows)

        self._build_analysis_summary(analysis)

        # Network IOCs
        for w in self.iocs_frame.winfo_children():
            w.destroy()

        self._build_iocs(network, dynamic)

    def _add_flow_row(self, idx: int, flow: Dict):
        row = ctk.CTkFrame(self.flows_frame, fg_color=("gray95", "gray10") if idx % 2 == 0 else ("gray90", "gray15"))
        row.grid(row=idx, column=0, sticky="ew", pady=2)
        row.grid_columnconfigure((0, 1, 2, 3), weight=1)

        method = flow.get("method", "")
        url = flow.get("url", "")
        status = flow.get("response_code", 0)
        scheme = flow.get("scheme", "")

        # Method badge
        colors = {"GET": "#3498db", "POST": "#e67e22", "PUT": "#f39c12", "DELETE": "#e74c3c"}
        badge = ctk.CTkLabel(row, text=method, font=ctk.CTkFont(size=10, weight="bold"),
                            text_color="white", fg_color=colors.get(method, "#95a5a6"),
                            corner_radius=4, width=50)
        badge.grid(row=0, column=0, padx=10, pady=5)

        # URL (truncated)
        display_url = url[:80] + "..." if len(url) > 80 else url
        ctk.CTkLabel(row, text=display_url, anchor="w").grid(row=0, column=1, padx=10, pady=5, sticky="w")

        # Status
        status_color = "#2ecc71" if 200 <= status < 300 else "#f39c12" if 300 <= status < 400 else "#e74c3c"
        ctk.CTkLabel(row, text=str(status), font=ctk.CTkFont(size=11, weight="bold"),
                    text_color=status_color).grid(row=0, column=2, padx=10, pady=5)

        # Scheme
        scheme_color = "#2ecc71" if scheme == "https" else "#e74c3c"
        ctk.CTkLabel(row, text=scheme.upper(), font=ctk.CTkFont(size=10, weight="bold"),
                    text_color=scheme_color).grid(row=0, column=3, padx=10, pady=5)

    def _build_analysis_summary(self, analysis: Dict):
        if not analysis:
            ctk.CTkLabel(self.analysis_frame, text="No traffic captured",
                        text_color=("gray50", "gray70")).pack(pady=20)
            return

        items = [
            ("Total Requests", analysis.get("total_requests", 0)),
            ("Unique Hosts", len(analysis.get("unique_hosts", []))),
            ("Cleartext Requests", analysis.get("cleartext_requests", 0)),
            ("Suspicious Domains", len(analysis.get("suspicious_domains", []))),
            ("Potential C2", len(analysis.get("potential_c2", []))),
            ("Exfiltration Indicators", len(analysis.get("exfiltration_indicators", []))),
            ("Large Responses", analysis.get("large_responses", 0)),
            ("Certificate Issues", analysis.get("certificate_issues", 0)),
        ]

        for i, (label, value) in enumerate(items):
            row = ctk.CTkFrame(self.analysis_frame, fg_color="transparent")
            row.grid(row=i, column=0, sticky="ew", pady=3)
            row.grid_columnconfigure(1, weight=1)

            ctk.CTkLabel(row, text=label, anchor="w").grid(row=0, column=0, padx=10, sticky="w")

            color = "#e74c3c" if value > 0 and "Suspicious" in label or "C2" in label or "Exfil" in label else "#2ecc71"
            if "Cleartext" in label and value > 0:
                color = "#e67e22"
            ctk.CTkLabel(row, text=str(value), font=ctk.CTkFont(size=14, weight="bold"),
                        text_color=color).grid(row=0, column=1, padx=10, sticky="e")

    def _build_iocs(self, network: Dict, dynamic: Dict):
        iocs = []

        # From static network analysis
        for url in network.get("urls", [])[:20]:
            iocs.append(("URL", url, "static"))
        for domain in network.get("domains", [])[:20]:
            iocs.append(("Domain", domain, "static"))
        for ip in network.get("ips", [])[:20]:
            iocs.append(("IP", ip, "static"))

        # From dynamic
        for flow in dynamic.get("http_flows", [])[:20]:
            iocs.append(("URL (dynamic)", flow.get("url", ""), "dynamic"))
            if flow.get("host"):
                iocs.append(("Host", flow["host"], "dynamic"))
            if flow.get("server_ip"):
                iocs.append(("IP (dynamic)", flow["server_ip"], "dynamic"))

        for i, (itype, value, source) in enumerate(iocs):
            row = ctk.CTkFrame(self.iocs_frame, fg_color=("gray95", "gray10") if i % 2 == 0 else ("gray90", "gray15"))
            row.grid(row=i, column=0, sticky="ew", pady=1)
            row.grid_columnconfigure(1, weight=1)

            ctk.CTkLabel(row, text=itype, font=ctk.CTkFont(size=10, weight="bold"), width=100).grid(
                row=0, column=0, padx=10, pady=3)
            ctk.CTkLabel(row, text=value[:100], anchor="w").grid(
                row=0, column=1, padx=10, pady=3, sticky="w")
            source_color = "#3498db" if source == "static" else "#e67e22"
            ctk.CTkLabel(row, text=source, text_color=source_color, font=ctk.CTkFont(size=9)).grid(
                row=0, column=2, padx=10, pady=3)