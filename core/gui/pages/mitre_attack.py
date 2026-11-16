"""
MITRE ATT&CK Page for APKStudioAI 2.1
ATT&CK matrix visualization with technique mappings.
"""
import customtkinter as ctk
from typing import Dict, Any
from ..main_window import BasePage, register_page


@register_page("mitre_attack", "MITRE ATT&CK", "🎯")
class MITREAttackPage(BasePage):
    """MITRE ATT&CK mapping page."""

    def _build_ui(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        header = ctk.CTkFrame(self, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew", padx=20, pady=20)

        ctk.CTkLabel(header, text="MITRE ATT&CK Mobile", font=ctk.CTkFont(size=28, weight="bold")).pack(anchor="w")

        # Matrix view
        self.matrix_frame = ctk.CTkScrollableFrame(self)
        self.matrix_frame.grid(row=1, column=0, sticky="nsew", padx=20, pady=(0, 20))
        self.matrix_frame.grid_columnconfigure(0, weight=1)

        # Summary bar
        summary_frame = ctk.CTkFrame(self, height=60)
        summary_frame.grid(row=2, column=0, sticky="ew", padx=20, pady=(0, 20))
        summary_frame.grid_propagate(False)
        summary_frame.grid_columnconfigure((0, 1, 2, 3), weight=1)

        self.summary_labels = {}
        for i, (key, title) in enumerate([
            ("techniques", "Techniques Mapped"),
            ("tactics", "Tactics Covered"),
            ("high_conf", "High Confidence"),
            ("coverage", "Coverage %")
        ]):
            frame = ctk.CTkFrame(summary_frame, fg_color="transparent")
            frame.grid(row=0, column=i, sticky="nsew")
            ctk.CTkLabel(frame, text=title, font=ctk.CTkFont(size=11)).pack()
            label = ctk.CTkLabel(frame, text="0", font=ctk.CTkFont(size=18, weight="bold"))
            label.pack()
            self.summary_labels[key] = label

    def _refresh_ui(self):
        if not self.analysis_results:
            return

        mitre_results = self.analysis_results.get("mitre", {})
        matrix = mitre_results.get("matrix", {})
        summary = mitre_results.get("summary", {})

        # Update summary
        self.summary_labels["techniques"].configure(text=str(summary.get("unique_techniques", 0)))
        self.summary_labels["tactics"].configure(text=str(summary.get("tactics_covered", 0)))
        self.summary_labels["high_conf"].configure(text=str(summary.get("high_confidence", 0)))
        self.summary_labels["coverage"].configure(text=f"{summary.get('avg_confidence', 0)*100:.0f}%")

        # Clear matrix
        for w in self.matrix_frame.winfo_children():
            w.destroy()

        # Build matrix
        tactic_order = [
            "reconnaissance", "resource_development", "initial_access", "execution",
            "persistence", "privilege_escalation", "defense_evasion", "credential_access",
            "discovery", "lateral_movement", "collection", "command_and_control",
            "exfiltration", "impact"
        ]

        for tactic_name in tactic_order:
            tactic_data = matrix.get(tactic_name, [])
            if not tactic_data:
                continue

            # Check if any technique is detected
            detected = any(t.get("detected", False) for t in tactic_data)
            if not detected:
                continue  # Only show tactics with detections

            section = ctk.CTkFrame(self.matrix_frame)
            section.pack(fill="x", pady=5)
            section.grid_columnconfigure(0, weight=1)

            # Tactic header
            header = ctk.CTkFrame(section, fg_color=("#3d8bcf", "#1f6aa5"))
            header.pack(fill="x")
            header.grid_columnconfigure(0, weight=1)

            ctk.CTkLabel(header, text=tactic_name.replace("_", " ").title(),
                        font=ctk.CTkFont(size=14, weight="bold"), text_color="white").grid(
                row=0, column=0, padx=15, pady=10, sticky="w")

            # Techniques
            for tech in tactic_data:
                tech_frame = ctk.CTkFrame(section, fg_color=("gray95", "gray10"))
                tech_frame.pack(fill="x", padx=2, pady=2)
                tech_frame.grid_columnconfigure(1, weight=1)

                detected = tech.get("detected", False)
                confidence = tech.get("confidence", 0)

                # Status indicator
                if detected:
                    status_color = "#e74c3c" if confidence > 0.8 else "#f39c12" if confidence > 0.5 else "#3498db"
                    status_text = "DETECTED"
                else:
                    status_color = "#95a5a6"
                    status_text = "Not detected"

                indicator = ctk.CTkLabel(tech_frame, text=status_text,
                                        font=ctk.CTkFont(size=10, weight="bold"),
                                        text_color="white", fg_color=status_color,
                                        corner_radius=4, width=80)
                indicator.grid(row=0, column=0, padx=10, pady=5)

                # Technique info
                info = ctk.CTkFrame(tech_frame, fg_color="transparent")
                info.grid(row=0, column=1, sticky="ew", padx=10, pady=5)
                info.grid_columnconfigure(0, weight=1)

                ctk.CTkLabel(info, text=f"{tech['id']}: {tech['name']}",
                            font=ctk.CTkFont(size=12, weight="bold"), anchor="w").grid(
                    row=0, column=0, sticky="w")

                ctk.CTkLabel(info, text=tech['description'],
                            font=ctk.CTkFont(size=10), text_color=("gray50", "gray70"),
                            anchor="w").grid(row=1, column=0, sticky="w")

                # Mappings
                mappings = tech.get("mappings", [])
                if mappings:
                    map_text = " • ".join([f"{m['finding_id']} ({m['confidence']:.0%})" for m in mappings[:3]])
                    ctk.CTkLabel(info, text=map_text, font=ctk.CTkFont(size=9),
                                text_color=("gray40", "gray60"), anchor="w").grid(
                        row=2, column=0, sticky="w")

                # Confidence bar
                if detected:
                    prog = ctk.CTkProgressBar(tech_frame, width=100)
                    prog.grid(row=0, column=2, padx=10, pady=5)
                    prog.set(confidence)
                    prog.configure(progress_color=status_color)