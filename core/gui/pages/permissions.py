"""
Permissions Page for APKSTUDIOAI 2.1
Detailed permission analysis with risk assessment.
"""
import customtkinter as ctk
from typing import Dict, Any
from ..main_window import BasePage, register_page


@register_page("permissions", "Permissions", "🔐")
class PermissionsPage(BasePage):
    """Permissions analysis page."""

    def _build_ui(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        header = ctk.CTkFrame(self, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew", padx=20, pady=20)

        ctk.CTkLabel(header, text="Permission Analysis", font=ctk.CTkFont(size=28, weight="bold")).pack(anchor="w")

        # Risk summary
        risk_frame = ctk.CTkFrame(self)
        risk_frame.grid(row=1, column=0, sticky="ew", padx=20, pady=(0, 20))
        risk_frame.grid_columnconfigure((0, 1, 2, 3), weight=1)

        self.risk_labels = {}
        for i, (key, title) in enumerate([("total", "Total"), ("dangerous", "Dangerous"),
                                           ("runtime", "Runtime"), ("custom", "Custom")]):
            frame = ctk.CTkFrame(risk_frame)
            frame.grid(row=0, column=i, padx=10, pady=10, sticky="ew")
            ctk.CTkLabel(frame, text=title, font=ctk.CTkFont(size=11)).pack(pady=(10, 0))
            label = ctk.CTkLabel(frame, text="0", font=ctk.CTkFont(size=18, weight="bold"))
            label.pack(pady=(0, 10))
            self.risk_labels[key] = label

        # Permissions table
        self.table_frame = ctk.CTkScrollableFrame(self)
        self.table_frame.grid(row=2, column=0, sticky="nsew", padx=20, pady=(0, 20))
        self.table_frame.grid_columnconfigure(0, weight=1)

        self._create_header()

    def _create_header(self):
        header_row = ctk.CTkFrame(self.table_frame, fg_color=("gray85", "gray20"))
        header_row.grid(row=0, column=0, sticky="ew")
        header_row.grid_columnconfigure((0, 1, 2, 3, 4), weight=1)

        for i, h in enumerate(["Permission", "Protection Level", "Risk", "Used", "Description"]):
            ctk.CTkLabel(header_row, text=h, font=ctk.CTkFont(size=12, weight="bold"),
                        anchor="w").grid(row=0, column=i, padx=10, pady=8, sticky="w")

    def _refresh_ui(self):
        if not self.analysis_results:
            return

        manifest = self.analysis_results.get("manifest", {})
        behavior = self.analysis_results.get("behavior", {})

        perms = manifest.get("permissions", [])
        used_perms = set(behavior.get("used_permissions", []))

        # Risk counts
        dangerous = ["SEND_SMS", "READ_SMS", "READ_CONTACTS", "ACCESS_FINE_LOCATION",
                    "RECORD_AUDIO", "CAMERA", "READ_CALL_LOG", "SYSTEM_ALERT_WINDOW",
                    "READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE", "GET_ACCOUNTS"]
        runtime = ["CAMERA", "RECORD_AUDIO", "ACCESS_FINE_LOCATION", "READ_CONTACTS",
                  "READ_SMS", "SEND_SMS", "READ_CALL_LOG", "READ_EXTERNAL_STORAGE"]

        danger_count = sum(1 for p in perms if any(d in p for d in dangerous))
        runtime_count = sum(1 for p in perms if any(r in p for r in runtime))

        self.risk_labels["total"].configure(text=str(len(perms)))
        self.risk_labels["dangerous"].configure(text=str(danger_count), text_color="#e74c3c")
        self.risk_labels["runtime"].configure(text=str(runtime_count))
        self.risk_labels["custom"].configure(text=str(len([p for p in perms if "custom" in p.lower()])))

        # Clear rows
        for w in self.table_frame.winfo_children()[1:]:
            w.destroy()

        # Permission details (simplified)
        perm_details = {
            "android.permission.SEND_SMS": ("dangerous", "high", "Can send SMS"),
            "android.permission.READ_SMS": ("dangerous", "high", "Can read SMS"),
            "android.permission.READ_CONTACTS": ("dangerous", "high", "Can read contacts"),
            "android.permission.ACCESS_FINE_LOCATION": ("dangerous", "high", "Precise location"),
            "android.permission.RECORD_AUDIO": ("dangerous", "high", "Record audio"),
            "android.permission.CAMERA": ("dangerous", "high", "Camera access"),
            "android.permission.READ_CALL_LOG": ("dangerous", "high", "Call log access"),
            "android.permission.SYSTEM_ALERT_WINDOW": ("dangerous", "high", "Overlay windows"),
        }

        for i, perm in enumerate(perms):
            row = ctk.CTkFrame(self.table_frame, fg_color=("gray95", "gray10") if i % 2 == 0 else ("gray90", "gray15"))
            row.grid(row=i+1, column=0, sticky="ew")
            row.grid_columnconfigure((0, 1, 2, 3, 4), weight=1)

            detail = perm_details.get(perm, ("normal", "low", "Standard permission"))
            protection, risk, desc = detail

            ctk.CTkLabel(row, text=perm, anchor="w").grid(row=0, column=0, padx=10, pady=3, sticky="w")
            ctk.CTkLabel(row, text=protection.capitalize()).grid(row=0, column=1, padx=10, pady=3)

            risk_color = "#e74c3c" if risk == "high" else "#f39c12" if risk == "medium" else "#2ecc71"
            ctk.CTkLabel(row, text=risk.upper(), font=ctk.CTkFont(size=10, weight="bold"),
                        text_color="white", fg_color=risk_color, corner_radius=3, width=70).grid(
                row=0, column=2, padx=10, pady=3)

            used = "Yes" if perm in used_perms else "No"
            ctk.CTkLabel(row, text=used, text_color="#2ecc71" if used == "Yes" else "#e74c3c").grid(
                row=0, column=3, padx=10, pady=3)
            ctk.CTkLabel(row, text=desc, text_color=("gray50", "gray70")).grid(
                row=0, column=4, padx=10, pady=3, sticky="w")