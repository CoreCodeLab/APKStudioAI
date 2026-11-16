"""
Manifest Page for APKSTUDIOAI 2.1
AndroidManifest.xml analysis with component tree.
"""
import customtkinter as ctk
from typing import Dict, Any
from ..main_window import BasePage, register_page


@register_page("manifest", "Manifest", "📋")
class ManifestPage(BasePage):
    """Manifest analysis page."""

    def _build_ui(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        header = ctk.CTkFrame(self, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew", padx=20, pady=20)

        ctk.CTkLabel(header, text="Manifest Analysis", font=ctk.CTkFont(size=28, weight="bold")).pack(anchor="w")

        # Package info
        info_frame = ctk.CTkFrame(self)
        info_frame.grid(row=1, column=0, sticky="ew", padx=20, pady=(0, 20))
        info_frame.grid_columnconfigure((0, 1, 2, 3), weight=1)

        self.info_labels = {}
        for i, (key, title) in enumerate([("package", "Package"), ("version", "Version"),
                                           ("min_sdk", "Min SDK"), ("target_sdk", "Target SDK")]):
            frame = ctk.CTkFrame(info_frame)
            frame.grid(row=0, column=i, padx=10, pady=10, sticky="ew")
            ctk.CTkLabel(frame, text=title, font=ctk.CTkFont(size=11)).pack(pady=(10, 0))
            label = ctk.CTkLabel(frame, text="—", font=ctk.CTkFont(size=16, weight="bold"))
            label.pack(pady=(0, 10))
            self.info_labels[key] = label

        # Components tabs
        self.tabview = ctk.CTkTabview(self)
        self.tabview.grid(row=2, column=0, sticky="nsew", padx=20, pady=(0, 20))

        for tab in ["Activities", "Services", "Receivers", "Providers", "Permissions"]:
            self.tabview.add(tab)
            self.tabview.tab(tab).grid_columnconfigure(0, weight=1)
            self.tabview.tab(tab).grid_rowconfigure(0, weight=1)

        self.tab_frames = {tab: ctk.CTkScrollableFrame(self.tabview.tab(tab))
                          for tab in ["Activities", "Services", "Receivers", "Providers", "Permissions"]}
        for tab, frame in self.tab_frames.items():
            frame.grid(row=0, column=0, sticky="nsew")

    def _refresh_ui(self):
        if not self.analysis_results:
            return

        manifest = self.analysis_results.get("manifest", {})

        # Package info
        self.info_labels["package"].configure(text=manifest.get("package", "Unknown"))
        self.info_labels["version"].configure(text=manifest.get("version_name", "Unknown"))
        self.info_labels["min_sdk"].configure(text=f"API {manifest.get('min_sdk', '?')}")
        self.info_labels["target_sdk"].configure(text=f"API {manifest.get('target_sdk', '?')}")

        # Components
        components = {
            "Activities": manifest.get("activities", []),
            "Services": manifest.get("services", []),
            "Receivers": manifest.get("receivers", []),
            "Providers": manifest.get("providers", []),
        }

        for tab_name, comps in components.items():
            frame = self.tab_frames[tab_name]
            for w in frame.winfo_children():
                w.destroy()

            for i, comp in enumerate(comps):
                row = ctk.CTkFrame(frame, fg_color=("gray95", "gray10") if i % 2 == 0 else ("gray90", "gray15"))
                row.grid(row=i, column=0, sticky="ew", pady=2)
                row.grid_columnconfigure(1, weight=1)

                ctk.CTkLabel(row, text=comp.get("name", "Unknown"), font=ctk.CTkFont(size=11, weight="bold")).grid(
                    row=0, column=0, padx=10, pady=5, sticky="w")

                attrs = []
                if comp.get("exported"):
                    attrs.append("Exported")
                if comp.get("permission"):
                    attrs.append(f"Perm: {comp['permission']}")
                ctk.CTkLabel(row, text=" • ".join(attrs), text_color=("gray50", "gray70")).grid(
                    row=0, column=1, padx=10, pady=5, sticky="w")

        # Permissions
        perm_frame = self.tab_frames["Permissions"]
        for w in perm_frame.winfo_children():
            w.destroy()

        perms = manifest.get("permissions", [])
        for i, perm in enumerate(perms):
            row = ctk.CTkFrame(perm_frame, fg_color=("gray95", "gray10") if i % 2 == 0 else ("gray90", "gray15"))
            row.grid(row=i, column=0, sticky="ew", pady=2)
            row.grid_columnconfigure(1, weight=1)

            ctk.CTkLabel(row, text=perm, anchor="w").grid(row=0, column=0, padx=10, pady=3, sticky="w")

            # Check if dangerous
            dangerous = ["SEND_SMS", "READ_SMS", "READ_CONTACTS", "ACCESS_FINE_LOCATION",
                        "RECORD_AUDIO", "CAMERA", "READ_CALL_LOG", "SYSTEM_ALERT_WINDOW"]
            is_dangerous = any(d in perm for d in dangerous)
            if is_dangerous:
                ctk.CTkLabel(row, text="DANGEROUS", font=ctk.CTkFont(size=9, weight="bold"),
                            text_color="white", fg_color="#e74c3c", corner_radius=3, width=80).grid(
                    row=0, column=1, padx=10, pady=3)