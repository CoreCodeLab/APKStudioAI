"""
Strings Page for APKSTUDIOAI 2.1
Extracted strings with filtering and categorization.
"""
import customtkinter as ctk
from typing import Dict, Any
from ..main_window import BasePage, register_page


@register_page("strings", "Strings", "🔤")
class StringsPage(BasePage):
    """Strings analysis page."""

    def _build_ui(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        header = ctk.CTkFrame(self, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew", padx=20, pady=20)
        header.grid_columnconfigure(2, weight=1)

        ctk.CTkLabel(header, text="Strings Analysis", font=ctk.CTkFont(size=28, weight="bold")).grid(
            row=0, column=0, sticky="w")

        # Filters
        self.category_var = ctk.StringVar(value="all")
        ctk.CTkOptionMenu(header, values=["all", "urls", "ips", "emails", "crypto", "suspicious", "paths"],
                         variable=self.category_var, command=self._filter, width=150).grid(row=0, column=1, padx=10)

        self.search_entry = ctk.CTkEntry(header, placeholder_text="Search strings...", width=300)
        self.search_entry.grid(row=0, column=2, padx=10, sticky="e")
        self.search_entry.bind("<Return>", lambda e: self._filter())

        # Strings table
        self.table_frame = ctk.CTkScrollableFrame(self)
        self.table_frame.grid(row=1, column=0, sticky="nsew", padx=20, pady=(0, 20))
        self.table_frame.grid_columnconfigure(0, weight=1)

        self._create_header()

        # Stats
        stats_frame = ctk.CTkFrame(self, height=50)
        stats_frame.grid(row=2, column=0, sticky="ew", padx=20, pady=(0, 20))
        stats_frame.grid_propagate(False)
        stats_frame.grid_columnconfigure((0, 1, 2, 3), weight=1)

        self.stat_labels = {}
        for i, (key, title) in enumerate([("total", "Total"), ("urls", "URLs"), ("ips", "IPs"), ("suspicious", "Suspicious")]):
            frame = ctk.CTkFrame(stats_frame, fg_color="transparent")
            frame.grid(row=0, column=i, sticky="nsew")
            ctk.CTkLabel(frame, text=title, font=ctk.CTkFont(size=11)).pack()
            label = ctk.CTkLabel(frame, text="0", font=ctk.CTkFont(size=18, weight="bold"))
            label.pack()
            self.stat_labels[key] = label

    def _create_header(self):
        header_row = ctk.CTkFrame(self.table_frame, fg_color=("gray85", "gray20"))
        header_row.grid(row=0, column=0, sticky="ew")
        header_row.grid_columnconfigure((0, 1, 2), weight=1)

        for i, h in enumerate(["Category", "String", "Context"]):
            ctk.CTkLabel(header_row, text=h, font=ctk.CTkFont(size=12, weight="bold"),
                        anchor="w").grid(row=0, column=i, padx=10, pady=8, sticky="w")

    def _filter(self, _=None):
        self._refresh_ui()

    def _refresh_ui(self):
        if not self.analysis_results:
            return

        strings_data = self.analysis_results.get("strings", {})
        all_strings = strings_data.get("all_strings", [])
        categorized = strings_data.get("categorized", {})

        # Update stats
        self.stat_labels["total"].configure(text=str(len(all_strings)))
        self.stat_labels["urls"].configure(text=str(len(categorized.get("urls", []))))
        self.stat_labels["ips"].configure(text=str(len(categorized.get("ips", []))))
        self.stat_labels["suspicious"].configure(text=str(len(categorized.get("suspicious", []))))

        # Clear rows
        for w in self.table_frame.winfo_children()[1:]:
            w.destroy()

        category = self.category_var.get()
        search = self.search_entry.get().lower()

        # Build filtered list
        display_strings = []
        for cat, strings in categorized.items():
            if category != "all" and cat != category:
                continue
            for s in strings:
                if search and search not in s.lower():
                    continue
                display_strings.append((cat, s))

        for i, (cat, s) in enumerate(display_strings[:500]):
            row = ctk.CTkFrame(self.table_frame, fg_color=("gray95", "gray10") if i % 2 == 0 else ("gray90", "gray15"))
            row.grid(row=i+1, column=0, sticky="ew")
            row.grid_columnconfigure((0, 1, 2), weight=1)

            cat_colors = {"urls": "#3498db", "ips": "#e67e22", "emails": "#9b59b6",
                         "crypto": "#f39c12", "suspicious": "#e74c3c", "paths": "#2ecc71"}
            ctk.CTkLabel(row, text=cat, font=ctk.CTkFont(size=10, weight="bold"),
                        text_color=cat_colors.get(cat, "white"),
                        fg_color=cat_colors.get(cat, "#95a5a6"), corner_radius=4, width=80).grid(
                row=0, column=0, padx=10, pady=3)

            display = s[:200] + "..." if len(s) > 200 else s
            ctk.CTkLabel(row, text=display, anchor="w").grid(row=0, column=1, padx=10, pady=3, sticky="w")