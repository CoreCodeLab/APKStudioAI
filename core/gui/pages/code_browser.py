"""
Code Browser Page for APKStudioAI 2.1
Decompiled code viewer with syntax highlighting.
"""
import customtkinter as ctk
from typing import Dict, Any
from ..main_window import BasePage, register_page


@register_page("code_browser", "Code Browser", "💻")
class CodeBrowserPage(BasePage):
    """Code browser page."""

    def _build_ui(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        header = ctk.CTkFrame(self, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew", padx=20, pady=20)
        header.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(header, text="Code Browser", font=ctk.CTkFont(size=28, weight="bold")).grid(
            row=0, column=0, sticky="w")

        # Navigation
        nav = ctk.CTkFrame(header, fg_color="transparent")
        nav.grid(row=0, column=1, sticky="e")

        self.class_var = ctk.StringVar()
        self.class_menu = ctk.CTkOptionMenu(nav, variable=self.class_var, values=["Select class..."],
                                           command=self._load_class, width=300)
        self.class_menu.pack(side="left", padx=5)

        self.method_var = ctk.StringVar()
        self.method_menu = ctk.CTkOptionMenu(nav, variable=self.method_var, values=["Select method..."],
                                            command=self._load_method, width=250)
        self.method_menu.pack(side="left", padx=5)

        # Code view
        self.code_frame = ctk.CTkFrame(self)
        self.code_frame.grid(row=1, column=0, sticky="nsew", padx=20, pady=(0, 20))
        self.code_frame.grid_rowconfigure(0, weight=1)
        self.code_frame.grid_columnconfigure(0, weight=1)

        self.code_text = ctk.CTkTextbox(self.code_frame, font=ctk.CTkFont(family="Consolas", size=12))
        self.code_text.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)

        # Search
        search_frame = ctk.CTkFrame(self, height=50)
        search_frame.grid(row=2, column=0, sticky="ew", padx=20, pady=(0, 20))
        search_frame.grid_propagate(False)

        self.search_entry = ctk.CTkEntry(search_frame, placeholder_text="Search in code...", width=400)
        self.search_entry.pack(side="left", padx=10, pady=10)
        self.search_entry.bind("<Return>", lambda e: self._search_code())

        ctk.CTkButton(search_frame, text="Search", command=self._search_code).pack(side="left", padx=5)
        ctk.CTkButton(search_frame, text="Find Next", command=self._find_next).pack(side="left", padx=5)

    def _refresh_ui(self):
        if not self.analysis_results:
            return

        # Populate class list from JADX decompilation
        jadx = self.analysis_results.get("jadx", {})
        classes = []

        # Extract classes from decompiled sources
        sources = jadx.get("sources", {})
        for filepath, content in sources.items():
            if filepath.endswith(".java"):
                # Extract class name
                lines = content.split("\n")
                for line in lines:
                    if line.strip().startswith("public class ") or line.strip().startswith("class "):
                        class_name = line.strip().split("class ")[1].split("{")[0].split(" ")[0]
                        classes.append(class_name)
                        break

        classes = sorted(set(classes))
        self.class_menu.configure(values=classes if classes else ["No classes found"])
        if classes:
            self.class_var.set(classes[0])
            self._load_class(classes[0])

    def _load_class(self, class_name: str):
        if not self.analysis_results:
            return

        jadx = self.analysis_results.get("jadx", {})
        sources = jadx.get("sources", {})

        # Find class file
        for filepath, content in sources.items():
            if class_name in filepath or class_name in content.split("\n")[0]:
                self.code_text.delete("1.0", "end")
                self.code_text.insert("1.0", content)

                # Extract methods
                methods = []
                for line in content.split("\n"):
                    line = line.strip()
                    if (line.startswith("public ") or line.startswith("private ") or
                        line.startswith("protected ")) and "(" in line and ")" in line and "{" in line:
                        method_name = line.split("(")[0].split()[-1]
                        methods.append(method_name)

                self.method_menu.configure(values=methods if methods else ["No methods"])
                if methods:
                    self.method_var.set(methods[0])
                break

    def _load_method(self, method_name: str):
        # Scroll to method in code
        content = self.code_text.get("1.0", "end")
        idx = content.find(method_name)
        if idx >= 0:
            line_num = content[:idx].count("\n") + 1
            self.code_text.see(f"{line_num}.0")

    def _search_code(self):
        query = self.search_entry.get()
        if not query:
            return

        content = self.code_text.get("1.0", "end")
        idx = content.find(query)
        if idx >= 0:
            line_num = content[:idx].count("\n") + 1
            self.code_text.see(f"{line_num}.0")
            self.code_text.tag_remove("search", "1.0", "end")
            self.code_text.tag_add("search", f"{line_num}.0", f"{line_num}.{len(query)}")
            self.code_text.tag_config("search", background="yellow", foreground="black")

    def _find_next(self):
        query = self.search_entry.get()
        if not query:
            return

        content = self.code_text.get("1.0", "end")
        # Find from current position
        pass