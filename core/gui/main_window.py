"""
Main Window for APKStudioAI 2.1 Professional GUI
20-page SOC-style interface with CustomTkinter.
"""
import customtkinter as ctk
import tkinter as tk
from tkinter import filedialog, messagebox
from pathlib import Path
from typing import Dict, List, Any, Optional, Callable
import threading
import time
import json
from ..config_manager import get_config
from ..logging_setup import get_module_logger

logger = get_module_logger("main_window")


# Page registry
PAGE_CLASSES = {}


def register_page(name: str, title: str, icon: str = ""):
    """Decorator to register a page class."""
    def decorator(cls):
        PAGE_CLASSES[name] = {"class": cls, "title": title, "icon": icon}
        return cls
    return decorator


class BasePage(ctk.CTkFrame):
    """Base class for all pages."""

    def __init__(self, parent, app, **kwargs):
        super().__init__(parent, **kwargs)
        self.app = app
        self.config = app.config
        self.analysis_results = None
        self._build_ui()

    def _build_ui(self):
        """Build the page UI. Override in subclasses."""
        pass

    def on_show(self):
        """Called when page is shown."""
        pass

    def on_hide(self):
        """Called when page is hidden."""
        pass

    def update_analysis(self, results: Dict):
        """Update page with new analysis results."""
        self.analysis_results = results
        self._refresh_ui()

    def _refresh_ui(self):
        """Refresh UI with current analysis results. Override in subclasses."""
        pass


class MainWindow(ctk.CTk):
    """Main application window with 20-page sidebar navigation."""

    def __init__(self, config: Dict = None):
        super().__init__()
        self.config = config or get_config().get_all()
        self.analysis_results = None
        self.current_page = None
        self.pages: Dict[str, BasePage] = {}
        self.page_order = [
            "dashboard",
            "static_analysis",
            "dynamic_analysis",
            "network_analysis",
            "threat_intel",
            "ml_classifier",
            "mitre_attack",
            "malware_families",
            "ioc_graph",
            "code_browser",
            "timeline",
            "behavioral",
            "strings",
            "manifest",
            "permissions",
            "components",
            "advanced_static",
            "correlation",
            "reporting",
            "rea_analysis",
            "settings",
        ]

        self._setup_window()
        self._build_ui()
        self._load_pages()

    def _setup_window(self):
        """Configure main window."""
        self.title("APKStudioAI 2.1 - Android Malware Intelligence Platform")
        self.geometry("1600x900")
        self.minsize(1200, 700)

        # Theme
        ctk.set_appearance_mode(self.config.get("gui", {}).get("theme", "dark"))
        ctk.set_default_color_theme("blue")

        # Grid config
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=1)

    def _build_ui(self):
        """Build main UI layout."""
        # Sidebar
        self.sidebar = ctk.CTkFrame(self, width=280, corner_radius=0)
        self.sidebar.grid(row=0, column=0, sticky="nsew")
        self.sidebar.grid_rowconfigure(1, weight=1)
        self.sidebar.grid_propagate(False)

        # Logo/Title
        self.logo_frame = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        self.logo_frame.grid(row=0, column=0, sticky="ew", padx=20, pady=20)

        self.logo_label = ctk.CTkLabel(
            self.logo_frame,
            text="APKStudioAI",
            font=ctk.CTkFont(size=24, weight="bold"),
            text_color=("#1f6aa5", "#3d8bcf")
        )
        self.logo_label.pack()

        self.version_label = ctk.CTkLabel(
            self.logo_frame,
            text="v2.1 - Malware Intelligence",
            font=ctk.CTkFont(size=11),
            text_color=("gray50", "gray70")
        )
        self.version_label.pack()

        # Navigation
        self.nav_frame = ctk.CTkScrollableFrame(self.sidebar, fg_color="transparent")
        self.nav_frame.grid(row=1, column=0, sticky="nsew", padx=10, pady=10)
        self.nav_frame.grid_columnconfigure(0, weight=1)

        # Page buttons will be added in _load_pages

        # Status bar at bottom of sidebar
        self.status_frame = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        self.status_frame.grid(row=2, column=0, sticky="ew", padx=10, pady=10)

        self.connection_status = ctk.CTkLabel(
            self.status_frame,
            text="● Ready",
            font=ctk.CTkFont(size=11),
            text_color="green"
        )
        self.connection_status.pack(anchor="w")

        # Main content area
        self.content_frame = ctk.CTkFrame(self, corner_radius=0)
        self.content_frame.grid(row=0, column=1, sticky="nsew")
        self.content_frame.grid_rowconfigure(0, weight=1)
        self.content_frame.grid_columnconfigure(0, weight=1)

        # Top toolbar
        self.toolbar = ctk.CTkFrame(self.content_frame, height=50, corner_radius=0)
        self.toolbar.grid(row=0, column=0, sticky="ew", padx=0, pady=0)
        self.toolbar.grid_propagate(False)
        self.toolbar.grid_columnconfigure(1, weight=1)

        # Toolbar buttons
        self.btn_new = ctk.CTkButton(
            self.toolbar,
            text="New Analysis",
            width=120,
            command=self._new_analysis
        )
        self.btn_new.grid(row=0, column=0, padx=10, pady=10)

        self.file_label = ctk.CTkLabel(
            self.toolbar,
            text="No file loaded",
            font=ctk.CTkFont(size=12),
            anchor="w"
        )
        self.file_label.grid(row=0, column=1, sticky="ew", padx=10)

        self.btn_export = ctk.CTkButton(
            self.toolbar,
            text="Export Report",
            width=120,
            command=self._export_report
        )
        self.btn_export.grid(row=0, column=2, padx=10, pady=10)

        # Page container
        self.page_container = ctk.CTkFrame(self.content_frame, corner_radius=0)
        self.page_container.grid(row=1, column=0, sticky="nsew")
        self.page_container.grid_rowconfigure(0, weight=1)
        self.page_container.grid_columnconfigure(0, weight=1)

        # Status bar at bottom
        self.status_bar = ctk.CTkFrame(self.content_frame, height=30, corner_radius=0)
        self.status_bar.grid(row=2, column=0, sticky="ew")
        self.status_bar.grid_propagate(False)
        self.status_bar.grid_columnconfigure(0, weight=1)

        self.status_text = ctk.CTkLabel(
            self.status_bar,
            text="Ready",
            font=ctk.CTkFont(size=11),
            anchor="w"
        )
        self.status_text.grid(row=0, column=0, sticky="w", padx=10)

        self.progress_bar = ctk.CTkProgressBar(self.status_bar, width=200)
        self.progress_bar.grid(row=0, column=1, padx=10)
        self.progress_bar.set(0)

    def _load_pages(self):
        """Load all page classes and create navigation buttons."""
        # Import page modules
        from .pages import (
            DashboardPage, StaticAnalysisPage, DynamicAnalysisPage,
            NetworkAnalysisPage, ThreatIntelPage, MLClassifierPage,
            MITREAttackPage, MalwareFamiliesPage, IOCGraphPage,
            CodeBrowserPage, TimelinePage, BehavioralPage,
            StringsPage, ManifestPage, PermissionsPage,
            ComponentsPage, AdvancedStaticPage, CorrelationPage,
            ReportingPage, SettingsPage, REAAnalysisPage
        )

        page_map = {
            "dashboard": DashboardPage,
            "static_analysis": StaticAnalysisPage,
            "dynamic_analysis": DynamicAnalysisPage,
            "network_analysis": NetworkAnalysisPage,
            "threat_intel": ThreatIntelPage,
            "ml_classifier": MLClassifierPage,
            "mitre_attack": MITREAttackPage,
            "malware_families": MalwareFamiliesPage,
            "ioc_graph": IOCGraphPage,
            "code_browser": CodeBrowserPage,
            "timeline": TimelinePage,
            "behavioral": BehavioralPage,
            "strings": StringsPage,
            "manifest": ManifestPage,
            "permissions": PermissionsPage,
            "components": ComponentsPage,
            "advanced_static": AdvancedStaticPage,
            "correlation": CorrelationPage,
            "reporting": ReportingPage,
            "rea_analysis": REAAnalysisPage,
            "settings": SettingsPage,
        }

        for i, page_name in enumerate(self.page_order):
            page_class = page_map.get(page_name)
            if page_class:
                # Create page instance
                page = page_class(self.page_container, self)
                self.pages[page_name] = page
                page.grid(row=0, column=0, sticky="nsew")
                page.grid_remove()  # Hide initially

                # Create nav button
                page_info = PAGE_CLASSES.get(page_name, {})
                title = page_info.get("title", page_name.replace("_", " ").title())
                icon = page_info.get("icon", "")

                btn = ctk.CTkButton(
                    self.nav_frame,
                    text=f"{icon} {title}" if icon else title,
                    anchor="w",
                    height=36,
                    font=ctk.CTkFont(size=12),
                    command=lambda n=page_name: self._switch_page(n),
                    fg_color="transparent",
                    text_color=("gray10", "gray90"),
                    hover_color=("gray80", "gray20"),
                )
                btn.grid(row=i, column=0, sticky="ew", pady=2)
                setattr(self, f"nav_btn_{page_name}", btn)

        # Show first page
        self._switch_page("dashboard")

    def _switch_page(self, page_name: str):
        """Switch to a different page."""
        if page_name not in self.pages:
            return

        # Hide current page
        if self.current_page:
            self.current_page.on_hide()
            self.current_page.grid_remove()

        # Update nav button styles
        for name in self.page_order:
            btn = getattr(self, f"nav_btn_{name}", None)
            if btn:
                if name == page_name:
                    btn.configure(fg_color=("gray75", "gray25"), text_color=("white", "white"))
                else:
                    btn.configure(fg_color="transparent", text_color=("gray10", "gray90"))

        # Show new page
        self.current_page = self.pages[page_name]
        self.current_page.grid()
        self.current_page.on_show()

        # Update analysis if available
        if self.analysis_results:
            self.current_page.update_analysis(self.analysis_results)

    def _new_analysis(self):
        """Start a new analysis."""
        file_path = filedialog.askopenfilename(
            title="Select APK File",
            filetypes=[("APK Files", "*.apk"), ("All Files", "*.*")]
        )
        if file_path:
            self._run_analysis(file_path)

    def _run_analysis(self, file_path: str):
        """Run analysis in background thread."""
        self.file_label.configure(text=f"Analyzing: {Path(file_path).name}")
        self.progress_bar.set(0)
        self.status_text.configure(text="Starting analysis...")
        self.connection_status.configure(text="● Analyzing", text_color="orange")

        def analysis_worker():
            try:
                from ..scanner import scan_apk
                self.analysis_results = scan_apk(file_path, self.config)

                # Update UI on main thread
                self.after(0, lambda: self._analysis_complete(file_path))
            except Exception as e:
                self.after(0, lambda: self._analysis_error(str(e)))

        thread = threading.Thread(target=analysis_worker, daemon=True)
        thread.start()

        # Simulate progress updates
        def update_progress():
            if thread.is_alive():
                current = self.progress_bar.get()
                self.progress_bar.set(min(current + 0.02, 0.95))
                self.after(500, update_progress)

        update_progress()

    def _analysis_complete(self, file_path: str):
        """Handle analysis completion."""
        self.file_label.configure(text=f"Loaded: {Path(file_path).name}")
        self.progress_bar.set(1.0)
        self.status_text.configure(text="Analysis complete")
        self.connection_status.configure(text="● Complete", text_color="green")

        # Update current page
        if self.current_page:
            self.current_page.update_analysis(self.analysis_results)

    def _analysis_error(self, error: str):
        """Handle analysis error."""
        self.progress_bar.set(0)
        self.status_text.configure(text=f"Error: {error}")
        self.connection_status.configure(text="● Error", text_color="red")
        messagebox.showerror("Analysis Error", f"Analysis failed:\n{error}")

    def _export_report(self):
        """Export analysis report."""
        if not self.analysis_results:
            messagebox.showwarning("No Data", "No analysis results to export")
            return

        file_path = filedialog.asksaveasfilename(
            title="Export Report",
            defaultextension=".json",
            filetypes=[("JSON Report", "*.json"), ("HTML Report", "*.html"), ("PDF Report", "*.pdf")]
        )
        if file_path:
            try:
                if file_path.endswith(".json"):
                    with open(file_path, "w") as f:
                        json.dump(self.analysis_results, f, indent=2, default=str)
                elif file_path.endswith(".html"):
                    self._export_html_report(file_path)
                elif file_path.endswith(".pdf"):
                    self._export_pdf_report(file_path)

                messagebox.showinfo("Export Complete", f"Report saved to {file_path}")
            except Exception as e:
                messagebox.showerror("Export Error", f"Failed to export: {e}")

    def _export_html_report(self, output_path: str):
        """Export HTML report."""
        # Placeholder for HTML report generation
        html = f"""
        <!DOCTYPE html>
        <html>
        <head><title>APKStudioAI Analysis Report</title></head>
        <body>
        <h1>APKStudioAI 2.1 Analysis Report</h1>
        <pre>{json.dumps(self.analysis_results, indent=2, default=str)}</pre>
        </body>
        </html>
        """
        with open(output_path, "w") as f:
            f.write(html)

    def _export_pdf_report(self, output_path: str):
        """Export PDF report."""
        # Placeholder - would use reportlab or similar
        messagebox.showinfo("PDF Export", "PDF export not yet implemented")


def run_gui(config: Dict = None):
    """Run the GUI application."""
    app = MainWindow(config)
    app.mainloop()


if __name__ == "__main__":
    run_gui()