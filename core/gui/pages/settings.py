"""
Settings Page for APKSTUDIOAI 2.1
Configuration management for all analyzers and integrations.
"""
import customtkinter as ctk
from typing import Dict, Any
from ..main_window import BasePage, register_page


@register_page("settings", "Settings", "⚙️")
class SettingsPage(BasePage):
    """Application settings page."""

    def _build_ui(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        header = ctk.CTkFrame(self, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew", padx=20, pady=20)

        ctk.CTkLabel(header, text="Settings", font=ctk.CTkFont(size=28, weight="bold")).pack(anchor="w")

        # Settings tabs
        self.tabview = ctk.CTkTabview(self)
        self.tabview.grid(row=1, column=0, sticky="nsew", padx=20, pady=(0, 20))

        tabs = ["General", "Analysis", "AI/ML", "Dynamic", "Threat Intel", "REA", "GUI", "Advanced"]
        for tab in tabs:
            self.tabview.add(tab)
            self.tabview.tab(tab).grid_columnconfigure(0, weight=1)
            self.tabview.tab(tab).grid_rowconfigure(0, weight=1)

        self.tab_frames = {tab: ctk.CTkScrollableFrame(self.tabview.tab(tab)) for tab in tabs}
        for tab, frame in self.tab_frames.items():
            frame.grid(row=0, column=0, sticky="nsew")

        self._build_general_tab(self.tab_frames["General"])
        self._build_analysis_tab(self.tab_frames["Analysis"])
        self._build_ai_tab(self.tab_frames["AI/ML"])
        self._build_dynamic_tab(self.tab_frames["Dynamic"])
        self._build_threat_intel_tab(self.tab_frames["Threat Intel"])
        self._build_rea_tab(self.tab_frames["REA"])
        self._build_gui_tab(self.tab_frames["GUI"])
        self._build_advanced_tab(self.tab_frames["Advanced"])

        # Save button
        save_frame = ctk.CTkFrame(self, fg_color="transparent")
        save_frame.grid(row=2, column=0, sticky="ew", padx=20, pady=(0, 20))
        ctk.CTkButton(save_frame, text="Save Settings", command=self._save_settings,
                     font=ctk.CTkFont(size=14, weight="bold"), height=40).pack(side="right")

    def _build_general_tab(self, frame):
        # Theme
        row = ctk.CTkFrame(frame)
        row.pack(fill="x", padx=15, pady=10)
        ctk.CTkLabel(row, text="Theme:", width=150, anchor="w").pack(side="left", padx=10)
        self.theme_var = ctk.StringVar(value=self.config.get("gui", {}).get("theme", "dark"))
        ctk.CTkOptionMenu(row, values=["dark", "light", "system"], variable=self.theme_var, width=200).pack(side="left")

        # Language
        row = ctk.CTkFrame(frame)
        row.pack(fill="x", padx=15, pady=10)
        ctk.CTkLabel(row, text="Language:", width=150, anchor="w").pack(side="left", padx=10)
        self.lang_var = ctk.StringVar(value="en")
        ctk.CTkOptionMenu(row, values=["en", "zh", "es", "fr"], variable=self.lang_var, width=200).pack(side="left")

        # Auto-save
        self.autosave_var = ctk.BooleanVar(value=self.config.get("general", {}).get("auto_save", True))
        ctk.CTkCheckBox(frame, text="Auto-save analysis results", variable=self.autosave_var).pack(anchor="w", padx=15, pady=10)

        # Max recent files
        row = ctk.CTkFrame(frame)
        row.pack(fill="x", padx=15, pady=10)
        ctk.CTkLabel(row, text="Max Recent Files:", width=150, anchor="w").pack(side="left", padx=10)
        self.max_recent_var = ctk.IntVar(value=self.config.get("general", {}).get("max_recent", 10))
        ctk.CTkEntry(row, textvariable=self.max_recent_var, width=100).pack(side="left")

    def _build_analysis_tab(self, frame):
        # JADX path
        row = ctk.CTkFrame(frame)
        row.pack(fill="x", padx=15, pady=10)
        ctk.CTkLabel(row, text="JADX Path:", width=150, anchor="w").pack(side="left", padx=10)
        self.jadx_var = ctk.StringVar(value=self.config.get("analysis", {}).get("jadx_path", "jadx"))
        ctk.CTkEntry(row, textvariable=self.jadx_var, width=300).pack(side="left", padx=10)
        ctk.CTkButton(row, text="Browse", width=80, command=lambda: self._browse(self.jadx_var)).pack(side="left")

        # APKiD enabled
        self.apkid_var = ctk.BooleanVar(value=self.config.get("analysis", {}).get("apkid_enabled", True))
        ctk.CTkCheckBox(frame, text="Enable APKiD packer detection", variable=self.apkid_var).pack(anchor="w", padx=15, pady=10)

        # YARA rules path
        row = ctk.CTkFrame(frame)
        row.pack(fill="x", padx=15, pady=10)
        ctk.CTkLabel(row, text="YARA Rules Dir:", width=150, anchor="w").pack(side="left", padx=10)
        self.yara_var = ctk.StringVar(value=self.config.get("analysis", {}).get("yara_rules_dir", ""))
        ctk.CTkEntry(row, textvariable=self.yara_var, width=300).pack(side="left", padx=10)
        ctk.CTkButton(row, text="Browse", width=80, command=lambda: self._browse_dir(self.yara_var)).pack(side="left")

        # Timeout
        row = ctk.CTkFrame(frame)
        row.pack(fill="x", padx=15, pady=10)
        ctk.CTkLabel(row, text="Analysis Timeout (s):", width=150, anchor="w").pack(side="left", padx=10)
        self.timeout_var = ctk.IntVar(value=self.config.get("analysis", {}).get("timeout", 300))
        ctk.CTkEntry(row, textvariable=self.timeout_var, width=100).pack(side="left")

        # Deep analysis
        self.deep_var = ctk.BooleanVar(value=self.config.get("analysis", {}).get("deep_analysis", False))
        ctk.CTkCheckBox(frame, text="Enable deep analysis (slower)", variable=self.deep_var).pack(anchor="w", padx=15, pady=10)

    def _build_ai_tab(self, frame):
        # Ollama host
        row = ctk.CTkFrame(frame)
        row.pack(fill="x", padx=15, pady=10)
        ctk.CTkLabel(row, text="Ollama Host:", width=150, anchor="w").pack(side="left", padx=10)
        self.ollama_host_var = ctk.StringVar(value=self.config.get("ai", {}).get("ollama_host", "http://localhost:11434"))
        ctk.CTkEntry(row, textvariable=self.ollama_host_var, width=300).pack(side="left", padx=10)

        # Default model
        row = ctk.CTkFrame(frame)
        row.pack(fill="x", padx=15, pady=10)
        ctk.CTkLabel(row, text="Default Model:", width=150, anchor="w").pack(side="left", padx=10)
        self.model_var = ctk.StringVar(value=self.config.get("ai", {}).get("default_model", "qwen2.5-coder:3b"))
        ctk.CTkEntry(row, textvariable=self.model_var, width=300).pack(side="left", padx=10)

        # Temperature
        row = ctk.CTkFrame(frame)
        row.pack(fill="x", padx=15, pady=10)
        ctk.CTkLabel(row, text="Temperature:", width=150, anchor="w").pack(side="left", padx=10)
        self.temp_var = ctk.DoubleVar(value=self.config.get("ai", {}).get("temperature", 0.1))
        ctk.CTkSlider(row, from_=0.0, to=1.0, variable=self.temp_var, width=200).pack(side="left", padx=10)
        self.temp_label = ctk.CTkLabel(row, text=f"{self.temp_var.get():.1f}")
        self.temp_label.pack(side="left")
        self.temp_var.trace_add("write", lambda *_: self.temp_label.configure(text=f"{self.temp_var.get():.1f}"))

        # RAG enabled
        self.rag_var = ctk.BooleanVar(value=self.config.get("ai", {}).get("rag_enabled", True))
        ctk.CTkCheckBox(frame, text="Enable RAG (Retrieval-Augmented Generation)", variable=self.rag_var).pack(anchor="w", padx=15, pady=10)

        # ChromaDB path
        row = ctk.CTkFrame(frame)
        row.pack(fill="x", padx=15, pady=10)
        ctk.CTkLabel(row, text="ChromaDB Path:", width=150, anchor="w").pack(side="left", padx=10)
        self.chroma_var = ctk.StringVar(value=self.config.get("ai", {}).get("chroma_path", "./chroma_db"))
        ctk.CTkEntry(row, textvariable=self.chroma_var, width=300).pack(side="left", padx=10)
        ctk.CTkButton(row, text="Browse", width=80, command=lambda: self._browse_dir(self.chroma_var)).pack(side="left")

    def _build_dynamic_tab(self, frame):
        # AVD name
        row = ctk.CTkFrame(frame)
        row.pack(fill="x", padx=15, pady=10)
        ctk.CTkLabel(row, text="AVD Name:", width=150, anchor="w").pack(side="left", padx=10)
        self.avd_var = ctk.StringVar(value=self.config.get("dynamic", {}).get("avd_name", "apkstudio_avd"))
        ctk.CTkEntry(row, textvariable=self.avd_var, width=300).pack(side="left", padx=10)

        # Emulator path
        row = ctk.CTkFrame(frame)
        row.pack(fill="x", padx=15, pady=10)
        ctk.CTkLabel(row, text="Emulator Path:", width=150, anchor="w").pack(side="left", padx=10)
        self.emu_var = ctk.StringVar(value=self.config.get("dynamic", {}).get("emulator_path", "emulator"))
        ctk.CTkEntry(row, textvariable=self.emu_var, width=300).pack(side="left", padx=10)
        ctk.CTkButton(row, text="Browse", width=80, command=lambda: self._browse(self.emu_var)).pack(side="left")

        # Frida enabled
        self.frida_var = ctk.BooleanVar(value=self.config.get("dynamic", {}).get("frida_enabled", True))
        ctk.CTkCheckBox(frame, text="Enable Frida instrumentation", variable=self.frida_var).pack(anchor="w", padx=15, pady=10)

        # mitmproxy enabled
        self.mitm_var = ctk.BooleanVar(value=self.config.get("dynamic", {}).get("mitmproxy_enabled", True))
        ctk.CTkCheckBox(frame, text="Enable mitmproxy TLS interception", variable=self.mitm_var).pack(anchor="w", padx=15, pady=10)

        # Dynamic timeout
        row = ctk.CTkFrame(frame)
        row.pack(fill="x", padx=15, pady=10)
        ctk.CTkLabel(row, text="Dynamic Timeout (s):", width=150, anchor="w").pack(side="left", padx=10)
        self.dyn_timeout_var = ctk.IntVar(value=self.config.get("dynamic", {}).get("timeout", 120))
        ctk.CTkEntry(row, textvariable=self.dyn_timeout_var, width=100).pack(side="left")

    def _build_threat_intel_tab(self, frame):
        # VirusTotal API key
        row = ctk.CTkFrame(frame)
        row.pack(fill="x", padx=15, pady=10)
        ctk.CTkLabel(row, text="VirusTotal API Key:", width=150, anchor="w").pack(side="left", padx=10)
        self.vt_key_var = ctk.StringVar(value=self.config.get("threat_intel", {}).get("virustotal_key", ""))
        ctk.CTkEntry(row, textvariable=self.vt_key_var, width=300, show="*").pack(side="left", padx=10)

        # URLhaus enabled
        self.urlhaus_var = ctk.BooleanVar(value=self.config.get("threat_intel", {}).get("urlhaus_enabled", True))
        ctk.CTkCheckBox(frame, text="Enable URLhaus feed", variable=self.urlhaus_var).pack(anchor="w", padx=15, pady=10)

        # MalwareBazaar enabled
        self.mbazaar_var = ctk.BooleanVar(value=self.config.get("threat_intel", {}).get("malwarebazaar_enabled", True))
        ctk.CTkCheckBox(frame, text="Enable MalwareBazaar feed", variable=self.mbazaar_var).pack(anchor="w", padx=15, pady=10)

        # ThreatFox enabled
        self.threatfox_var = ctk.BooleanVar(value=self.config.get("threat_intel", {}).get("threatfox_enabled", True))
        ctk.CTkCheckBox(frame, text="Enable ThreatFox feed", variable=self.threatfox_var).pack(anchor="w", padx=15, pady=10)

        # Feed update interval
        row = ctk.CTkFrame(frame)
        row.pack(fill="x", padx=15, pady=10)
        ctk.CTkLabel(row, text="Feed Update Interval (h):", width=150, anchor="w").pack(side="left", padx=10)
        self.feed_interval_var = ctk.IntVar(value=self.config.get("threat_intel", {}).get("feed_interval", 24))
        ctk.CTkEntry(row, textvariable=self.feed_interval_var, width=100).pack(side="left")

    def _build_rea_tab(self, frame):
        """Build REA (Reverse Engineering Assistant) settings tab"""
        rea_config = self.config.get("rea", {})

        # REA Enabled
        self.rea_enabled_var = ctk.BooleanVar(value=rea_config.get("enabled", True))
        ctk.CTkCheckBox(frame, text="Enable REA Enhanced Reverse Engineering",
                       variable=self.rea_enabled_var, font=ctk.CTkFont(size=13, weight="bold")).pack(anchor="w", padx=15, pady=15)

        # GHIDRA Path
        row = ctk.CTkFrame(frame)
        row.pack(fill="x", padx=15, pady=10)
        ctk.CTkLabel(row, text="Ghidra Install Dir:", width=150, anchor="w").pack(side="left", padx=10)
        self.ghidra_path_var = ctk.StringVar(value=rea_config.get("ghidra_path", ""))
        ctk.CTkEntry(row, textvariable=self.ghidra_path_var, width=400).pack(side="left", padx=10)
        ctk.CTkButton(row, text="Browse", width=80, command=lambda: self._browse_dir(self.ghidra_path_var)).pack(side="left")

        # Skill Path (optional)
        row = ctk.CTkFrame(frame)
        row.pack(fill="x", padx=15, pady=10)
        ctk.CTkLabel(row, text="REA Skill Path:", width=150, anchor="w").pack(side="left", padx=10)
        self.skill_path_var = ctk.StringVar(value=rea_config.get("skill_path", ""))
        ctk.CTkEntry(row, textvariable=self.skill_path_var, width=400).pack(side="left", padx=10)
        ctk.CTkButton(row, text="Browse", width=80, command=lambda: self._browse_dir(self.skill_path_var)).pack(side="left")

        # Analyze Native Libraries
        self.rea_native_var = ctk.BooleanVar(value=rea_config.get("analyze_native_libs", True))
        ctk.CTkCheckBox(frame, text="Analyze Native Libraries with Ghidra",
                       variable=self.rea_native_var).pack(anchor="w", padx=15, pady=10)

        # Analyze DEX (future JADX provider)
        self.rea_dex_var = ctk.BooleanVar(value=rea_config.get("analyze_dex", False))
        ctk.CTkCheckBox(frame, text="Analyze DEX with JADX Provider (requires REA_JADX_MCP_JAR)",
                       variable=self.rea_dex_var).pack(anchor="w", padx=15, pady=10)

        # Pattern Search
        self.rea_pattern_var = ctk.BooleanVar(value=rea_config.get("pattern_search", True))
        ctk.CTkCheckBox(frame, text="Search for Suspicious Patterns in Native Code",
                       variable=self.rea_pattern_var).pack(anchor="w", padx=15, pady=10)

        # Max Analysis Time
        row = ctk.CTkFrame(frame)
        row.pack(fill="x", padx=15, pady=10)
        ctk.CTkLabel(row, text="Max Analysis Time (s):", width=150, anchor="w").pack(side="left", padx=10)
        self.rea_timeout_var = ctk.IntVar(value=rea_config.get("max_analysis_time_sec", 300))
        ctk.CTkEntry(row, textvariable=self.rea_timeout_var, width=100).pack(side="left")

        # MCP Command
        row = ctk.CTkFrame(frame)
        row.pack(fill="x", padx=15, pady=10)
        ctk.CTkLabel(row, text="MCP Command:", width=150, anchor="w").pack(side="left", padx=10)
        self.mcp_cmd_var = ctk.StringVar(value=rea_config.get("mcp_command", "npx -y rea-agents@latest mcp"))
        ctk.CTkEntry(row, textvariable=self.mcp_cmd_var, width=400).pack(side="left", padx=10)

        # Status info
        ctk.CTkLabel(frame, text="Note: Ghidra path can also be set via GHIDRA_INSTALL_DIR or APKSTUDIO_GHIDRA_PATH env vars",
                    text_color=("gray50", "gray70"), font=ctk.CTkFont(size=11)).pack(anchor="w", padx=15, pady=15)

    def _build_gui_tab(self, frame):
        # Window size
        row = ctk.CTkFrame(frame)
        row.pack(fill="x", padx=15, pady=10)
        ctk.CTkLabel(row, text="Default Window Size:", width=150, anchor="w").pack(side="left", padx=10)
        self.width_var = ctk.IntVar(value=self.config.get("gui", {}).get("width", 1600))
        ctk.CTkEntry(row, textvariable=self.width_var, width=80).pack(side="left")
        ctk.CTkLabel(row, text="x").pack(side="left", padx=5)
        self.height_var = ctk.IntVar(value=self.config.get("gui", {}).get("height", 900))
        ctk.CTkEntry(row, textvariable=self.height_var, width=80).pack(side="left")

        # Font size
        row = ctk.CTkFrame(frame)
        row.pack(fill="x", padx=15, pady=10)
        ctk.CTkLabel(row, text="Base Font Size:", width=150, anchor="w").pack(side="left", padx=10)
        self.font_size_var = ctk.IntVar(value=self.config.get("gui", {}).get("font_size", 12))
        ctk.CTkSlider(row, from_=10, to=18, variable=self.font_size_var, width=200).pack(side="left", padx=10)
        self.font_label = ctk.CTkLabel(row, text=str(self.font_size_var.get()))
        self.font_label.pack(side="left")
        self.font_size_var.trace_add("write", lambda *_: self.font_label.configure(text=str(self.font_size_var.get())))

        # Show toolbar
        self.toolbar_var = ctk.BooleanVar(value=self.config.get("gui", {}).get("show_toolbar", True))
        ctk.CTkCheckBox(frame, text="Show toolbar", variable=self.toolbar_var).pack(anchor="w", padx=15, pady=10)

        # Show status bar
        self.statusbar_var = ctk.BooleanVar(value=self.config.get("gui", {}).get("show_statusbar", True))
        ctk.CTkCheckBox(frame, text="Show status bar", variable=self.statusbar_var).pack(anchor="w", padx=15, pady=10)

    def _build_advanced_tab(self, frame):
        # Logging level
        row = ctk.CTkFrame(frame)
        row.pack(fill="x", padx=15, pady=10)
        ctk.CTkLabel(row, text="Log Level:", width=150, anchor="w").pack(side="left", padx=10)
        self.log_level_var = ctk.StringVar(value=self.config.get("logging", {}).get("level", "INFO"))
        ctk.CTkOptionMenu(row, values=["DEBUG", "INFO", "WARNING", "ERROR"], variable=self.log_level_var, width=200).pack(side="left")

        # Log file
        row = ctk.CTkFrame(frame)
        row.pack(fill="x", padx=15, pady=10)
        ctk.CTkLabel(row, text="Log File:", width=150, anchor="w").pack(side="left", padx=10)
        self.log_file_var = ctk.StringVar(value=self.config.get("logging", {}).get("file", "apkstudio.log"))
        ctk.CTkEntry(row, textvariable=self.log_file_var, width=300).pack(side="left", padx=10)
        ctk.CTkButton(row, text="Browse", width=80, command=lambda: self._browse(self.log_file_var)).pack(side="left")

        # Evidence DB path
        row = ctk.CTkFrame(frame)
        row.pack(fill="x", padx=15, pady=10)
        ctk.CTkLabel(row, text="Evidence DB:", width=150, anchor="w").pack(side="left", padx=10)
        self.evidence_db_var = ctk.StringVar(value=self.config.get("storage", {}).get("evidence_db", "evidence.db"))
        ctk.CTkEntry(row, textvariable=self.evidence_db_var, width=300).pack(side="left", padx=10)
        ctk.CTkButton(row, text="Browse", width=80, command=lambda: self._browse(self.evidence_db_var)).pack(side="left")

        # Max evidence entries
        row = ctk.CTkFrame(frame)
        row.pack(fill="x", padx=15, pady=10)
        ctk.CTkLabel(row, text="Max Evidence Entries:", width=150, anchor="w").pack(side="left", padx=10)
        self.max_evidence_var = ctk.IntVar(value=self.config.get("storage", {}).get("max_evidence", 10000))
        ctk.CTkEntry(row, textvariable=self.max_evidence_var, width=100).pack(side="left")

        # Reset to defaults
        ctk.CTkButton(frame, text="Reset to Defaults", command=self._reset_defaults,
                     fg_color="transparent", border_width=1, text_color=("gray50", "gray70")).pack(anchor="w", padx=15, pady=20)

    def _browse(self, var: ctk.StringVar):
        from tkinter import filedialog
        path = filedialog.askopenfilename()
        if path:
            var.set(path)

    def _browse_dir(self, var: ctk.StringVar):
        from tkinter import filedialog
        path = filedialog.askdirectory()
        if path:
            var.set(path)

    def _save_settings(self):
        """Save settings to config."""
        from ..config_manager import get_config
        config = get_config()

        # Update config
        config.set("gui.theme", self.theme_var.get())
        config.set("general.auto_save", self.autosave_var.get())
        config.set("general.max_recent", self.max_recent_var.get())
        config.set("analysis.jadx_path", self.jadx_var.get())
        config.set("analysis.apkid_enabled", self.apkid_var.get())
        config.set("analysis.yara_rules_dir", self.yara_var.get())
        config.set("analysis.timeout", self.timeout_var.get())
        config.set("analysis.deep_analysis", self.deep_var.get())
        config.set("ai.ollama_host", self.ollama_host_var.get())
        config.set("ai.default_model", self.model_var.get())
        config.set("ai.temperature", self.temp_var.get())
        config.set("ai.rag_enabled", self.rag_var.get())
        config.set("ai.chroma_path", self.chroma_var.get())
        config.set("dynamic.avd_name", self.avd_var.get())
        config.set("dynamic.emulator_path", self.emu_var.get())
        config.set("dynamic.frida_enabled", self.frida_var.get())
        config.set("dynamic.mitmproxy_enabled", self.mitm_var.get())
        config.set("dynamic.timeout", self.dyn_timeout_var.get())
        config.set("threat_intel.virustotal_key", self.vt_key_var.get())
        config.set("threat_intel.urlhaus_enabled", self.urlhaus_var.get())
        config.set("threat_intel.malwarebazaar_enabled", self.mbazaar_var.get())
        config.set("threat_intel.threatfox_enabled", self.threatfox_var.get())
        config.set("threat_intel.feed_interval", self.feed_interval_var.get())

        # REA settings
        config.set("rea.enabled", self.rea_enabled_var.get())
        config.set("rea.ghidra_path", self.ghidra_path_var.get())
        config.set("rea.skill_path", self.skill_path_var.get())
        config.set("rea.analyze_native_libs", self.rea_native_var.get())
        config.set("rea.analyze_dex", self.rea_dex_var.get())
        config.set("rea.pattern_search", self.rea_pattern_var.get())
        config.set("rea.max_analysis_time_sec", self.rea_timeout_var.get())
        config.set("rea.mcp_command", self.mcp_cmd_var.get())

        config.set("gui.width", self.width_var.get())
        config.set("gui.height", self.height_var.get())
        config.set("gui.font_size", self.font_size_var.get())
        config.set("gui.show_toolbar", self.toolbar_var.get())
        config.set("gui.show_statusbar", self.statusbar_var.get())
        config.set("logging.level", self.log_level_var.get())
        config.set("logging.file", self.log_file_var.get())
        config.set("storage.evidence_db", self.evidence_db_var.get())
        config.set("storage.max_evidence", self.max_evidence_var.get())

        config.save()
        self.app.connection_status.configure(text="● Settings Saved", text_color="green")
        self.app.status_text.configure(text="Settings saved successfully")

    def _reset_defaults(self):
        """Reset settings to defaults."""
        from ..config_manager import get_config
        config = get_config()
        config.reset_to_defaults()
        config.save()
        self.app.status_text.configure(text="Settings reset to defaults")

    def _refresh_ui(self):
        """Refresh UI with current config values."""
        pass  # Values are loaded in _build_ui