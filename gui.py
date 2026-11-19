"""
APKStudioAI 2.1 - Professional Android Malware Analysis GUI
Complete interface with 12 analysis tabs
"""
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
from pathlib import Path
import json
from datetime import datetime
from core.scanner import APKScanner
from core.utils import calculate_sha256


class APKStudioGUI:
    def __init__(self, root, project_dir):
        self.root = root
        self.project_dir = Path(project_dir)
        self.scanner = APKScanner(self._load_config(), progress_callback=self._on_progress)
        self.current_result = None
        self.analysis_thread = None
        self.cancelled = False

        # Setup UI
        self._setup_window()
        self._create_menu()
        self._create_toolbar()
        self._create_main_panels()
        self._create_status_bar()
        self._check_tools_status()

    def _load_config(self):
        """Load configuration from config.json"""
        config_path = self.project_dir / "config.json"
        if config_path.exists():
            try:
                with open(config_path, 'r') as f:
                    return json.load(f)
            except Exception:
                pass
        return {"tools": {}, "ollama": {}}

    def _setup_window(self):
        """Configure main window"""
        self.root.title("APKStudioAI 2.1 — Advanced Android Malware Analysis Platform")
        self.root.geometry("1400x900")
        self.root.minsize(1000, 700)

        # Style
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('Title.TLabel', font=('Segoe UI', 18, 'bold'))
        style.configure('Subtitle.TLabel', font=('Segoe UI', 10))
        style.configure('Header.TLabel', font=('Segoe UI', 11, 'bold'))
        style.configure('Critical.TLabel', foreground='#d32f2f')
        style.configure('High.TLabel', foreground='#f57c00')
        style.configure('Medium.TLabel', foreground='#fbc02d')
        style.configure('Low.TLabel', foreground='#388e3c')
        style.configure('Info.TLabel', foreground='#1976d2')

    def _create_menu(self):
        """Create menu bar"""
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)

        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Fichier", menu=file_menu)
        file_menu.add_command(label="Nouvelle analyse", command=self._new_analysis, accelerator="Ctrl+N")
        file_menu.add_command(label="Ouvrir rapport...", command=self._open_report, accelerator="Ctrl+O")
        file_menu.add_separator()
        file_menu.add_command(label="Analyse par lot...", command=self._batch_analysis)
        file_menu.add_separator()
        file_menu.add_command(label="Quitter", command=self.root.quit, accelerator="Ctrl+Q")

        # Tools menu
        tools_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Outils", menu=tools_menu)
        tools_menu.add_command(label="Vérifier les outils", command=self._check_tools_status)
        tools_menu.add_command(label="Configuration IA (Backend)", command=self._configure_ai_backend)
        tools_menu.add_command(label="Configuration Ollama", command=self._configure_ollama)
        tools_menu.add_command(label="Diagnostiquer", command=self._run_diagnostic)

        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Aide", menu=help_menu)
        help_menu.add_command(label="Documentation", command=self._show_docs)
        help_menu.add_command(label="À propos", command=self._show_about)

        # Bind shortcuts
        self.root.bind('<Control-n>', lambda e: self._new_analysis())
        self.root.bind('<Control-o>', lambda e: self._open_report())
        self.root.bind('<Control-q>', lambda e: self.root.quit())

    def _create_toolbar(self):
        """Create toolbar with APK selection and controls"""
        toolbar = ttk.Frame(self.root, padding=(10, 5))
        toolbar.pack(fill='x')

        # APK selection
        ttk.Label(toolbar, text="APK:", font=('Segoe UI', 10, 'bold')).pack(side='left', padx=(0, 5))

        self.apk_var = tk.StringVar()
        self.apk_entry = ttk.Entry(toolbar, textvariable=self.apk_var, width=60)
        self.apk_entry.pack(side='left', padx=5, fill='x', expand=True)

        ttk.Button(toolbar, text="📁 Parcourir", command=self._choose_apk).pack(side='left', padx=5)

        # Buttons
        self.scan_btn = ttk.Button(toolbar, text="▶ ANALYSE COMPLÈTE", command=self._start_analysis, style='Accent.TButton')
        self.scan_btn.pack(side='left', padx=10)

        self.cancel_btn = ttk.Button(toolbar, text="⏹ Annuler", command=self._cancel_analysis, state='disabled')
        self.cancel_btn.pack(side='left', padx=5)

        # SHA256 display
        self.sha256_var = tk.StringVar(value="SHA256: —")
        ttk.Label(toolbar, textvariable=self.sha256_var, font=('Consolas', 9)).pack(side='right', padx=10)

        # Ollama status
        self.ollama_status_var = tk.StringVar(value="🤖 IA: Vérification...")
        self.ollama_label = ttk.Label(toolbar, textvariable=self.ollama_status_var)
        self.ollama_label.pack(side='right', padx=10)

    def _create_main_panels(self):
        """Create main content area with notebook tabs"""
        # Main container
        main_container = ttk.PanedWindow(self.root, orient='vertical')
        main_container.pack(fill='both', expand=True, padx=10, pady=(0, 10))

        # Top panel: Notebook with 12 tabs
        self.notebook = ttk.Notebook(main_container)
        main_container.add(self.notebook, weight=3)

        # Create all 12 tabs
        self._create_overview_tab()
        self._create_manifest_tab()
        self._create_permissions_tab()
        self._create_dex_tab()
        self._create_java_tab()
        self._create_smali_tab()
        self._create_native_tab()
        self._create_jni_tab()
        self._create_network_tab()
        self._create_malware_tab()
        self._create_ai_tab()
        self._create_logs_tab()

        # Bottom panel: Progress and log
        bottom_frame = ttk.Frame(main_container)
        main_container.add(bottom_frame, weight=1)

        # Progress bar
        progress_frame = ttk.Frame(bottom_frame)
        progress_frame.pack(fill='x', pady=(0, 5))

        self.progress = ttk.Progressbar(progress_frame, mode='determinate', maximum=100)
        self.progress.pack(fill='x', side='left', expand=True, padx=(0, 10))

        self.progress_label = ttk.Label(progress_frame, text="Prêt", width=30)
        self.progress_label.pack(side='left')

        # Log output
        log_frame = ttk.LabelFrame(bottom_frame, text="Journal d'analyse", padding=5)
        log_frame.pack(fill='both', expand=True)

        self.log_output = scrolledtext.ScrolledText(
            log_frame, wrap='word', font=('Consolas', 9), height=8,
            bg='#1e1e1e', fg='#d4d4d4', insertbackground='white'
        )
        self.log_output.pack(fill='both', expand=True)
        self.log_output.insert('end', "[INFO] APKStudioAI 2.1 prêt. Sélectionnez un APK et cliquez sur ANALYSE COMPLÈTE.\n")
        self.log_output.configure(state='disabled')

        # Configure log tags
        self.log_output.tag_config('info', foreground='#4fc3f7')
        self.log_output.tag_config('success', foreground='#81c784')
        self.log_output.tag_config('warning', foreground='#ffb74d')
        self.log_output.tag_config('error', foreground='#e57373')
        self.log_output.tag_config('debug', foreground='#9575cd')

    def _create_overview_tab(self):
        """Tab 1: Overview - Summary dashboard"""
        frame = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(frame, text="📊 Overview")

        # Risk score card
        risk_frame = ttk.LabelFrame(frame, text="Score de Risque", padding=15)
        risk_frame.pack(fill='x', pady=(0, 10))

        self.risk_score_var = tk.StringVar(value="0/100")
        self.risk_level_var = tk.StringVar(value="INCONNU")
        self.risk_desc_var = tk.StringVar(value="Aucune analyse effectuée")

        score_card = ttk.Frame(risk_frame)
        score_card.pack(fill='x')

        ttk.Label(score_card, text="SCORE:", font=('Segoe UI', 12, 'bold')).pack(side='left', padx=(0, 10))
        self.risk_score_label = ttk.Label(score_card, textvariable=self.risk_score_var, font=('Segoe UI', 28, 'bold'))
        self.risk_score_label.pack(side='left', padx=10)

        ttk.Label(score_card, text="NIVEAU:", font=('Segoe UI', 12, 'bold')).pack(side='left', padx=(30, 10))
        self.risk_level_label = ttk.Label(score_card, textvariable=self.risk_level_var, font=('Segoe UI', 16, 'bold'))
        self.risk_level_label.pack(side='left', padx=10)

        ttk.Label(risk_frame, textvariable=self.risk_desc_var, font=('Segoe UI', 10), wraplength=800).pack(anchor='w', pady=(10, 0))

        # APK Info
        info_frame = ttk.LabelFrame(frame, text="Informations APK", padding=10)
        info_frame.pack(fill='x', pady=(0, 10))

        self.apk_info_vars = {}
        info_fields = [
            ("Fichier", "apk_path"),
            ("SHA256", "sha256"),
            ("Package", "package"),
            ("Version", "version"),
            ("Min SDK", "min_sdk"),
            ("Target SDK", "target_sdk"),
            ("Taille", "file_size"),
            ("Date analyse", "scan_time")
        ]

        info_grid = ttk.Frame(info_frame)
        info_grid.pack(fill='x')
        for i, (label, key) in enumerate(info_fields):
            row = i // 4
            col = (i % 4) * 2
            ttk.Label(info_grid, text=f"{label}:", font=('Segoe UI', 9, 'bold')).grid(row=row, column=col, sticky='w', padx=5, pady=3)
            var = tk.StringVar(value="—")
            self.apk_info_vars[key] = var
            ttk.Label(info_grid, textvariable=var, font=('Segoe UI', 9)).grid(row=row, column=col+1, sticky='w', padx=5, pady=3)

        # Quick stats
        stats_frame = ttk.LabelFrame(frame, text="Statistiques rapides", padding=10)
        stats_frame.pack(fill='x', pady=(0, 10))

        self.stats_vars = {}
        stats_fields = [
            ("Permissions totales", "total_perms"),
            ("Permissions critiques", "critical_perms"),
            ("Bibliothèques natives", "native_libs"),
            ("Fonctions JNI", "jni_functions"),
            ("DEX fichiers", "dex_count"),
            ("Classes Java", "java_classes"),
            ("URLs détectées", "url_count"),
            ("Domaines", "domain_count"),
            ("Détections malware", "malware_detections")
        ]

        stats_grid = ttk.Frame(stats_frame)
        stats_grid.pack(fill='x')
        for i, (label, key) in enumerate(stats_fields):
            row = i // 3
            col = (i % 3) * 2
            ttk.Label(stats_grid, text=f"{label}:", font=('Segoe UI', 9)).grid(row=row, column=col, sticky='w', padx=10, pady=3)
            var = tk.StringVar(value="0")
            self.stats_vars[key] = var
            ttk.Label(stats_grid, textvariable=var, font=('Segoe UI', 9, 'bold')).grid(row=row, column=col+1, sticky='w', padx=5, pady=3)

        # Risk factors
        risk_factors_frame = ttk.LabelFrame(frame, text="Facteurs de risque principaux", padding=10)
        risk_factors_frame.pack(fill='both', expand=True)

        self.risk_factors_tree = ttk.Treeview(risk_factors_frame, columns=('severity', 'factor', 'detail'), show='headings', height=6)
        self.risk_factors_tree.heading('severity', text='Sévérité')
        self.risk_factors_tree.heading('factor', text='Facteur')
        self.risk_factors_tree.heading('detail', text='Détail')
        self.risk_factors_tree.column('severity', width=100)
        self.risk_factors_tree.column('factor', width=250)
        self.risk_factors_tree.column('detail', width=500)
        self.risk_factors_tree.pack(fill='both', expand=True)

        # Tag colors
        self.risk_factors_tree.tag_configure('critical', background='#ffebee')
        self.risk_factors_tree.tag_configure('high', background='#fff3e0')
        self.risk_factors_tree.tag_configure('medium', background='#fffde7')
        self.risk_factors_tree.tag_configure('low', background='#e8f5e9')

    def _create_manifest_tab(self):
        """Tab 2: Manifest - AndroidManifest.xml analysis"""
        frame = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(frame, text="📋 Manifest")

        # Toolbar
        tb = ttk.Frame(frame)
        tb.pack(fill='x', pady=(0, 5))
        ttk.Label(tb, text="AndroidManifest.xml Analysis", style='Header.TLabel').pack(side='left')
        ttk.Button(tb, text="📋 Copier XML brut", command=lambda: self._copy_to_clipboard(self.manifest_raw_text)).pack(side='right')

        # Paned view
        paned = ttk.PanedWindow(frame, orient='horizontal')
        paned.pack(fill='both', expand=True)

        # Left: Components tree
        left_frame = ttk.LabelFrame(paned, text="Composants", padding=5)
        paned.add(left_frame, weight=1)

        self.manifest_tree = ttk.Treeview(left_frame, columns=('exported', 'permission'), show='tree headings')
        self.manifest_tree.heading('#0', text='Composant')
        self.manifest_tree.heading('exported', text='Exported')
        self.manifest_tree.heading('permission', text='Permission')
        self.manifest_tree.column('#0', width=300)
        self.manifest_tree.column('exported', width=80, anchor='center')
        self.manifest_tree.column('permission', width=200)
        self.manifest_tree.pack(fill='both', expand=True)

        # Right: Details
        right_frame = ttk.Frame(paned)
        paned.add(right_frame, weight=1)

        # Manifest details
        details_frame = ttk.LabelFrame(right_frame, text="Détails", padding=5)
        details_frame.pack(fill='x', pady=(0, 5))

        self.manifest_details = scrolledtext.ScrolledText(details_frame, height=10, font=('Consolas', 9), wrap='word')
        self.manifest_details.pack(fill='both', expand=True)
        self.manifest_details.configure(state='disabled')

        # Raw XML
        raw_frame = ttk.LabelFrame(right_frame, text="XML Brut", padding=5)
        raw_frame.pack(fill='both', expand=True)

        self.manifest_raw_text = scrolledtext.ScrolledText(raw_frame, font=('Consolas', 9), wrap='none')
        self.manifest_raw_text.pack(fill='both', expand=True)
        self.manifest_raw_text.configure(state='disabled')

    def _create_permissions_tab(self):
        """Tab 3: Permissions - Permission analysis with risk levels"""
        frame = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(frame, text="🔐 Permissions")

        # Toolbar
        tb = ttk.Frame(frame)
        tb.pack(fill='x', pady=(0, 5))
        ttk.Label(tb, text="Analyse des permissions", style='Header.TLabel').pack(side='left')

        # Filter
        ttk.Label(tb, text="Filtrer:").pack(side='right', padx=(10, 5))
        self.perm_filter_var = tk.StringVar(value="Toutes")
        perm_filter = ttk.Combobox(tb, textvariable=self.perm_filter_var, values=["Toutes", "Critiques", "Élevées", "Moyennes", "Faibles", "Normales"], state='readonly', width=12)
        perm_filter.pack(side='right', padx=5)
        perm_filter.bind('<<ComboboxSelected>>', lambda e: self._filter_permissions())

        # Permissions tree
        columns = ('permission', 'risk', 'description', 'capability', 'mitre')
        self.perm_tree = ttk.Treeview(frame, columns=columns, show='headings')
        self.perm_tree.heading('permission', text='Permission')
        self.perm_tree.heading('risk', text='Risque')
        self.perm_tree.heading('description', text='Description')
        self.perm_tree.heading('capability', text='Capacité')
        self.perm_tree.heading('mitre', text='MITRE ATT&CK')
        self.perm_tree.column('permission', width=300)
        self.perm_tree.column('risk', width=80, anchor='center')
        self.perm_tree.column('description', width=350)
        self.perm_tree.column('capability', width=150)
        self.perm_tree.column('mitre', width=200)
        self.perm_tree.pack(fill='both', expand=True)

        # Tag colors
        self.perm_tree.tag_configure('critical', background='#ffebee')
        self.perm_tree.tag_configure('high', background='#fff3e0')
        self.perm_tree.tag_configure('medium', background='#fffde7')
        self.perm_tree.tag_configure('low', background='#e8f5e9')
        self.perm_tree.tag_configure('normal', background='#f5f5f5')

        # Details panel
        details_frame = ttk.LabelFrame(frame, text="Détail de la permission", padding=10)
        details_frame.pack(fill='x', pady=(10, 0))

        self.perm_detail_text = scrolledtext.ScrolledText(details_frame, height=6, font=('Consolas', 9), wrap='word')
        self.perm_detail_text.pack(fill='both', expand=True)
        self.perm_detail_text.configure(state='disabled')

        self.perm_tree.bind('<<TreeviewSelect>>', self._on_perm_select)

    def _create_dex_tab(self):
        """Tab 4: DEX - DEX file analysis"""
        frame = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(frame, text="📦 DEX")

        # Toolbar
        tb = ttk.Frame(frame)
        tb.pack(fill='x', pady=(0, 5))
        ttk.Label(tb, text="Analyse des fichiers DEX", style='Header.TLabel').pack(side='left')

        # DEX list
        left_frame = ttk.LabelFrame(frame, text="Fichiers DEX détectés", padding=5)
        left_frame.pack(fill='x', pady=(0, 10))

        dex_columns = ('file', 'sha256', 'size', 'valid', 'classes', 'methods', 'api_level')
        self.dex_tree = ttk.Treeview(left_frame, columns=dex_columns, show='headings', height=6)
        for col in dex_columns:
            self.dex_tree.heading(col, text=col.capitalize())
            self.dex_tree.column(col, width=120, anchor='center' if col != 'file' else 'w')
        self.dex_tree.column('file', width=200)
        self.dex_tree.column('sha256', width=200)
        self.dex_tree.pack(fill='x')

        # DEX details
        right_frame = ttk.LabelFrame(frame, text="Détails & Méthodes suspectes", padding=5)
        right_frame.pack(fill='both', expand=True)

        self.dex_details = scrolledtext.ScrolledText(right_frame, font=('Consolas', 9), wrap='word')
        self.dex_details.pack(fill='both', expand=True)
        self.dex_details.configure(state='disabled')

        self.dex_tree.bind('<<TreeviewSelect>>', self._on_dex_select)

    def _create_java_tab(self):
        """Tab 5: Java - JADX decompiled source"""
        frame = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(frame, text="☕ Java")

        # Toolbar
        tb = ttk.Frame(frame)
        tb.pack(fill='x', pady=(0, 5))
        ttk.Label(tb, text="Code Java décompilé (JADX)", style='Header.TLabel').pack(side='left')

        # Search
        ttk.Label(tb, text="Rechercher:").pack(side='right', padx=(10, 5))
        self.java_search_var = tk.StringVar()
        java_search = ttk.Entry(tb, textvariable=self.java_search_var, width=30)
        java_search.pack(side='right', padx=5)
        java_search.bind('<Return>', lambda e: self._search_java())
        ttk.Button(tb, text="🔍", command=self._search_java).pack(side='right')

        # Paned view
        paned = ttk.PanedWindow(frame, orient='horizontal')
        paned.pack(fill='both', expand=True)

        # Left: Class tree
        left_frame = ttk.LabelFrame(paned, text="Classes", padding=5)
        paned.add(left_frame, weight=1)

        self.java_tree = ttk.Treeview(left_frame, show='tree')
        self.java_tree.pack(fill='both', expand=True)

        # Right: Source code
        right_frame = ttk.LabelFrame(paned, text="Code source", padding=5)
        paned.add(right_frame, weight=2)

        self.java_source = scrolledtext.ScrolledText(right_frame, font=('Consolas', 9), wrap='none')
        self.java_source.pack(fill='both', expand=True)
        self.java_source.configure(state='disabled')

        self.java_tree.bind('<<TreeviewSelect>>', self._on_java_select)

    def _create_smali_tab(self):
        """Tab 6: Smali - Apktool smali analysis"""
        frame = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(frame, text="📝 Smali")

        # Toolbar
        tb = ttk.Frame(frame)
        tb.pack(fill='x', pady=(0, 5))
        ttk.Label(tb, text="Code Smali (Apktool)", style='Header.TLabel').pack(side='left')

        # Search
        ttk.Label(tb, text="Rechercher:").pack(side='right', padx=(10, 5))
        self.smali_search_var = tk.StringVar()
        smali_search = ttk.Entry(tb, textvariable=self.smali_search_var, width=30)
        smali_search.pack(side='right', padx=5)
        smali_search.bind('<Return>', lambda e: self._search_smali())
        ttk.Button(tb, text="🔍", command=self._search_smali).pack(side='right')

        # Paned view
        paned = ttk.PanedWindow(frame, orient='horizontal')
        paned.pack(fill='both', expand=True)

        # Left: File tree
        left_frame = ttk.LabelFrame(paned, text="Fichiers Smali", padding=5)
        paned.add(left_frame, weight=1)

        self.smali_tree = ttk.Treeview(left_frame, show='tree')
        self.smali_tree.pack(fill='both', expand=True)

        # Right: Smali code
        right_frame = ttk.LabelFrame(paned, text="Code Smali", padding=5)
        paned.add(right_frame, weight=2)

        self.smali_source = scrolledtext.ScrolledText(right_frame, font=('Consolas', 9), wrap='none')
        self.smali_source.pack(fill='both', expand=True)
        self.smali_source.configure(state='disabled')

        self.smali_tree.bind('<<TreeviewSelect>>', self._on_smali_select)

    def _create_native_tab(self):
        """Tab 7: Native libraries - ELF analysis"""
        frame = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(frame, text="🔧 Native")

        # Toolbar
        tb = ttk.Frame(frame)
        tb.pack(fill='x', pady=(0, 5))
        ttk.Label(tb, text="Bibliothèques natives (ELF)", style='Header.TLabel').pack(side='left')

        # Library list
        left_frame = ttk.LabelFrame(frame, text="Bibliothèques détectées", padding=5)
        left_frame.pack(fill='x', pady=(0, 10))

        lib_columns = ('name', 'arch', 'path', 'size', 'jni_methods', 'exports', 'imports')
        self.native_tree = ttk.Treeview(left_frame, columns=lib_columns, show='headings', height=6)
        for col in lib_columns:
            self.native_tree.heading(col, text=col.capitalize().replace('_', ' '))
            self.native_tree.column(col, width=120, anchor='center' if col != 'name' and col != 'path' else 'w')
        self.native_tree.column('name', width=180)
        self.native_tree.column('path', width=250)
        self.native_tree.pack(fill='x')

        # Details
        right_frame = ttk.LabelFrame(frame, text="Analyse ELF détaillée", padding=5)
        right_frame.pack(fill='both', expand=True)

        # Notebook for native details
        self.native_notebook = ttk.Notebook(right_frame)
        self.native_notebook.pack(fill='both', expand=True)

        self.native_summary = scrolledtext.ScrolledText(self.native_notebook, font=('Consolas', 9), wrap='word')
        self.native_notebook.add(self.native_summary, text="Résumé")

        self.native_sections = scrolledtext.ScrolledText(self.native_notebook, font=('Consolas', 9), wrap='word')
        self.native_notebook.add(self.native_sections, text="Sections")

        self.native_symbols = scrolledtext.ScrolledText(self.native_notebook, font=('Consolas', 9), wrap='word')
        self.native_notebook.add(self.native_symbols, text="Symboles")

        self.native_imports = scrolledtext.ScrolledText(self.native_notebook, font=('Consolas', 9), wrap='word')
        self.native_notebook.add(self.native_imports, text="Imports")

        self.native_strings = scrolledtext.ScrolledText(self.native_notebook, font=('Consolas', 9), wrap='word')
        self.native_notebook.add(self.native_strings, text="Strings")

        for w in [self.native_summary, self.native_sections, self.native_symbols, self.native_imports, self.native_strings]:
            w.configure(state='disabled')

        self.native_tree.bind('<<TreeviewSelect>>', self._on_native_select)

    def _create_jni_tab(self):
        """Tab 8: JNI - JNI analysis"""
        frame = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(frame, text="🔗 JNI")

        # Toolbar
        tb = ttk.Frame(frame)
        tb.pack(fill='x', pady=(0, 5))
        ttk.Label(tb, text="Analyse JNI (JNI_OnLoad, RegisterNatives)", style='Header.TLabel').pack(side='left')

        # JNI results
        left_frame = ttk.LabelFrame(frame, text="Bibliothèques avec JNI", padding=5)
        left_frame.pack(fill='x', pady=(0, 10))

        jni_lib_columns = ('library', 'jni_onload', 'register_natives', 'native_methods')
        self.jni_lib_tree = ttk.Treeview(left_frame, columns=jni_lib_columns, show='headings', height=4)
        for col in jni_lib_columns:
            self.jni_lib_tree.heading(col, text=col.replace('_', ' ').title())
            self.jni_lib_tree.column(col, width=150, anchor='center' if col != 'library' else 'w')
        self.jni_lib_tree.column('library', width=250)
        self.jni_lib_tree.pack(fill='x')

        # JNI Methods table
        right_frame = ttk.LabelFrame(frame, text="Méthodes natives mappées (Java ↔ Native)", padding=5)
        right_frame.pack(fill='both', expand=True)

        jni_method_columns = ('java_class', 'java_method', 'jni_signature', 'native_function', 'address', 'native_name')
        self.jni_method_tree = ttk.Treeview(right_frame, columns=jni_method_columns, show='headings')
        for col in jni_method_columns:
            self.jni_method_tree.heading(col, text=col.replace('_', ' ').title())
            self.jni_method_tree.column(col, width=150, anchor='w')
        self.jni_method_tree.column('jni_signature', width=200)
        self.jni_method_tree.column('address', width=120, anchor='center')
        self.jni_method_tree.pack(fill='both', expand=True)

        # Details
        details_frame = ttk.LabelFrame(frame, text="Détails JNI_OnLoad / RegisterNatives", padding=5)
        details_frame.pack(fill='x', pady=(10, 0))

        self.jni_details = scrolledtext.ScrolledText(details_frame, height=8, font=('Consolas', 9), wrap='word')
        self.jni_details.pack(fill='both', expand=True)
        self.jni_details.configure(state='disabled')

        self.jni_lib_tree.bind('<<TreeviewSelect>>', self._on_jni_lib_select)

    def _create_network_tab(self):
        """Tab 9: Network IOC - Network indicators"""
        frame = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(frame, text="🌐 Network IOC")

        # Toolbar
        tb = ttk.Frame(frame)
        tb.pack(fill='x', pady=(0, 5))
        ttk.Label(tb, text="Indicateurs de compromission réseau", style='Header.TLabel').pack(side='left')

        # Filter
        ttk.Label(tb, text="Type:").pack(side='right', padx=(10, 5))
        self.net_filter_var = tk.StringVar(value="Tous")
        net_filter = ttk.Combobox(tb, textvariable=self.net_filter_var,
                                   values=["Tous", "URLs", "Domaines", "IPs", "Firebase", "Telegram", "Certificats", "C2", "WebSocket", "API Keys"],
                                   state='readonly', width=15)
        net_filter.pack(side='right', padx=5)
        net_filter.bind('<<ComboboxSelected>>', lambda e: self._filter_network())

        # Paned view
        paned = ttk.PanedWindow(frame, orient='horizontal')
        paned.pack(fill='both', expand=True)

        # Left: IOC list
        left_frame = ttk.LabelFrame(paned, text="IOCs détectés", padding=5)
        paned.add(left_frame, weight=1)

        net_columns = ('type', 'value', 'source', 'confidence', 'decoded')
        self.net_tree = ttk.Treeview(left_frame, columns=net_columns, show='headings')
        self.net_tree.heading('type', text='Type')
        self.net_tree.heading('value', text='Valeur')
        self.net_tree.heading('source', text='Source')
        self.net_tree.heading('confidence', text='Confiance')
        self.net_tree.heading('decoded', text='Décodé')
        self.net_tree.column('type', width=100, anchor='center')
        self.net_tree.column('value', width=250)
        self.net_tree.column('source', width=150)
        self.net_tree.column('confidence', width=80, anchor='center')
        self.net_tree.column('decoded', width=150)
        self.net_tree.pack(fill='both', expand=True)

        # Right: Details
        right_frame = ttk.Frame(paned)
        paned.add(right_frame, weight=1)

        # C2 Config
        c2_frame = ttk.LabelFrame(right_frame, text="Configuration C2", padding=5)
        c2_frame.pack(fill='x', pady=(0, 5))

        self.c2_text = scrolledtext.ScrolledText(c2_frame, height=6, font=('Consolas', 9), wrap='word')
        self.c2_text.pack(fill='both', expand=True)
        self.c2_text.configure(state='disabled')

        # Decoded strings
        decoded_frame = ttk.LabelFrame(right_frame, text="Chaînes décodées (Base64/Hex/XOR)", padding=5)
        decoded_frame.pack(fill='both', expand=True)

        self.decoded_text = scrolledtext.ScrolledText(decoded_frame, font=('Consolas', 9), wrap='word')
        self.decoded_text.pack(fill='both', expand=True)
        self.decoded_text.configure(state='disabled')

    def _create_malware_tab(self):
        """Tab 10: Malware indicators - Detection results"""
        frame = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(frame, text="🦠 Malware")

        # Toolbar
        tb = ttk.Frame(frame)
        tb.pack(fill='x', pady=(0, 5))
        ttk.Label(tb, text="Détections de malware (20 catégories)", style='Header.TLabel').pack(side='left')

        # Detections tree
        det_frame = ttk.LabelFrame(frame, text="Détections", padding=5)
        det_frame.pack(fill='x', pady=(0, 10))

        det_columns = ('category', 'classification', 'confidence', 'matched', 'required', 'mitre')
        self.malware_tree = ttk.Treeview(det_frame, columns=det_columns, show='headings', height=8)
        self.malware_tree.heading('category', text='Catégorie')
        self.malware_tree.heading('classification', text='Classification')
        self.malware_tree.heading('confidence', text='Confiance')
        self.malware_tree.heading('matched', text='Indicateurs')
        self.malware_tree.heading('required', text='Requis')
        self.malware_tree.heading('mitre', text='MITRE ATT&CK')
        self.malware_tree.column('category', width=180)
        self.malware_tree.column('classification', width=120, anchor='center')
        self.malware_tree.column('confidence', width=80, anchor='center')
        self.malware_tree.column('matched', width=80, anchor='center')
        self.malware_tree.column('required', width=80, anchor='center')
        self.malware_tree.column('mitre', width=300)
        self.malware_tree.pack(fill='x')

        # Tag colors
        self.malware_tree.tag_configure('confirmed', background='#ffcdd2')
        self.malware_tree.tag_configure('likely', background='#ffe0b2')
        self.malware_tree.tag_configure('possible', background='#fff9c4')
        self.malware_tree.tag_configure('suspected', background='#e8f5e9')

        # Evidence details
        ev_frame = ttk.LabelFrame(frame, text="Preuves détaillées", padding=5)
        ev_frame.pack(fill='both', expand=True)

        # Evidence notebook
        self.evidence_notebook = ttk.Notebook(ev_frame)
        self.evidence_notebook.pack(fill='both', expand=True)

        self.ev_indicators = scrolledtext.ScrolledText(self.evidence_notebook, font=('Consolas', 9), wrap='word')
        self.evidence_notebook.add(self.ev_indicators, text="Indicateurs")

        self.ev_capabilities = scrolledtext.ScrolledText(self.evidence_notebook, font=('Consolas', 9), wrap='word')
        self.evidence_notebook.add(self.ev_capabilities, text="Capacités")

        self.ev_confirmed = scrolledtext.ScrolledText(self.evidence_notebook, font=('Consolas', 9), wrap='word')
        self.evidence_notebook.add(self.ev_confirmed, text="Confirmés")

        self.ev_hypothesis = scrolledtext.ScrolledText(self.evidence_notebook, font=('Consolas', 9), wrap='word')
        self.evidence_notebook.add(self.ev_hypothesis, text="Hypothèses")

        self.ev_unverifiable = scrolledtext.ScrolledText(self.evidence_notebook, font=('Consolas', 9), wrap='word')
        self.evidence_notebook.add(self.ev_unverifiable, text="Non vérifiables")

        for w in [self.ev_indicators, self.ev_capabilities, self.ev_confirmed, self.ev_hypothesis, self.ev_unverifiable]:
            w.configure(state='disabled')

        # Matched signatures
        sig_frame = ttk.LabelFrame(frame, text="Signatures connues匹配ées", padding=5)
        sig_frame.pack(fill='x', pady=(10, 0))

        sig_columns = ('signature', 'type', 'matched', 'confidence')
        self.sig_tree = ttk.Treeview(sig_frame, columns=sig_columns, show='headings', height=4)
        for col in sig_columns:
            self.sig_tree.heading(col, text=col.title())
            self.sig_tree.column(col, width=200, anchor='center' if col != 'signature' else 'w')
        self.sig_tree.pack(fill='x')

        self.malware_tree.bind('<<TreeviewSelect>>', self._on_malware_select)

    def _create_ai_tab(self):
        """Tab 11: AI Analysis - Ollama analysis"""
        frame = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(frame, text="🤖 AI Analysis")

        # Toolbar
        tb = ttk.Frame(frame)
        tb.pack(fill='x', pady=(0, 5))
        ttk.Label(tb, text="Analyse IA locale (Ollama qwen2.5-coder:3b)", style='Header.TLabel').pack(side='left')

        self.ai_status_var = tk.StringVar(value="En attente d'analyse...")
        ttk.Label(tb, textvariable=self.ai_status_var).pack(side='right')

        # AI Results
        results_frame = ttk.LabelFrame(frame, text="Résultats de l'analyse IA", padding=10)
        results_frame.pack(fill='both', expand=True, pady=(0, 10))

        # Summary cards
        summary_frame = ttk.Frame(results_frame)
        summary_frame.pack(fill='x', pady=(0, 10))

        self.ai_category_var = tk.StringVar(value="—")
        self.ai_confidence_var = tk.StringVar(value="—")
        self.ai_risk_var = tk.StringVar(value="—")

        for label, var in [("Catégorie:", self.ai_category_var), ("Confiance:", self.ai_confidence_var), ("Risque:", self.ai_risk_var)]:
            card = ttk.Frame(summary_frame)
            card.pack(side='left', padx=10, fill='y')
            ttk.Label(card, text=label, font=('Segoe UI', 9, 'bold')).pack(anchor='w')
            ttk.Label(card, textvariable=var, font=('Segoe UI', 11)).pack(anchor='w')

        # AI Analysis text
        self.ai_analysis_text = scrolledtext.ScrolledText(results_frame, font=('Segoe UI', 10), wrap='word')
        self.ai_analysis_text.pack(fill='both', expand=True)
        self.ai_analysis_text.configure(state='disabled')

        # Raw AI response
        raw_frame = ttk.LabelFrame(frame, text="Réponse brute IA", padding=5)
        raw_frame.pack(fill='both', expand=True)

        self.ai_raw_text = scrolledtext.ScrolledText(raw_frame, font=('Consolas', 9), wrap='word')
        self.ai_raw_text.pack(fill='both', expand=True)
        self.ai_raw_text.configure(state='disabled')

    def _create_logs_tab(self):
        """Tab 12: Logs - Full analysis logs"""
        frame = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(frame, text="📜 Logs")

        # Toolbar
        tb = ttk.Frame(frame)
        tb.pack(fill='x', pady=(0, 5))
        ttk.Label(tb, text="Journal complet d'analyse", style='Header.TLabel').pack(side='left')
        ttk.Button(tb, text="🗑 Effacer", command=self._clear_logs).pack(side='right', padx=5)
        ttk.Button(tb, text="💾 Sauvegarder", command=self._save_logs).pack(side='right', padx=5)

        # Filter
        ttk.Label(tb, text="Niveau:").pack(side='right', padx=(10, 5))
        self.log_level_var = tk.StringVar(value="Tous")
        log_filter = ttk.Combobox(tb, textvariable=self.log_level_var,
                                   values=["Tous", "INFO", "SUCCESS", "WARNING", "ERROR", "DEBUG"],
                                   state='readonly', width=10)
        log_filter.pack(side='right', padx=5)
        log_filter.bind('<<ComboboxSelected>>', lambda e: self._filter_logs())

        # Log output
        self.full_log_output = scrolledtext.ScrolledText(frame, font=('Consolas', 9), wrap='word',
                                                          bg='#1e1e1e', fg='#d4d4d4', insertbackground='white')
        self.full_log_output.pack(fill='both', expand=True)
        self.full_log_output.configure(state='disabled')

        # Tag colors
        for tag, color in [('info', '#4fc3f7'), ('success', '#81c784'), ('warning', '#ffb74d'),
                           ('error', '#e57373'), ('debug', '#9575cd')]:
            self.full_log_output.tag_config(tag, foreground=color)

    def _create_status_bar(self):
        """Create status bar"""
        self.status_var = tk.StringVar(value="Prêt")
        status_bar = ttk.Label(self.root, textvariable=self.status_var, relief='sunken', anchor='w', padding=(10, 5))
        status_bar.pack(fill='x', side='bottom')

    def _check_tools_status(self):
        """Check external tools availability"""
        self._log("Vérification des outils externes...", 'info')
        threading.Thread(target=self._check_tools_worker, daemon=True).start()

    def _check_tools_worker(self):
        """Worker to check tools"""
        config = self._load_config()
        tools = config.get("tools", {})

        # Default paths relative to project directory
        project_dir = self.project_dir
        jadx_path = tools.get("jadx_path", str(project_dir / "tools" / "jadx" / "bin" / "jadx.bat"))
        apktool_path = tools.get("apktool_path", str(project_dir / "tools" / "apktool.jar"))

        jadx_ok = Path(jadx_path).exists()
        apktool_ok = Path(apktool_path).exists()

        # Check Ollama
        ollama_ok = False
        try:
            import requests
            r = requests.get("http://127.0.0.1:11434/api/tags", timeout=3)
            ollama_ok = r.status_code == 200
        except Exception:
            pass

        self.root.after(0, lambda: self._update_tools_status(jadx_ok, apktool_ok, ollama_ok))

    def _update_tools_status(self, jadx_ok, apktool_ok, ollama_ok):
        """Update tools status display"""
        status = []
        if jadx_ok:
            status.append("JADX ✓")
        else:
            status.append("JADX ✗")

        if apktool_ok:
            status.append("Apktool ✓")
        else:
            status.append("Apktool ✗")

        if ollama_ok:
            status.append("Ollama ✓")
            self.ollama_status_var.set("🤖 IA: Connecté")
            self.ollama_label.configure(style='Success.TLabel')
        else:
            status.append("Ollama ✗")
            self.ollama_status_var.set("🤖 IA: Déconnecté")
            self.ollama_label.configure(style='Error.TLabel')

        self._log(f"Outils: {' | '.join(status)}", 'success' if all([jadx_ok, apktool_ok]) else 'warning')

    def _choose_apk(self):
        """Open file dialog to choose APK"""
        path = filedialog.askopenfilename(
            title="Sélectionner un APK",
            filetypes=[("Android APK", "*.apk"), ("Tous les fichiers", "*.*")]
        )
        if path:
            self.apk_var.set(path)
            # Calculate SHA256 immediately
            self._log(f"Calcul SHA256 pour {Path(path).name}...", 'info')
            threading.Thread(target=lambda: self._calc_sha256(path), daemon=True).start()

    def _calc_sha256(self, path):
        """Calculate SHA256 in background"""
        sha256 = calculate_sha256(Path(path))
        self.root.after(0, lambda: self.sha256_var.set(f"SHA256: {sha256}"))

    def _new_analysis(self):
        """Reset for new analysis"""
        self.apk_var.set("")
        self.sha256_var.set("SHA256: —")
        self.current_result = None
        self._clear_all_tabs()
        self._log("Nouvelle analyse prête.", 'info')

    def _start_analysis(self):
        """Start full analysis"""
        apk = self.apk_var.get().strip()
        if not apk or not Path(apk).is_file():
            messagebox.showerror("APKStudioAI", "Veuillez sélectionner un fichier APK valide.")
            return

        self.cancelled = False
        self.scan_btn.configure(state='disabled')
        self.cancel_btn.configure(state='normal')
        self.progress['value'] = 0
        self._clear_all_tabs()
        self._log(f"\n{'='*60}", 'info')
        self._log(f"DÉBUT ANALYSE: {Path(apk).name}", 'info')
        self._log(f"{'='*60}", 'info')

        self.analysis_thread = threading.Thread(target=self._analysis_worker, args=(apk,), daemon=True)
        self.analysis_thread.start()

    def _cancel_analysis(self):
        """Cancel ongoing analysis"""
        self.cancelled = True
        self.scanner.cancel()
        self._log("Annulation demandée...", 'warning')
        self.cancel_btn.configure(state='disabled')

    def _analysis_worker(self, apk_path):
        """Background analysis worker"""
        try:
            result = self.scanner.scan(apk_path, no_ai=False)
            if not self.cancelled:
                self.root.after(0, lambda: self._analysis_finished(result))
        except Exception as e:
            import traceback
            if not self.cancelled:
                self.root.after(0, lambda: self._analysis_failed(str(e), traceback.format_exc()))

    def _analysis_finished(self, result):
        """Handle analysis completion"""
        self.current_result = result
        self.progress['value'] = 100
        self.progress_label.configure(text="Terminé")
        self.scan_btn.configure(state='normal')
        self.cancel_btn.configure(state='disabled')
        self.status_var.set("Analyse terminée avec succès")

        # Populate all tabs
        self._populate_all_tabs(result)

        # Generate reports
        self._generate_reports(result)

        self._log(f"\n{'='*60}", 'success')
        self._log("ANALYSE TERMINÉE AVEC SUCCÈS", 'success')
        self._log(f"Rapport HTML: {result.get('report_html', 'N/A')}", 'success')
        self._log(f"{'='*60}", 'success')

        messagebox.showinfo("Analyse terminée", f"Analyse terminée avec succès!\n\nRapport: {result.get('report_html', 'N/A')}")

    def _analysis_failed(self, error, traceback_str):
        """Handle analysis failure"""
        self.progress['value'] = 0
        self.progress_label.configure(text="Échec")
        self.scan_btn.configure(state='normal')
        self.cancel_btn.configure(state='disabled')
        self.status_var.set("Échec de l'analyse")
        self._log(f"\n[ERREUR] {error}", 'error')
        self._log(traceback_str, 'debug')
        messagebox.showerror("Erreur d'analyse", f"L'analyse a échoué:\n{error}")

    def _on_progress(self, stage, percent, message):
        """Progress callback from scanner"""
        self.root.after(0, lambda: self._update_progress(stage, percent, message))

    def _update_progress(self, stage, percent, message):
        """Update progress UI"""
        self.progress['value'] = percent
        self.progress_label.configure(text=f"{stage}: {message}")
        self._log(f"[{percent:3d}%] {stage}: {message}", 'info' if percent < 100 else 'success')

    def _log(self, message, level='info'):
        """Log to both log outputs"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        formatted = f"[{timestamp}] {message}"

        # Main log (bottom panel)
        self.log_output.configure(state='normal')
        self.log_output.insert('end', formatted + '\n', level)
        self.log_output.see('end')
        self.log_output.configure(state='disabled')

        # Full logs tab
        self.full_log_output.configure(state='normal')
        self.full_log_output.insert('end', formatted + '\n', level)
        self.full_log_output.see('end')
        self.full_log_output.configure(state='disabled')

    def _clear_all_tabs(self):
        """Clear all tab contents"""
        # Overview
        self.risk_score_var.set("0/100")
        self.risk_level_var.set("INCONNU")
        self.risk_desc_var.set("Aucune analyse effectuée")
        for var in self.apk_info_vars.values():
            var.set("—")
        for var in self.stats_vars.values():
            var.set("0")
        for item in self.risk_factors_tree.get_children():
            self.risk_factors_tree.delete(item)

        # Manifest
        for item in self.manifest_tree.get_children():
            self.manifest_tree.delete(item)
        self._set_text(self.manifest_details, "")
        self._set_text(self.manifest_raw_text, "")

        # Permissions
        for item in self.perm_tree.get_children():
            self.perm_tree.delete(item)
        self._set_text(self.perm_detail_text, "")

        # DEX
        for item in self.dex_tree.get_children():
            self.dex_tree.delete(item)
        self._set_text(self.dex_details, "")

        # Java
        for item in self.java_tree.get_children():
            self.java_tree.delete(item)
        self._set_text(self.java_source, "")

        # Smali
        for item in self.smali_tree.get_children():
            self.smali_tree.delete(item)
        self._set_text(self.smali_source, "")

        # Native
        for item in self.native_tree.get_children():
            self.native_tree.delete(item)
        for w in [self.native_summary, self.native_sections, self.native_symbols, self.native_imports, self.native_strings]:
            self._set_text(w, "")

        # JNI
        for item in self.jni_lib_tree.get_children():
            self.jni_lib_tree.delete(item)
        for item in self.jni_method_tree.get_children():
            self.jni_method_tree.delete(item)
        self._set_text(self.jni_details, "")

        # Network
        for item in self.net_tree.get_children():
            self.net_tree.delete(item)
        self._set_text(self.c2_text, "")
        self._set_text(self.decoded_text, "")

        # Malware
        for item in self.malware_tree.get_children():
            self.malware_tree.delete(item)
        for item in self.sig_tree.get_children():
            self.sig_tree.delete(item)
        for w in [self.ev_indicators, self.ev_capabilities, self.ev_confirmed, self.ev_hypothesis, self.ev_unverifiable]:
            self._set_text(w, "")

        # AI
        self.ai_category_var.set("—")
        self.ai_confidence_var.set("—")
        self.ai_risk_var.set("—")
        self.ai_status_var.set("En attente d'analyse...")
        self._set_text(self.ai_analysis_text, "")
        self._set_text(self.ai_raw_text, "")

    def _populate_all_tabs(self, result):
        """Populate all tabs with analysis results"""
        self._populate_overview(result)
        self._populate_manifest(result)
        self._populate_permissions(result)
        self._populate_dex(result)
        self._populate_java(result)
        self._populate_smali(result)
        self._populate_native(result)
        self._populate_jni(result)
        self._populate_network(result)
        self._populate_malware(result)
        self._populate_ai(result)

    def _populate_overview(self, result):
        """Populate overview tab"""
        risk = result.get('risk', {})
        score = risk.get('score', 0)
        level = risk.get('risk_level', 'UNKNOWN')
        summary = risk.get('summary', {})

        self.risk_score_var.set(f"{score}/100")
        self.risk_level_var.set(level)
        self.risk_desc_var.set(summary.get('description', 'N/A'))

        # Color code risk level
        colors = {'FAIBLE': '#388e3c', 'MODÉRÉ': '#fbc02d', 'ÉLEVÉ': '#f57c00', 'TRÈS ÉLEVÉ': '#e65100', 'CRITIQUE': '#d32f2f'}
        self.risk_level_label.configure(foreground=colors.get(level, '#000'))

        # APK Info
        manifest = result.get('manifest', {})
        self.apk_info_vars['apk_path'].set(str(result.get('apk_path', 'N/A')))
        self.apk_info_vars['sha256'].set(result.get('sha256', 'N/A')[:64])
        self.apk_info_vars['package'].set(manifest.get('package', 'N/A'))
        self.apk_info_vars['version'].set(manifest.get('version_name', 'N/A'))
        self.apk_info_vars['min_sdk'].set(str(manifest.get('min_sdk', 'N/A')))
        self.apk_info_vars['target_sdk'].set(str(manifest.get('target_sdk', 'N/A')))
        self.apk_info_vars['file_size'].set(self._format_size(Path(result.get('apk_path', '')).stat().st_size if Path(result.get('apk_path', '')).exists() else 0))
        self.apk_info_vars['scan_time'].set(result.get('scan_time', 'N/A'))

        # Stats
        perm_analysis = result.get('permission_analysis', {})
        native = result.get('native', {})
        network = result.get('network', {})
        malware = result.get('malware', {})
        dex = result.get('dex', {})
        jadx = result.get('java', {})

        self.stats_vars['total_perms'].set(str(perm_analysis.get('total_count', 0)))
        self.stats_vars['critical_perms'].set(str(len(perm_analysis.get('by_risk', {}).get('critical', []))))
        self.stats_vars['native_libs'].set(str(len(native.get('libraries', []))))
        self.stats_vars['jni_functions'].set(str(sum(len(lib.get('native_methods', [])) for lib in native.get('libraries', []))))
        self.stats_vars['dex_count'].set(str(len(dex.get('dex_files', []))))
        self.stats_vars['java_classes'].set(str(len(jadx.get('classes', []))))
        self.stats_vars['url_count'].set(str(len(network.get('urls', []))))
        self.stats_vars['domain_count'].set(str(len(network.get('domains', []))))
        self.stats_vars['malware_detections'].set(str(malware.get('summary', {}).get('total', 0)))

        # Risk factors
        for item in self.risk_factors_tree.get_children():
            self.risk_factors_tree.delete(item)
        for rf in result.get('risk', {}).get('risk_factors', []):
            self.risk_factors_tree.insert('', 'end', values=(
                rf.get('severity', '').upper(),
                rf.get('factor', ''),
                rf.get('detail', '')
            ), tags=(rf.get('severity', 'low'),))

    def _populate_manifest(self, result):
        """Populate manifest tab"""
        manifest = result.get('manifest', {})

        # Clear
        for item in self.manifest_tree.get_children():
            self.manifest_tree.delete(item)

        # Add components
        for comp_type in ['activities', 'services', 'receivers', 'providers']:
            parent = self.manifest_tree.insert('', 'end', text=f"📁 {comp_type.capitalize()}", open=True)
            for comp in manifest.get(comp_type, []):
                exported = "✓" if comp.get('exported') else "✗"
                perm = comp.get('permission', '—')
                self.manifest_tree.insert(parent, 'end', text=comp.get('name', 'N/A'), values=(exported, perm))

        # Permissions
        perm_parent = self.manifest_tree.insert('', 'end', text="🔐 Permissions", open=True)
        for perm in manifest.get('permissions', []):
            self.manifest_tree.insert(perm_parent, 'end', text=perm, values=('', ''))

        # Details
        details = f"Package: {manifest.get('package', 'N/A')}\n"
        details += f"Version: {manifest.get('version_name', 'N/A')} ({manifest.get('version_code', 'N/A')})\n"
        details += f"Min SDK: {manifest.get('min_sdk', 'N/A')}\n"
        details += f"Target SDK: {manifest.get('target_sdk', 'N/A')}\n"
        details += f"Debuggable: {manifest.get('debuggable', False)}\n"
        details += f"Allow Backup: {manifest.get('allow_backup', True)}\n"
        details += f"Supports Screens: {manifest.get('supports_screens', 'N/A')}\n"
        self._set_text(self.manifest_details, details)

        # Raw XML
        self._set_text(self.manifest_raw_text, manifest.get('raw_xml', 'Non disponible'))

    def _populate_permissions(self, result):
        """Populate permissions tab"""
        perm_analysis = result.get('permission_analysis', {})

        for item in self.perm_tree.get_children():
            self.perm_tree.delete(item)

        for risk_level in ['critical', 'high', 'medium', 'low', 'normal']:
            for perm in perm_analysis.get('by_risk', {}).get(risk_level, []):
                self.perm_tree.insert('', 'end', values=(
                    perm.get('permission', ''),
                    risk_level.upper(),
                    perm.get('description', ''),
                    perm.get('capability', ''),
                    ', '.join(perm.get('mitre', []))
                ), tags=(risk_level,))

    def _populate_dex(self, result):
        """Populate DEX tab"""
        dex = result.get('dex', {})

        for item in self.dex_tree.get_children():
            self.dex_tree.delete(item)

        for dex_file in dex.get('dex_files', []):
            self.dex_tree.insert('', 'end', values=(
                dex_file.get('name', ''),
                dex_file.get('sha256', '')[:32] + '...',
                self._format_size(dex_file.get('size', 0)),
                '✓' if dex_file.get('valid') else '✗',
                dex_file.get('class_count', 0),
                dex_file.get('method_count', 0),
                dex_file.get('api_level', 'N/A')
            ))

    def _populate_java(self, result):
        """Populate Java tab"""
        jadx = result.get('java', {})

        for item in self.java_tree.get_children():
            self.java_tree.delete(item)

        # Build package tree
        packages = {}
        for cls in jadx.get('classes', []):
            pkg = cls.get('package', 'default')
            if pkg not in packages:
                packages[pkg] = []
            packages[pkg].append(cls)

        for pkg, classes in sorted(packages.items()):
            pkg_node = self.java_tree.insert('', 'end', text=f"📦 {pkg}", open=False)
            for cls in sorted(classes, key=lambda x: x.get('name', '')):
                cls_node = self.java_tree.insert(pkg_node, 'end', text=f"📄 {cls.get('name', 'N/A')}", values=(cls,))
                for method in cls.get('methods', [])[:10]:  # Limit methods shown
                    self.java_tree.insert(cls_node, 'end', text=f"🔧 {method.get('name', 'N/A')}")

    def _populate_smali(self, result):
        """Populate Smali tab"""
        smali = result.get('smali', {})

        for item in self.smali_tree.get_children():
            self.smali_tree.delete(item)

        # Add smali files by directory
        for root_dir, files in smali.get('smali_files', {}).items():
            dir_node = self.smali_tree.insert('', 'end', text=f"📁 {root_dir}", open=False)
            for f in sorted(files)[:50]:  # Limit
                self.smali_tree.insert(dir_node, 'end', text=f"📄 {f}")

    def _populate_native(self, result):
        """Populate Native tab"""
        native = result.get('native', {})

        for item in self.native_tree.get_children():
            self.native_tree.delete(item)

        for lib in native.get('libraries', []):
            self.native_tree.insert('', 'end', values=(
                lib.get('name', ''),
                lib.get('architecture', ''),
                lib.get('path', ''),
                self._format_size(lib.get('size', 0)),
                len(lib.get('native_methods', [])),
                len(lib.get('exports', [])),
                len(lib.get('imports', []))
            ))

    def _populate_jni(self, result):
        """Populate JNI tab"""
        jni = result.get('jni', {})

        for item in self.jni_lib_tree.get_children():
            self.jni_lib_tree.delete(item)

        for lib_jni in jni.get('libraries', []):
            self.jni_lib_tree.insert('', 'end', values=(
                lib_jni.get('library', ''),
                '✓' if lib_jni.get('jni_onload', {}).get('found') else '✗',
                '✓' if lib_jni.get('register_natives', {}).get('found') else '✗',
                len(lib_jni.get('mapped_methods', []))
            ))

    def _populate_network(self, result):
        """Populate Network IOC tab"""
        network = result.get('network', {})

        for item in self.net_tree.get_children():
            self.net_tree.delete(item)

        # URLs
        for url in network.get('urls', [])[:50]:
            self.net_tree.insert('', 'end', values=('URL', url, 'Strings', 'High', ''), tags=('url',))

        # Domains
        for domain in network.get('domains', [])[:50]:
            self.net_tree.insert('', 'end', values=('Domaine', domain, 'Strings', 'Medium', ''), tags=('domain',))

        # IPs
        for ip in network.get('ips', [])[:20]:
            self.net_tree.insert('', 'end', values=('IP', ip, 'Strings', 'Medium', ''), tags=('ip',))

        # Firebase
        for fb in network.get('firebase_config', []):
            self.net_tree.insert('', 'end', values=('Firebase', str(fb)[:100], 'Manifest/Strings', 'High', ''), tags=('firebase',))

        # Telegram
        for tel in network.get('telegram_bots', []):
            self.net_tree.insert('', 'end', values=('Telegram', str(tel)[:100], 'Strings', 'Critical', ''), tags=('telegram',))

        # C2
        c2_text = "Configurations C2 détectées:\n\n"
        for c2 in network.get('c2_config', []):
            c2_text += f"{json.dumps(c2, indent=2)}\n\n"
        self._set_text(self.c2_text, c2_text or "Aucune configuration C2 détectée")

        # Decoded strings
        strings_data = result.get('strings', {})
        decoded_text = "Chaînes décodées:\n\n"
        for ds in strings_data.get('decoded_strings', [])[:30]:
            decoded_text += f"[{ds.get('method', '?')}] {ds.get('original', '')[:80]}...\n"
            decoded_text += f"  → {ds.get('decoded', '')[:200]}\n\n"
        self._set_text(self.decoded_text, decoded_text or "Aucune chaîne décodée")

    def _populate_malware(self, result):
        """Populate Malware tab"""
        malware = result.get('malware', {})

        for item in self.malware_tree.get_children():
            self.malware_tree.delete(item)

        for det in malware.get('detections', []):
            self.malware_tree.insert('', 'end', values=(
                det.get('category', '').upper(),
                det.get('classification', '').upper(),
                f"{det.get('confidence_score', 0)}%",
                det.get('matched_indicators', 0),
                det.get('required_indicators', 0),
                ', '.join(det.get('mitre_techniques', []))
            ), tags=(det.get('classification', 'suspected'),))

        # Signatures
        for item in self.sig_tree.get_children():
            self.sig_tree.delete(item)
        for sig in malware.get('matched_signatures', []):
            self.sig_tree.insert('', 'end', values=(
                sig.get('name', ''),
                sig.get('type', ''),
                sig.get('match_count', 0),
                f"{sig.get('confidence', 0)}%"
            ))

    def _populate_ai(self, result):
        """Populate AI Analysis tab"""
        ai = result.get('ai_analysis', {})

        if ai.get('success'):
            analysis = ai.get('analysis', {})
            self.ai_category_var.set(analysis.get('malware_category', 'inconnu').upper())
            self.ai_confidence_var.set(f"{analysis.get('confidence', 0)}%")
            self.ai_risk_var.set(analysis.get('risk_level', 'INCONNU'))

            ai_text = f"RÉSUMÉ:\n{analysis.get('summary', 'N/A')}\n\n"
            ai_text += f"DÉTAILS:\n{analysis.get('details', 'N/A')}\n\n"
            ai_text += f"INDICATEURS CLÉS:\n"
            for ind in analysis.get('key_indicators', []):
                ai_text += f"  • {ind}\n"
            ai_text += f"\nRECOMMANDATIONS:\n"
            for rec in analysis.get('recommendations', []):
                ai_text += f"  • {rec}\n"
            ai_text += f"\nLIMITES:\n{analysis.get('limitations', 'N/A')}"

            self._set_text(self.ai_analysis_text, ai_text)
            self.ai_status_var.set("Analyse IA terminée")
        else:
            self.ai_status_var.set(f"Échec IA: {ai.get('error', 'Inconnu')}")
            self._set_text(self.ai_analysis_text, f"Erreur: {ai.get('error', 'Inconnue')}")

        self._set_text(self.ai_raw_text, ai.get('raw_response', 'Pas de réponse brute'))

    # Event handlers
    def _on_perm_select(self, event):
        """Handle permission selection"""
        selection = self.perm_tree.selection()
        if selection:
            item = self.perm_tree.item(selection[0])
            values = item['values']
            detail = f"Permission: {values[0]}\nRisque: {values[1]}\nDescription: {values[2]}\nCapacité: {values[3]}\nMITRE: {values[4]}"
            self._set_text(self.perm_detail_text, detail)

    def _on_dex_select(self, event):
        """Handle DEX selection"""
        selection = self.dex_tree.selection()
        if selection:
            item = self.dex_tree.item(selection[0])
            values = item['values']
            detail = f"Fichier: {values[0]}\nSHA256: {values[1]}\nTaille: {values[2]}\nValide: {values[3]}\nClasses: {values[4]}\nMéthodes: {values[5]}\nAPI Level: {values[6]}"
            self._set_text(self.dex_details, detail)

    def _on_java_select(self, event):
        """Handle Java class selection"""
        selection = self.java_tree.selection()
        if selection:
            item = self.java_tree.item(selection[0])
            # Get class data from values
            if 'values' in item and item['values']:
                cls = item['values'][0]
                source = cls.get('source', 'Code source non disponible')
                self._set_text(self.java_source, source)

    def _on_smali_select(self, event):
        """Handle Smali file selection"""
        selection = self.smali_tree.selection()
        if selection:
            item = self.smali_tree.item(selection[0])
            text = item['text']
            self._set_text(self.smali_source, f"Fichier: {text}\n\nContenu non chargé (trop volumineux). Utilisez la recherche.")

    def _on_native_select(self, event):
        """Handle Native library selection"""
        selection = self.native_tree.selection()
        if selection:
            item = self.native_tree.item(selection[0])
            values = item['values']
            # Would need to fetch full lib data from result
            detail = f"Bibliothèque: {values[0]}\nArchitecture: {values[1]}\nChemin: {values[2]}\nTaille: {values[3]}\nMéthodes JNI: {values[4]}\nExports: {values[5]}\nImports: {values[6]}"
            self._set_text(self.native_summary, detail)

    def _on_jni_lib_select(self, event):
        """Handle JNI library selection"""
        selection = self.jni_lib_tree.selection()
        if selection:
            item = self.jni_lib_tree.item(selection[0])
            values = item['values']
            detail = f"Bibliothèque: {values[0]}\nJNI_OnLoad: {values[1]}\nRegisterNatives: {values[2]}\nMéthodes mappées: {values[3]}"
            self._set_text(self.jni_details, detail)

            # Populate methods
            for item2 in self.jni_method_tree.get_children():
                self.jni_method_tree.delete(item2)

    def _on_malware_select(self, event):
        """Handle malware detection selection"""
        selection = self.malware_tree.selection()
        if selection and self.current_result:
            item = self.malware_tree.item(selection[0])
            category = item['values'][0].lower()
            malware = self.current_result.get('malware', {})
            for det in malware.get('detections', []):
                if det.get('category', '').lower() == category:
                    ev = det.get('evidence', {})
                    self._set_text(self.ev_indicators, json.dumps(ev.get('indicators', []), indent=2))
                    self._set_text(self.ev_capabilities, json.dumps(ev.get('capabilities', []), indent=2))
                    self._set_text(self.ev_confirmed, json.dumps(ev.get('confirmed', []), indent=2))
                    self._set_text(self.ev_hypothesis, json.dumps(ev.get('hypothesis', []), indent=2))
                    self._set_text(self.ev_unverifiable, json.dumps(ev.get('unverifiable', []), indent=2))
                    break

    def _filter_permissions(self):
        """Filter permissions by risk level"""
        filter_val = self.perm_filter_var.get()
        # Implementation would filter tree view
        pass

    def _filter_network(self):
        """Filter network IOCs by type"""
        pass

    def _filter_logs(self):
        """Filter logs by level"""
        pass

    def _search_java(self):
        """Search in Java source"""
        query = self.java_search_var.get().lower()
        # Implementation would highlight matches
        pass

    def _search_smali(self):
        """Search in Smali source"""
        pass

    def _clear_logs(self):
        """Clear log outputs"""
        self.log_output.configure(state='normal')
        self.log_output.delete('1.0', 'end')
        self.log_output.configure(state='disabled')
        self.full_log_output.configure(state='normal')
        self.full_log_output.delete('1.0', 'end')
        self.full_log_output.configure(state='disabled')

    def _save_logs(self):
        """Save logs to file"""
        path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text", "*.txt")])
        if path:
            with open(path, 'w') as f:
                f.write(self.full_log_output.get('1.0', 'end'))
            self._log(f"Logs sauvegardés: {path}", 'success')

    def _copy_to_clipboard(self, widget):
        """Copy widget content to clipboard"""
        try:
            text = widget.get('1.0', 'end-1c')
            self.root.clipboard_clear()
            self.root.clipboard_append(text)
            self._log("Copié dans le presse-papiers", 'success')
        except Exception:
            pass

    def _set_text(self, widget, text):
        """Set text widget content"""
        widget.configure(state='normal')
        widget.delete('1.0', 'end')
        widget.insert('1.0', text)
        widget.configure(state='disabled')

    def _format_size(self, size):
        """Format file size"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024:
                return f"{size:.1f} {unit}"
            size /= 1024
        return f"{size:.1f} TB"

    def _generate_reports(self, result):
        """Generate HTML, JSON, TXT reports"""
        try:
            from core.reporter import ReportGenerator
            reporter = ReportGenerator(self.project_dir)
            paths = reporter.generate_all(result)
            result['report_html'] = paths.get('html', '')
            result['report_json'] = paths.get('json', '')
            result['report_txt'] = paths.get('txt', '')
            self._log(f"Rapports générés: {paths.get('html', 'N/A')}", 'success')
        except Exception as e:
            self._log(f"Erreur génération rapport: {e}", 'error')

    def _open_report(self):
        """Open report file"""
        if self.current_result and self.current_result.get('report_html'):
            import os
            os.startfile(self.current_result['report_html'])

    def _batch_analysis(self):
        """Batch analysis dialog"""
        directory = filedialog.askdirectory(title="Sélectionner le dossier d'APK")
        if directory:
            self._log(f"Analyse par lot: {directory}", 'info')
            # Would implement batch scanning

    def _configure_ollama(self):
        """Ollama configuration dialog"""
        dialog = tk.Toplevel(self.root)
        dialog.title("Configuration Ollama")
        dialog.geometry("400x200")
        dialog.transient(self.root)
        dialog.grab_set()

        ttk.Label(dialog, text="URL API:").pack(pady=10)
        url_var = tk.StringVar(value="http://127.0.0.1:11434")
        ttk.Entry(dialog, textvariable=url_var, width=40).pack()

        ttk.Label(dialog, text="Modèle:").pack(pady=10)
        model_var = tk.StringVar(value="qwen2.5-coder:3b")
        ttk.Entry(dialog, textvariable=model_var, width=40).pack()

        def save():
            config = self._load_config()
            config['ollama'] = {'api_url': url_var.get(), 'model': model_var.get()}
            with open(self.project_dir / 'config.json', 'w') as f:
                json.dump(config, f, indent=2)
            self._log("Configuration Ollama mise à jour", 'success')
            dialog.destroy()

        ttk.Button(dialog, text="Enregistrer", command=save).pack(pady=20)

    def _configure_ai_backend(self):
        """AI Backend selection dialog"""
        config = self._load_config()
        freellmapi_cfg = config.get("freellmapi", {})
        ollama_cfg = config.get("ollama", {})

        dialog = tk.Toplevel(self.root)
        dialog.title("Configuration IA - Backend Selection")
        dialog.geometry("500x450")
        dialog.transient(self.root)
        dialog.grab_set()

        # Backend selection
        ttk.Label(dialog, text="Choisir le backend IA:", font=('Segoe UI', 10, 'bold')).pack(pady=10)

        backend_var = tk.StringVar(value=config.get("ai_backend", "auto"))

        # Backend options with descriptions
        backends = [
            ("auto", "🔄 Auto (Recommandé)", "Essaie FreeLLMAPI → Ollama → Rule-based"),
            ("freellmapi", "☁️ FreeLLMAPI", "API agrégée gratuite (port 3001) - 1313 modèles"),
            ("ollama", "🦙 Ollama Local", "Modèle local qwen2.5-coder:3b (port 11434)"),
            ("rule_based", "📋 Rule-based", "Analyse sans IA - Moteur de règles intégré"),
            ("disabled", "🚫 Désactivé", "Pas d'analyse IA"),
        ]

        backend_frame = ttk.Frame(dialog)
        backend_frame.pack(fill='x', padx=20, pady=5)

        for value, label, desc in backends:
            rb = ttk.Radiobutton(backend_frame, text=label, variable=backend_var, value=value)
            rb.pack(anchor='w', pady=2)
            ttk.Label(backend_frame, text=f"  {desc}", font=('Segoe UI', 8), foreground='gray').pack(anchor='w', padx=20)

        # FreeLLMAPI settings
        fl_frame = ttk.LabelFrame(dialog, text="FreeLLMAPI Settings", padding=10)
        fl_frame.pack(fill='x', padx=20, pady=10)

        ttk.Label(fl_frame, text="URL API:").grid(row=0, column=0, sticky='w', pady=2)
        fl_url_var = tk.StringVar(value=freellmapi_cfg.get("api_url", "http://localhost:3001/v1"))
        ttk.Entry(fl_frame, textvariable=fl_url_var, width=40).grid(row=0, column=1, pady=2, padx=5)

        ttk.Label(fl_frame, text="Modèle:").grid(row=1, column=0, sticky='w', pady=2)
        fl_model_var = tk.StringVar(value=freellmapi_cfg.get("model", "auto"))
        ttk.Entry(fl_frame, textvariable=fl_model_var, width=40).grid(row=1, column=1, pady=2, padx=5)

        ttk.Label(fl_frame, text="API Key:").grid(row=2, column=0, sticky='w', pady=2)
        fl_key_var = tk.StringVar(value=freellmapi_cfg.get("api_key", ""))
        ttk.Entry(fl_frame, textvariable=fl_key_var, width=40, show='*').grid(row=2, column=1, pady=2, padx=5)

        # Ollama settings
        oll_frame = ttk.LabelFrame(dialog, text="Ollama Settings", padding=10)
        oll_frame.pack(fill='x', padx=20, pady=10)

        ttk.Label(oll_frame, text="URL API:").grid(row=0, column=0, sticky='w', pady=2)
        oll_url_var = tk.StringVar(value=ollama_cfg.get("api_url", "http://127.0.0.1:11434"))
        ttk.Entry(oll_frame, textvariable=oll_url_var, width=40).grid(row=0, column=1, pady=2, padx=5)

        ttk.Label(oll_frame, text="Modèle:").grid(row=1, column=0, sticky='w', pady=2)
        oll_model_var = tk.StringVar(value=ollama_cfg.get("model", "qwen2.5-coder:3b"))
        ttk.Entry(oll_frame, textvariable=oll_model_var, width=40).grid(row=1, column=1, pady=2, padx=5)

        def save():
            config = self._load_config()
            config["ai_backend"] = backend_var.get()
            config["freellmapi"] = {
                "api_url": fl_url_var.get(),
                "model": fl_model_var.get(),
                "api_key": fl_key_var.get(),
                "timeout": 120,
                "enabled": True,
                "fallback_order": "freellmapi,ollama,rule_based",
                "max_chunk_chars": 8000,
                "temperature": 0.1,
                "max_tokens": 4096,
                "rule_based_fallback": True
            }
            config["ollama"] = {
                "api_url": oll_url_var.get(),
                "model": oll_model_var.get(),
                "timeout": 180,
                "enable_streaming": True,
                "max_chunk_chars": 8000,
                "fallback_enabled": True
            }
            with open(self.project_dir / 'config.json', 'w') as f:
                json.dump(config, f, indent=2)
            self._log(f"Configuration IA mise à jour: {backend_var.get()}", 'success')
            dialog.destroy()

        def test_backends():
            """Test backend connectivity"""
            import requests
            results = []

            # Test FreeLLMAPI
            try:
                r = requests.get(f"{fl_url_var.get()}/models", timeout=5)
                results.append(f"FreeLLMAPI: {'✓ Connecté' if r.status_code == 200 else '✗ Erreur'}")
            except Exception as e:
                results.append(f"FreeLLMAPI: ✗ {e}")

            # Test Ollama
            try:
                r = requests.get(f"{oll_url_var.get()}/api/tags", timeout=5)
                results.append(f"Ollama: {'✓ Connecté' if r.status_code == 200 else '✗ Erreur'}")
            except Exception as e:
                results.append(f"Ollama: ✗ {e}")

            messagebox.showinfo("Test Backends", "\n".join(results))

        btn_frame = ttk.Frame(dialog)
        btn_frame.pack(pady=15)
        ttk.Button(btn_frame, text="🔍 Tester les backends", command=test_backends).pack(side='left', padx=5)
        ttk.Button(btn_frame, text="💾 Enregistrer", command=save).pack(side='left', padx=5)
        ttk.Button(btn_frame, text="Annuler", command=dialog.destroy).pack(side='left', padx=5)

    def _run_diagnostic(self):
        """Run diagnostic"""
        self._log("Lancement diagnostic...", 'info')
        # Would run diagnostic.bat

    def _show_docs(self):
        """Show documentation"""
        messagebox.showinfo("Documentation", "Consultez README.md pour la documentation complète.")

    def _show_about(self):
        """Show about dialog"""
        messagebox.showinfo("À propos", "APKStudioAI 2.1\nAdvanced Android Malware Analysis Platform\n\n© 2024 - Local Static Analysis Laboratory")


def main():
    """Main entry point for GUI"""
    root = tk.Tk()
    app = APKStudioGUI(root, Path.cwd())
    root.mainloop()


if __name__ == '__main__':
    main()