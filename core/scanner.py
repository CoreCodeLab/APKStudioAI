"""
Main scanner orchestrator for APKStudioAI 2.1
Coordinates all analyzers: archive, manifest, DEX, Java, native, JNI, strings, permissions, behavior, network, malware, risk
"""
import os
import json
import hashlib
import shutil
import tempfile
import threading
import time
import concurrent.futures
import uuid
from pathlib import Path
from typing import Dict, List, Any, Optional, Callable
from datetime import datetime

from .archive_analyzer import ArchiveAnalyzer
from .manifest_analyzer import ManifestAnalyzer
from .dex_analyzer import DexAnalyzer
from .jadx_engine import JadxEngine
from .apktool_engine import ApktoolEngine
from .native_analyzer import NativeAnalyzer
from .string_analyzer import StringAnalyzer
from .permission_analyzer import PermissionAnalyzer
from .behavior_analyzer import BehaviorAnalyzer
from .network_analyzer import NetworkAnalyzer
from .malware_detector import MalwareDetector
from .risk_engine import RiskEngine
from .freellmapi import FreeLLMAPIClient, LLMBackend
from .advanced_static_analyzer import AdvancedStaticAnalyzer
from .androguard_engine import AndroguardEngine, get_androguard_engine
from .apkid_engine import APKiDEngine, get_apkid_engine
from .config_manager import get_config
from .cache_manager import get_cache
from .incremental_analyzer import get_incremental_analyzer
from .rea_analyzer import REAAnalyzer
from .utils import run_command, calculate_sha256, safe_extract_zip, ProgressTracker
from .logging_setup import configure_logging, get_module_logger, ScanContext
from .ai.agent_base import create_agent_manager
from .ai.evidence_repository import get_evidence_repository, EvidenceRepository
from .ai.rag_engine import get_rag_engine

# Forensics modules
from .forensics import (
    CaseManager, ForensicCase, CaseStatus,
    EvidenceIntegrityManager, HashAlgorithm,
    TimelineReconstructor, TimelineEvent,
    ForensicArtifactExtractor, ExtractedArtifact,
    ForensicReporter, ReportTemplate,
    AuditLogger, AuditEvent, AuditLevel,
    ForensicStandardsManager,
    EvidenceContainer, ContainerFormat,
    get_case_manager, get_timeline_reconstructor,
    get_artifact_extractor, get_forensic_reporter,
    get_audit_logger, get_standards_manager,
    get_evidence_container,
)


class APKScanner:
    def __init__(self, config: Dict[str, Any] = None, progress_callback: Callable = None, config_path: str = None):
        # Load configuration using ConfigManager
        self.config_manager = get_config(config_path)
        self.config = self.config_manager.get_all()

        # Override with passed config if provided
        if config:
            self._merge_config(self.config, config)

        # Configure structured logging
        logging_config = self.config.get("logging", {})
        configure_logging(
            level=logging_config.get("level", "INFO"),
            json_output=logging_config.get("json_output", False),
            include_timestamp=logging_config.get("include_timestamp", True)
        )
        self.logger = get_module_logger("scanner")

        self.progress_callback = progress_callback
        self.tracker = ProgressTracker(progress_callback)

        # Get config sections
        analysis_config = self.config.get("analysis", {})
        timeouts = self.config.get("timeouts", {})
        limits = self.config.get("limits", {})
        ollama_config = self.config.get("ollama", {})
        tools_config = self.config.get("tools", {})

        # Initialize analyzers with config
        self.archive_analyzer = ArchiveAnalyzer(
            max_extract_mb=analysis_config.get("max_total_extract_mb", 500),
            max_file_mb=analysis_config.get("max_file_size_mb", 100)
        )
        self.manifest_analyzer = ManifestAnalyzer(
            config=tools_config,
            max_file_mb=analysis_config.get("max_file_size_mb", 100)
        )
        self.dex_analyzer = DexAnalyzer(
            config=tools_config,
            max_file_mb=analysis_config.get("max_dex_size_mb", 50)
        )
        self.jadx_engine = JadxEngine(tools_config)
        self.apktool_engine = ApktoolEngine(tools_config)
        self.native_analyzer = NativeAnalyzer()
        self.string_analyzer = StringAnalyzer(
            min_length=analysis_config.get("min_string_length", 5)
        )
        self.permission_analyzer = PermissionAnalyzer()
        self.behavior_analyzer = BehaviorAnalyzer()
        self.network_analyzer = NetworkAnalyzer()
        self.malware_detector = MalwareDetector()
        self.risk_engine = RiskEngine()
        self.ollama_client = FreeLLMAPIClient(self.config)
        self.advanced_static_analyzer = AdvancedStaticAnalyzer(self.config)
        self.androguard_engine = get_androguard_engine(self.config)
        self.apkid_engine = get_apkid_engine(self.config)

        # Initialize REA analyzer for enhanced reverse engineering
        self.rea_analyzer = REAAnalyzer(self.config)

        # Initialize Forensics modules
        forensics_config = self.config.get("forensics", {})
        self.case_manager = get_case_manager(self.config, forensics_config.get("cases_dir", "./forensic_cases"))
        self.timeline = get_timeline_reconstructor(self.config)
        self.artifact_extractor = get_artifact_extractor(self.config, forensics_config.get("artifacts_dir", "./extracted_artifacts"))
        self.forensic_reporter = get_forensic_reporter(self.config, self.case_manager, self.timeline, self.artifact_extractor)
        self.audit_logger = get_audit_logger(self.config, forensics_config.get("audit_dir", "./audit_logs"))
        self.standards_manager = get_standards_manager()
        self.evidence_container = get_evidence_container(ContainerFormat.CUSTOM)

        # Initialize cache manager
        self.cache = get_cache(config_path)

        # Parallel execution config
        parallel_config = self.config.get("scanner", {}).get("parallel_stages", {})
        self.parallel_enabled = parallel_config.get("enabled", False)
        self.max_workers = parallel_config.get("max_workers", 4)
        self.parallel_groups = parallel_config.get("parallel_groups", [
            ["dex", "jadx", "smali"],
            ["native", "strings"],
            ["permissions", "behavior", "network"]
        ])

        # Thread pool for parallel execution
        self._executor = None

        # Initialize incremental analyzer
        self.incremental = get_incremental_analyzer(config_path)

        # Initialize AI components for multi-agent pipeline
        self.evidence_repo = get_evidence_repository(self.config)
        self.rag_engine = get_rag_engine(self.config)
        self.agent_manager = create_agent_manager(
            config=self.config,
            evidence_repo=self.evidence_repo,
            ollama_client=self.ollama_client,
            rag_engine=self.rag_engine,
        )

        # Store config values for use in scan
        self.stage_weights = self.config.get("scanner", {}).get("stage_weights", {})
        self.default_stage_weights = {
            "archive": 5, "extract": 10, "manifest": 20, "dex": 30, "jadx": 40,
            "smali": 50, "native": 60, "jni": 65, "rea": 67, "strings": 70, "permissions": 75,
            "behavior": 80, "network": 85, "malware": 90, "risk": 95, "ai": 98, "complete": 100
        }

        # State
        self.extract_dir = None
        self.apk_path = None
        self.cancelled = False

    def _merge_config(self, base: Dict, override: Dict):
        """Recursively merge override config into base."""
        for key, value in override.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                self._merge_config(base[key], value)
            else:
                base[key] = value

    def _get_stage_percent(self, stage: str) -> int:
        """Get progress percentage for a stage from config."""
        return self.stage_weights.get(stage, self.default_stage_weights.get(stage, 0))

    def _update_progress(self, stage: str, percent: int = None, message: str = ""):
        """Update progress via callback."""
        if percent is None:
            percent = self._get_stage_percent(stage)
        if self.progress_callback:
            self.progress_callback(stage, percent, message)
        self.tracker.update(stage, percent, message)

    def _get_executor(self):
        """Get or create thread pool executor."""
        if self._executor is None and self.parallel_enabled:
            self._executor = concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers)
        return self._executor

    def _shutdown_executor(self):
        """Shutdown thread pool executor."""
        if self._executor:
            self._executor.shutdown(wait=True)
            self._executor = None

    def _run_parallel_group(self, group: List[str], context: Dict) -> Dict[str, Any]:
        """Run a group of stages in parallel."""
        executor = self._get_executor()
        if not executor:
            # Sequential fallback
            results = {}
            for stage in group:
                stage_result = self._run_stage(stage, context)
                # Merge stage result keys into results (don't use stage name as key)
                if isinstance(stage_result, dict):
                    results.update(stage_result)
                else:
                    results[stage] = stage_result
            return results

        futures = {}
        for stage in group:
            future = executor.submit(self._run_stage, stage, context)
            futures[stage] = future

        results = {}
        for stage, future in futures.items():
            try:
                stage_result = future.result()
                # Merge stage result keys into results (don't use stage name as key)
                if isinstance(stage_result, dict):
                    results.update(stage_result)
                else:
                    results[stage] = stage_result
            except Exception as e:
                results[stage] = {"error": str(e)}

        return results

    def _run_stage(self, stage: str, context: Dict) -> Dict[str, Any]:
        """Run a single analysis stage."""
        apk_path = context["apk_path"]
        extract_dir = context["extract_dir"]
        result = context.get("result", {})

        if stage == "dex":
            return {"dex": self.dex_analyzer.analyze(apk_path, extract_dir)}
        elif stage == "jadx":
            return {"java": self.jadx_engine.decompile_apk(apk_path, extract_dir)}
        elif stage == "smali":
            return {"smali": self.apktool_engine.decode(apk_path, extract_dir)}
        elif stage == "native":
            return {"native": self.native_analyzer.analyze(extract_dir)}
        elif stage == "strings":
            return {"strings": self.string_analyzer.analyze(extract_dir)}
        elif stage == "permissions":
            perms = result.get("permissions", [])
            return {"permission_analysis": self.permission_analyzer.analyze(perms),
                    "permissions": perms}  # Preserve permissions list
        elif stage == "behavior":
            strings_result = result.get("strings", {})
            manifest_result = result.get("manifest", {})
            java_classes = result.get("java", {}).get("classes", [])
            native_libs = result.get("native", {}).get("libraries", [])
            return {"behavior": self.behavior_analyzer.analyze(
                result.get("raw_findings", []),
                strings_result.get("all_strings", []),
                manifest_result,
                java_classes,
                native_libs
            )}
        elif stage == "network":
            strings_result = result.get("strings", {})
            manifest_result = result.get("manifest", {})
            java_classes = result.get("java", {}).get("classes", [])
            native_libs = result.get("native", {}).get("libraries", [])
            return {"network": self.network_analyzer.analyze(
                strings_result.get("all_strings", []),
                manifest_result,
                java_classes,
                native_libs,
                strings_result.get("decoded_strings", [])
            )}
        else:
            return {"error": f"Unknown stage: {stage}"}

    def _configure_ai_backend(self, backend: str) -> None:
        """Configure FreeLLMAPIClient based on selected backend."""
        if backend == "auto":
            # Default: FreeLLMAPI -> Ollama -> Rule-based
            self.ollama_client.llm_config.fallback_order = [
                LLMBackend.FREELLM_API,
                LLMBackend.OLLAMA,
                LLMBackend.RULE_BASED
            ]
        elif backend == "freellmapi":
            self.ollama_client.llm_config.fallback_order = [
                LLMBackend.FREELLM_API,
                LLMBackend.RULE_BASED
            ]
        elif backend == "ollama":
            self.ollama_client.llm_config.fallback_order = [
                LLMBackend.OLLAMA,
                LLMBackend.RULE_BASED
            ]
        elif backend == "rule_based":
            self.ollama_client.llm_config.fallback_order = [
                LLMBackend.RULE_BASED
            ]
        elif backend == "disabled":
            self.ollama_client.no_ai_mode = True
            self.ollama_client.llm_config.fallback_order = [
                LLMBackend.RULE_BASED
            ]

    def scan(self, apk_path: str, no_ai: bool = False) -> Dict[str, Any]:
        """Perform complete APK scan."""
        self.apk_path = Path(apk_path)
        self.cancelled = False

        # Configure AI backend based on config
        ai_backend = self.config.get("ai_backend", "auto")
        self._configure_ai_backend(ai_backend)

        if no_ai:
            self.ollama_client.no_ai_mode = True

        # Generate scan ID for correlation
        scan_id = str(uuid.uuid4())[:8]

        # Initialize result structure
        result = {
            "scan_id": scan_id,
            "apk_path": str(self.apk_path),
            "scan_time": datetime.now().isoformat(),
            "sha256": "",
            "manifest": {},
            "permissions": [],
            "dex": {},
            "java": {},
            "smali": {},
            "native": {},
            "jni": {},
            "strings": {},
            "behavior": {},
            "network": {},
            "malware": {},
            "risk": {},
            "ai_analysis": {},
            "errors": [],
            "warnings": []
        }

        # Use structured logging context
        with ScanContext(scan_id, str(self.apk_path)) as scan_ctx:
            try:
                self.logger.info("scan_started", scan_id=scan_id, apk=str(self.apk_path))

                # Stage 1: Archive analysis & SHA256
                self._update_progress("archive", message="Analyzing APK archive...")
                result["sha256"] = calculate_sha256(self.apk_path)
                archive_result = self.archive_analyzer.analyze(self.apk_path)
                result["archive"] = archive_result
                if archive_result.get("errors"):
                    result["errors"].extend(archive_result["errors"])
                if archive_result.get("warnings"):
                    result["warnings"].extend(archive_result["warnings"])

                if self.cancelled:
                    return result
    
                # Stage 2: Extract APK
                self._update_progress("extract", message="Extracting APK...")
                self.extract_dir = self._extract_apk()
                if not self.extract_dir:
                    result["errors"].append("Failed to extract APK")
                    return result
    
                if self.cancelled:
                    return result
    
                # Stage 3: Manifest analysis
                self._update_progress("manifest", message="Analyzing AndroidManifest.xml...")
                manifest_result = self.manifest_analyzer.analyze(self.apk_path, self.extract_dir)
                result["manifest"] = manifest_result
                # Get permissions from either 'permissions' (Apktool) or 'uses_permissions' (binary XML fallback)
                result["permissions"] = manifest_result.get("permissions", []) or manifest_result.get("uses_permissions", [])
    
                # Stage 3b: Androguard analysis (enhanced APK parsing)
                self._update_progress("androguard", message="Running Androguard analysis...")
                androguard_result = self.androguard_engine.analyze_apk(self.apk_path, self.extract_dir)
                result["androguard"] = androguard_result
                # Merge Androguard findings
                if androguard_result.get("findings"):
                    result.setdefault("raw_findings", []).extend(androguard_result["findings"])
                # Enhance permissions with Androguard data (merge, don't replace)
                if androguard_result.get("permissions"):
                    # Androguard returns list of dicts with "name" key; extract names
                    ag_perms = [p.get("name", "") for p in androguard_result["permissions"] if p.get("name")]
                    # Merge with existing, avoiding duplicates
                    existing = set(result.get("permissions", []))
                    for p in ag_perms:
                        if p not in existing:
                            result["permissions"].append(p)
                # Enhance components
                if androguard_result.get("components"):
                    result["components"] = androguard_result["components"]
                # Enhance certificates
                if androguard_result.get("certificates"):
                    result["certificates"] = androguard_result["certificates"]
    
                # Stage 3c: APKiD analysis (packer/obfuscator detection)
                self._update_progress("apkid", message="Running APKiD analysis...")
                apkid_result = self.apkid_engine.analyze(self.apk_path)
                result["apkid"] = apkid_result
                if apkid_result.get("raw_matches"):
                    result.setdefault("raw_findings", []).extend(apkid_result["raw_matches"])
    
                if self.cancelled:
                    return result
    
                # Build context for parallel execution
                context = {
                    "apk_path": self.apk_path,
                    "extract_dir": self.extract_dir,
                    "result": result
                }
    
                # Stage 4-6: DEX, JADX, Smali (parallel group 1)
                self._update_progress("dex", message="Analyzing DEX files...")
                self._update_progress("jadx", message="Decompiling with JADX...")
                self._update_progress("smali", message="Analyzing Smali with Apktool...")
    
                parallel_results = self._run_parallel_group(["dex", "jadx", "smali"], context)
                result.update(parallel_results)
                dex_result = result.get("dex", {})
                jadx_result = result.get("java", {})
                apktool_result = result.get("smali", {})
    
                if self.cancelled:
                    return result
    
                # Stage 7: Advanced Static Analysis (call graphs, taint, CFG, YARA)
                self._update_progress("advanced_static", message="Running advanced static analysis...")
                advanced_static_result = self.advanced_static_analyzer.analyze(
                    dex_analysis=dex_result,
                    extracted_dir=self.extract_dir,
                    apk_path=self.apk_path,
                    strings=result.get("strings", {}).get("all_strings", [])
                )
                result["advanced_static"] = advanced_static_result
    
                if self.cancelled:
                    return result
    
                # Stage 8-9: Native, Strings (parallel group 2)
                self._update_progress("native", message="Analyzing native libraries...")
                self._update_progress("strings", message="Analyzing strings...")
    
                parallel_results = self._run_parallel_group(["native", "strings"], context)
                result.update(parallel_results)
                native_result = result.get("native", {})
                strings_result = result.get("strings", {})
    
                if self.cancelled:
                    return result
    
                # Stage 8: JNI analysis (depends on native + jadx)
                self._update_progress("jni", message="Analyzing JNI...")
                jni_result = self._analyze_jni(native_result, jadx_result)
                result["jni"] = jni_result

                if self.cancelled:
                    return result

                # Stage 8b: REA Analysis (enhanced reverse engineering for native libs)
                rea_enabled = self.config.get("rea", {}).get("enabled", True)
                rea_available = self.rea_analyzer.is_available()
                self.logger.info("rea_stage_check", rea_enabled=rea_enabled, rea_available=rea_available)
                if rea_enabled and rea_available:
                    self._update_progress("rea", message="Running REA enhanced reverse engineering...")
                    rea_result = self.rea_analyzer.analyze_apk_with_rea(str(self.apk_path), str(self.extract_dir))
                    result["rea"] = rea_result
                    if rea_result.get("errors"):
                        result["errors"].extend(rea_result["errors"])
                    if rea_result.get("warnings"):
                        result["warnings"].extend(rea_result["warnings"])
                    self.logger.info("rea_stage_completed", native_libs=len(rea_result.get("native_libraries", [])))
                else:
                    self.logger.warning("rea_stage_skipped", rea_enabled=rea_enabled, rea_available=rea_available)

                if self.cancelled:
                    return result

                # Update context for next group
                context["result"] = result
    
                # Stage 10-12: Permissions, Behavior, Network (parallel group 3)
                self._update_progress("permissions", message="Analyzing permissions...")
                self._update_progress("behavior", message="Analyzing behaviors...")
                self._update_progress("network", message="Analyzing network IOCs...")
    
                parallel_results = self._run_parallel_group(["permissions", "behavior", "network"], context)
                result.update(parallel_results)
                perm_result = result.get("permission_analysis", {})
                behavior_result = result.get("behavior", {})
                network_result = result.get("network", {})
    
                if self.cancelled:
                    return result
    
                # Stage 13: Malware detection
                self._update_progress("malware", message="Running malware detection...")
                malware_result = self.malware_detector.detect({
                    "permissions": result["permissions"],
                    "behavior": behavior_result,
                    "network": network_result,
                    "strings": strings_result,
                    "manifest": manifest_result,
                    "native": native_result,
                    "dex": dex_result,
                    "raw_findings": result.get("raw_findings", [])
                })
                result["malware"] = malware_result
    
                if self.cancelled:
                    return result
    
                # Stage 14: Risk scoring
                self._update_progress("risk", message="Calculating risk score...")
                risk_result = self.risk_engine.calculate({
                    "permissions": result["permissions"],
                    "behavior": behavior_result,
                    "network": network_result,
                    "strings": strings_result,
                    "manifest": manifest_result,
                    "native": native_result,
                    "malware": malware_result,
                    "permission_analysis": perm_result
                })
                result["risk"] = risk_result
    
                if self.cancelled:
                    return result
    
                # Stage 15: AI Analysis - Multi-Agent Pipeline
                self._update_progress("ai", message="Running multi-agent AI analysis...")
                ai_result = self._run_multi_agent_pipeline(result)
                result["ai_analysis"] = ai_result

                # Stage 16: Forensics - Case Management & Evidence Collection
                forensics_enabled = self.config.get("forensics", {}).get("enabled", True)
                if forensics_enabled:
                    self._update_progress("forensics_case", message="Creating forensic case...")
                    forensics_result = self._run_forensics_pipeline(result)
                    result["forensics"] = forensics_result
                    if forensics_result.get("errors"):
                        result["errors"].extend(forensics_result["errors"])
                    if forensics_result.get("warnings"):
                        result["warnings"].extend(forensics_result["warnings"])

                self._update_progress("complete", message="Scan complete!")

            except Exception as e:
                result["errors"].append(f"Scan error: {str(e)}")
                import traceback
                result["errors"].append(traceback.format_exc())
                self.logger.error("scan_failed", scan_id=scan_id, error=str(e))
            finally:
                # Cleanup
                if self.extract_dir and self.extract_dir.exists():
                    try:
                        shutil.rmtree(self.extract_dir)
                    except Exception:
                        pass
                # Shutdown executor
                self._shutdown_executor()

        return result

    def _run_multi_agent_pipeline(self, result: Dict[str, Any]) -> Dict[str, Any]:
        """Run the full 8-agent investigation pipeline."""
        try:
            from .ai.agent_base import AgentTask, AgentID
            import uuid
            from datetime import datetime

            scan_id = result.get("scan_id", str(uuid.uuid4())[:8])

            # Create tasks for each agent with dependencies
            tasks = []

            # Agent 1: APK Intelligence (no dependencies)
            task1 = AgentTask(
                task_id=str(uuid.uuid4()),
                agent_id=AgentID.APK_INTELLIGENCE.value,
                description="Analyze APK architecture and metadata",
                input_data={
                    "apk_path": result.get("apk_path"),
                    "sha256": result.get("sha256"),
                    "manifest": result.get("manifest", {}),
                    "archive": result.get("archive", {}),
                    "androguard": result.get("androguard", {}),
                    "apkid": result.get("apkid", {}),
                    "certificates": result.get("certificates", {}),
                },
                priority=10,
            )
            tasks.append(task1)

            # Agent 2: Static Analysis (depends on 1)
            task2 = AgentTask(
                task_id=str(uuid.uuid4()),
                agent_id=AgentID.STATIC_ANALYSIS.value,
                description="Analyze manifest, permissions, DEX, and code",
                input_data={
                    "manifest": result.get("manifest", {}),
                    "permissions": result.get("permissions", []),
                    "dex": result.get("dex", {}),
                    "java": result.get("java", {}),
                    "smali": result.get("smali", {}),
                    "advanced_static": result.get("advanced_static", {}),
                    "raw_findings": result.get("raw_findings", []),
                },
                dependencies=[task1.task_id],
                priority=9,
            )
            tasks.append(task2)

            # Agent 3: Reverse Engineering (depends on 1, 2)
            task3 = AgentTask(
                task_id=str(uuid.uuid4()),
                agent_id=AgentID.REVERSE_ENGINEERING.value,
                description="Investigate obfuscation, reflection, dynamic loading",
                input_data={
                    "java": result.get("java", {}),
                    "smali": result.get("smali", {}),
                    "dex": result.get("dex", {}),
                    "advanced_static": result.get("advanced_static", {}),
                    "native": result.get("native", {}),
                    "jni": result.get("jni", {}),
                    "apkid": result.get("apkid", {}),
                },
                dependencies=[task1.task_id, task2.task_id],
                priority=8,
            )
            tasks.append(task3)

            # Agent 4: Behavioral Analysis (depends on 1, 2)
            task4 = AgentTask(
                task_id=str(uuid.uuid4()),
                agent_id=AgentID.BEHAVIORAL.value,
                description="Analyze runtime behaviors and suspicious patterns",
                input_data={
                    "behavior": result.get("behavior", {}),
                    "manifest": result.get("manifest", {}),
                    "permissions": result.get("permissions", []),
                    "strings": result.get("strings", {}),
                    "network": result.get("network", {}),
                    "native": result.get("native", {}),
                },
                dependencies=[task1.task_id, task2.task_id],
                priority=7,
            )
            tasks.append(task4)

            # Agent 5: Network Intelligence (depends on 1, 2, 4)
            task5 = AgentTask(
                task_id=str(uuid.uuid4()),
                agent_id=AgentID.NETWORK_INTELLIGENCE.value,
                description="Extract and analyze network IOCs and C2 infrastructure",
                input_data={
                    "network": result.get("network", {}),
                    "strings": result.get("strings", {}),
                    "behavior": result.get("behavior", {}),
                    "manifest": result.get("manifest", {}),
                    "java": result.get("java", {}),
                },
                dependencies=[task1.task_id, task2.task_id, task4.task_id],
                priority=6,
            )
            tasks.append(task5)

            # Agent 6: Threat Researcher (depends on 1, 2, 3, 4, 5)
            task6 = AgentTask(
                task_id=str(uuid.uuid4()),
                agent_id=AgentID.THREAT_RESEARCHER.value,
                description="Compare with known malware, attribute family, calculate risk",
                input_data={
                    "malware": result.get("malware", {}),
                    "risk": result.get("risk", {}),
                    "androguard": result.get("androguard", {}),
                    "apkid": result.get("apkid", {}),
                    "advanced_static": result.get("advanced_static", {}),
                    "network": result.get("network", {}),
                    "strings": result.get("strings", {}),
                    "manifest": result.get("manifest", {}),
                },
                dependencies=[task1.task_id, task2.task_id, task3.task_id, task4.task_id, task5.task_id],
                priority=5,
            )
            tasks.append(task6)

            # Agent 7: Verification (depends on 2, 3, 4, 5, 6)
            task7 = AgentTask(
                task_id=str(uuid.uuid4()),
                agent_id=AgentID.VERIFICATION.value,
                description="Independently verify all findings, refute false positives",
                input_data={},
                dependencies=[task2.task_id, task3.task_id, task4.task_id, task5.task_id, task6.task_id],
                priority=4,
            )
            tasks.append(task7)

            # Agent 8: Senior Analyst (depends on all)
            task8 = AgentTask(
                task_id=str(uuid.uuid4()),
                agent_id=AgentID.SENIOR_ANALYST.value,
                description="Synthesize final assessment, build timeline, produce report",
                input_data={},
                dependencies=[task1.task_id, task2.task_id, task3.task_id, task4.task_id, task5.task_id, task6.task_id, task7.task_id],
                priority=3,
            )
            tasks.append(task8)

            # Execute pipeline
            self.logger.info("multi_agent_pipeline_started", scan_id=scan_id, agents=len(tasks))
            pipeline_results = self.agent_manager.execute_pipeline(tasks)

            # Collect all evidence
            all_evidence = self.agent_manager.get_all_evidence()
            verified_evidence = [e for e in all_evidence if e.verification_status == "verified"]

            # Build final result
            agent_findings = {}
            for agent_id, agent in self.agent_manager.agents.items():
                agent_evidence = self.evidence_repo.get_by_agent(agent_id)
                agent_findings[agent_id] = {
                    "evidence_count": len(agent_evidence),
                    "verified_count": len([e for e in agent_evidence if e.verification_status == "verified"]),
                    "evidence": [e.to_dict() for e in agent_evidence],
                }

            final_result = {
                "success": True,
                "scan_id": scan_id,
                "pipeline_completed": True,
                "agents_executed": len(pipeline_results),
                "total_evidence": len(all_evidence),
                "verified_evidence": len(verified_evidence),
                "agent_findings": agent_findings,
                "evidence_summary": self.evidence_repo.get_statistics(),
            }

            # Extract senior analyst summary
            senior_agent = self.agent_manager.get_agent("senior_analyst")
            if senior_agent and senior_agent.results:
                latest = senior_agent.results[-1]
                final_result["senior_assessment"] = latest.findings

            # Extract threat researcher risk
            threat_agent = self.agent_manager.get_agent("threat_researcher")
            if threat_agent and threat_agent.results:
                latest = threat_agent.results[-1]
                final_result["threat_research"] = latest.findings

            # Extract verification results
            verify_agent = self.agent_manager.get_agent("verification")
            if verify_agent and verify_agent.results:
                latest = verify_agent.results[-1]
                final_result["verification"] = latest.findings

            self.logger.info("multi_agent_pipeline_completed", scan_id=scan_id,
                           total_evidence=len(all_evidence), verified=len(verified_evidence))

            return final_result

        except Exception as e:
            self.logger.error("multi_agent_pipeline_failed", scan_id=result.get("scan_id"), error=str(e))
            import traceback
            return {
                "success": False,
                "error": str(e),
                "traceback": traceback.format_exc(),
                "fallback": self.ollama_client._no_ai_analysis(result) if self.ollama_client else {}
            }

    def _run_forensics_pipeline(self, result: Dict[str, Any]) -> Dict[str, Any]:
        """Run the forensics pipeline: case creation, evidence collection, timeline, artifacts, reporting."""
        try:
            scan_id = result.get("scan_id", "unknown")
            apk_path = result.get("apk_path", "")
            sha256 = result.get("sha256", "")

            self.logger.info("forensics_pipeline_started", scan_id=scan_id)

            # Create forensic case
            case_name = f"APK Analysis - {Path(apk_path).name}"
            case_description = f"Automated forensic analysis of {Path(apk_path).name} (SHA256: {sha256[:16]}...)"

            case = self.case_manager.create_case(
                name=case_name,
                description=case_description,
                created_by="APKStudioAI Scanner",
                examiner="APKStudioAI 2.1",
                examiner_organization="APKStudioAI",
                priority="normal",
                classification="confidential",
                tags=["automated", "android", "malware_analysis"],
            )

            # Log case creation in audit
            self.audit_logger.log(
                event_type="case_created",
                level="info",
                actor="APKStudioAI Scanner",
                actor_role="system",
                action="create",
                resource_type="case",
                resource_id=case.case_id,
                details={"case_name": case_name, "apk_path": apk_path, "sha256": sha256},
            )

            # Add APK as primary evidence
            apk_evidence = self.case_manager.add_evidence(
                case_id=case.case_id,
                name=Path(apk_path).name,
                description=f"Original APK file: {Path(apk_path).name}",
                evidence_type="apk_file",
                file_path=apk_path,
                collected_by="APKStudioAI Scanner",
                collection_location="automated_scan",
                collection_method="direct_acquisition",
                tags=["primary", "apk", "original"],
                metadata={"sha256": sha256, "scan_id": scan_id},
            )

            # Extract artifacts from APK
            self._update_progress("forensics_extract", message="Extracting forensic artifacts...")
            artifacts = self.artifact_extractor.extract_apk(apk_path)

            # Add artifacts as evidence
            for artifact in artifacts:
                if artifact.artifact_type in ["dex", "native_library", "manifest", "certificates", "resources", "strings"]:
                    self.case_manager.add_evidence(
                        case_id=case.case_id,
                        name=artifact.name,
                        description=f"Extracted {artifact.artifact_type}: {artifact.name}",
                        evidence_type=artifact.artifact_type,
                        file_path=artifact.extracted_path,
                        collected_by="APKStudioAI Scanner",
                        collection_location="extracted_from_apk",
                        collection_method="automated_extraction",
                        tags=["extracted", artifact.artifact_type],
                        metadata={
                            "artifact_id": artifact.artifact_id,
                            "source_path": artifact.source_path,
                            "size_bytes": artifact.size_bytes,
                            "hashes": artifact.hashes,
                            "mime_type": artifact.mime_type,
                            **artifact.metadata,
                        },
                    )

            # Build timeline from analysis results
            self._update_progress("forensics_timeline", message="Reconstructing timeline...")
            self._build_forensic_timeline(result, case.case_id)

            # Verify evidence integrity
            self._update_progress("forensics_verify", message="Verifying evidence integrity...")
            self._verify_evidence_integrity(case.case_id)

            # Run standards compliance check
            self._update_progress("forensics_standards", message="Checking forensic standards compliance...")
            compliance_result = self._check_forensic_standards(case.case_id)

            # Generate forensic report
            self._update_progress("forensics_report", message="Generating forensic report...")
            report_result = self._generate_forensic_report(case.case_id)

            # Create evidence container
            self._update_progress("forensics_container", message="Creating evidence container...")
            container_result = self._create_evidence_container(case.case_id)

            # Finalize case
            self.case_manager.update_case(case.case_id, {
                "analysis_results": {
                    "scan_id": scan_id,
                    "apk_path": apk_path,
                    "sha256": sha256,
                    "risk_score": result.get("risk", {}).get("score", 0),
                    "risk_level": result.get("risk", {}).get("risk_level", "UNKNOWN"),
                    "malware_detections": len(result.get("malware", {}).get("detections", [])),
                    "artifacts_extracted": len(artifacts),
                    "timeline_events": len(self.timeline.events),
                    "compliance_score": compliance_result.get("overall", {}).get("average_compliance_score", 0),
                }
            })

            self.logger.info("forensics_pipeline_completed", scan_id=scan_id, case_id=case.case_id)

            return {
                "success": True,
                "case_id": case.case_id,
                "case_number": case.case_number,
                "evidence_count": len(self.case_manager.get_case_evidence(case.case_id)),
                "artifacts_extracted": len(artifacts),
                "timeline_events": len(self.timeline.events),
                "compliance": compliance_result.get("overall", {}),
                "report_path": report_result.get("report_path", ""),
                "container_path": container_result.get("container_path", ""),
                "errors": [],
                "warnings": [],
            }

        except Exception as e:
            import traceback
            tb = traceback.format_exc()
            self.logger.error("forensics_pipeline_failed", scan_id=result.get("scan_id"), error=str(e), traceback=tb)
            return {
                "success": False,
                "error": str(e),
                "traceback": traceback.format_exc(),
                "errors": [str(e)],
                "warnings": [],
            }

    def _build_forensic_timeline(self, result: Dict[str, Any], case_id: str):
        """Build forensic timeline from analysis results."""
        from .forensics.timeline_reconstructor import (
            EventSource, EventCategory, EventSeverity,
            create_file_event, create_network_event, create_malware_event
        )
        from datetime import datetime, timezone

        scan_time = datetime.fromisoformat(result.get("scan_time", datetime.now(timezone.utc).isoformat()))

        # File system events (APK extraction)
        self.timeline.create_event(
            timestamp=scan_time,
            source=EventSource.FILE_SYSTEM.value,
            category=EventCategory.FILE_CREATED.value,
            severity=EventSeverity.INFORMATIONAL.value,
            title=f"APK Extracted: {Path(result.get('apk_path', '')).name}",
            description=f"APK extracted for analysis",
            details={"apk_path": result.get("apk_path"), "sha256": result.get("sha256")},
            tags=["extraction", "apk"],
            analyzer="archive_analyzer",
        )

        # Manifest events
        manifest = result.get("manifest", {})
        if manifest.get("package"):
            self.timeline.create_event(
                timestamp=scan_time,
                source=EventSource.APK_MANIFEST.value,
                category=EventCategory.CONFIGURATION_CHANGE.value,
                severity=EventSeverity.INFORMATIONAL.value,
                title=f"Package Identified: {manifest.get('package')}",
                description=f"Application package: {manifest.get('package')}, version: {manifest.get('version_name')}",
                details={"package": manifest.get("package"), "version": manifest.get("version_name")},
                tags=["manifest", "package"],
                analyzer="manifest_analyzer",
            )

        # Permissions events
        perm_analysis = result.get("permission_analysis", {})
        for level in ["critical", "high"]:
            for perm in perm_analysis.get("by_risk", {}).get(level, []):
                self.timeline.create_event(
                    timestamp=scan_time,
                    source=EventSource.PERMISSION_ANALYSIS.value,
                    category=EventCategory.PERMISSION_REQUESTED.value,
                    severity=EventSeverity.HIGH.value if level == "critical" else EventSeverity.MEDIUM.value,
                    title=f"High-Risk Permission: {perm.get('permission')}",
                    description=perm.get("description", ""),
                    details={"permission": perm.get("permission"), "risk_level": level, "capability": perm.get("capability")},
                    tags=["permission", level, "risk"],
                    mitre_techniques=perm.get("mitre", []),
                    confidence=80,
                    analyzer="permission_analyzer",
                )

        # Network IOCs
        network = result.get("network", {})
        for url in network.get("urls", [])[:20]:
            self.timeline.create_event(
                timestamp=scan_time,
                source=EventSource.NETWORK_ANALYSIS.value,
                category=EventCategory.NETWORK_HTTP.value,
                severity=EventSeverity.INFORMATIONAL.value,
                title=f"URL Found: {url[:80]}",
                description=f"URL extracted from strings: {url}",
                details={"url": url, "source": "string_analysis"},
                tags=["network", "url", "ioc"],
                analyzer="network_analyzer",
            )

        for domain in network.get("domains", [])[:20]:
            self.timeline.create_event(
                timestamp=scan_time,
                source=EventSource.NETWORK_ANALYSIS.value,
                category=EventCategory.NETWORK_DNS.value,
                severity=EventSeverity.INFORMATIONAL.value,
                title=f"Domain Found: {domain}",
                description=f"Domain extracted from strings",
                details={"domain": domain, "source": "string_analysis"},
                tags=["network", "domain", "ioc"],
                analyzer="network_analyzer",
            )

        # Malware detections
        malware = result.get("malware", {})
        for det in malware.get("detections", []):
            if det.get("confidence_score", 0) >= 50:
                severity_map = {
                    "confirmed": EventSeverity.CRITICAL,
                    "likely": EventSeverity.HIGH,
                    "possible": EventSeverity.MEDIUM,
                    "suspected": EventSeverity.LOW,
                }
                self.timeline.create_event(
                    timestamp=scan_time,
                    source=EventSource.MALWARE_DETECTION.value,
                    category=EventCategory.MALWARE_INDICATOR.value,
                    severity=severity_map.get(det.get("classification", ""), EventSeverity.MEDIUM).value,
                    title=f"Malware Detected: {det.get('category', '').upper()}",
                    description=f"{det.get('category')}: {det.get('classification')} ({det.get('confidence_score')}%) - {det.get('description', '')}",
                    details={"malware_family": det.get("category"), "classification": det.get("classification"), "confidence": det.get("confidence_score")},
                    tags=["malware", det.get("category", ""), det.get("classification", "")],
                    mitre_techniques=det.get("mitre_techniques", []),
                    confidence=det.get("confidence_score", 50),
                    analyzer="malware_detector",
                )

        # Native libraries
        native = result.get("native", {})
        for lib in native.get("libraries", []):
            self.timeline.create_event(
                timestamp=scan_time,
                source=EventSource.NATIVE_ANALYSIS.value,
                category=EventCategory.FILE_CREATED.value,
                severity=EventSeverity.INFORMATIONAL.value,
                title=f"Native Library: {lib.get('name')} ({lib.get('architecture')})",
                description=f"Native library found with {len(lib.get('native_methods', []))} JNI methods",
                details={"library": lib.get("name"), "arch": lib.get("architecture"), "jni_methods": len(lib.get("native_methods", []))},
                tags=["native", "elf", lib.get("architecture", "")],
                analyzer="native_analyzer",
            )

        # REA analysis events
        rea = result.get("rea", {})
        for pattern in rea.get("patterns", [])[:20]:
            severity_map = {"critical": EventSeverity.CRITICAL, "high": EventSeverity.HIGH, "medium": EventSeverity.MEDIUM, "low": EventSeverity.LOW}
            self.timeline.create_event(
                timestamp=scan_time,
                source=EventSource.REA_ANALYSIS.value,
                category=EventCategory.MALWARE_INDICATOR.value,
                severity=severity_map.get(pattern.get("severity", "low"), EventSeverity.MEDIUM).value,
                title=f"REA Pattern: {pattern.get('pattern')} ({pattern.get('severity')})",
                description=pattern.get("description", ""),
                details={"pattern": pattern.get("pattern"), "type": pattern.get("type"), "matches": pattern.get("matches"), "offsets": pattern.get("offsets", [])[:10]},
                tags=["rea", pattern.get("type", ""), pattern.get("severity", "")],
                confidence=80,
                analyzer="rea_analyzer",
            )

    def _verify_evidence_integrity(self, case_id: str):
        """Verify integrity of all evidence in case."""
        evidence_list = self.case_manager.get_case_evidence(case_id)

        for evidence in evidence_list:
            report = self.artifact_extractor.integrity_mgr.verify_file_detailed(
                evidence.file_path, evidence.hashes
            )

            # Log verification
            self.audit_logger.log(
                event_type="integrity_check_passed" if report.all_match and report.size_match else "integrity_check_failed",
                level="info" if report.all_match and report.size_match else "warning",
                actor="APKStudioAI Scanner",
                actor_role="system",
                action="verify",
                resource_type="evidence",
                resource_id=evidence.evidence_id,
                details={
                    "file": evidence.file_path,
                    "hashes_match": report.all_match,
                    "size_match": report.size_match,
                    "expected_hashes": evidence.hashes,
                    "calculated_hashes": report.calculated_hashes,
                },
                outcome="success" if report.all_match and report.size_match else "failure",
            )

    def _check_forensic_standards(self, case_id: str) -> Dict[str, Any]:
        """Check forensic standards compliance for case."""
        case = self.case_manager.get_case(case_id)
        evidence = self.case_manager.get_case_evidence(case_id)

        case_data = {
            "case": case.to_dict() if case else {},
            "evidence": [e.to_dict() for e in evidence],
            "timeline": [e.to_dict() for e in self.timeline.events],
            "artifacts": [a.to_dict() for a in self.artifact_extractor.artifacts.values()],
            "audit_log": [],  # Would include audit events
        }

        return self.standards_manager.check_all_compliance(case_data)

    def _generate_forensic_report(self, case_id: str) -> Dict[str, Any]:
        """Generate forensic report for case."""
        from .forensics.forensic_reporter import ReportTemplate, ReportFormat, ReportConfig

        report_config = ReportConfig(
            template=ReportTemplate.FULL_FORENSIC.value,
            format=ReportFormat.HTML.value,
            include_chain_of_custody=True,
            include_timeline=True,
            include_artifacts=True,
            include_iocs=True,
            include_mitre=True,
            include_recommendations=True,
            include_appendices=True,
            classification="CONFIDENTIAL",
            examiner_name="APKStudioAI 2.1",
            examiner_organization="APKStudioAI",
        )

        # Create reports directory for case
        reports_dir = Path("reports") / case_id
        reports_dir.mkdir(parents=True, exist_ok=True)

        report_path = str(reports_dir / f"forensic_report_{case_id}.html")

        success = self.forensic_reporter.generate_report(case_id, report_config, report_path)

        return {
            "success": success,
            "report_path": report_path if success else "",
            "template": report_config.template,
            "format": report_config.format,
        }

    def _create_evidence_container(self, case_id: str) -> Dict[str, Any]:
        """Create evidence container for case."""
        from .forensics.evidence_container import ContainerFormat, ContainerBuilder

        builder = ContainerBuilder(self.case_manager, self.artifact_extractor)

        containers_dir = Path("evidence_containers") / case_id
        containers_dir.mkdir(parents=True, exist_ok=True)

        container_path = str(containers_dir / f"evidence_{case_id}.aec")

        success = builder.create_case_container(
            case_id=case_id,
            output_path=container_path,
            format=ContainerFormat.CUSTOM,
            include_evidence=True,
            include_artifacts=True,
            include_reports=True,
            include_audit=True,
        )

        return {
            "success": success,
            "container_path": container_path if success else "",
            "format": ContainerFormat.CUSTOM.value,
        }

    def _extract_apk(self) -> Optional[Path]:
        """Extract APK to temporary directory."""
        try:
            temp_dir = Path(tempfile.mkdtemp(prefix="apkstudio_"))
            success = safe_extract_zip(
                self.apk_path, temp_dir,
                max_total_mb=self.config.get("analysis", {}).get("max_total_extract_mb", 500),
                max_file_mb=self.config.get("analysis", {}).get("max_file_size_mb", 100)
            )
            if success:
                return temp_dir
            else:
                shutil.rmtree(temp_dir, ignore_errors=True)
                return None
        except Exception:
            return None

    def _analyze_jni(self, native_result: Dict, jadx_result: Dict) -> Dict[str, Any]:
        """Analyze JNI for all native libraries."""
        jni_results = []
        java_classes = jadx_result.get("classes", [])

        for lib in native_result.get("libraries", []):
            lib_path = Path(lib.get("path", ""))
            if lib_path.exists():
                # Import JNIAnalyzer here to avoid circular imports
                from .jni_analyzer import JNIAnalyzer
                jni_analyzer = JNIAnalyzer()
                jni_result = jni_analyzer.analyze(lib_path, java_classes)
                jni_results.append(jni_result)

        return {"libraries": jni_results}

    def cancel(self):
        """Cancel ongoing scan."""
        self.cancelled = True

    def get_incremental_summary(self, apk_path: str) -> Dict[str, Any]:
        """Get summary of what would be scanned incrementally."""
        return self.incremental.get_scan_summary(Path(apk_path))

    def force_full_scan(self, apk_path: str = None):
        """Force a full scan by bumping analysis version."""
        self.incremental.analyzer.bump_version()
        if apk_path:
            self.incremental.analyzer.clear_file(Path(apk_path))

    def batch_scan(self, directory: str, no_ai: bool = False) -> List[Dict[str, Any]]:
        """Scan all APKs in a directory."""
        results = []
        apk_files = list(Path(directory).rglob("*.apk"))

        for i, apk_file in enumerate(apk_files):
            self._update_progress("batch", int((i / len(apk_files)) * 100),
                                  f"Scanning {apk_file.name} ({i+1}/{len(apk_files)})")
            result = self.scan(str(apk_file), no_ai=no_ai)
            results.append(result)

        return results


def scan_apk(apk_path: str, config: Dict = None, no_ai: bool = False, progress_callback=None) -> Dict[str, Any]:
    """Convenience function to scan an APK file.

    Args:
        apk_path: Path to the APK file
        config: Configuration dictionary (optional)
        no_ai: Disable AI analysis
        progress_callback: Optional callback for progress updates

    Returns:
        Analysis results dictionary
    """
    scanner = APKScanner(config=config, progress_callback=progress_callback)
    return scanner.scan(apk_path, no_ai=no_ai)


def main():
    """CLI entry point."""
    import argparse
    parser = argparse.ArgumentParser(description="APKStudioAI 2.1 - Android Malware Analyzer")
    parser.add_argument("apk", nargs="?", help="Path to APK file")
    parser.add_argument("--batch", help="Batch scan directory")
    parser.add_argument("--no-ai", action="store_true", help="Disable AI analysis")
    parser.add_argument("--json", action="store_true", help="Output JSON")
    parser.add_argument("--output", help="Output file path")
    parser.add_argument("--config", help="Config file path")

    args = parser.parse_args()

    # Progress callback
    def progress(stage, percent, message):
        print(f"[{percent:3d}%] {stage}: {message}")

    scanner = APKScanner(config_path=args.config, progress_callback=progress)

    if args.batch:
        results = scanner.batch_scan(args.batch, no_ai=args.no_ai)
        output_data = {"batch_results": results}
    elif args.apk:
        result = scanner.scan(args.apk, no_ai=args.no_ai)
        output_data = result
    else:
        parser.print_help()
        return

    # Output
    if args.json:
        output = json.dumps(output_data, indent=2, default=str)
    else:
        output = format_text_output(output_data)

    if args.output:
        with open(args.output, "w") as f:
            f.write(output)
        print(f"Results saved to {args.output}")
    else:
        print(output)


def format_text_output(data: Dict) -> str:
    """Format results as text."""
    lines = []
    lines.append("=" * 60)
    lines.append("APKStudioAI 2.1 - Analysis Report")
    lines.append("=" * 60)
    lines.append(f"APK: {data.get('apk_path', 'N/A')}")
    lines.append(f"SHA256: {data.get('sha256', 'N/A')}")
    lines.append(f"Scan Time: {data.get('scan_time', 'N/A')}")
    lines.append("")

    # Risk
    risk = data.get("risk", {})
    lines.append(f"RISK SCORE: {risk.get('score', 0)}/100 ({risk.get('risk_level', 'UNKNOWN')})")
    lines.append(f"Summary: {risk.get('summary', {}).get('description', 'N/A')}")
    lines.append("")

    # Malware
    malware = data.get("malware", {})
    detections = malware.get("detections", [])
    if detections:
        lines.append("MALWARE DETECTIONS:")
        for det in detections[:5]:
            lines.append(f"  - {det['category'].upper()}: {det['classification']} ({det['confidence_score']}%)")
    else:
        lines.append("MALWARE DETECTIONS: None")
    lines.append("")

    # Permissions
    perm = data.get("permission_analysis", {})
    lines.append(f"PERMISSIONS: {perm.get('total_count', 0)} total")
    for level in ["critical", "high", "medium", "low"]:
        count = len(perm.get("by_risk", {}).get(level, []))
        if count:
            lines.append(f"  {level.capitalize()}: {count}")
    lines.append("")

    # Network
    net = data.get("network", {})
    lines.append(f"NETWORK IOCs: {len(net.get('urls', []))} URLs, {len(net.get('domains', []))} domains")
    if net.get("telegram_bots"):
        lines.append(f"  Telegram bots: {len(net['telegram_bots'])}")
    if net.get("c2_config"):
        lines.append(f"  C2 configs: {len(net['c2_config'])}")
    lines.append("")

    # Native
    native = data.get("native", {})
    lines.append(f"NATIVE LIBS: {len(native.get('libraries', []))}")
    for lib in native.get("libraries", [])[:3]:
        lines.append(f"  - {lib.get('name', 'unknown')}: {len(lib.get('native_methods', []))} JNI methods")
    lines.append("")

    # AI Analysis
    ai = data.get("ai_analysis", {})
    if ai.get("success"):
        analysis = ai.get("analysis", {})
        lines.append("AI ANALYSIS:")
        lines.append(f"  Category: {analysis.get('malware_category', 'unknown')}")
        lines.append(f"  Confidence: {analysis.get('confidence', 0)}%")
        lines.append(f"  Risk: {analysis.get('risk_level', 'UNKNOWN')}")
        lines.append(f"  Summary: {analysis.get('summary', 'N/A')}")
    else:
        lines.append(f"AI ANALYSIS: {ai.get('error', 'Not available')}")

    # REA Analysis
    rea = data.get("rea", {})
    if rea.get("enabled"):
        lines.append("")
        lines.append("REA ANALYSIS (Enhanced Reverse Engineering):")
        native_libs = rea.get("native_libraries", [])
        lines.append(f"  Native Libraries Analyzed: {len(native_libs)}")
        for lib in native_libs:
            lines.append(f"  - {lib.get('name', 'unknown')} ({lib.get('arch', 'unknown')})")

        patterns = rea.get("patterns", [])
        if patterns:
            lines.append(f"  Suspicious Patterns Found: {len(patterns)}")
            for p in patterns[:10]:
                lines.append(f"    - {p['pattern']} ({p['severity']}): {p['matches']} matches - {p['description']}")

        ghidra_analysis = rea.get("ghidra_analysis", {})
        if ghidra_analysis:
            lines.append(f"  Ghidra Analysis: {len(ghidra_analysis)} libraries processed")
            for lib_name, analysis in ghidra_analysis.items():
                if analysis.get("success"):
                    lines.append(f"    - {lib_name}: Success")
                elif analysis.get("error"):
                    lines.append(f"    - {lib_name}: {analysis['error']}")
    elif rea.get("error"):
        lines.append("")
        lines.append(f"REA ANALYSIS: {rea['error']}")

    # Forensics Analysis
    forensics = data.get("forensics", {})
    if forensics.get("success"):
        lines.append("")
        lines.append("FORENSICS ANALYSIS:")
        lines.append(f"  Case ID: {forensics.get('case_id', 'N/A')}")
        lines.append(f"  Case Number: {forensics.get('case_number', 'N/A')}")
        lines.append(f"  Evidence Items: {forensics.get('evidence_count', 0)}")
        lines.append(f"  Artifacts Extracted: {forensics.get('artifacts_extracted', 0)}")
        lines.append(f"  Timeline Events: {forensics.get('timeline_events', 0)}")

        compliance = forensics.get("compliance", {})
        if compliance:
            lines.append(f"  Standards Compliance: {compliance.get('average_compliance_score', 0):.1f}%")
            lines.append(f"  Standards Checked: {compliance.get('standards_checked', 0)}")

        if forensics.get("report_path"):
            lines.append(f"  Report: {forensics['report_path']}")
        if forensics.get("container_path"):
            lines.append(f"  Evidence Container: {forensics['container_path']}")
    elif forensics.get("error"):
        lines.append("")
        lines.append(f"FORENSICS ANALYSIS: {forensics['error']}")

    return "\n".join(lines)


if __name__ == "__main__":
    main()