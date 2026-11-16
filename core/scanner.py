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
from .ollama_client import OllamaClient
from .advanced_static_analyzer import AdvancedStaticAnalyzer
from .androguard_engine import AndroguardEngine, get_androguard_engine
from .apkid_engine import APKiDEngine, get_apkid_engine
from .config_manager import get_config
from .cache_manager import get_cache
from .incremental_analyzer import get_incremental_analyzer
from .utils import run_command, calculate_sha256, safe_extract_zip, ProgressTracker
from .logging_setup import configure_logging, get_module_logger, ScanContext
from .ai.agent_base import create_agent_manager
from .ai.evidence_repository import get_evidence_repository, EvidenceRepository
from .ai.rag_engine import get_rag_engine


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
        self.ollama_client = OllamaClient(ollama_config)
        self.advanced_static_analyzer = AdvancedStaticAnalyzer(self.config)
        self.androguard_engine = get_androguard_engine(self.config)
        self.apkid_engine = get_apkid_engine(self.config)

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
        self.ollama_client = OllamaClient(self.config.get("ollama", {}))
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
            "smali": 50, "native": 60, "jni": 65, "strings": 70, "permissions": 75,
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

    def scan(self, apk_path: str, no_ai: bool = False) -> Dict[str, Any]:
        """Perform complete APK scan."""
        self.apk_path = Path(apk_path)
        self.cancelled = False

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

    return "\n".join(lines)


if __name__ == "__main__":
    main()