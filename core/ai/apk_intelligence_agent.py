"""
APK Intelligence Agent - Agent 1
Identifies APK architecture, extracts metadata, calculates hashes,
analyzes signing certificates, identifies components, detects unusual structures.
"""
from pathlib import Path
from typing import Dict, List, Any, Optional
from .agent_base import BaseAgent, AgentTask, AgentResult
from .evidence_repository import Evidence, Severity, AgentID
from ..config_manager import get_config
from ..logging_setup import get_module_logger

logger = get_module_logger("apk_intelligence_agent")


class APKIntelligenceAgent(BaseAgent):
    """Agent 1: APK Intelligence - Architecture, metadata, certificates, components."""

    def __init__(self, config: Dict = None, evidence_repo = None,
                 ollama_client = None, rag_engine = None):
        super().__init__(AgentID.APK_INTELLIGENCE, config, evidence_repo, ollama_client, rag_engine)

    def investigate(self, task: AgentTask) -> AgentResult:
        """Investigate APK structure and metadata."""
        apk_path = task.input_data.get("apk_path")
        archive_analysis = task.input_data.get("archive_analysis", {})
        manifest_analysis = task.input_data.get("manifest_analysis", {})
        dex_analysis = task.input_data.get("dex_analysis", {})

        evidence_ids = []
        findings = {
            "architecture": {},
            "metadata": {},
            "certificates": [],
            "components": {},
            "unusual_structures": [],
            "embedded_files": [],
        }

        # 1. APK Architecture
        arch_info = self._analyze_architecture(archive_analysis, dex_analysis)
        findings["architecture"] = arch_info
        evidence_ids.append(self._create_architecture_evidence(apk_path, arch_info).evidence_id)

        # 2. Package Metadata
        metadata = self._extract_metadata(manifest_analysis, archive_analysis)
        findings["metadata"] = metadata
        evidence_ids.append(self._create_metadata_evidence(apk_path, metadata).evidence_id)

        # 3. Signing Certificates
        certs = self._analyze_certificates(archive_analysis)
        findings["certificates"] = certs
        for cert in certs:
            evidence_ids.append(self._create_certificate_evidence(apk_path, cert).evidence_id)

        # 4. Application Components
        components = self._analyze_components(manifest_analysis)
        findings["components"] = components
        evidence_ids.append(self._create_components_evidence(apk_path, components).evidence_id)

        # 5. Unusual Archive Structures
        unusual = self._detect_unusual_structures(archive_analysis)
        findings["unusual_structures"] = unusual
        for item in unusual:
            evidence_ids.append(self._create_unusual_evidence(apk_path, item).evidence_id)

        # 6. Suspicious Embedded Files
        embedded = self._find_embedded_files(archive_analysis)
        findings["embedded_files"] = embedded
        for item in embedded:
            evidence_ids.append(self._create_embedded_evidence(apk_path, item).evidence_id)

        return AgentResult(
            task_id=task.task_id,
            agent_id=self.agent_id,
            success=True,
            evidence_ids=evidence_ids,
            findings=findings,
        )

    def _analyze_architecture(self, archive: Dict, dex: Dict) -> Dict:
        """Analyze APK architecture."""
        arch = {
            "is_multidex": dex.get("dex_count", 1) > 1,
            "dex_count": dex.get("dex_count", 1),
            "total_classes": dex.get("total_classes", 0),
            "total_methods": dex.get("total_methods", 0),
            "has_native_libs": archive.get("native_libs_count", 0) > 0,
            "native_lib_count": archive.get("native_libs_count", 0),
            "native_architectures": archive.get("native_architectures", []),
            "min_sdk": archive.get("min_sdk", 0),
            "target_sdk": archive.get("target_sdk", 0),
            "file_size_mb": archive.get("file_size_mb", 0),
        }
        return arch

    def _extract_metadata(self, manifest: Dict, archive: Dict) -> Dict:
        """Extract package metadata."""
        return {
            "package_name": manifest.get("package", "unknown"),
            "version_code": manifest.get("version_code", 0),
            "version_name": manifest.get("version_name", "unknown"),
            "min_sdk_version": manifest.get("min_sdk_version", 0),
            "target_sdk_version": manifest.get("target_sdk_version", 0),
            "max_sdk_version": manifest.get("max_sdk_version", 0),
            "compile_sdk_version": manifest.get("compile_sdk_version", 0),
            "shared_user_id": manifest.get("shared_user_id"),
            "install_location": manifest.get("install_location"),
            "is_debuggable": manifest.get("debuggable", False),
            "uses_cleartext_traffic": manifest.get("uses_cleartext_traffic", False),
            "backup_allowed": manifest.get("allow_backup", True),
        }

    def _analyze_certificates(self, archive: Dict) -> List[Dict]:
        """Analyze signing certificates."""
        certs = []
        for cert in archive.get("certificates", []):
            cert_info = {
                "subject": cert.get("subject", {}),
                "issuer": cert.get("issuer", {}),
                "serial_number": cert.get("serial_number"),
                "not_before": cert.get("not_before"),
                "not_after": cert.get("not_after"),
                "signature_algorithm": cert.get("signature_algorithm"),
                "public_key_algorithm": cert.get("public_key_algorithm"),
                "key_size": cert.get("key_size"),
                "is_self_signed": cert.get("is_self_signed", False),
                "is_expired": cert.get("is_expired", False),
                "sha256": cert.get("sha256"),
            }
            certs.append(cert_info)
        return certs

    def _analyze_components(self, manifest: Dict) -> Dict:
        """Analyze application components."""
        return {
            "activities": manifest.get("activities", []),
            "services": manifest.get("services", []),
            "receivers": manifest.get("receivers", []),
            "providers": manifest.get("providers", []),
            "total_exported": sum(
                1 for c in manifest.get("activities", []) if c.get("exported")
            ) + sum(
                1 for c in manifest.get("services", []) if c.get("exported")
            ) + sum(
                1 for c in manifest.get("receivers", []) if c.get("exported")
            ) + sum(
                1 for c in manifest.get("providers", []) if c.get("exported")
            ),
        }

    def _detect_unusual_structures(self, archive: Dict) -> List[Dict]:
        """Detect unusual archive structures."""
        unusual = []

        # Check for multiple DEX files in unexpected locations
        dex_files = archive.get("dex_files", [])
        if len(dex_files) > 1:
            for dex in dex_files[1:]:
                unusual.append({
                    "type": "multidex",
                    "description": f"Additional DEX file: {dex}",
                    "severity": "medium",
                })

        # Check for suspicious file types
        suspicious_exts = [".so", ".jar", ".dex", ".class", ".zip", ".apk"]
        for file_info in archive.get("files", []):
            name = file_info.get("name", "")
            if any(name.endswith(ext) for ext in suspicious_exts):
                if name not in ["classes.dex", "classes2.dex", "classes3.dex"]:
                    unusual.append({
                        "type": "suspicious_file",
                        "description": f"Unexpected file type: {name}",
                        "path": name,
                        "severity": "medium",
                    })

        # Check for hidden directories
        for file_info in archive.get("files", []):
            name = file_info.get("name", "")
            if name.startswith(".") and name not in [".", ".."]:
                unusual.append({
                    "type": "hidden_file",
                    "description": f"Hidden file/directory: {name}",
                    "path": name,
                    "severity": "low",
                })

        return unusual

    def _find_embedded_files(self, archive: Dict) -> List[Dict]:
        """Find suspicious embedded files."""
        embedded = []

        for file_info in archive.get("files", []):
            name = file_info.get("name", "")
            size = file_info.get("size", 0)

            # Check for embedded APKs/DEXs in assets
            if name.startswith("assets/") and (name.endswith(".apk") or name.endswith(".dex") or name.endswith(".jar")):
                embedded.append({
                    "type": "embedded_apk",
                    "path": name,
                    "size": size,
                    "description": f"Embedded APK/DEX in assets: {name}",
                    "severity": "high",
                })

            # Check for raw DEX files outside normal locations
            if name.endswith(".dex") and not name.startswith("classes"):
                embedded.append({
                    "type": "raw_dex",
                    "path": name,
                    "size": size,
                    "description": f"Raw DEX file: {name}",
                    "severity": "high",
                })

            # Check for encrypted/packed files (high entropy)
            entropy = file_info.get("entropy", 0)
            if entropy > 7.5 and size > 1024:
                embedded.append({
                    "type": "high_entropy",
                    "path": name,
                    "size": size,
                    "entropy": entropy,
                    "description": f"High entropy file (possible encryption): {name}",
                    "severity": "high",
                })

        return embedded

    def _create_architecture_evidence(self, apk_path: str, arch: Dict) -> Evidence:
        return self.create_evidence(
            analysis_module="apk_architecture",
            file_path=apk_path,
            description=f"APK Architecture: {arch['dex_count']} DEX, {arch['total_classes']} classes, "
                       f"{arch['native_lib_count']} native libs ({', '.join(arch['native_architectures'])})",
            raw_data=arch,
            confidence=90,
            severity="info",
            tags=["architecture", "multidex" if arch["is_multidex"] else "single_dex"],
        )

    def _create_metadata_evidence(self, apk_path: str, metadata: Dict) -> Evidence:
        return self.create_evidence(
            analysis_module="package_metadata",
            file_path=apk_path,
            description=f"Package: {metadata['package_name']} v{metadata['version_name']} "
                       f"(code: {metadata['version_code']}), SDK: {metadata['min_sdk_version']}-{metadata['target_sdk_version']}",
            raw_data=metadata,
            confidence=95,
            severity="info",
            tags=["metadata", "package_info"],
        )

    def _create_certificate_evidence(self, apk_path: str, cert: Dict) -> Evidence:
        severity = "high" if cert.get("is_self_signed") else "info"
        if cert.get("is_expired"):
            severity = "medium"

        return self.create_evidence(
            analysis_module="signing_certificate",
            file_path=apk_path,
            description=f"Certificate: {cert.get('subject', {}).get('CN', 'Unknown')} "
                       f"(alg: {cert.get('signature_algorithm')}, key: {cert.get('key_size')} bits, "
                       f"{'self-signed' if cert.get('is_self_signed') else 'CA-signed'})",
            raw_data=cert,
            confidence=90,
            severity=severity,
            tags=["certificate", "signing", "self_signed" if cert.get("is_self_signed") else "ca_signed"],
        )

    def _create_components_evidence(self, apk_path: str, components: Dict) -> Evidence:
        exported = components.get("total_exported", 0)
        severity = "high" if exported > 10 else "medium" if exported > 5 else "info"

        return self.create_evidence(
            analysis_module="app_components",
            file_path=apk_path,
            description=f"Components: {len(components['activities'])} activities, "
                       f"{len(components['services'])} services, "
                       f"{len(components['receivers'])} receivers, "
                       f"{len(components['providers'])} providers "
                       f"({exported} exported)",
            raw_data=components,
            confidence=90,
            severity=severity,
            tags=["components", "attack_surface", "exported" if exported > 0 else "no_exported"],
        )

    def _create_unusual_evidence(self, apk_path: str, item: Dict) -> Evidence:
        return self.create_evidence(
            analysis_module="unusual_structure",
            file_path=apk_path,
            description=item.get("description", "Unusual structure detected"),
            raw_data=item,
            confidence=70,
            severity=item.get("severity", "medium"),
            tags=["unusual", item.get("type", "unknown")],
        )

    def _create_embedded_evidence(self, apk_path: str, item: Dict) -> Evidence:
        return self.create_evidence(
            analysis_module="embedded_file",
            file_path=apk_path,
            description=item.get("description", "Embedded file detected"),
            raw_data=item,
            confidence=80,
            severity=item.get("severity", "medium"),
            tags=["embedded", item.get("type", "unknown")],
        )