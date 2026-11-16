"""
MITRE ATT&CK Mapper for APKStudioAI 2.1
Maps findings to MITRE ATT&CK Mobile tactics and techniques.
"""
import json
from pathlib import Path
from typing import Dict, List, Any, Optional, Set
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict
from ..config_manager import get_config
from ..logging_setup import get_module_logger

logger = get_module_logger("mitre_mapper")


class Tactic(Enum):
    """MITRE ATT&CK Mobile Tactics."""
    RECONNAISSANCE = "reconnaissance"
    RESOURCE_DEVELOPMENT = "resource_development"
    INITIAL_ACCESS = "initial_access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DEFENSE_EVASION = "defense_evasion"
    CREDENTIAL_ACCESS = "credential_access"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral_movement"
    COLLECTION = "collection"
    COMMAND_AND_CONTROL = "command_and_control"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"


@dataclass
class Technique:
    """MITRE ATT&CK Technique."""
    id: str  # e.g., T1471
    name: str
    description: str
    tactic: Tactic
    platforms: List[str] = field(default_factory=list)
    data_sources: List[str] = field(default_factory=list)
    detection: str = ""
    sub_techniques: List[str] = field(default_factory=list)


@dataclass
class TTPMapping:
    """Mapping from finding to TTP."""
    finding_id: str
    finding_type: str
    technique_id: str
    technique_name: str
    tactic: Tactic
    confidence: float
    evidence: Dict[str, Any]


# MITRE ATT&CK Mobile Matrix (subset for Android)
MOBILE_TECHNIQUES = {
    # Initial Access
    "T1471": Technique("T1471", "Application Store", "Malicious apps distributed via app stores",
                       Tactic.INITIAL_ACCESS, platforms=["Android", "iOS"],
                       data_sources=["Application Store Metadata"]),
    "T1472": Technique("T1472", "Malicious Link", "User clicks malicious link",
                       Tactic.INITIAL_ACCESS, platforms=["Android", "iOS"],
                       data_sources=["Network Traffic", "URL Analysis"]),
    "T1658": Technique("T1658", "Drive-by Compromise", "Compromise via browsing",
                       Tactic.INITIAL_ACCESS, platforms=["Android", "iOS"],
                       data_sources=["Browser History", "Network Traffic"]),

    # Execution
    "T1106": Technique("T1106", "Native API", "Use of native APIs",
                       Tactic.EXECUTION, platforms=["Android", "iOS"],
                       data_sources=["API Monitoring", "Native Code Analysis"]),
    "T1474": Technique("T1474", "Dynamic Code Loading", "Loading code at runtime",
                       Tactic.EXECUTION, platforms=["Android"],
                       data_sources=["Class Loading Monitoring", "File Monitoring"]),
    "T1475": Technique("T1475", "Inter-Process Communication", "IPC for execution",
                       Tactic.EXECUTION, platforms=["Android"],
                       data_sources=["IPC Monitoring", "Binder Analysis"]),

    # Persistence
    "T1476": Technique("T1476", "Boot or Logon Autostart", "Auto-start at boot",
                       Tactic.PERSISTENCE, platforms=["Android"],
                       data_sources=["Boot Receiver Analysis", "Manifest Analysis"]),
    "T1477": Technique("T1477", "Event Triggered Execution", "Execution on events",
                       Tactic.PERSISTENCE, platforms=["Android"],
                       data_sources=["Broadcast Receiver Analysis"]),
    "T1659": Technique("T1659", "Malicious App Update", "Update adds malicious code",
                       Tactic.PERSISTENCE, platforms=["Android"],
                       data_sources=["Version Analysis", "Code Diffing"]),

    # Privilege Escalation
    "T1478": Technique("T1478", "Exploit for Privilege Escalation", "OS exploit for root",
                       Tactic.PRIVILEGE_ESCALATION, platforms=["Android"],
                       data_sources=["Exploit Detection", "Kernel Logs"]),
    "T1479": Technique("T1479", "Permission Request", "Requesting dangerous permissions",
                       Tactic.PRIVILEGE_ESCALATION, platforms=["Android"],
                       data_sources=["Manifest Analysis", "Permission Usage"]),

    # Defense Evasion
    "T1480": Technique("T1480", "Obfuscated/Stored Files", "Packed/encrypted files",
                       Tactic.DEFENSE_EVASION, platforms=["Android"],
                       data_sources=["Packer Detection", "Entropy Analysis"]),
    "T1481": Technique("T1481", "Rootkit", "Kernel/user-mode rootkit",
                       Tactic.DEFENSE_EVASION, platforms=["Android"],
                       data_sources=["Rootkit Detection", "System Call Analysis"]),
    "T1482": Technique("T1482", "Anti-Forensics", "Evading analysis",
                       Tactic.DEFENSE_EVASION, platforms=["Android"],
                       data_sources=["Anti-Debug Detection", "Anti-VM Detection"]),
    "T1483": Technique("T1483", "Code Signing", "Misuse of code signing",
                       Tactic.DEFENSE_EVASION, platforms=["Android"],
                       data_sources=["Certificate Analysis", "Signature Verification"]),
    "T1484": Technique("T1484", "File Deletion", "Deleting files to hide tracks",
                       Tactic.DEFENSE_EVASION, platforms=["Android"],
                       data_sources=["File System Monitoring"]),
    "T1485": Technique("T1485", "Indicator Removal", "Removing indicators",
                       Tactic.DEFENSE_EVASION, platforms=["Android"],
                       data_sources=["Log Analysis", "Registry Monitoring"]),

    # Credential Access
    "T1486": Technique("T1486", "Keylogging", "Capturing keystrokes",
                       Tactic.CREDENTIAL_ACCESS, platforms=["Android"],
                       data_sources=["Input Monitoring", "Accessibility Service Analysis"]),
    "T1487": Technique("T1487", "Credential Dumping", "Extracting credentials",
                       Tactic.CREDENTIAL_ACCESS, platforms=["Android"],
                       data_sources=["Memory Analysis", "Shared Preferences Monitoring"]),
    "T1488": Technique("T1488", "Network Sniffing", "Capturing network traffic",
                       Tactic.CREDENTIAL_ACCESS, platforms=["Android"],
                       data_sources=["Network Monitoring", "VPN Detection"]),

    # Discovery
    "T1489": Technique("T1489", "Device Information", "Enumerating device info",
                       Tactic.DISCOVERY, platforms=["Android"],
                       data_sources=["Build.prop Access", "System Property Access"]),
    "T1490": Technique("T1490", "Installed Applications", "Listing installed apps",
                       Tactic.DISCOVERY, platforms=["Android"],
                       data_sources=["Package Manager Queries"]),
    "T1491": Technique("T1491", "Network Discovery", "Discovering network topology",
                       Tactic.DISCOVERY, platforms=["Android"],
                       data_sources=["Network Scanning", "ARP Monitoring"]),
    "T1492": Technique("T1492", "Location Tracking", "Accessing location",
                       Tactic.DISCOVERY, platforms=["Android"],
                       data_sources=["GPS Access", "Network Location Access"]),

    # Lateral Movement
    "T1493": Technique("T1493", "Nearby Device Discovery", "Bluetooth/NFC discovery",
                       Tactic.LATERAL_MOVEMENT, platforms=["Android"],
                       data_sources=["Bluetooth Scanning", "NFC Tag Reading"]),
    "T1494": Technique("T1494", "Application Cast", "Casting to other devices",
                       Tactic.LATERAL_MOVEMENT, platforms=["Android"],
                       data_sources=["Cast API Usage"]),

    # Collection
    "T1495": Technique("T1495", "Audio Capture", "Recording audio",
                       Tactic.COLLECTION, platforms=["Android"],
                       data_sources=["Microphone Access", "MediaRecorder Usage"]),
    "T1496": Technique("T1496", "Screen Capture", "Capturing screen",
                       Tactic.COLLECTION, platforms=["Android"],
                       data_sources=["MediaProjection API", "Screenshot Detection"]),
    "T1497": Technique("T1497", "SMS Collection", "Reading SMS messages",
                       Tactic.COLLECTION, platforms=["Android"],
                       data_sources=["SMS Content Provider", "Broadcast Receivers"]),
    "T1498": Technique("T1498", "Contact Collection", "Reading contacts",
                       Tactic.COLLECTION, platforms=["Android"],
                       data_sources=["Contacts Provider Access"]),
    "T1499": Technique("T1499", "Call Log Collection", "Reading call logs",
                       Tactic.COLLECTION, platforms=["Android"],
                       data_sources=["Call Log Provider Access"]),
    "T1500": Technique("T1500", "File Collection", "Collecting files",
                       Tactic.COLLECTION, platforms=["Android"],
                       data_sources=["File System Access", "MediaStore Access"]),
    "T1501": Technique("T1501", "Data from Local System", "Extracting local data",
                       Tactic.COLLECTION, platforms=["Android"],
                       data_sources=["Database Access", "Shared Preferences Access"]),

    # Command and Control
    "T1502": Technique("T1502", "Encrypted Channel", "C2 over encryption",
                       Tactic.COMMAND_AND_CONTROL, platforms=["Android"],
                       data_sources=["TLS Inspection", "Certificate Analysis"]),
    "T1503": Technique("T1503", "Non-Standard Port", "C2 on non-standard ports",
                       Tactic.COMMAND_AND_CONTROL, platforms=["Android"],
                       data_sources=["Network Traffic Analysis"]),
    "T1504": Technique("T1504", "Protocol Tunneling", "Tunneling protocols",
                       Tactic.COMMAND_AND_CONTROL, platforms=["Android"],
                       data_sources=["DNS Tunneling Detection", "HTTP Tunneling Detection"]),
    "T1505": Technique("T1505", "Web Service", "C2 via web services",
                       Tactic.COMMAND_AND_CONTROL, platforms=["Android"],
                       data_sources=["API Call Analysis", "WebSocket Monitoring"]),
    "T1506": Technique("T1506", "Push Notification", "C2 via push",
                       Tactic.COMMAND_AND_CONTROL, platforms=["Android"],
                       data_sources=["FCM/GCM Analysis", "Notification Monitoring"]),
    "T1507": Technique("T1507", "Domain Generation Algorithm", "DGA for C2",
                       Tactic.COMMAND_AND_CONTROL, platforms=["Android"],
                       data_sources=["DNS Analysis", "DGA Detection"]),

    # Exfiltration
    "T1508": Technique("T1508", "Exfiltration Over Web Service", "Exfil via API",
                       Tactic.EXFILTRATION, platforms=["Android"],
                       data_sources=["Network Traffic", "API Monitoring"]),
    "T1509": Technique("T1509", "Exfiltration Over C2 Channel", "Exfil via C2",
                       Tactic.EXFILTRATION, platforms=["Android"],
                       data_sources=["C2 Traffic Analysis"]),
    "T1510": Technique("T1510", "Scheduled Transfer", "Timed exfiltration",
                       Tactic.EXFILTRATION, platforms=["Android"],
                       data_sources=["Alarm/JobScheduler Analysis", "WorkManager Analysis"]),

    # Impact
    "T1511": Technique("T1511", "Data Encryption", "Ransomware encryption",
                       Tactic.IMPACT, platforms=["Android"],
                       data_sources=["File System Monitoring", "Crypto API Usage"]),
    "T1512": Technique("T1512", "Device Lock", "Locking device",
                       Tactic.IMPACT, platforms=["Android"],
                       data_sources=["Device Admin API", "Lock Screen Analysis"]),
    "T1513": Technique("T1513", "Financial Theft", "Stealing money",
                       Tactic.IMPACT, platforms=["Android"],
                       data_sources=["Banking App Overlay", "SMS Interception"]),
    "T1514": Technique("T1514", "Service Stop", "Stopping services",
                       Tactic.IMPACT, platforms=["Android"],
                       data_sources=["Service Management", "Accessibility Service Abuse"]),
}


class MITREMapper:
    """Maps analysis findings to MITRE ATT&CK techniques."""

    def __init__(self, config: Dict = None):
        self.config = config or get_config().get_all()
        self.techniques = MOBILE_TECHNIQUES
        self.mappings: List[TTPMapping] = []

        # Mapping rules: finding_type -> list of technique IDs
        self.mapping_rules = {
            # Network/Communication
            "network_connection": ["T1502", "T1503", "T1505"],
            "c2_beacon": ["T1502", "T1505", "T1507"],
            "dga_domain": ["T1507"],
            "suspicious_domain": ["T1472", "T1502"],
            "cleartext_traffic": ["T1502"],
            "certificate_pinning_bypass": ["T1483", "T1502"],

            # Dynamic Code Loading
            "dexclassloader": ["T1474"],
            "pathclassloader": ["T1474"],
            "inmemorydexclassloader": ["T1474"],
            "dynamic_loading": ["T1474"],
            "load_dex": ["T1474"],
            "dll_injection": ["T1474"],

            # Reflection
            "reflection": ["T1106", "T1480"],
            "class_forname": ["T1106"],
            "method_invoke": ["T1106"],
            "field_access": ["T1106"],

            # Crypto
            "crypto_init": ["T1511"],
            "crypto_dofinal": ["T1511"],
            "crypto_cipher": ["T1511"],
            "keystore_access": ["T1487"],
            "weak_crypto": ["T1502"],

            # File Operations
            "file_write": ["T1500", "T1511"],
            "file_read": ["T1501"],
            "file_delete": ["T1484"],
            "external_storage_write": ["T1500"],
            "shared_preferences_write": ["T1501"],

            # Permissions
            "dangerous_permission": ["T1479"],
            "permission_request": ["T1479"],
            "runtime_permission": ["T1479"],
            "sms_permission": ["T1497"],
            "contacts_permission": ["T1498"],
            "location_permission": ["T1492"],
            "microphone_permission": ["T1495"],
            "camera_permission": ["T1496"],
            "call_log_permission": ["T1499"],
            "device_admin": ["T1512", "T1514"],

            # Components
            "boot_receiver": ["T1476"],
            "broadcast_receiver": ["T1477"],
            "service": ["T1477", "T1514"],
            "accessibility_service": ["T1486", "T1514"],
            "overlay_permission": ["T1513"],
            "content_provider": ["T1501"],

            # Obfuscation/Anti-Analysis
            "packed": ["T1480"],
            "obfuscated": ["T1480"],
            "obfuscation": ["T1480"],
            "packer": ["T1480"],
            "anti_debug": ["T1482"],
            "anti_vm": ["T1482"],
            "anti_emulator": ["T1482"],
            "root_detection": ["T1482"],
            "debugger_detection": ["T1482"],
            "anti_analysis": ["T1482"],

            # Root Exploits
            "root_exploit": ["T1478"],
            "privilege_escalation": ["T1478"],
            "kernel_exploit": ["T1478"],

            # Data Collection
            "sms_read": ["T1497"],
            "contacts_read": ["T1498"],
            "call_log_read": ["T1499"],
            "location_access": ["T1492"],
            "audio_record": ["T1495"],
            "screen_capture": ["T1496"],
            "file_access": ["T1500"],
            "database_access": ["T1501"],
            "keylogging": ["T1486"],

            # IPC
            "intent_send": ["T1475"],
            "binder_call": ["T1475"],
            "ipc_communication": ["T1475"],

            # Network Discovery
            "network_scan": ["T1491"],
            "bluetooth_scan": ["T1493"],
            "wifi_scan": ["T1491"],

            # Exfiltration
            "large_upload": ["T1508", "T1509"],
            "periodic_upload": ["T1510"],
            "data_exfiltration": ["T1508", "T1509"],

            # Financial
            "overlay_attack": ["T1513"],
            "sms_intercept": ["T1497", "T1513"],
            "banking_trojan": ["T1513"],
        }

    def map_finding(self, finding: Dict) -> List[TTPMapping]:
        """Map a single finding to MITRE techniques."""
        finding_id = finding.get("id", "unknown")
        finding_type = finding.get("type", "").lower()
        evidence = finding.get("evidence", {})
        severity = finding.get("severity", "info")

        mappings = []

        # Direct mapping from rules
        for rule_type, technique_ids in self.mapping_rules.items():
            if rule_type in finding_type or finding_type in rule_type:
                for tech_id in technique_ids:
                    tech = self.techniques.get(tech_id)
                    if tech:
                        confidence = self._calculate_confidence(finding, tech, evidence)
                        mappings.append(TTPMapping(
                            finding_id=finding_id,
                            finding_type=finding_type,
                            technique_id=tech.id,
                            technique_name=tech.name,
                            tactic=tech.tactic,
                            confidence=confidence,
                            evidence={
                                "finding_evidence": evidence,
                                "mapping_rule": rule_type,
                                "severity": severity,
                            }
                        ))

        # Evidence-based mapping
        mappings.extend(self._map_by_evidence(finding))

        # Deduplicate by technique
        seen = set()
        unique_mappings = []
        for m in mappings:
            key = (m.finding_id, m.technique_id)
            if key not in seen:
                seen.add(key)
                unique_mappings.append(m)

        self.mappings.extend(unique_mappings)
        return unique_mappings

    def _calculate_confidence(self, finding: Dict, technique: Technique, evidence: Dict) -> float:
        """Calculate mapping confidence."""
        base_confidence = 0.7

        # Boost for severity
        severity_boost = {"critical": 0.2, "high": 0.1, "medium": 0.05, "low": 0}.get(
            finding.get("severity", "").lower(), 0
        )

        # Boost for specific evidence
        evidence_boost = 0
        if technique.id == "T1474" and evidence.get("class_loader"):
            evidence_boost += 0.15
        if technique.id == "T1480" and evidence.get("packer"):
            evidence_boost += 0.2
        if technique.id == "T1507" and evidence.get("dga_score", 0) > 0.7:
            evidence_boost += 0.2
        if technique.id == "T1511" and evidence.get("crypto_algorithm") in ["AES", "RSA"]:
            evidence_boost += 0.1

        return min(1.0, base_confidence + severity_boost + evidence_boost)

    def _map_by_evidence(self, finding: Dict) -> List[TTPMapping]:
        """Map based on specific evidence in finding."""
        mappings = []
        finding_id = finding.get("id", "unknown")
        finding_type = finding.get("type", "").lower()
        evidence = finding.get("evidence", {})

        # API calls
        api_calls = evidence.get("api_calls", [])
        for api in api_calls:
            class_name = api.get("class", "").lower()
            method_name = api.get("method", "").lower()

            # Crypto APIs
            if "cipher" in class_name or "cipher" in method_name:
                tech = self.techniques.get("T1511")
                if tech:
                    mappings.append(TTPMapping(finding_id, finding_type, tech.id, tech.name,
                                               tech.tactic, 0.8, {"api": api}))

            # Reflection APIs
            if "reflect" in class_name or "class" in class_name and "forname" in method_name:
                tech = self.techniques.get("T1106")
                if tech:
                    mappings.append(TTPMapping(finding_id, finding_type, tech.id, tech.name,
                                               tech.tactic, 0.7, {"api": api}))

            # Dynamic loading
            if "dexclassloader" in class_name or "loadclass" in method_name:
                tech = self.techniques.get("T1474")
                if tech:
                    mappings.append(TTPMapping(finding_id, finding_type, tech.id, tech.name,
                                               tech.tactic, 0.85, {"api": api}))

            # Device info
            if "build" in class_name or "telephonymanager" in class_name:
                tech = self.techniques.get("T1489")
                if tech:
                    mappings.append(TTPMapping(finding_id, finding_type, tech.id, tech.name,
                                               tech.tactic, 0.7, {"api": api}))

        # Strings
        strings = evidence.get("strings", [])
        for s in strings:
            s_lower = s.lower()
            if "encrypt" in s_lower or "decrypt" in s_lower or "ransom" in s_lower:
                tech = self.techniques.get("T1511")
                if tech:
                    mappings.append(TTPMapping(finding_id, finding_type, tech.id, tech.name,
                                               tech.tactic, 0.6, {"string": s}))

            if any(kw in s_lower for kw in ["c2", "command", "control", "beacon", "heartbeat"]):
                tech = self.techniques.get("T1505")
                if tech:
                    mappings.append(TTPMapping(finding_id, finding_type, tech.id, tech.name,
                                               tech.tactic, 0.75, {"string": s}))

        # Network indicators
        urls = evidence.get("urls", [])
        for url in urls:
            if any(kw in url for kw in ["/api/command", "/cmd", "/control", "/beacon"]):
                tech = self.techniques.get("T1505")
                if tech:
                    mappings.append(TTPMapping(finding_id, finding_type, tech.id, tech.name,
                                               tech.tactic, 0.8, {"url": url}))

        # File hashes matching known malware
        file_hashes = evidence.get("file_hashes", {})
        if file_hashes:
            tech = self.techniques.get("T1480")
            if tech:
                mappings.append(TTPMapping(finding_id, finding_type, tech.id, tech.name,
                                           tech.tactic, 0.6, {"hashes": file_hashes}))

        return mappings

    def map_analysis_results(self, analysis_results: Dict) -> List[TTPMapping]:
        """Map all findings from analysis results."""
        all_mappings = []

        # Static analysis findings
        for analyzer_name in ["manifest", "strings", "network", "behavior", "dex", "advanced_static"]:
            findings = analysis_results.get(analyzer_name, {}).get("findings", [])
            for finding in findings:
                finding["analyzer"] = analyzer_name
                all_mappings.extend(self.map_finding(finding))

        # Dynamic analysis findings
        dynamic = analysis_results.get("dynamic", {})
        for event in dynamic.get("events", []):
            finding = {
                "id": event.get("id", "dynamic"),
                "type": event.get("event_type", "unknown"),
                "severity": event.get("severity", "info"),
                "evidence": event.get("data", {}),
            }
            all_mappings.extend(self.map_finding(finding))

        # Correlation findings
        correlations = analysis_results.get("correlations", [])
        for corr in correlations:
            finding = {
                "id": corr.get("id", "correlation"),
                "type": corr.get("correlation_type", "unknown"),
                "severity": "high",
                "evidence": corr.get("evidence", {}),
            }
            all_mappings.extend(self.map_finding(finding))

        return all_mappings

    def get_tactic_coverage(self) -> Dict[Tactic, List[TTPMapping]]:
        """Get mappings grouped by tactic."""
        coverage = defaultdict(list)
        for mapping in self.mappings:
            coverage[mapping.tactic].append(mapping)
        return dict(coverage)

    def get_technique_coverage(self) -> Dict[str, List[TTPMapping]]:
        """Get mappings grouped by technique."""
        coverage = defaultdict(list)
        for mapping in self.mappings:
            coverage[mapping.technique_id].append(mapping)
        return dict(coverage)

    def get_attack_matrix(self) -> Dict:
        """Get ATT&CK matrix with coverage."""
        matrix = {}
        for tactic in Tactic:
            techniques = [t for t in self.techniques.values() if t.tactic == tactic]
            matrix[tactic.value] = []
            for tech in techniques:
                mappings = [m for m in self.mappings if m.technique_id == tech.id]
                matrix[tactic.value].append({
                    "id": tech.id,
                    "name": tech.name,
                    "description": tech.description,
                    "platforms": tech.platforms,
                    "data_sources": tech.data_sources,
                    "detected": len(mappings) > 0,
                    "confidence": max((m.confidence for m in mappings), default=0),
                    "mappings": [
                        {"finding_id": m.finding_id, "confidence": m.confidence}
                        for m in mappings
                    ],
                })
        return matrix

    def get_summary(self) -> Dict:
        """Get mapping summary."""
        tactic_coverage = self.get_tactic_coverage()
        technique_coverage = self.get_technique_coverage()

        return {
            "total_mappings": len(self.mappings),
            "unique_techniques": len(technique_coverage),
            "tactics_covered": len(tactic_coverage),
            "by_tactic": {t.value: len(m) for t, m in tactic_coverage.items()},
            "by_technique": {tid: len(m) for tid, m in technique_coverage.items()},
            "high_confidence": len([m for m in self.mappings if m.confidence >= 0.8]),
            "avg_confidence": sum(m.confidence for m in self.mappings) / len(self.mappings) if self.mappings else 0,
        }

    def export_mappings(self, output_path: str) -> bool:
        """Export mappings to JSON."""
        try:
            data = [
                {
                    "finding_id": m.finding_id,
                    "finding_type": m.finding_type,
                    "technique_id": m.technique_id,
                    "technique_name": m.technique_name,
                    "tactic": m.tactic.value,
                    "confidence": m.confidence,
                    "evidence": m.evidence,
                }
                for m in self.mappings
            ]
            with open(output_path, "w") as f:
                json.dump(data, f, indent=2)
            return True
        except Exception as e:
            logger.error("mitre_export_error", error=str(e))
            return False

    def clear(self):
        """Clear mappings."""
        self.mappings.clear()


_mitre_mapper_instance = None


def get_mitre_mapper(config: Dict = None) -> MITREMapper:
    """Get singleton MITRE mapper instance."""
    global _mitre_mapper_instance
    if _mitre_mapper_instance is None:
        _mitre_mapper_instance = MITREMapper(config)
    return _mitre_mapper_instance