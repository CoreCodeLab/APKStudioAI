"""
Correlation Engine for APKStudioAI 2.1
Maps static analysis findings to dynamic runtime behavior.
"""
import json
import time
from pathlib import Path
from typing import Dict, List, Any, Optional, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict
from ..config_manager import get_config
from ..logging_setup import get_module_logger

logger = get_module_logger("correlation_engine")


class CorrelationType(Enum):
    """Types of static-dynamic correlations."""
    API_CALL_MATCH = "api_call_match"
    NETWORK_CONNECTION = "network_connection"
    FILE_ACCESS = "file_access"
    REFLECTION_USAGE = "reflection_usage"
    DYNAMIC_LOADING = "dynamic_loading"
    CRYPTO_OPERATION = "crypto_operation"
    COMPONENT_LIFECYCLE = "component_lifecycle"
    PERMISSION_USAGE = "permission_usage"
    STRING_MATCH = "string_match"
    ICC_COMMUNICATION = "icc_communication"
    OBFUSCATION_EVIDENCE = "obfuscation_evidence"
    BEHAVIOR_PATTERN = "behavior_pattern"


class ConfidenceLevel(Enum):
    """Correlation confidence levels."""
    DEFINITE = "definite"      # Direct match (e.g., same method called)
    HIGH = "high"              # Strong evidence (e.g., same class + method pattern)
    MEDIUM = "medium"          # Moderate evidence (e.g., same package + behavior)
    LOW = "low"                # Weak evidence (e.g., string match only)
    SPECULATIVE = "speculative" # Possible but unconfirmed


@dataclass
class StaticFinding:
    """Static analysis finding."""
    id: str
    analyzer: str
    finding_type: str
    severity: str
    location: Dict[str, Any]  # class, method, line, etc.
    evidence: Dict[str, Any]
    description: str


@dataclass
class DynamicEvent:
    """Dynamic runtime event."""
    id: str
    event_type: str
    timestamp: float
    data: Dict[str, Any]
    source: str


@dataclass
class Correlation:
    """Static-dynamic correlation result."""
    id: str
    correlation_type: CorrelationType
    confidence: ConfidenceLevel
    static_finding: StaticFinding
    dynamic_events: List[DynamicEvent]
    description: str
    evidence: Dict[str, Any]
    risk_contribution: float  # 0-100


class CorrelationEngine:
    """Correlates static analysis findings with dynamic runtime behavior."""

    def __init__(self, config: Dict = None):
        self.config = config or get_config().get_all()
        self.static_findings: List[StaticFinding] = []
        self.dynamic_events: List[DynamicEvent] = []
        self.correlations: List[Correlation] = []

        # Mapping indexes for fast lookup
        self._api_call_index: Dict[str, List[StaticFinding]] = defaultdict(list)
        self._network_index: Dict[str, List[StaticFinding]] = defaultdict(list)
        self._file_index: Dict[str, List[StaticFinding]] = defaultdict(list)
        self._reflection_index: List[StaticFinding] = []
        self._dynamic_load_index: List[StaticFinding] = []
        self._crypto_index: List[StaticFinding] = []
        self._component_index: Dict[str, List[StaticFinding]] = defaultdict(list)
        self._permission_index: Dict[str, List[StaticFinding]] = defaultdict(list)
        self._string_index: Dict[str, List[StaticFinding]] = defaultdict(list)
        self._icc_index: List[StaticFinding] = []
        self._obfuscation_index: List[StaticFinding] = []

    def load_static_findings(self, findings: List[Dict]):
        """Load static analysis findings and build indexes."""
        self.static_findings = []
        self._clear_indexes()

        for f in findings:
            finding = StaticFinding(
                id=f.get("id", f"static_{len(self.static_findings)}"),
                analyzer=f.get("analyzer", "unknown"),
                finding_type=f.get("type", "unknown"),
                severity=f.get("severity", "info"),
                location=f.get("location", {}),
                evidence=f.get("evidence", {}),
                description=f.get("description", ""),
            )
            self.static_findings.append(finding)
            self._index_finding(finding)

        logger.info("static_findings_loaded", count=len(self.static_findings))

    def _clear_indexes(self):
        """Clear all indexes."""
        self._api_call_index.clear()
        self._network_index.clear()
        self._file_index.clear()
        self._reflection_index.clear()
        self._dynamic_load_index.clear()
        self._crypto_index.clear()
        self._component_index.clear()
        self._permission_index.clear()
        self._string_index.clear()
        self._icc_index.clear()
        self._obfuscation_index.clear()

    def _index_finding(self, finding: StaticFinding):
        """Index a single finding for correlation."""
        evidence = finding.evidence
        location = finding.location

        # API calls
        if finding.finding_type in ["api_call", "sensitive_api", "dangerous_api"]:
            class_name = location.get("class", "")
            method_name = location.get("method", "")
            if class_name and method_name:
                key = f"{class_name}->{method_name}"
                self._api_call_index[key].append(finding)

            # Also index by class
            if class_name:
                self._api_call_index[class_name].append(finding)

        # Network indicators
        if finding.finding_type in ["network", "url", "ip_address", "endpoint"]:
            urls = evidence.get("urls", [])
            ips = evidence.get("ips", [])
            domains = evidence.get("domains", [])
            for u in urls:
                self._network_index[u].append(finding)
            for ip in ips:
                self._network_index[ip].append(finding)
            for d in domains:
                self._network_index[d].append(finding)

        # File access
        if finding.finding_type in ["file_access", "file_io", "path"]:
            paths = evidence.get("paths", [])
            for p in paths:
                self._file_index[p].append(finding)

        # Reflection
        if finding.finding_type in ["reflection", "reflective_call"]:
            self._reflection_index.append(finding)

        # Dynamic loading
        if finding.finding_type in ["dynamic_loading", "dexclassloader", "class_loading"]:
            self._dynamic_load_index.append(finding)

        # Crypto
        if finding.finding_type in ["crypto", "cryptographic_operation"]:
            self._crypto_index.append(finding)

        # Components
        if finding.finding_type in ["component", "activity", "service", "receiver", "provider"]:
            comp_name = location.get("component", "") or location.get("class", "")
            if comp_name:
                self._component_index[comp_name].append(finding)

        # Permissions
        if finding.finding_type in ["permission", "permission_usage"]:
            perms = evidence.get("permissions", [])
            for p in perms:
                self._permission_index[p].append(finding)

        # Strings
        if finding.finding_type in ["string", "hardcoded_string", "sensitive_string"]:
            strings = evidence.get("strings", [])
            for s in strings:
                self._string_index[s].append(finding)

        # ICC
        if finding.finding_type in ["icc", "intent", "ipc", "binder"]:
            self._icc_index.append(finding)

        # Obfuscation
        if finding.finding_type in ["obfuscation", "packer", "anti_analysis"]:
            self._obfuscation_index.append(finding)

    def load_dynamic_events(self, events: List[Dict]):
        """Load dynamic runtime events."""
        self.dynamic_events = []

        for e in events:
            event = DynamicEvent(
                id=e.get("id", f"dynamic_{len(self.dynamic_events)}"),
                event_type=e.get("event_type", "unknown"),
                timestamp=e.get("timestamp", time.time()),
                data=e.get("data", {}),
                source=e.get("source", "unknown"),
            )
            self.dynamic_events.append(event)

        logger.info("dynamic_events_loaded", count=len(self.dynamic_events))

    def correlate(self) -> List[Correlation]:
        """Perform static-dynamic correlation."""
        self.correlations = []

        # Run all correlation strategies
        self._correlate_api_calls()
        self._correlate_network()
        self._correlate_file_access()
        self._correlate_reflection()
        self._correlate_dynamic_loading()
        self._correlate_crypto()
        self._correlate_components()
        self._correlate_permissions()
        self._correlate_strings()
        self._correlate_icc()
        self._correlate_obfuscation()

        # Sort by confidence and risk contribution
        confidence_order = {
            ConfidenceLevel.DEFINITE: 5,
            ConfidenceLevel.HIGH: 4,
            ConfidenceLevel.MEDIUM: 3,
            ConfidenceLevel.LOW: 2,
            ConfidenceLevel.SPECULATIVE: 1,
        }

        self.correlations.sort(
            key=lambda c: (confidence_order[c.confidence], c.risk_contribution),
            reverse=True
        )

        logger.info("correlation_completed", total=len(self.correlations))
        return self.correlations

    def _correlate_api_calls(self):
        """Correlate static API calls with dynamic method invocations."""
        for event in self.dynamic_events:
            if event.event_type not in ["method_entry", "method_exit", "native_entry"]:
                continue

            data = event.data
            class_name = data.get("class", "")
            method_name = data.get("method", "")

            if not class_name or not method_name:
                continue

            # Direct match
            key = f"{class_name}->{method_name}"
            if key in self._api_call_index:
                for finding in self._api_call_index[key]:
                    self._create_correlation(
                        CorrelationType.API_CALL_MATCH,
                        ConfidenceLevel.DEFINITE,
                        finding,
                        [event],
                        f"Static API call {key} observed at runtime",
                        {"static_location": finding.location, "dynamic_call": data},
                        15.0
                    )

            # Class-level match
            if class_name in self._api_call_index:
                for finding in self._api_call_index[class_name]:
                    # Avoid duplicates
                    if not any(c.static_finding.id == finding.id and c.correlation_type == CorrelationType.API_CALL_MATCH for c in self.correlations):
                        self._create_correlation(
                            CorrelationType.API_CALL_MATCH,
                            ConfidenceLevel.HIGH,
                            finding,
                            [event],
                            f"Static API class {class_name} observed at runtime",
                            {"static_location": finding.location, "dynamic_call": data},
                            10.0
                        )

    def _correlate_network(self):
        """Correlate static network indicators with dynamic connections."""
        for event in self.dynamic_events:
            if event.event_type != "network":
                continue

            data = event.data
            url = data.get("url", "")
            host = data.get("host", "")
            ip = data.get("server_ip", "") or data.get("ip", "")

            # Check URLs
            for indicator in [url, host, ip]:
                if indicator and indicator in self._network_index:
                    for finding in self._network_index[indicator]:
                        self._create_correlation(
                            CorrelationType.NETWORK_CONNECTION,
                            ConfidenceLevel.DEFINITE,
                            finding,
                            [event],
                            f"Static network indicator {indicator} connected at runtime",
                            {"static_evidence": finding.evidence, "dynamic_connection": data},
                            20.0
                        )

    def _correlate_file_access(self):
        """Correlate static file paths with dynamic file operations."""
        for event in self.dynamic_events:
            if event.event_type != "file_io":
                continue

            data = event.data
            path = data.get("path", "") or data.get("file", "")

            if path and path in self._file_index:
                for finding in self._file_index[path]:
                    self._create_correlation(
                        CorrelationType.FILE_ACCESS,
                        ConfidenceLevel.DEFINITE,
                        finding,
                        [event],
                        f"Static file path {path} accessed at runtime",
                        {"static_evidence": finding.evidence, "dynamic_access": data},
                        10.0
                    )

    def _correlate_reflection(self):
        """Correlate static reflection findings with dynamic reflection usage."""
        reflection_events = [e for e in self.dynamic_events if e.event_type == "reflection"]

        if not reflection_events or not self._reflection_index:
            return

        # If reflection was used dynamically and found statically
        for finding in self._reflection_index:
            if reflection_events:
                self._create_correlation(
                    CorrelationType.REFLECTION_USAGE,
                    ConfidenceLevel.HIGH,
                    finding,
                    reflection_events[:5],  # Limit events
                    "Static reflection usage confirmed by dynamic analysis",
                    {"static_evidence": finding.evidence, "dynamic_calls": [e.data for e in reflection_events[:5]]},
                    15.0
                )

    def _correlate_dynamic_loading(self):
        """Correlate static dynamic loading findings with runtime class loading."""
        dynload_events = [e for e in self.dynamic_events if e.event_type == "dynamic_loading"]

        if not dynload_events or not self._dynamic_load_index:
            return

        for finding in self._dynamic_load_index:
            if dynload_events:
                self._create_correlation(
                    CorrelationType.DYNAMIC_LOADING,
                    ConfidenceLevel.HIGH,
                    finding,
                    dynload_events[:5],
                    "Static dynamic code loading confirmed at runtime",
                    {"static_evidence": finding.evidence, "dynamic_loads": [e.data for e in dynload_events[:5]]},
                    25.0
                )

    def _correlate_crypto(self):
        """Correlate static crypto findings with runtime crypto operations."""
        crypto_events = [e for e in self.dynamic_events if e.event_type == "crypto"]

        if not crypto_events or not self._crypto_index:
            return

        for finding in self._crypto_index:
            if crypto_events:
                self._create_correlation(
                    CorrelationType.CRYPTO_OPERATION,
                    ConfidenceLevel.HIGH,
                    finding,
                    crypto_events[:5],
                    "Static cryptographic operations observed at runtime",
                    {"static_evidence": finding.evidence, "dynamic_crypto": [e.data for e in crypto_events[:5]]},
                    15.0
                )

    def _correlate_components(self):
        """Correlate static component declarations with runtime lifecycle."""
        component_events = [e for e in self.dynamic_events if e.event_type == "component"]

        if not component_events:
            return

        for event in component_events:
            comp_name = event.data.get("component", "") or event.data.get("class", "")
            if comp_name and comp_name in self._component_index:
                for finding in self._component_index[comp_name]:
                    self._create_correlation(
                        CorrelationType.COMPONENT_LIFECYCLE,
                        ConfidenceLevel.MEDIUM,
                        finding,
                        [event],
                        f"Static component {comp_name} lifecycle observed",
                        {"static_evidence": finding.evidence, "dynamic_lifecycle": event.data},
                        5.0
                    )

    def _correlate_permissions(self):
        """Correlate static permissions with runtime permission usage."""
        perm_events = [e for e in self.dynamic_events if e.event_type == "permission"]

        if not perm_events:
            return

        for event in perm_events:
            perm = event.data.get("permission", "")
            if perm and perm in self._permission_index:
                for finding in self._permission_index[perm]:
                    self._create_correlation(
                        CorrelationType.PERMISSION_USAGE,
                        ConfidenceLevel.MEDIUM,
                        finding,
                        [event],
                        f"Static permission {perm} used at runtime",
                        {"static_evidence": finding.evidence, "dynamic_usage": event.data},
                        5.0
                    )

    def _correlate_strings(self):
        """Correlate static strings with runtime string usage."""
        for event in self.dynamic_events:
            data_str = json.dumps(event.data)
            for string_val, findings in self._string_index.items():
                if string_val in data_str:
                    for finding in findings:
                        self._create_correlation(
                            CorrelationType.STRING_MATCH,
                            ConfidenceLevel.LOW,
                            finding,
                            [event],
                            f"Static string '{string_val[:50]}' observed in runtime data",
                            {"static_string": string_val, "dynamic_context": event.data},
                            3.0
                        )

    def _correlate_icc(self):
        """Correlate static ICC findings with runtime IPC."""
        icc_events = [e for e in self.dynamic_events if e.event_type in ["ipc", "icc", "intent", "binder"]]

        if not icc_events or not self._icc_index:
            return

        for finding in self._icc_index:
            if icc_events:
                self._create_correlation(
                    CorrelationType.ICC_COMMUNICATION,
                    ConfidenceLevel.MEDIUM,
                    finding,
                    icc_events[:5],
                    "Static ICC communication pattern observed at runtime",
                    {"static_evidence": finding.evidence, "dynamic_icc": [e.data for e in icc_events[:5]]},
                    10.0
                )

    def _correlate_obfuscation(self):
        """Correlate static obfuscation findings with runtime anti-analysis."""
        anti_events = [e for e in self.dynamic_events if e.event_type == "anti_analysis"]

        if not anti_events or not self._obfuscation_index:
            return

        for finding in self._obfuscation_index:
            if anti_events:
                self._create_correlation(
                    CorrelationType.OBFUSCATION_EVIDENCE,
                    ConfidenceLevel.HIGH,
                    finding,
                    anti_events[:5],
                    "Static obfuscation/anti-analysis confirmed by runtime behavior",
                    {"static_evidence": finding.evidence, "dynamic_anti": [e.data for e in anti_events[:5]]},
                    20.0
                )

    def _create_correlation(self, corr_type: CorrelationType, confidence: ConfidenceLevel,
                           finding: StaticFinding, events: List[DynamicEvent],
                           description: str, evidence: Dict, risk: float):
        """Create a correlation record."""
        # Check for duplicate
        for existing in self.correlations:
            if (existing.static_finding.id == finding.id and
                existing.correlation_type == corr_type):
                return

        correlation = Correlation(
            id=f"corr_{len(self.correlations)}_{corr_type.value}",
            correlation_type=corr_type,
            confidence=confidence,
            static_finding=finding,
            dynamic_events=events,
            description=description,
            evidence=evidence,
            risk_contribution=risk,
        )
        self.correlations.append(correlation)

    def get_correlations(self, corr_type: CorrelationType = None,
                         confidence: ConfidenceLevel = None,
                         min_risk: float = 0) -> List[Correlation]:
        """Get filtered correlations."""
        results = self.correlations

        if corr_type:
            results = [c for c in results if c.correlation_type == corr_type]
        if confidence:
            results = [c for c in results if c.confidence == confidence]
        if min_risk:
            results = [c for c in results if c.risk_contribution >= min_risk]

        return results

    def get_high_confidence_correlations(self) -> List[Correlation]:
        """Get definite and high confidence correlations."""
        return [c for c in self.correlations if c.confidence in [ConfidenceLevel.DEFINITE, ConfidenceLevel.HIGH]]

    def get_summary(self) -> Dict[str, Any]:
        """Get correlation summary."""
        if not self.correlations:
            return {"total": 0}

        by_type = defaultdict(int)
        by_confidence = defaultdict(int)
        total_risk = 0

        for c in self.correlations:
            by_type[c.correlation_type.value] += 1
            by_confidence[c.confidence.value] += 1
            total_risk += c.risk_contribution

        return {
            "total": len(self.correlations),
            "by_type": dict(by_type),
            "by_confidence": dict(by_confidence),
            "total_risk_contribution": round(total_risk, 2),
            "high_confidence_count": len(self.get_high_confidence_correlations()),
            "unique_static_findings": len(set(c.static_finding.id for c in self.correlations)),
            "unique_dynamic_events": len(set(e.id for c in self.correlations for e in c.dynamic_events)),
        }

    def export_correlations(self, output_path: str) -> bool:
        """Export correlations to JSON."""
        try:
            data = []
            for c in self.correlations:
                data.append({
                    "id": c.id,
                    "correlation_type": c.correlation_type.value,
                    "confidence": c.confidence.value,
                    "static_finding": {
                        "id": c.static_finding.id,
                        "analyzer": c.static_finding.analyzer,
                        "type": c.static_finding.finding_type,
                        "severity": c.static_finding.severity,
                        "location": c.static_finding.location,
                        "description": c.static_finding.description,
                    },
                    "dynamic_events": [
                        {
                            "id": e.id,
                            "type": e.event_type,
                            "timestamp": e.timestamp,
                            "source": e.source,
                        }
                        for e in c.dynamic_events
                    ],
                    "description": c.description,
                    "evidence": c.evidence,
                    "risk_contribution": c.risk_contribution,
                })

            with open(output_path, "w") as f:
                json.dump(data, f, indent=2)
            return True
        except Exception as e:
            logger.error("export_error", error=str(e))
            return False


_correlation_engine_instance = None


def get_correlation_engine(config: Dict = None) -> CorrelationEngine:
    """Get singleton correlation engine instance."""
    global _correlation_engine_instance
    if _correlation_engine_instance is None:
        _correlation_engine_instance = CorrelationEngine(config)
    return _correlation_engine_instance