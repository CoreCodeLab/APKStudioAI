"""
Runtime Collector for APKStudioAI 2.1
Aggregates dynamic analysis events from Frida, mitmproxy, and system monitoring.
"""
import json
import subprocess
import threading
import time
from pathlib import Path
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict, deque
from ..config_manager import get_config
from ..logging_setup import get_module_logger

logger = get_module_logger("runtime_collector")


class EventType(Enum):
    """Runtime event types."""
    SYSCALL = "syscall"
    NETWORK = "network"
    FILE_IO = "file_io"
    IPC = "ipc"
    REFLECTION = "reflection"
    DYNAMIC_LOADING = "dynamic_loading"
    CRYPTO = "crypto"
    ANTI_ANALYSIS = "anti_analysis"
    PROCESS = "process"
    THREAD = "thread"
    MEMORY = "memory"
    COMPONENT = "component"


@dataclass
class RuntimeEvent:
    """Single runtime event."""
    id: str
    event_type: EventType
    timestamp: float
    pid: int
    tid: int
    package: str
    data: Dict[str, Any]
    source: str  # "frida", "mitmproxy", "system", "logcat"
    severity: str = "info"  # info, warning, critical


@dataclass
class ProcessInfo:
    """Process information."""
    pid: int
    ppid: int
    name: str
    uid: int
    cmdline: str
    start_time: float


class RuntimeCollector:
    """Collects and aggregates runtime events from multiple sources."""

    def __init__(self, config: Dict = None):
        self.config = config or get_config().get_all()
        self.events: List[RuntimeEvent] = []
        self.event_buffer = deque(maxlen=10000)
        self.callbacks: List[Callable[[RuntimeEvent], None]] = []
        self._lock = threading.Lock()
        self._running = False
        self._collection_threads: List[threading.Thread] = []

        # Event statistics
        self.stats = defaultdict(int)

        # Source integrations
        self.frida_bridge = None
        self.mitmproxy = None
        self.adb_path = self._find_adb()

        # Logcat monitoring
        self.logcat_process: Optional[subprocess.Popen] = None
        self.logcat_thread: Optional[threading.Thread] = None

    def _find_adb(self) -> str:
        """Find ADB executable."""
        import shutil
        return shutil.which("adb") or "adb"

    def start_collection(self, package: str, device_id: str = None,
                         enable_frida: bool = True, enable_mitmproxy: bool = True,
                         enable_logcat: bool = True, enable_syscalls: bool = False) -> bool:
        """Start collecting runtime events."""
        if self._running:
            logger.warning("collector_already_running")
            return True

        self._running = True
        self.events.clear()
        self.event_buffer.clear()
        self.stats.clear()

        # Initialize Frida if enabled
        if enable_frida:
            from .frida_bridge import get_frida_bridge
            self.frida_bridge = get_frida_bridge(self.config)
            if self.frida_bridge.is_available():
                session = self.frida_bridge.attach(package, device_id, spawn=True)
                if session:
                    # Add all pre-built hooks
                    for hook in self.frida_bridge.get_all_hooks():
                        self.frida_bridge.add_hook(session.session_id, hook)
                    # Register event callback
                    self.frida_bridge.register_callback(self._on_frida_event)
                    logger.info("frida_collection_started", package=package)
                else:
                    logger.warning("frida_attach_failed", package=package)

        # Initialize mitmproxy if enabled
        if enable_mitmproxy:
            from .mitmproxy_integration import get_mitmproxy_integration
            self.mitmproxy = get_mitmproxy_integration(self.config)
            if self.mitmproxy.is_available():
                self.mitmproxy.start_proxy(port=8080, ssl_insecure=True)
                logger.info("mitmproxy_collection_started")

        # Start logcat monitoring if enabled
        if enable_logcat:
            self._start_logcat_monitoring(package, device_id)

        # Start syscall tracing if enabled (requires root)
        if enable_syscalls:
            self._start_syscall_tracing(package, device_id)

        logger.info("runtime_collection_started", package=package,
                   frida=enable_frida, mitmproxy=enable_mitmproxy,
                   logcat=enable_logcat, syscalls=enable_syscalls)
        return True

    def stop_collection(self) -> Dict[str, Any]:
        """Stop collection and return summary."""
        self._running = False

        # Stop Frida
        if self.frida_bridge:
            for session_id in list(self.frida_bridge.sessions.keys()):
                self.frida_bridge.detach(session_id)

        # Stop mitmproxy
        if self.mitmproxy:
            self.mitmproxy.stop_proxy()

        # Stop logcat
        if self.logcat_process:
            self.logcat_process.terminate()
        if self.logcat_thread:
            self.logcat_thread.join(timeout=5)

        # Wait for collection threads
        for t in self._collection_threads:
            t.join(timeout=5)

        summary = self.get_summary()
        logger.info("runtime_collection_stopped", **summary)
        return summary

    def _on_frida_event(self, event: Dict):
        """Handle Frida event callback."""
        # Map Frida event types to our EventType
        type_map = {
            "method_entry": EventType.REFLECTION,
            "method_exit": EventType.REFLECTION,
            "constructor": EventType.REFLECTION,
            "native_entry": EventType.SYSCALL,
            "native_exit": EventType.SYSCALL,
        }

        event_type = type_map.get(event.get("type", ""), EventType.REFLECTION)

        runtime_event = RuntimeEvent(
            id=f"frida_{event.get('timestamp', time.time())}_{hash(str(event))}",
            event_type=event_type,
            timestamp=event.get("timestamp", time.time()) / 1000 if event.get("timestamp", 0) > 1e12 else event.get("timestamp", time.time()),
            pid=event.get("pid", 0),
            tid=event.get("tid", 0),
            package=event.get("package", ""),
            data=event,
            source="frida",
            severity=self._determine_severity(event),
        )

        self._add_event(runtime_event)

    def _determine_severity(self, event: Dict) -> str:
        """Determine event severity."""
        critical_keywords = ["exploit", "root", "su ", "debugger", "hook", "inject", "bypass"]
        warning_keywords = ["reflection", "dynamic", "dexclassloader", "loadclass", "crypto", "cipher"]

        event_str = json.dumps(event).lower()

        for kw in critical_keywords:
            if kw in event_str:
                return "critical"
        for kw in warning_keywords:
            if kw in event_str:
                return "warning"
        return "info"

    def _add_event(self, event: RuntimeEvent):
        """Add event to collection."""
        with self._lock:
            self.events.append(event)
            self.event_buffer.append(event)
            self.stats[event.event_type.value] += 1
            self.stats["total"] += 1
            if event.severity == "critical":
                self.stats["critical"] += 1
            elif event.severity == "warning":
                self.stats["warning"] += 1

        # Call callbacks
        for callback in self.callbacks:
            try:
                callback(event)
            except Exception:
                pass

    def _start_logcat_monitoring(self, package: str, device_id: str = None):
        """Start logcat monitoring thread."""
        def logcat_worker():
            cmd = [self.adb_path]
            if device_id:
                cmd.extend(["-s", device_id])
            cmd.extend(["logcat", "-v", "json", f"*:I", f"*:W", f"*:E"])

            try:
                self.logcat_process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )

                for line in iter(self.logcat_process.stdout.readline, b""):
                    if not self._running:
                        break
                    line = line.decode("utf-8").strip()
                    if line:
                        try:
                            log_entry = json.loads(line)
                            if package.lower() in log_entry.get("tag", "").lower() or \
                               package.lower() in log_entry.get("message", "").lower():
                                self._process_logcat_entry(log_entry, package)
                        except json.JSONDecodeError:
                            pass
            except Exception as e:
                logger.error("logcat_error", error=str(e))

        self.logcat_thread = threading.Thread(target=logcat_worker, daemon=True)
        self.logcat_thread.start()
        self._collection_threads.append(self.logcat_thread)

    def _process_logcat_entry(self, entry: Dict, package: str):
        """Process logcat entry."""
        event = RuntimeEvent(
            id=f"logcat_{entry.get('timestamp', time.time())}_{hash(str(entry))}",
            event_type=EventType.PROCESS,
            timestamp=time.time(),
            pid=entry.get("pid", 0),
            tid=entry.get("tid", 0),
            package=package,
            data=entry,
            source="logcat",
            severity="warning" if entry.get("level", "").upper() in ["W", "E"] else "info",
        )
        self._add_event(event)

    def _start_syscall_tracing(self, package: str, device_id: str = None):
        """Start syscall tracing (requires root)."""
        # This would use strace or similar - placeholder for root-required tracing
        logger.info("syscall_tracing_not_implemented", note="Requires root/strace")

    def register_callback(self, callback: Callable[[RuntimeEvent], None]):
        """Register event callback."""
        self.callbacks.append(callback)

    def get_events(self, event_type: EventType = None, since: float = 0,
                   severity: str = None, limit: int = 1000) -> List[RuntimeEvent]:
        """Get filtered events."""
        with self._lock:
            events = list(self.events)

        if event_type:
            events = [e for e in events if e.event_type == event_type]
        if since:
            events = [e for e in events if e.timestamp > since]
        if severity:
            events = [e for e in events if e.severity == severity]

        return events[-limit:]

    def get_events_by_type(self) -> Dict[str, List[RuntimeEvent]]:
        """Get events grouped by type."""
        with self._lock:
            events = list(self.events)

        grouped = defaultdict(list)
        for event in events:
            grouped[event.event_type.value].append(event)
        return dict(grouped)

    def get_recent_events(self, seconds: float = 60, limit: int = 100) -> List[RuntimeEvent]:
        """Get events from the last N seconds."""
        since = time.time() - seconds
        return self.get_events(since=since, limit=limit)

    def get_summary(self) -> Dict[str, Any]:
        """Get collection summary."""
        with self._lock:
            stats = dict(self.stats)
            event_count = len(self.events)

        # Get mitmproxy analysis if available
        traffic_analysis = {}
        if self.mitmproxy:
            try:
                flows = self.mitmproxy.get_flows()
                traffic_analysis = self.mitmproxy.analyze_traffic(flows)
            except Exception:
                pass

        # Get Frida events if available
        frida_summary = {}
        if self.frida_bridge:
            for session_id, session in self.frida_bridge.sessions.items():
                frida_summary[session_id] = {
                    "hooks": len(session.hooks),
                    "events": len(session.events),
                }

        return {
            "total_events": event_count,
            "stats": stats,
            "traffic_analysis": traffic_analysis,
            "frida_sessions": frida_summary,
            "collection_duration": time.time() - (self.events[0].timestamp if self.events else time.time()),
        }

    def export_events(self, output_path: str, format: str = "json") -> bool:
        """Export events to file."""
        with self._lock:
            events = list(self.events)

        try:
            if format == "json":
                data = [self._event_to_dict(e) for e in events]
                with open(output_path, "w") as f:
                    json.dump(data, f, indent=2)
            elif format == "csv":
                import csv
                with open(output_path, "w", newline="") as f:
                    writer = csv.writer(f)
                    writer.writerow(["id", "type", "timestamp", "pid", "tid", "package", "severity", "source", "data"])
                    for e in events:
                        writer.writerow([
                            e.id, e.event_type.value, e.timestamp, e.pid, e.tid,
                            e.package, e.severity, e.source, json.dumps(e.data)
                        ])
            return True
        except Exception as e:
            logger.error("export_error", error=str(e))
            return False

    def _event_to_dict(self, event: RuntimeEvent) -> Dict:
        """Convert event to dictionary."""
        return {
            "id": event.id,
            "event_type": event.event_type.value,
            "timestamp": event.timestamp,
            "pid": event.pid,
            "tid": event.tid,
            "package": event.package,
            "data": event.data,
            "source": event.source,
            "severity": event.severity,
        }

    def search_events(self, query: str, fields: List[str] = None) -> List[RuntimeEvent]:
        """Search events by text query."""
        with self._lock:
            events = list(self.events)

        query_lower = query.lower()
        results = []

        for event in events:
            search_text = json.dumps(event.data).lower()
            if query_lower in search_text:
                results.append(event)
            elif fields:
                for field in fields:
                    if field in event.data and query_lower in str(event.data[field]).lower():
                        results.append(event)
                        break

        return results

    def get_timeline(self, interval_seconds: float = 10) -> List[Dict]:
        """Get event timeline grouped by time intervals."""
        with self._lock:
            events = list(self.events)

        if not events:
            return []

        start_time = min(e.timestamp for e in events)
        end_time = max(e.timestamp for e in events)

        timeline = []
        current = start_time
        while current < end_time:
            interval_end = current + interval_seconds
            interval_events = [e for e in events if current <= e.timestamp < interval_end]

            type_counts = defaultdict(int)
            severity_counts = defaultdict(int)
            for e in interval_events:
                type_counts[e.event_type.value] += 1
                severity_counts[e.severity] += 1

            timeline.append({
                "interval_start": current,
                "interval_end": interval_end,
                "event_count": len(interval_events),
                "type_counts": dict(type_counts),
                "severity_counts": dict(severity_counts),
            })
            current = interval_end

        return timeline

    def clear(self):
        """Clear collected events."""
        with self._lock:
            self.events.clear()
            self.event_buffer.clear()
            self.stats.clear()


_runtime_collector_instance = None


def get_runtime_collector(config: Dict = None) -> RuntimeCollector:
    """Get singleton runtime collector instance."""
    global _runtime_collector_instance
    if _runtime_collector_instance is None:
        _runtime_collector_instance = RuntimeCollector(config)
    return _runtime_collector_instance