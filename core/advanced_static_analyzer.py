"""
Advanced Static Analysis for APKStudioAI 2.1
Includes: Call graphs, Control Flow Graphs, Taint Analysis, YARA Integration,
ICC Analysis, Obfuscation Detection, Reflection Resolution, Dynamic Code Loading Analysis
"""
import hashlib
import json
import os
import re
import shutil
import tempfile
from pathlib import Path
from typing import Dict, List, Any, Optional, Set, Tuple
from collections import defaultdict, deque
from dataclasses import dataclass, field
import networkx as nx

from .config_manager import get_config
from .utils import calculate_sha256, run_command
from .dex_bytecode_analyzer import DEXBytecodeAnalyzer
from .logging_setup import get_module_logger

logger = get_module_logger("advanced_static")


def _find_yara() -> Optional[str]:
    """Find yara executable."""
    for path in ["yara", "/usr/bin/yara", "/usr/local/bin/yara", "yara64.exe", "yara.exe"]:
        if shutil.which(path):
            return path
    return None


def _find_flowdroid() -> Optional[str]:
    """Find FlowDroid executable or JAR."""
    # Check for FlowDroid JAR
    for path in [
        "/opt/flowdroid/soot-infoflow-cmd.jar",
        "/usr/local/bin/flowdroid",
        os.path.expanduser("~/flowdroid/soot-infoflow-cmd.jar"),
        "flowdroid"
    ]:
        if shutil.which(path) or Path(path).exists():
            return path
    return None


def _find_yara() -> Optional[str]:
    """Find yara executable."""
    for path in ["yara", "/usr/bin/yara", "/usr/local/bin/yara", "yara64.exe", "yara.exe"]:
        if shutil.which(path):
            return path
    return None


@dataclass
class CallGraphNode:
    """Represents a method in the call graph."""
    method_id: str
    class_name: str
    method_name: str
    signature: str
    is_native: bool = False
    is_entry_point: bool = False
    is_sensitive: bool = False
    metadata: Dict = field(default_factory=dict)


@dataclass
class CFGBlock:
    """Represents a basic block in control flow graph."""
    block_id: int
    start_pc: int
    end_pc: int
    instructions: List[Dict]
    predecessors: List[int] = field(default_factory=list)
    successors: List[int] = field(default_factory=list)
    is_entry: bool = False
    is_exit: bool = False


class CallGraphAnalyzer:
    """Builds and analyzes method call graphs."""

    def __init__(self, config: Dict = None):
        self.config = config or {}
        self.max_nodes = self.config.get("max_call_graph_nodes", 10000)
        self.max_edges = self.config.get("max_call_graph_edges", 50000)
        self.call_graph = nx.DiGraph()
        self.method_map = {}  # method_id -> CallGraphNode

    def _normalize_class_name(self, class_name: str) -> str:
        """Normalize DEX class name (Lcom/example/Class;) to standard format (com.example.Class)."""
        if class_name.startswith('L') and class_name.endswith(';'):
            return class_name[1:-1].replace('/', '.')
        return class_name.replace('/', '.')

    def build_from_dex_analysis(self, dex_analysis: Dict) -> nx.DiGraph:
        """Build call graph from DEX bytecode analysis."""
        self.call_graph.clear()
        self.method_map.clear()

        api_calls = dex_analysis.get("api_calls", [])

        # First pass: create nodes for all methods
        for call in api_calls:
            class_name = call.get("class", "")
            method_name = call.get("method", "")
            call_str = call.get("call", "")

            if not class_name or not method_name:
                continue

            # Normalize class name for consistent method IDs
            norm_class = self._normalize_class_name(class_name)
            method_id = f"{norm_class}.{method_name}"
            if method_id not in self.method_map:
                node = CallGraphNode(
                    method_id=method_id,
                    class_name=norm_class,
                    method_name=method_name,
                    signature=call_str,
                    is_native=call.get("is_native", False)
                )
                # Mark sensitive APIs
                if self._is_sensitive_api(call_str):
                    node.is_sensitive = True
                # Mark entry points (onCreate, onStart, etc.)
                if self._is_entry_point(method_name):
                    node.is_entry_point = True
                self.method_map[method_id] = node
                self.call_graph.add_node(method_id, data=node)

        # Second pass: build edges from bytecode analysis
        # We need to analyze the bytecode to find actual calls
        # For now, use the api_calls as edges
        for call in api_calls:
            caller_class = call.get("class", "")
            caller_method = call.get("method", "")
            call_str = call.get("call", "")

            if not caller_class or not caller_method:
                continue

            # Normalize caller class name
            caller_id = f"{self._normalize_class_name(caller_class)}.{caller_method}"

            # Parse callee from call_str (format: Lclass;.method(sig))
            callee_id = self._parse_callee_id(call_str)
            if callee_id:
                # Ensure callee node exists (even if not a caller in our data)
                if callee_id not in self.method_map:
                    # Parse class and method from callee_id
                    parts = callee_id.rsplit('.', 1)
                    if len(parts) == 2:
                        callee_class, callee_method = parts
                        node = CallGraphNode(
                            method_id=callee_id,
                            class_name=callee_class,
                            method_name=callee_method,
                            signature=call_str,
                            is_native=False
                        )
                        if self._is_sensitive_api(call_str):
                            node.is_sensitive = True
                        self.method_map[callee_id] = node
                        self.call_graph.add_node(callee_id, data=node)
                self.call_graph.add_edge(caller_id, callee_id)

        # Limit graph size
        if len(self.call_graph.nodes()) > self.max_nodes:
            # Keep only sensitive and entry point nodes plus their neighbors
            important_nodes = set()
            for node_id, node in self.method_map.items():
                if node.is_sensitive or node.is_entry_point:
                    important_nodes.add(node_id)
                    # Add neighbors
                    important_nodes.update(self.call_graph.predecessors(node_id))
                    important_nodes.update(self.call_graph.successors(node_id))

            self.call_graph = self.call_graph.subgraph(important_nodes).copy()

        return self.call_graph

    def _parse_callee_id(self, call_str: str) -> Optional[str]:
        """Parse callee method ID from call string."""
        # Format: Lclass;.method(sig) -> class.method
        if not call_str:
            return None
        try:
            # Remove signature part
            if '(' in call_str:
                call_str = call_str[:call_str.index('(')]
            # Convert Lclass; to class
            if call_str.startswith('L') and ';' in call_str:
                class_part = call_str[1:call_str.index(';')].replace('/', '.')
                method_part = call_str[call_str.index(';')+1:]
                # Remove leading dot from method part if present
                if method_part.startswith('.'):
                    method_part = method_part[1:]
                return f"{class_part}.{method_part}"
            return call_str
        except Exception:
            return None

    def _is_sensitive_api(self, call_str: str) -> bool:
        """Check if API call is sensitive."""
        sensitive_patterns = [
            "Runtime.exec", "ProcessBuilder", "loadLibrary", "load",
            "DexClassLoader", "PathClassLoader", "InMemoryDexClassLoader",
            "Class.forName", "Method.invoke", "Field.set",
            "addJavascriptInterface", "setJavaScriptEnabled",
            "sendTextMessage", "sendMultipartTextMessage",
            "getDeviceId", "getSubscriberId", "getSimSerialNumber",
            "Cipher.getInstance", "MessageDigest.getInstance",
            "HttpURLConnection", "OkHttpClient", "WebSocket",
            "Socket", "ServerSocket", "DatagramSocket",
            "DevicePolicyManager", "DeviceAdminReceiver",
            "VpnService", "MediaProjection", "AccessibilityService",
            "isDebuggerConnected", "waitingForDebugger"
        ]
        return any(pattern in call_str for pattern in sensitive_patterns)

    def _is_entry_point(self, method_name: str) -> bool:
        """Check if method is an Android entry point."""
        entry_points = [
            "onCreate", "onStart", "onResume", "onPause", "onStop", "onDestroy",
            "onReceive", "onBind", "onStartCommand", "onHandleIntent",
            "onServiceConnected", "onServiceDisconnected",
            "onActivityResult", "onRequestPermissionsResult",
            "onNewIntent", "onConfigurationChanged",
            "run", "call", "execute", "doInBackground"
        ]
        return any(ep in method_name for ep in entry_points)

    def find_paths_to_sensitive(self, max_depth: int = 10) -> List[List[str]]:
        """Find all paths from entry points to sensitive APIs."""
        paths = []
        entry_points = [n for n, d in self.call_graph.nodes(data=True)
                       if d.get('data', CallGraphNode('', '', '', '')).is_entry_point]
        sensitive_nodes = [n for n, d in self.call_graph.nodes(data=True)
                          if d.get('data', CallGraphNode('', '', '', '')).is_sensitive]

        for entry in entry_points:
            for sensitive in sensitive_nodes:
                try:
                    for path in nx.all_simple_paths(self.call_graph, entry, sensitive, cutoff=max_depth):
                        paths.append(path)
                except nx.NetworkXNoPath:
                    pass

        return paths[:100]  # Limit

    def get_statistics(self) -> Dict[str, Any]:
        """Get call graph statistics."""
        return {
            "nodes": self.call_graph.number_of_nodes(),
            "edges": self.call_graph.number_of_edges(),
            "entry_points": sum(1 for n, d in self.call_graph.nodes(data=True)
                              if d.get('data', CallGraphNode('', '', '', '')).is_entry_point),
            "sensitive_apis": sum(1 for n, d in self.call_graph.nodes(data=True)
                                if d.get('data', CallGraphNode('', '', '', '')).is_sensitive),
            "native_methods": sum(1 for n, d in self.call_graph.nodes(data=True)
                                if d.get('data', CallGraphNode('', '', '', '')).is_native),
            "connected_components": nx.number_weakly_connected_components(self.call_graph),
            "density": nx.density(self.call_graph) if self.call_graph.number_of_nodes() > 0 else 0
        }

    def export_dot(self) -> str:
        """Export call graph as DOT format."""
        return nx.nx_pydot.to_pydot(self.call_graph).to_string()


class CFGBuilder:
    """Builds Control Flow Graphs from DEX bytecode."""

    def __init__(self, config: Dict = None):
        self.config = config or {}
        self.max_blocks = self.config.get("max_cfg_blocks", 5000)

    def build_from_method(self, method_bytecode: Dict) -> nx.DiGraph:
        """Build CFG from a single method's bytecode."""
        cfg = nx.DiGraph()
        instructions = method_bytecode.get("instructions", [])

        if not instructions:
            return cfg

        # Identify basic block boundaries
        block_boundaries = self._find_block_boundaries(instructions)

        # Create blocks
        blocks = []
        for i, (start_pc, end_pc) in enumerate(block_boundaries):
            block_instrs = [ins for ins in instructions if start_pc <= ins.get("pc", 0) < end_pc]
            block = CFGBlock(
                block_id=i,
                start_pc=start_pc,
                end_pc=end_pc,
                instructions=block_instrs,
                is_entry=(i == 0),
                is_exit=(i == len(block_boundaries) - 1)
            )
            blocks.append(block)
            cfg.add_node(i, data=block)

        # Build edges based on control flow
        for i, block in enumerate(blocks):
            self._add_cfg_edges(cfg, block, blocks, i, instructions)

        return cfg

    def _find_block_boundaries(self, instructions: List[Dict]) -> List[Tuple[int, int]]:
        """Find basic block boundaries from instructions."""
        if not instructions:
            return []

        boundaries = set()
        boundaries.add(instructions[0].get("pc", 0))

        # Instructions that end a block
        branch_opcodes = {
            "if-eq", "if-ne", "if-lt", "if-ge", "if-gt", "if-le",
            "if-eqz", "if-nez", "if-ltz", "if-gez", "if-gtz", "if-lez",
            "goto", "goto/16", "goto/32",
            "return", "return-wide", "return-object", "return-void",
            "throw", "return-void"
        }

        switch_opcodes = {"packed-switch", "sparse-switch"}

        for ins in instructions:
            name = ins.get("name", "")
            pc = ins.get("pc", 0)

            if name in branch_opcodes or name in switch_opcodes:
                # Next instruction starts a new block
                next_idx = instructions.index(ins) + 1
                if next_idx < len(instructions):
                    boundaries.add(instructions[next_idx].get("pc", 0))
                # Target also starts a block
                if name in switch_opcodes:
                    pass  # Switch targets handled separately

            # Exception handlers would also start blocks
            # (would need tries data from code_item)

        sorted_pcs = sorted(boundaries)
        block_ranges = []
        for i in range(len(sorted_pcs)):
            start = sorted_pcs[i]
            end = sorted_pcs[i + 1] if i + 1 < len(sorted_pcs) else instructions[-1].get("pc", 0) + 1
            block_ranges.append((start, end))

        return block_ranges

    def _add_cfg_edges(self, cfg: nx.DiGraph, block: CFGBlock,
                       blocks: List[CFGBlock], block_idx: int,
                       all_instructions: List[Dict]):
        """Add control flow edges for a block."""
        if not block.instructions:
            return

        last_ins = block.instructions[-1]
        name = last_ins.get("name", "")
        pc = last_ins.get("pc", 0)

        # Unconditional branch
        if name in ["goto", "goto/16", "goto/32"]:
            target_pc = self._get_branch_target(last_ins)
            if target_pc is not None:
                target_block = self._find_block_for_pc(blocks, target_pc)
                if target_block is not None:
                    cfg.add_edge(block.block_id, target_block.block_id)

        # Conditional branch
        elif name in ["if-eq", "if-ne", "if-lt", "if-ge", "if-gt", "if-le",
                      "if-eqz", "if-nez", "if-ltz", "if-gez", "if-gtz", "if-lez"]:
            target_pc = self._get_branch_target(last_ins)
            if target_pc is not None:
                target_block = self._find_block_for_pc(blocks, target_pc)
                if target_block is not None:
                    cfg.add_edge(block.block_id, target_block.block_id)
            # Fall through to next block
            if block_idx + 1 < len(blocks):
                cfg.add_edge(block.block_id, block_idx + 1)

        # Return/throw - exit block
        elif name in ["return", "return-wide", "return-object", "return-void", "throw"]:
            pass  # No successors

        # Switch statements
        elif name in ["packed-switch", "sparse-switch"]:
            # Would need to parse switch data
            pass

        # Normal fall-through
        else:
            if block_idx + 1 < len(blocks):
                cfg.add_edge(block.block_id, block_idx + 1)

    def _get_branch_target(self, ins: Dict) -> Optional[int]:
        """Extract branch target PC from instruction."""
        # This is simplified - real implementation would parse the actual bytecode
        # For now, we'd need the raw bytecode data
        return None

    def _find_block_for_pc(self, blocks: List[CFGBlock], pc: int) -> Optional[CFGBlock]:
        """Find block containing given PC."""
        for block in blocks:
            if block.start_pc <= pc < block.end_pc:
                return block
        return None

    def analyze_complexity(self, cfg: nx.DiGraph) -> Dict[str, Any]:
        """Calculate cyclomatic complexity and other metrics."""
        if cfg.number_of_nodes() == 0:
            return {"cyclomatic_complexity": 0, "max_depth": 0, "num_blocks": 0}

        # Cyclomatic complexity = E - N + 2P (for single component)
        edges = cfg.number_of_edges()
        nodes = cfg.number_of_nodes()
        components = nx.number_weakly_connected_components(cfg)

        complexity = edges - nodes + 2 * components

        # Max depth from entry
        entry_nodes = [n for n, d in cfg.nodes(data=True) if d.get('data', CFGBlock(0,0,0,[])).is_entry]
        max_depth = 0
        for entry in entry_nodes:
            try:
                lengths = nx.single_source_shortest_path_length(cfg, entry)
                max_depth = max(max_depth, max(lengths.values()) if lengths else 0)
            except Exception:
                pass

        return {
            "cyclomatic_complexity": complexity,
            "max_depth": max_depth,
            "num_blocks": nodes,
            "num_edges": edges,
            "components": components
        }


class TaintAnalyzer:
    """Performs taint analysis to track data flow from sources to sinks."""

    def __init__(self, config: Dict = None):
        self.config = config or {}
        self.max_paths = self.config.get("max_taint_paths", 100)

        # Define source and sink patterns
        self.sources = {
            "device_id": ["getDeviceId", "getSubscriberId", "getSimSerialNumber",
                         "getImei", "getMeid", "getSerial"],
            "location": ["getLastKnownLocation", "requestLocationUpdates",
                        "getLatitude", "getLongitude"],
            "contacts": ["query", "getContentResolver", "ContactsContract"],
            "sms": ["getMessageBody", "getOriginatingAddress", "PDU"],
            "network": ["openConnection", "getInputStream", "getOutputStream"],
            "file": ["openFileInput", "openFileOutput", "getCacheDir", "getFilesDir"],
            "intent": ["getIntent", "getExtras", "getData", "getAction"],
            "system": ["getSystemService", "getPackageManager", "getApplicationContext"]
        }

        self.sinks = {
            "network_send": ["write", "sendTextMessage", "sendMultipartTextMessage", "connect",
                            "HttpURLConnection", "OkHttpClient", "WebSocket", "getOutputStream"],
            "file_write": ["FileOutputStream", "openFileOutput", "write"],
            "sms_send": ["sendTextMessage", "sendMultipartTextMessage"],
            "log": ["Log.d", "Log.i", "Log.w", "Log.e", "Log.v", "System.out.println"],
            "intent_send": ["startActivity", "sendBroadcast", "startService", "sendOrderedBroadcast"],
            "exec": ["exec", "ProcessBuilder", "Runtime.getRuntime"],
            "crypto": ["Cipher.init", "Cipher.doFinal", "MessageDigest.digest"],
            "reflection": ["Method.invoke", "Field.set", "Constructor.newInstance"]
        }

    def _normalize_class_name(self, class_name: str) -> str:
        """Normalize DEX class name (Lcom/example/Class;) to standard format (com.example.Class)."""
        if class_name.startswith('L') and class_name.endswith(';'):
            return class_name[1:-1].replace('/', '.')
        return class_name.replace('/', '.')

    def analyze(self, dex_analysis: Dict, call_graph: nx.DiGraph) -> Dict[str, Any]:
        """Perform taint analysis using call graph and DEX analysis."""
        api_calls = dex_analysis.get("api_calls", [])

        # Build method info map
        method_info = {}
        for call in api_calls:
            class_name = call.get("class", "")
            method_name = call.get("method", "")
            call_str = call.get("call", "")

            if not class_name or not method_name:
                continue

            # Normalize class name for consistent method IDs
            norm_class = self._normalize_class_name(class_name)
            method_id = f"{norm_class}.{method_name}"
            if method_id not in method_info:
                method_info[method_id] = {
                    "calls": [],
                    "is_source": False,
                    "is_sink": False,
                    "source_types": [],
                    "sink_types": []
                }

            method_info[method_id]["calls"].append(call_str)

            # Check if this call is a source
            for source_type, patterns in self.sources.items():
                if any(p in call_str for p in patterns):
                    method_info[method_id]["is_source"] = True
                    if source_type not in method_info[method_id]["source_types"]:
                        method_info[method_id]["source_types"].append(source_type)

            # Check if this call is a sink
            for sink_type, patterns in self.sinks.items():
                if any(p in call_str for p in patterns):
                    method_info[method_id]["is_sink"] = True
                    if sink_type not in method_info[method_id]["sink_types"]:
                        method_info[method_id]["sink_types"].append(sink_type)

        # Propagate taint through call graph
        taint_results = self._propagate_taint(method_info, call_graph)

        return {
            "tainted_methods": taint_results["tainted"],
            "source_to_sink_paths": taint_results["paths"][:self.max_paths],
            "statistics": taint_results["stats"]
        }

    def _propagate_taint(self, method_info: Dict, call_graph: nx.DiGraph) -> Dict:
        """Propagate taint from sources through call graph to sinks."""
        # Find source methods
        sources = [m for m, info in method_info.items() if info["is_source"]]
        sinks = [m for m, info in method_info.items() if info["is_sink"]]

        tainted = set()
        paths = []
        stats = {
            "total_sources": len(sources),
            "total_sinks": len(sinks),
            "tainted_methods": 0,
            "source_sink_paths": 0
        }

        # Forward propagation from sources
        for source in sources:
            if source in call_graph:
                try:
                    # BFS from source
                    visited = set()
                    queue = deque([(source, [source])])

                    while queue and len(paths) < self.max_paths:
                        current, path = queue.popleft()

                        if current in visited:
                            continue
                        visited.add(current)

                        # Mark as tainted
                        tainted.add(current)

                        # Check if we reached a sink
                        if current in sinks:
                            paths.append({
                                "source": source,
                                "sink": current,
                                "path": path,
                                "source_types": method_info[source]["source_types"],
                                "sink_types": method_info[current]["sink_types"],
                                "direct_flow": source == current
                            })
                            stats["source_sink_paths"] += 1

                        # Continue propagation
                        for succ in call_graph.successors(current):
                            if succ not in visited:
                                queue.append((succ, path + [succ]))

                except Exception:
                    pass

        stats["tainted_methods"] = len(tainted)

        return {
            "tainted": list(tainted),
            "paths": paths,
            "stats": stats
        }

    def get_taint_summary(self, taint_results: Dict) -> List[Dict]:
        """Get human-readable taint flow summaries."""
        summaries = []
        for path_info in taint_results.get("source_to_sink_paths", []):
            is_direct = path_info.get("direct_flow", False)
            summaries.append({
                "description": f"Data flows from {path_info['source']} to {path_info['sink']}",
                "source_types": path_info["source_types"],
                "sink_types": path_info["sink_types"],
                "path_length": len(path_info["path"]),
                "path": " -> ".join(path_info["path"][:10]) + ("..." if len(path_info["path"]) > 10 else ""),
                "direct_flow": is_direct,
                "flow_type": "direct" if is_direct else "multi-hop"
            })
        return summaries


class YARAScanner:
    """Integrates YARA pattern matching for malware detection."""

    def __init__(self, config: Dict = None):
        self.config = config or {}
        found_yara = _find_yara()
        config_yara = self.config.get("tools", {}).get("yara_path")
        self.yara_path = found_yara or config_yara
        self.rules_dir = Path(self.config.get("yara_rules_dir", "./yara_rules"))
        self.rules_dir.mkdir(parents=True, exist_ok=True)
        # Only available if we actually found a working yara binary
        self.yara_available = found_yara is not None
        if self.yara_available:
            self._compile_rules()
        else:
            self.compiled_rules = None
            self._create_default_rules()  # Still create rules for reference

    def _compile_rules(self):
        """Compile YARA rules from rules directory."""
        self.compiled_rules = None
        self.rule_files = list(self.rules_dir.glob("*.yar")) + list(self.rules_dir.glob("*.yara"))

        if not self.rule_files:
            # Create default rules if none exist
            self._create_default_rules()
            self.rule_files = list(self.rules_dir.glob("*.yar")) + list(self.rules_dir.glob("*.yara"))

        if self.rule_files:
            try:
                # Combine all rules into a single file for compilation
                combined = self.rules_dir / "_combined.yar"
                with open(combined, "w") as f:
                    for rf in self.rule_files:
                        f.write(f'include "{rf.name}"\n')

                # Test compilation
                result = run_command([self.yara_path, "-c", str(combined), "/dev/null"], timeout=30)
                if result["success"]:
                    self.compiled_rules = combined
            except Exception:
                pass

    def _create_default_rules(self):
        """Create default YARA rules for Android malware."""
        default_rules = '''
rule Android_Trojan_Generic {
    meta:
        description = "Generic Android trojan indicators"
        author = "APKStudioAI"
        severity = "high"
    strings:
        $send_sms = "sendTextMessage" ascii
        $device_id = "getDeviceId" ascii
        $runtime_exec = "Runtime.getRuntime().exec" ascii
        $dex_loader = "DexClassLoader" ascii
        $crypto = "Cipher.getInstance" ascii
        $http = "HttpURLConnection" ascii
        $websocket = "WebSocket" ascii
        $reflection = "Class.forName" ascii
        $accessibility = "AccessibilityService" ascii
        $vpn = "VpnService" ascii
    condition:
        3 of them
}

rule Android_Spyware {
    meta:
        description = "Android spyware indicators"
        author = "APKStudioAI"
        severity = "critical"
    strings:
        $record_audio = "MediaRecorder" ascii
        $camera = "Camera.open" ascii
        $location = "LocationManager" ascii
        $contacts = "ContactsContract" ascii
        $sms_read = "content://sms" ascii
        $call_log = "CallLog.Calls" ascii
        $keylogger = "onKeyDown" ascii
        $screen_capture = "MediaProjection" ascii
    condition:
        2 of them
}

rule Android_Ransomware {
    meta:
        description = "Android ransomware indicators"
        author = "APKStudioAI"
        severity = "critical"
    strings:
        $encrypt = "Cipher.init" ascii
        $encrypt2 = "Cipher.doFinal" ascii
        $file_enum = "listFiles" ascii
        $delete = "delete" ascii
        $lock_screen = "DevicePolicyManager.lockNow" ascii
        $reset_pass = "DevicePolicyManager.resetPassword" ascii
        $wipe = "DevicePolicyManager.wipeData" ascii
        $bitcoin = "bitcoin" ascii nocase
        $ransom = "ransom" ascii nocase
    condition:
        3 of them
}

rule Android_Banking_Trojan {
    meta:
        description = "Android banking trojan indicators"
        author = "APKStudioAI"
        severity = "critical"
    strings:
        $overlay = "SYSTEM_ALERT_WINDOW" ascii
        $accessibility = "AccessibilityService" ascii
        $keylog = "onAccessibilityEvent" ascii
        $sms_intercept = "abortBroadcast" ascii
        $ussd = "USSD" ascii
        $bank = "bank" ascii nocase
        $login = "login" ascii nocase
        $credential = "credential" ascii nocase
        $webview = "addJavascriptInterface" ascii
    condition:
        3 of them
}

rule Android_Dropper {
    meta:
        description = "Android dropper/downloader indicators"
        author = "APKStudioAI"
        severity = "high"
    strings:
        $download = "download" ascii
        $exec = "exec" ascii
        $load_dex = "loadDex" ascii
        $dex_class_loader = "DexClassLoader" ascii
        $path_class_loader = "PathClassLoader" ascii
        $write_file = "FileOutputStream" ascii
        $chmod = "chmod" ascii
        $install = "installPackage" ascii
    condition:
        3 of them
}

rule Android_Adware {
    meta:
        description = "Android adware indicators"
        author = "APKStudioAI"
        severity = "medium"
    strings:
        $ad_sdk = "AdView" ascii
        $interstitial = "InterstitialAd" ascii
        $rewarded = "RewardedAd" ascii
        $ad_request = "AdRequest" ascii
        $ad_mob = "AdMob" ascii
        $ad_size = "AdSize" ascii
        $load_ad = "loadAd" ascii
    condition:
        2 of them
}

rule Android_Root_Exploit {
    meta:
        description = "Android root exploit indicators"
        author = "APKStudioAI"
        severity = "critical"
    strings:
        $su = "/system/bin/su" ascii
        $su2 = "/system/xbin/su" ascii
        $root = "ROOT" ascii
        $exploit = "exploit" ascii nocase
        $dirtycow = "dirtycow" ascii nocase
        $cve = "CVE-" ascii
        $kernel = "kernel" ascii
        $privilege = "privilege" ascii nocase
        $escalation = "escalation" ascii nocase
    condition:
        2 of them
}

rule Suspicious_Native_Code {
    meta:
        description = "Suspicious native code patterns"
        author = "APKStudioAI"
        severity = "high"
    strings:
        $jni_onload = "JNI_OnLoad" ascii
        $system_load = "System.loadLibrary" ascii
        $system_load2 = "System.load" ascii
        $dlopen = "dlopen" ascii
        $dlsym = "dlsym" ascii
        $mprotect = "mprotect" ascii
        $mmap = "mmap" ascii
        $ptrace = "ptrace" ascii
        $anti_debug = "anti_debug" ascii nocase
    condition:
        2 of them
}
'''
        rules_file = self.rules_dir / "default_rules.yar"
        with open(rules_file, "w") as f:
            f.write(default_rules)

    def scan_file(self, file_path: Path) -> List[Dict]:
        """Scan a file with YARA rules."""
        if not self.compiled_rules:
            return []

        results = []
        try:
            result = run_command([
                self.yara_path, "-r", str(self.compiled_rules), str(file_path)
            ], timeout=60)

            if result["success"] and result["stdout"]:
                for line in result["stdout"].strip().split("\n"):
                    if line:
                        parts = line.split(" ", 1)
                        if len(parts) >= 2:
                            rule_name = parts[0]
                            file_matched = parts[1]
                            results.append({
                                "rule": rule_name,
                                "file": file_matched,
                                "matched": True
                            })
        except Exception as e:
            results.append({"error": str(e)})

        return results

    def scan_strings(self, strings: List[str]) -> List[Dict]:
        """Scan extracted strings with YARA."""
        # Write strings to temp file and scan
        results = []
        try:
            with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
                for s in strings[:10000]:  # Limit
                    f.write(s + "\n")
                temp_file = f.name

            try:
                result = run_command([
                    self.yara_path, "-r", str(self.compiled_rules), temp_file
                ], timeout=60)

                if result["success"] and result["stdout"]:
                    for line in result["stdout"].strip().split("\n"):
                        if line:
                            parts = line.split(" ", 1)
                            if len(parts) >= 2:
                                results.append({
                                    "rule": parts[0],
                                    "matched": True
                                })
            finally:
                os.unlink(temp_file)
        except Exception as e:
            results.append({"error": str(e)})

        return results

    def add_custom_rule(self, name: str, rule_content: str) -> bool:
        """Add a custom YARA rule."""
        try:
            rule_file = self.rules_dir / f"{name}.yar"
            with open(rule_file, "w") as f:
                f.write(rule_content)
            self._compile_rules()
            return True
        except Exception:
            return False


class AdvancedStaticAnalyzer:
    """Main orchestrator for advanced static analysis."""

    def __init__(self, config: Dict = None):
        self.config = config or get_config().get_all()
        self.call_graph_analyzer = CallGraphAnalyzer(self.config.get("advanced_static", {}))
        self.cfg_builder = CFGBuilder(self.config.get("advanced_static", {}))
        self.taint_analyzer = TaintAnalyzer(self.config.get("advanced_static", {}))
        self.yara_scanner = YARAScanner(self.config)

    def analyze(self, dex_analysis: Dict, extracted_dir: Path = None,
                apk_path: Path = None, strings: List[str] = None) -> Dict[str, Any]:
        """Run all advanced static analyses."""
        results = {}

        # 1. Call Graph Analysis
        print("Building call graph...")
        call_graph = self.call_graph_analyzer.build_from_dex_analysis(dex_analysis)
        results["call_graph"] = {
            "statistics": self.call_graph_analyzer.get_statistics(),
            "sensitive_paths": self.call_graph_analyzer.find_paths_to_sensitive(),
            "dot_export": self.call_graph_analyzer.export_dot() if call_graph.number_of_nodes() < 1000 else None
        }

        # 2. CFG Analysis (sample key methods)
        print("Building CFGs for key methods...")
        cfg_results = {}
        api_calls = dex_analysis.get("api_calls", [])
        for call in api_calls[:20]:  # Sample first 20
            method_name = call.get("method", "")
            if self.call_graph_analyzer._is_entry_point(method_name) or \
               self.call_graph_analyzer._is_sensitive_api(call.get("call", "")):
                # Would need actual bytecode for this method
                pass

        results["cfg"] = cfg_results

        # 3. Taint Analysis
        print("Performing taint analysis...")
        taint_results = self.taint_analyzer.analyze(dex_analysis, call_graph)
        results["taint"] = {
            "summary": self.taint_analyzer.get_taint_summary(taint_results),
            "statistics": taint_results["statistics"]
        }

        # 4. YARA Scanning
        print("Scanning with YARA...")
        yara_results = []
        if self.yara_scanner.yara_available:
            if apk_path and apk_path.exists():
                yara_results.extend(self.yara_scanner.scan_file(apk_path))
            if extracted_dir and extracted_dir.exists():
                for f in extracted_dir.rglob("*"):
                    if f.is_file() and f.suffix in [".dex", ".so", ".jar", ".class"]:
                        yara_results.extend(self.yara_scanner.scan_file(f))
            if strings:
                yara_results.extend(self.yara_scanner.scan_strings(strings))
        else:
            yara_results.append({"status": "yara_not_available", "message": "YARA binary not found. Install yara for pattern matching."})

        results["yara"] = {
            "matches": yara_results,
            "total_matches": len([r for r in yara_results if r.get("matched")]),
            "yara_available": self.yara_scanner.yara_available
        }

        return results


# ============================================================
# ICC ANALYZER - Inter-Component Communication
# ============================================================

@dataclass
class ICCEdge:
    """Represents an ICC connection between components."""
    source_component: str
    source_type: str  # activity, service, receiver, provider
    target_component: str
    target_type: str
    intent_action: Optional[str] = None
    intent_data: Optional[str] = None
    intent_category: Optional[List[str]] = None
    is_explicit: bool = False
    is_exported: bool = False
    permission: Optional[str] = None
    extras: Dict[str, Any] = field(default_factory=dict)


class ICCAnalyzer:
    """Analyzes Inter-Component Communication (ICC) in Android applications."""

    def __init__(self, config: Dict = None):
        self.config = config or {}
        self.icc_graph = nx.DiGraph()
        self.components = {}  # component_name -> component_info
        self.intent_filters = defaultdict(list)

    def analyze(self, manifest_analysis: Dict, dex_analysis: Dict) -> Dict[str, Any]:
        """Analyze ICC from manifest and DEX analysis."""
        logger.info("icc_analysis_started")

        self.icc_graph.clear()
        self.components.clear()
        self.intent_filters.clear()

        # Extract components from manifest
        self._extract_components(manifest_analysis)

        # Extract intent filters
        self._extract_intent_filters(manifest_analysis)

        # Analyze explicit ICC from DEX
        explicit_edges = self._analyze_explicit_icc(dex_analysis)

        # Analyze implicit ICC from intent filters
        implicit_edges = self._analyze_implicit_icc()

        # Combine all edges
        all_edges = explicit_edges + implicit_edges

        # Build ICC graph
        for edge in all_edges:
            self.icc_graph.add_edge(
                edge.source_component,
                edge.target_component,
                data=edge
            )

        # Find attack surface
        attack_surface = self._analyze_attack_surface()

        # Find sensitive data flows via ICC
        sensitive_flows = self._find_sensitive_icc_flows(dex_analysis)

        result = {
            "components": self.components,
            "intent_filters": dict(self.intent_filters),
            "icc_edges": [
                {
                    "source": e.source_component,
                    "source_type": e.source_type,
                    "target": e.target_component,
                    "target_type": e.target_type,
                    "action": e.intent_action,
                    "is_explicit": e.is_explicit,
                    "is_exported": e.is_exported,
                    "permission": e.permission,
                }
                for e in all_edges
            ],
            "statistics": {
                "total_components": len(self.components),
                "exported_components": sum(1 for c in self.components.values() if c.get("exported", False)),
                "total_icc_edges": len(all_edges),
                "explicit_edges": len(explicit_edges),
                "implicit_edges": len(implicit_edges),
            },
            "attack_surface": attack_surface,
            "sensitive_flows": sensitive_flows,
        }

        logger.info("icc_analysis_completed", **result["statistics"])
        return result

    def _extract_components(self, manifest_analysis: Dict):
        """Extract all components from manifest."""
        for comp_type in ["activities", "services", "receivers", "providers"]:
            components = manifest_analysis.get(comp_type, [])
            for comp in components:
                name = comp.get("name", "")
                if name:
                    self.components[name] = {
                        "type": comp_type[:-1],  # activity, service, receiver, provider
                        "name": name,
                        "exported": comp.get("exported", False),
                        "permission": comp.get("permission"),
                        "enabled": comp.get("enabled", True),
                    }
                    # Add to graph
                    self.icc_graph.add_node(name, **self.components[name])

    def _extract_intent_filters(self, manifest_analysis: Dict):
        """Extract intent filters from manifest."""
        for comp_type in ["activities", "services", "receivers"]:
            components = manifest_analysis.get(comp_type, [])
            for comp in components:
                name = comp.get("name", "")
                filters = comp.get("intent_filters", [])
                for f in filters:
                    self.intent_filters[name].append({
                        "actions": f.get("actions", []),
                        "categories": f.get("categories", []),
                        "data": f.get("data", []),
                    })

    def _analyze_explicit_icc(self, dex_analysis: Dict) -> List[ICCEdge]:
        """Analyze explicit ICC from DEX bytecode (startActivity, sendBroadcast, etc.)."""
        edges = []
        api_calls = dex_analysis.get("api_calls", [])

        # ICC-related API patterns
        icc_apis = {
            "startActivity": ("activity", "activity"),
            "startActivityForResult": ("activity", "activity"),
            "startService": ("activity", "service"),
            "bindService": ("activity", "service"),
            "sendBroadcast": ("activity", "receiver"),
            "sendOrderedBroadcast": ("activity", "receiver"),
            "sendStickyBroadcast": ("activity", "receiver"),
            "startActivity": ("service", "activity"),
            "sendBroadcast": ("service", "receiver"),
        }

        for call in api_calls:
            call_str = call.get("call", "")
            class_name = call.get("class", "")
            method_name = call.get("method", "")

            # Check for ICC API calls
            for api, (source_type, target_type) in icc_apis.items():
                if api in call_str:
                    # Try to extract target component from string analysis
                    # This is simplified - real implementation would parse the actual intent construction
                    source_component = self._normalize_class_name(class_name)
                    if source_component in self.components:
                        # Try to find target from string constants or class references
                        target = self._extract_intent_target(call_str, dex_analysis)
                        if target:
                            edge = ICCEdge(
                                source_component=source_component,
                                source_type=source_type,
                                target_component=target,
                                target_type=target_type,
                                is_explicit=True,
                                extras={"call_site": f"{class_name}.{method_name}", "api": api}
                            )
                            edges.append(edge)

        return edges

    def _analyze_implicit_icc(self) -> List[ICCEdge]:
        """Analyze implicit ICC from intent filters."""
        edges = []

        # For each exported component with intent filters
        for comp_name, filters in self.intent_filters.items():
            if comp_name not in self.components:
                continue
            comp_info = self.components[comp_name]
            if not comp_info.get("exported", False):
                continue

            for filter_data in filters:
                for action in filter_data.get("actions", []):
                    # Find components that can send this action
                    # In reality, any component can send an implicit intent
                    # We note the capability
                    edge = ICCEdge(
                        source_component="ANY",
                        source_type="any",
                        target_component=comp_name,
                        target_type=comp_info["type"],
                        intent_action=action,
                        is_explicit=False,
                        is_exported=True,
                        permission=comp_info.get("permission"),
                    )
                    edges.append(edge)

        return edges

    def _extract_intent_target(self, call_str: str, dex_analysis: Dict) -> Optional[str]:
        """Try to extract target component from intent construction."""
        # This is a simplified implementation
        # Real implementation would do data-flow analysis on intent construction
        strings = dex_analysis.get("strings", [])
        for s in strings:
            if "ComponentName" in s or "setClassName" in s:
                # Extract class name from string
                match = re.search(r'[L]?([a-zA-Z0-9_\$\.]+)[;]?', s)
                if match:
                    return match.group(1).replace('/', '.')
        return None

    def _normalize_class_name(self, class_name: str) -> str:
        """Normalize DEX class name."""
        if class_name.startswith('L') and class_name.endswith(';'):
            return class_name[1:-1].replace('/', '.')
        return class_name.replace('/', '.')

    def _analyze_attack_surface(self) -> Dict[str, Any]:
        """Analyze the ICC attack surface."""
        exported = []
        for name, info in self.components.items():
            if info.get("exported", False):
                exported.append({
                    "component": name,
                    "type": info["type"],
                    "permission": info.get("permission"),
                })

        return {
            "exported_components": exported,
            "total_exported": len(exported),
            "unprotected_exported": len([e for e in exported if not e.get("permission")]),
        }

    def _find_sensitive_icc_flows(self, dex_analysis: Dict) -> List[Dict]:
        """Find sensitive data flows through ICC."""
        flows = []
        api_calls = dex_analysis.get("api_calls", [])

        sensitive_sources = [
            "getDeviceId", "getSubscriberId", "getLastKnownLocation",
            "query", "getContentResolver", "getMessageBody",
            "getLatitude", "getLongitude", "getContacts"
        ]

        icc_sinks = [
            "startActivity", "startService", "sendBroadcast",
            "sendOrderedBroadcast", "startActivityForResult"
        ]

        # Simplified: look for sensitive sources followed by ICC sinks in same method
        for call in api_calls:
            call_str = call.get("call", "")
            if any(source in call_str for source in sensitive_sources):
                method = call.get("method", "")
                # Check if same method has ICC sink
                for other in api_calls:
                    if other.get("method") == method:
                        other_call = other.get("call", "")
                        if any(sink in other_call for sink in icc_sinks):
                            flows.append({
                                "source": call_str,
                                "sink": other_call,
                                "method": method,
                                "class": call.get("class", ""),
                            })
                            break

        return flows[:50]


# ============================================================
# OBfuscation DETECTOR
# ============================================================

@dataclass
class ObfuscationFinding:
    """Represents an obfuscation finding."""
    type: str
    severity: str
    location: str
    description: str
    evidence: Dict[str, Any] = field(default_factory=dict)


class ObfuscationDetector:
    """Detects advanced obfuscation techniques."""

    def __init__(self, config: Dict = None):
        self.config = config or {}
        self.findings = []

    def analyze(self, dex_analysis: Dict, extracted_dir: Path = None,
                manifest_analysis: Dict = None) -> Dict[str, Any]:
        """Run all obfuscation detection."""
        logger.info("obfuscation_analysis_started")

        self.findings = []

        # 1. String encryption detection
        self._detect_string_encryption(dex_analysis)

        # 2. Reflection detection
        self._detect_reflection(dex_analysis)

        # 3. Dynamic code loading detection
        self._detect_dynamic_loading(dex_analysis)

        # 4. Control-flow obfuscation detection
        self._detect_control_flow_obfuscation(dex_analysis)

        # 5. Packer/protector detection (using APKiD patterns)
        self._detect_packers(dex_analysis, extracted_dir)

        # 6. Anti-analysis detection
        self._detect_anti_analysis(dex_analysis)

        # 7. Native code obfuscation
        self._detect_native_obfuscation(extracted_dir)

        # Categorize findings
        by_type = defaultdict(list)
        for f in self.findings:
            by_type[f.type].append(f)

        result = {
            "total_findings": len(self.findings),
            "by_type": {k: len(v) for k, v in by_type.items()},
            "findings": [
                {
                    "type": f.type,
                    "severity": f.severity,
                    "location": f.location,
                    "description": f.description,
                    "evidence": f.evidence,
                }
                for f in self.findings
            ],
            "risk_score": self._calculate_obfuscation_risk(),
        }

        logger.info("obfuscation_analysis_completed", total=len(self.findings))
        return result

    def _detect_string_encryption(self, dex_analysis: Dict):
        """Detect string encryption/decryption patterns."""
        api_calls = dex_analysis.get("api_calls", [])
        strings = dex_analysis.get("strings", [])

        # Look for crypto APIs used in suspicious ways
        crypto_patterns = [
            "Cipher.init", "Cipher.doFinal", "Cipher.getInstance",
            "SecretKeySpec", "IvParameterSpec", "KeyGenerator",
            "MessageDigest", "Mac", "Signature"
        ]

        decryption_patterns = [
            "Base64.decode", "Base64.decodeBase64",
            "DatatypeConverter.parseBase64Binary",
            "Hex.decodeHex", "parseHexBinary"
        ]

        xor_patterns = ["xor", "^"]

        crypto_calls = [c for c in api_calls if any(p in c.get("call", "") for p in crypto_patterns)]
        decode_calls = [c for c in api_calls if any(p in c.get("call", "") for p in decryption_patterns)]

        if crypto_calls or decode_calls:
            self.findings.append(ObfuscationFinding(
                type="string_encryption",
                severity="high" if crypto_calls else "medium",
                location="multiple_methods",
                description=f"Found {len(crypto_calls)} crypto API calls and {len(decode_calls)} decoding calls - possible string encryption",
                evidence={
                    "crypto_calls": len(crypto_calls),
                    "decode_calls": len(decode_calls),
                    "sample_calls": [c.get("call") for c in (crypto_calls + decode_calls)[:10]],
                }
            ))

        # Check for high entropy strings (encrypted)
        high_entropy = [s for s in strings if len(s) > 20 and self._calculate_entropy(s) > 4.5]
        if len(high_entropy) > 10:
            self.findings.append(ObfuscationFinding(
                type="high_entropy_strings",
                severity="medium",
                location="string_pool",
                description=f"Found {len(high_entropy)} high-entropy strings (possible encrypted strings)",
                evidence={"count": len(high_entropy), "sample": high_entropy[:5]}
            ))

    def _detect_reflection(self, dex_analysis: Dict):
        """Detect reflection usage."""
        api_calls = dex_analysis.get("api_calls", [])

        reflection_patterns = [
            "Class.forName", "Class.getMethod", "Class.getField",
            "Method.invoke", "Field.get", "Field.set",
            "Constructor.newInstance", "Class.newInstance",
            "Method.setAccessible", "Field.setAccessible"
        ]

        reflection_calls = [c for c in api_calls if any(p in c.get("call", "") for p in reflection_patterns)]

        if reflection_calls:
            # Group by method
            by_method = defaultdict(list)
            for c in reflection_calls:
                key = f"{c.get('class', '')}.{c.get('method', '')}"
                by_method[key].append(c.get("call", ""))

            self.findings.append(ObfuscationFinding(
                type="reflection",
                severity="high",
                location=f"{len(by_method)} methods",
                description=f"Found reflection usage in {len(by_method)} methods - may hide API calls",
                evidence={
                    "total_calls": len(reflection_calls),
                    "methods_affected": len(by_method),
                    "sample": dict(list(by_method.items())[:5]),
                }
            ))

    def _detect_dynamic_loading(self, dex_analysis: Dict):
        """Detect dynamic DEX/class loading."""
        api_calls = dex_analysis.get("api_calls", [])

        dynamic_loading_patterns = [
            "DexClassLoader", "PathClassLoader", "InMemoryDexClassLoader",
            "DexFile.loadDex", "ClassLoader.loadClass",
            "System.loadLibrary", "System.load",
            "Runtime.loadLibrary", "Runtime.load"
        ]

        loading_calls = [c for c in api_calls if any(p in c.get("call", "") for p in dynamic_loading_patterns)]

        if loading_calls:
            self.findings.append(ObfuscationFinding(
                type="dynamic_code_loading",
                severity="critical",
                location=f"{len(loading_calls)} call sites",
                description="Dynamic code loading detected - may load malicious payloads at runtime",
                evidence={
                    "calls": [c.get("call") for c in loading_calls],
                    "locations": [f"{c.get('class', '')}.{c.get('method', '')}" for c in loading_calls],
                }
            ))

    def _detect_control_flow_obfuscation(self, dex_analysis: Dict):
        """Detect control-flow obfuscation (opaque predicates, junk code, etc.)."""
        # This would need actual bytecode analysis
        # For now, we look for suspicious patterns in method structure
        api_calls = dex_analysis.get("api_calls", [])

        # Look for anti-emulator/anti-debug patterns that suggest obfuscation
        anti_analysis = [
            "isDebuggerConnected", "waitingForDebugger",
            "getprop", "ro.build.tags", "ro.kernel.qemu",
            "checkEmulator", "detectFrida", "detectXposed"
        ]

        anti_calls = [c for c in api_calls if any(p in c.get("call", "") for p in anti_analysis)]

        if anti_calls:
            self.findings.append(ObfuscationFinding(
                type="anti_analysis",
                severity="high",
                location=f"{len(anti_calls)} call sites",
                description="Anti-analysis/anti-emulation checks detected - often used with obfuscation",
                evidence={"calls": [c.get("call") for c in anti_calls]}
            ))

    def _detect_packers(self, dex_analysis: Dict, extracted_dir: Path = None):
        """Detect known packers/protectors."""
        # Check for known packer signatures in strings
        strings = dex_analysis.get("strings", [])

        packer_signatures = {
            "dexguard": ["dexguard", "DexGuard"],
            "proguard": ["proguard", "ProGuard"],
            "bangcle": ["bangcle", "Bangcle", "secshell"],
            "ijiami": ["ijiami", "Ijiami", "love"],
            "qihoo": ["qihoo", "360", "Qihoo"],
            "baidu": ["baiduprotect", "BaiduProtect"],
            "apkprotect": ["apkprotect", "APKProtect"],
            "naga": ["naga", "NAGA"],
            "tencent": ["tencent", "legu", "LeGu"],
            "ali": ["aliprotect", "AliProtect", "ali"],
        }

        detected = []
        for packer, sigs in packer_signatures.items():
            for s in strings:
                if any(sig.lower() in s.lower() for sig in sigs):
                    detected.append(packer)
                    break

        if detected:
            self.findings.append(ObfuscationFinding(
                type="packer_detected",
                severity="high",
                location="string_pool",
                description=f"Possible packer/protector detected: {', '.join(detected)}",
                evidence={"packers": detected}
            ))

    def _detect_anti_analysis(self, dex_analysis: Dict):
        """Detect anti-analysis techniques."""
        # Already partially covered in control-flow obfuscation
        pass

    def _detect_native_obfuscation(self, extracted_dir: Path = None):
        """Detect obfuscation in native libraries."""
        if not extracted_dir or not extracted_dir.exists():
            return

        # Look for suspicious native libraries
        so_files = list(extracted_dir.rglob("*.so"))
        for so_file in so_files:
            # Check for stripped symbols, anti-debug, etc.
            # This would need actual ELF analysis
            pass

    def _calculate_entropy(self, s: str) -> float:
        """Calculate Shannon entropy of a string."""
        if not s:
            return 0
        import math
        freq = defaultdict(int)
        for c in s:
            freq[c] += 1
        entropy = 0
        for count in freq.values():
            p = count / len(s)
            entropy -= p * math.log2(p)
        return entropy

    def _calculate_obfuscation_risk(self) -> int:
        """Calculate overall obfuscation risk score (0-100)."""
        severity_weights = {"critical": 25, "high": 15, "medium": 8, "low": 3}
        score = sum(severity_weights.get(f.severity, 0) for f in self.findings)
        return min(100, score)


# ============================================================
# REFLECTION RESOLVER
# ============================================================

class ReflectionResolver:
    """Resolves reflection calls to concrete targets."""

    def __init__(self, config: Dict = None):
        self.config = config or {}
        self.resolved = {}  # call_site -> resolved_targets

    def resolve(self, dex_analysis: Dict, strings: List[str] = None) -> Dict[str, Any]:
        """Resolve reflection calls."""
        logger.info("reflection_resolution_started")

        api_calls = dex_analysis.get("api_calls", [])
        self.resolved = {}

        # Find all reflection call sites
        reflection_calls = []
        for call in api_calls:
            call_str = call.get("call", "")
            if any(p in call_str for p in [
                "Class.forName", "Method.invoke", "Field.get", "Field.set",
                "Constructor.newInstance", "Class.getMethod", "Class.getField"
            ]):
                reflection_calls.append(call)

        # Try to resolve each
        for call in reflection_calls:
            resolved = self._resolve_call(call, strings, dex_analysis)
            if resolved:
                key = f"{call.get('class', '')}.{call.get('method', '')}:{call.get('call', '')}"
                self.resolved[key] = resolved

        result = {
            "total_reflection_calls": len(reflection_calls),
            "resolved_count": len(self.resolved),
            "resolutions": self.resolved,
        }

        logger.info("reflection_resolution_completed", **result)
        return result

    def _resolve_call(self, call: Dict, strings: List[str], dex_analysis: Dict) -> Optional[List[str]]:
        """Try to resolve a single reflection call."""
        call_str = call.get("call", "")

        # For Class.forName, try to find the class name string
        if "Class.forName" in call_str:
            # Look for string constants that could be class names
            class_names = [s for s in (strings or []) if self._looks_like_class_name(s)]
            if class_names:
                return class_names[:10]

        # For Method.invoke, try to find method names
        if "Method.invoke" in call_str:
            method_names = [s for s in (strings or []) if self._looks_like_method_name(s)]
            if method_names:
                return method_names[:10]

        return None

    def _looks_like_class_name(self, s: str) -> bool:
        """Check if string looks like a Java class name."""
        if not s or len(s) < 5:
            return False
        # Must have at least one dot and valid chars
        if '.' not in s and '/' not in s:
            return False
        # Check for valid class name pattern
        return bool(re.match(r'^[a-zA-Z_$][a-zA-Z0-9_$.\/]*[;]?$', s))

    def _looks_like_method_name(self, s: str) -> bool:
        """Check if string looks like a method name."""
        if not s or len(s) < 2:
            return False
        # Simple check - alphanumeric with underscores
        return bool(re.match(r'^[a-zA-Z_$][a-zA-Z0-9_$]*$', s))


# ============================================================
# DYNAMIC CODE LOADING ANALYZER
# ============================================================

@dataclass
class DynamicLoadSite:
    """Represents a dynamic code loading site."""
    loader_type: str  # DexClassLoader, PathClassLoader, etc.
    class_name: str
    method_name: str
    dex_path: Optional[str] = None
    optimized_directory: Optional[str] = None
    library_path: Optional[str] = None
    parent_classloader: Optional[str] = None
    risk_level: str = "medium"


class DynamicCodeLoadingAnalyzer:
    """Analyzes dynamic code loading (DexClassLoader, PathClassLoader, etc.)."""

    def __init__(self, config: Dict = None):
        self.config = config or {}
        self.load_sites = []

    def analyze(self, dex_analysis: Dict, strings: List[str] = None) -> Dict[str, Any]:
        """Analyze dynamic code loading."""
        logger.info("dynamic_loading_analysis_started")

        self.load_sites = []
        api_calls = dex_analysis.get("api_calls", [])

        # Find all dynamic loading sites
        for call in api_calls:
            call_str = call.get("call", "")
            class_name = call.get("class", "")
            method_name = call.get("method", "")

            site = self._analyze_load_site(call_str, class_name, method_name, strings)
            if site:
                self.load_sites.append(site)

        # Categorize by risk
        critical = [s for s in self.load_sites if s.risk_level == "critical"]
        high = [s for s in self.load_sites if s.risk_level == "high"]
        medium = [s for s in self.load_sites if s.risk_level == "medium"]

        result = {
            "total_load_sites": len(self.load_sites),
            "critical": len(critical),
            "high": len(high),
            "medium": len(medium),
            "load_sites": [
                {
                    "loader_type": s.loader_type,
                    "class": s.class_name,
                    "method": s.method_name,
                    "dex_path": s.dex_path,
                    "optimized_directory": s.optimized_directory,
                    "library_path": s.library_path,
                    "risk_level": s.risk_level,
                }
                for s in self.load_sites
            ],
        }

        logger.info("dynamic_loading_analysis_completed", **{k: v for k, v in result.items() if k != "load_sites"})
        return result

    def _analyze_load_site(self, call_str: str, class_name: str, method_name: str,
                           strings: List[str] = None) -> Optional[DynamicLoadSite]:
        """Analyze a single dynamic loading call site."""
        site = None

        if "DexClassLoader" in call_str:
            site = DynamicLoadSite(
                loader_type="DexClassLoader",
                class_name=class_name,
                method_name=method_name,
                risk_level="high"
            )
            # Try to extract DEX path from strings
            if strings:
                for s in strings:
                    if s.endswith(".dex") or s.endswith(".jar") or s.endswith(".apk"):
                        site.dex_path = s
                        break

        elif "PathClassLoader" in call_str:
            site = DynamicLoadSite(
                loader_type="PathClassLoader",
                class_name=class_name,
                method_name=method_name,
                risk_level="medium"
            )

        elif "InMemoryDexClassLoader" in call_str:
            site = DynamicLoadSite(
                loader_type="InMemoryDexClassLoader",
                class_name=class_name,
                method_name=method_name,
                risk_level="critical"
            )

        elif "DexFile.loadDex" in call_str:
            site = DynamicLoadSite(
                loader_type="DexFile.loadDex",
                class_name=class_name,
                method_name=method_name,
                risk_level="high"
            )

        elif "System.loadLibrary" in call_str or "System.load" in call_str:
            site = DynamicLoadSite(
                loader_type="Native Library Loading",
                class_name=class_name,
                method_name=method_name,
                risk_level="high"
            )
            # Extract library name
            if strings:
                for s in strings:
                    if s.endswith(".so"):
                        site.library_path = s
                        break

        elif "Runtime.loadLibrary" in call_str or "Runtime.load" in call_str:
            site = DynamicLoadSite(
                loader_type="Runtime Native Loading",
                class_name=class_name,
                method_name=method_name,
                risk_level="high"
            )

        return site


# ============================================================
# FLOWDROID INTEGRATION (TAINT ANALYSIS)
# ============================================================

class FlowDroidBridge:
    """Bridge to FlowDroid for advanced taint analysis."""

    def __init__(self, config: Dict = None):
        self.config = config or {}
        self.flowdroid_path = _find_flowdroid()
        self.available = self.flowdroid_path is not None

    def analyze(self, apk_path: Path, sources: List[str] = None,
                sinks: List[str] = None) -> Dict[str, Any]:
        """Run FlowDroid taint analysis on APK."""
        if not self.available:
            return {
                "status": "unavailable",
                "message": "FlowDroid not found. Install FlowDroid for advanced taint analysis.",
                "fallback_used": True,
            }

        logger.info("flowdroid_analysis_started", apk=str(apk_path))

        # Build command
        cmd = ["java", "-jar", self.flowdroid_path]
        cmd.extend(["-a", str(apk_path)])
        cmd.extend(["-p", "/opt/android/platforms"])  # Android platform path

        if sources:
            cmd.extend(["-s", ",".join(sources)])
        if sinks:
            cmd.extend(["-t", ",".join(sinks)])

        # Run with timeout
        try:
            result = run_command(cmd, timeout=300)
            return self._parse_flowdroid_output(result)
        except Exception as e:
            logger.error("flowdroid_analysis_failed", error=str(e))
            return {"status": "error", "error": str(e)}

    def _parse_flowdroid_output(self, result: Dict) -> Dict[str, Any]:
        """Parse FlowDroid output."""
        # FlowDroid outputs in various formats - this is simplified
        return {
            "status": "completed" if result["success"] else "failed",
            "stdout": result.get("stdout", ""),
            "stderr": result.get("stderr", ""),
            "raw_output": result,
        }


# ============================================================
# ENHANCED CALL GRAPH ANALYZER WITH REFLECTION
# ============================================================

# The existing CallGraphAnalyzer class is kept but enhanced
# We'll add reflection resolution capabilities to it


# ============================================================
# ENHANCED CFG BUILDER WITH EXCEPTION HANDLING
# ============================================================

# The existing CFGBuilder class is kept but enhanced
# We'll add try-catch block handling


# ============================================================
# ADVANCED STATIC ANALYZER (MAIN ORCHESTRATOR)
# ============================================================

class AdvancedStaticAnalyzer:
    """Main orchestrator for advanced static analysis."""

    def __init__(self, config: Dict = None):
        self.config = config or get_config().get_all()
        adv_config = self.config.get("advanced_static", {})

        self.call_graph_analyzer = CallGraphAnalyzer(adv_config)
        self.cfg_builder = CFGBuilder(adv_config)
        self.taint_analyzer = TaintAnalyzer(adv_config)
        self.yara_scanner = YARAScanner(self.config)
        self.icc_analyzer = ICCAnalyzer(adv_config)
        self.obfuscation_detector = ObfuscationDetector(adv_config)
        self.reflection_resolver = ReflectionResolver(adv_config)
        self.dynamic_loading_analyzer = DynamicCodeLoadingAnalyzer(adv_config)
        self.flowdroid_bridge = FlowDroidBridge(adv_config)

    def analyze(self, dex_analysis: Dict, extracted_dir: Path = None,
                apk_path: Path = None, strings: List[str] = None,
                manifest_analysis: Dict = None) -> Dict[str, Any]:
        """Run all advanced static analyses."""
        results = {}

        # 1. Call Graph Analysis
        logger.info("Building call graph...")
        call_graph = self.call_graph_analyzer.build_from_dex_analysis(dex_analysis)
        results["call_graph"] = {
            "statistics": self.call_graph_analyzer.get_statistics(),
            "sensitive_paths": self.call_graph_analyzer.find_paths_to_sensitive(),
            "dot_export": self.call_graph_analyzer.export_dot() if call_graph.number_of_nodes() < 1000 else None
        }

        # 2. CFG Analysis (sample key methods)
        logger.info("Building CFGs for key methods...")
        cfg_results = self._analyze_key_method_cfgs(dex_analysis)
        results["cfg"] = cfg_results

        # 3. Taint Analysis (local)
        logger.info("Performing local taint analysis...")
        taint_results = self.taint_analyzer.analyze(dex_analysis, call_graph)
        results["taint"] = {
            "summary": self.taint_analyzer.get_taint_summary(taint_results),
            "statistics": taint_results["statistics"]
        }

        # 4. FlowDroid Taint Analysis (if available)
        if apk_path and apk_path.exists():
            logger.info("Running FlowDroid taint analysis...")
            flowdroid_results = self.flowdroid_bridge.analyze(apk_path)
            results["flowdroid"] = flowdroid_results

        # 5. ICC Analysis
        if manifest_analysis:
            logger.info("Analyzing ICC...")
            icc_results = self.icc_analyzer.analyze(manifest_analysis, dex_analysis)
            results["icc"] = icc_results

        # 6. Obfuscation Detection
        logger.info("Detecting obfuscation...")
        obfuscation_results = self.obfuscation_detector.analyze(
            dex_analysis, extracted_dir, manifest_analysis
        )
        results["obfuscation"] = obfuscation_results

        # 7. Reflection Resolution
        logger.info("Resolving reflection...")
        reflection_results = self.reflection_resolver.resolve(dex_analysis, strings)
        results["reflection"] = reflection_results

        # 8. Dynamic Code Loading Analysis
        logger.info("Analyzing dynamic code loading...")
        dynamic_loading_results = self.dynamic_loading_analyzer.analyze(dex_analysis, strings)
        results["dynamic_loading"] = dynamic_loading_results

        # 9. YARA Scanning
        logger.info("Scanning with YARA...")
        yara_results = self._run_yara_scans(apk_path, extracted_dir, strings)
        results["yara"] = yara_results

        # 10. Combined Risk Assessment
        results["risk_assessment"] = self._calculate_combined_risk(results)

        return results

    def _analyze_key_method_cfgs(self, dex_analysis: Dict) -> Dict[str, Any]:
        """Analyze CFGs for key methods (entry points, sensitive APIs)."""
        cfg_results = {}
        api_calls = dex_analysis.get("api_calls", [])

        # This would need actual bytecode per method
        # For now, return placeholder
        return {
            "analyzed_methods": 0,
            "note": "CFG analysis requires per-method bytecode from DEX parser"
        }

    def _run_yara_scans(self, apk_path: Path, extracted_dir: Path,
                        strings: List[str]) -> Dict[str, Any]:
        """Run YARA scans on various targets."""
        yara_results = []

        if self.yara_scanner.yara_available:
            if apk_path and apk_path.exists():
                yara_results.extend(self.yara_scanner.scan_file(apk_path))
            if extracted_dir and extracted_dir.exists():
                for f in extracted_dir.rglob("*"):
                    if f.is_file() and f.suffix in [".dex", ".so", ".jar", ".class", ".xml"]:
                        yara_results.extend(self.yara_scanner.scan_file(f))
            if strings:
                yara_results.extend(self.yara_scanner.scan_strings(strings))
        else:
            yara_results.append({
                "status": "yara_not_available",
                "message": "YARA binary not found. Install yara for pattern matching."
            })

        return {
            "matches": yara_results,
            "total_matches": len([r for r in yara_results if r.get("matched")]),
            "yara_available": self.yara_scanner.yara_available
        }

    def _calculate_combined_risk(self, results: Dict) -> Dict[str, Any]:
        """Calculate combined risk from all analyses."""
        risk_factors = []

        # Call graph risk
        cg_stats = results.get("call_graph", {}).get("statistics", {})
        if cg_stats.get("sensitive_apis", 0) > 10:
            risk_factors.append(("many_sensitive_apis", 15))
        elif cg_stats.get("sensitive_apis", 0) > 5:
            risk_factors.append(("some_sensitive_apis", 8))

        # Taint risk
        taint_stats = results.get("taint", {}).get("statistics", {})
        if taint_stats.get("source_sink_paths", 0) > 0:
            risk_factors.append(("taint_flows", 20))

        # ICC risk
        icc_stats = results.get("icc", {}).get("statistics", {})
        if icc_stats.get("unprotected_exported", 0) > 0:
            risk_factors.append(("unprotected_exported", 15))

        # Obfuscation risk
        obfu_risk = results.get("obfuscation", {}).get("risk_score", 0)
        if obfu_risk > 50:
            risk_factors.append(("high_obfuscation", 25))
        elif obfu_risk > 20:
            risk_factors.append(("moderate_obfuscation", 12))

        # Dynamic loading risk
        dyn_stats = results.get("dynamic_loading", {})
        if dyn_stats.get("critical", 0) > 0:
            risk_factors.append(("inmemory_dex_loading", 25))
        if dyn_stats.get("high", 0) > 0:
            risk_factors.append(("dexclassloader", 15))

        # Reflection risk
        refl_stats = results.get("reflection", {})
        if refl_stats.get("total_reflection_calls", 0) > 10:
            risk_factors.append(("heavy_reflection", 10))

        # YARA matches
        yara_matches = results.get("yara", {}).get("total_matches", 0)
        if yara_matches > 5:
            risk_factors.append(("many_yara_matches", 15))
        elif yara_matches > 0:
            risk_factors.append(("some_yara_matches", 8))

        total_score = sum(score for _, score in risk_factors)
        total_score = min(100, total_score)

        if total_score >= 80:
            classification = "Critical"
        elif total_score >= 60:
            classification = "High"
        elif total_score >= 40:
            classification = "Suspicious"
        elif total_score >= 20:
            classification = "Moderate"
        else:
            classification = "Low"

        return {
            "score": total_score,
            "classification": classification,
            "factors": [
                {"factor": f, "score": s} for f, s in risk_factors
            ],
            "max_possible": 100,
        }


def analyze_advanced_static(dex_analysis: Dict, config: Dict = None,
                           extracted_dir: Path = None, apk_path: Path = None,
                           strings: List[str] = None, manifest_analysis: Dict = None) -> Dict[str, Any]:
    """Convenience function for advanced static analysis."""
    analyzer = AdvancedStaticAnalyzer(config)
    return analyzer.analyze(dex_analysis, extracted_dir, apk_path, strings, manifest_analysis)