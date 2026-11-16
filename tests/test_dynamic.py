"""
Tests for Dynamic Analysis Module (Phase 5)
"""
import pytest
import json
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock


class TestMitmproxyIntegration:
    """Tests for mitmproxy integration."""

    def test_mitmproxy_integration_import(self):
        from core.dynamic.mitmproxy_integration import MitmproxyIntegration
        integration = MitmproxyIntegration()
        assert integration is not None

    def test_http_flow_dataclass(self):
        from core.dynamic.mitmproxy_integration import HTTPFlow
        flow = HTTPFlow(
            id="test_1",
            timestamp=1234567890.0,
            client_ip="192.168.1.1",
            server_ip="10.0.0.1",
            method="GET",
            url="http://example.com/api",
            scheme="http",
            host="example.com",
            port=80,
            path="/api",
            request_headers={"User-Agent": "test"},
            request_body="",
            response_headers={"Content-Type": "application/json"},
            response_body='{"status": "ok"}',
            response_code=200,
            response_reason="OK",
            duration_ms=150.0,
        )
        assert flow.id == "test_1"
        assert flow.method == "GET"
        assert flow.response_code == 200

    def test_websocket_flow_dataclass(self):
        from core.dynamic.mitmproxy_integration import WebSocketFlow
        ws = WebSocketFlow(
            id="ws_1",
            timestamp=1234567890.0,
            client_ip="192.168.1.1",
            server_ip="10.0.0.1",
            url="ws://example.com/ws",
            messages=[{"from_client": True, "content": "hello"}],
        )
        assert ws.id == "ws_1"
        assert len(ws.messages) == 1

    def test_analyze_traffic_empty(self):
        from core.dynamic.mitmproxy_integration import MitmproxyIntegration
        integration = MitmproxyIntegration()
        result = integration.analyze_traffic([])
        assert result["total_requests"] == 0
        assert result["unique_hosts"] == []

    def test_analyze_traffic_cleartext(self):
        from core.dynamic.mitmproxy_integration import MitmproxyIntegration, HTTPFlow
        integration = MitmproxyIntegration()
        flows = [
            HTTPFlow(
                id="1", timestamp=1234567890.0, client_ip="1.1.1.1", server_ip="2.2.2.2",
                method="GET", url="http://example.com/", scheme="http", host="example.com",
                port=80, path="/", request_headers={}, request_body="",
                response_headers={}, response_body="", response_code=200,
                response_reason="OK", duration_ms=100.0
            ),
            HTTPFlow(
                id="2", timestamp=1234567890.0, client_ip="1.1.1.1", server_ip="3.3.3.3",
                method="POST", url="https://secure.com/api", scheme="https", host="secure.com",
                port=443, path="/api", request_headers={}, request_body="data",
                response_headers={}, response_body="", response_code=200,
                response_reason="OK", duration_ms=100.0, tls_version="TLSv1.3"
            ),
        ]
        result = integration.analyze_traffic(flows)
        assert result["total_requests"] == 2
        assert result["cleartext_requests"] == 1
        assert len(result["unique_hosts"]) == 2

    def test_analyze_traffic_suspicious_tld(self):
        from core.dynamic.mitmproxy_integration import MitmproxyIntegration, HTTPFlow
        integration = MitmproxyIntegration()
        flows = [
            HTTPFlow(
                id="1", timestamp=1234567890.0, client_ip="1.1.1.1", server_ip="2.2.2.2",
                method="GET", url="http://malicious.top/", scheme="http", host="malicious.top",
                port=80, path="/", request_headers={}, request_body="",
                response_headers={}, response_body="", response_code=200,
                response_reason="OK", duration_ms=100.0
            ),
        ]
        result = integration.analyze_traffic(flows)
        assert "malicious.top" in result["suspicious_domains"]

    def test_analyze_traffic_c2_patterns(self):
        from core.dynamic.mitmproxy_integration import MitmproxyIntegration, HTTPFlow
        integration = MitmproxyIntegration()
        flows = [
            HTTPFlow(
                id="1", timestamp=1234567890.0, client_ip="1.1.1.1", server_ip="2.2.2.2",
                method="POST", url="http://c2.com/api/command", scheme="http", host="c2.com",
                port=80, path="/api/command", request_headers={}, request_body="cmd",
                response_headers={}, response_body="", response_code=200,
                response_reason="OK", duration_ms=100.0
            ),
        ]
        result = integration.analyze_traffic(flows)
        assert len(result["potential_c2"]) == 1
        assert result["potential_c2"][0]["pattern"] == "/api/command"

    def test_analyze_traffic_exfiltration(self):
        from core.dynamic.mitmproxy_integration import MitmproxyIntegration, HTTPFlow
        integration = MitmproxyIntegration()
        large_body = "x" * 15000
        flows = [
            HTTPFlow(
                id="1", timestamp=1234567890.0, client_ip="1.1.1.1", server_ip="2.2.2.2",
                method="POST", url="http://exfil.com/upload", scheme="http", host="exfil.com",
                port=80, path="/upload", request_headers={}, request_body=large_body,
                response_headers={}, response_body="", response_code=200,
                response_reason="OK", duration_ms=100.0
            ),
        ]
        result = integration.analyze_traffic(flows)
        assert len(result["exfiltration_indicators"]) == 1
        assert result["exfiltration_indicators"][0]["body_size"] == 15000

    def test_export_har(self):
        from core.dynamic.mitmproxy_integration import MitmproxyIntegration, HTTPFlow
        integration = MitmproxyIntegration()
        flows = [
            HTTPFlow(
                id="1", timestamp=1234567890.0, client_ip="1.1.1.1", server_ip="2.2.2.2",
                method="GET", url="http://example.com/", scheme="http", host="example.com",
                port=80, path="/", request_headers={"User-Agent": "test"}, request_body="",
                response_headers={"Content-Type": "text/html"}, response_body="<html></html>",
                response_code=200, response_reason="OK", duration_ms=100.0
            ),
        ]
        with tempfile.NamedTemporaryFile(suffix=".har", delete=False) as f:
            har_path = f.name
        try:
            result = integration.export_flows(har_path, format="har", flows=flows)
            assert result is True
            with open(har_path) as f:
                har = json.load(f)
            assert har["log"]["version"] == "1.2"
            assert len(har["log"]["entries"]) == 1
        finally:
            Path(har_path).unlink(missing_ok=True)


class TestFridaBridge:
    """Tests for Frida bridge."""

    def test_frida_bridge_import(self):
        from core.dynamic.frida_bridge import FridaBridge
        bridge = FridaBridge()
        assert bridge is not None

    def test_hook_dataclass(self):
        from core.dynamic.frida_bridge import Hook, HookType
        hook = Hook(
            id="test_1",
            target_class="java.lang.String",
            target_method="substring",
            hook_type=HookType.METHOD_ENTRY,
        )
        assert hook.id == "test_1"
        assert hook.target_class == "java.lang.String"
        assert hook.hook_type == HookType.METHOD_ENTRY

    def test_frida_session_dataclass(self):
        from core.dynamic.frida_bridge import FridaSession
        session = FridaSession(
            pid=1234,
            package="com.example.app",
            device_id="emulator-5554",
            session_id="session_1",
        )
        assert session.pid == 1234
        assert session.package == "com.example.app"

    def test_get_crypto_hooks(self):
        from core.dynamic.frida_bridge import FridaBridge
        bridge = FridaBridge()
        hooks = bridge.get_crypto_hooks()
        assert len(hooks) > 0
        assert all(h.hook_type.name == "METHOD_ENTRY" for h in hooks)
        # Check for key crypto classes
        classes = {h.target_class for h in hooks}
        assert "javax.crypto.Cipher" in classes
        assert "java.security.MessageDigest" in classes

    def test_get_network_hooks(self):
        from core.dynamic.frida_bridge import FridaBridge
        bridge = FridaBridge()
        hooks = bridge.get_network_hooks()
        assert len(hooks) > 0
        classes = {h.target_class for h in hooks}
        assert "java.net.HttpURLConnection" in classes
        assert "okhttp3.OkHttpClient" in classes

    def test_get_file_hooks(self):
        from core.dynamic.frida_bridge import FridaBridge
        bridge = FridaBridge()
        hooks = bridge.get_file_hooks()
        assert len(hooks) > 0
        classes = {h.target_class for h in hooks}
        assert "java.io.FileOutputStream" in classes
        assert "android.content.Context" in classes

    def test_get_reflection_hooks(self):
        from core.dynamic.frida_bridge import FridaBridge
        bridge = FridaBridge()
        hooks = bridge.get_reflection_hooks()
        assert len(hooks) > 0
        classes = {h.target_class for h in hooks}
        assert "java.lang.Class" in classes
        assert "java.lang.reflect.Method" in classes

    def test_get_dynamic_loading_hooks(self):
        from core.dynamic.frida_bridge import FridaBridge
        bridge = FridaBridge()
        hooks = bridge.get_dynamic_loading_hooks()
        assert len(hooks) > 0
        classes = {h.target_class for h in hooks}
        assert "dalvik.system.DexClassLoader" in classes
        assert "dalvik.system.PathClassLoader" in classes

    def test_get_anti_analysis_hooks(self):
        from core.dynamic.frida_bridge import FridaBridge
        bridge = FridaBridge()
        hooks = bridge.get_anti_analysis_hooks()
        assert len(hooks) > 0
        classes = {h.target_class for h in hooks}
        assert "android.os.Debug" in classes
        assert "java.lang.Runtime" in classes

    def test_get_all_hooks(self):
        from core.dynamic.frida_bridge import FridaBridge
        bridge = FridaBridge()
        hooks = bridge.get_all_hooks()
        # Should have hooks from all categories
        assert len(hooks) >= 30  # Approximate total

    def test_generate_hook_script_method_entry(self):
        from core.dynamic.frida_bridge import FridaBridge, Hook, HookType
        bridge = FridaBridge()
        hook = Hook(
            id="test_1",
            target_class="java.lang.String",
            target_method="substring",
            hook_type=HookType.METHOD_ENTRY,
        )
        script = bridge._generate_hook_script(hook)
        assert "method_entry" in script
        assert "java.lang.String" in script
        assert "substring" in script
        assert "Java.perform" in script

    def test_generate_hook_script_method_exit(self):
        from core.dynamic.frida_bridge import FridaBridge, Hook, HookType
        bridge = FridaBridge()
        hook = Hook(
            id="test_2",
            target_class="java.lang.String",
            target_method="substring",
            hook_type=HookType.METHOD_EXIT,
        )
        script = bridge._generate_hook_script(hook)
        assert "method_exit" in script
        assert "return_value" in script

    def test_generate_hook_script_constructor(self):
        from core.dynamic.frida_bridge import FridaBridge, Hook, HookType
        bridge = FridaBridge()
        hook = Hook(
            id="test_3",
            target_class="java.lang.String",
            target_method="<init>",
            hook_type=HookType.CONSTRUCTOR,
        )
        script = bridge._generate_hook_script(hook)
        assert "constructor" in script
        assert "$init" in script

    def test_generate_hook_script_native(self):
        from core.dynamic.frida_bridge import FridaBridge, Hook, HookType
        bridge = FridaBridge()
        hook = Hook(
            id="test_4",
            target_class="",
            target_method="SSL_write",
            hook_type=HookType.NATIVE,
        )
        script = bridge._generate_hook_script(hook)
        assert "native_entry" in script
        assert "Interceptor.attach" in script
        assert "SSL_write" in script


class TestAVDManager:
    """Tests for AVD Manager."""

    def test_avd_manager_import(self):
        from core.dynamic.avd_manager import AVDManager
        manager = AVDManager()
        assert manager is not None

    def test_avd_config_dataclass(self):
        from core.dynamic.avd_manager import AVDConfig
        config = AVDConfig(
            name="test_avd",
            api_level=33,
            abi="arm64-v8a",
            device="pixel_6",
            ram_size="2048",
            storage_size="4G",
        )
        assert config.name == "test_avd"
        assert config.api_level == 33
        assert config.abi == "arm64-v8a"

    def test_avd_instance_dataclass(self):
        from core.dynamic.avd_manager import AVDInstance, AVDConfig, AVDState
        config = AVDConfig(name="test")
        instance = AVDInstance(
            config=config,
            state=AVDState.RUNNING,
            pid=1234,
            port=5554,
            adb_port=5555,
        )
        assert instance.config.name == "test"
        assert instance.state == AVDState.RUNNING
        assert instance.pid == 1234

    def test_list_avds_empty(self):
        from core.dynamic.avd_manager import AVDManager
        manager = AVDManager()
        # Should not crash even if no AVDs exist
        avds = manager.list_avds()
        assert isinstance(avds, list)

    def test_list_system_images(self):
        from core.dynamic.avd_manager import AVDManager
        manager = AVDManager()
        images = manager.list_system_images()
        assert isinstance(images, list)


class TestRuntimeCollector:
    """Tests for Runtime Collector."""

    def test_runtime_collector_import(self):
        from core.dynamic.runtime_collector import RuntimeCollector
        collector = RuntimeCollector()
        assert collector is not None

    def test_runtime_event_dataclass(self):
        from core.dynamic.runtime_collector import RuntimeEvent, EventType
        event = RuntimeEvent(
            id="evt_1",
            event_type=EventType.NETWORK,
            timestamp=1234567890.0,
            pid=1234,
            tid=1235,
            package="com.example.app",
            data={"url": "http://example.com"},
            source="frida",
            severity="warning",
        )
        assert event.id == "evt_1"
        assert event.event_type == EventType.NETWORK
        assert event.severity == "warning"

    def test_process_info_dataclass(self):
        from core.dynamic.runtime_collector import ProcessInfo
        proc = ProcessInfo(
            pid=1234,
            ppid=1,
            name="com.example.app",
            uid=1000,
            cmdline="app_process",
            start_time=1234567890.0,
        )
        assert proc.pid == 1234
        assert proc.name == "com.example.app"

    def test_add_event(self):
        from core.dynamic.runtime_collector import RuntimeCollector, RuntimeEvent, EventType
        collector = RuntimeCollector()
        event = RuntimeEvent(
            id="evt_1",
            event_type=EventType.NETWORK,
            timestamp=1234567890.0,
            pid=1234,
            tid=1235,
            package="com.example.app",
            data={"url": "http://example.com"},
            source="frida",
        )
        collector._add_event(event)
        assert len(collector.events) == 1
        assert collector.stats["network"] == 1
        assert collector.stats["total"] == 1

    def test_get_events_filter_by_type(self):
        from core.dynamic.runtime_collector import RuntimeCollector, RuntimeEvent, EventType
        collector = RuntimeCollector()
        events = [
            RuntimeEvent("1", EventType.NETWORK, 1000.0, 1, 1, "pkg", {}, "frida"),
            RuntimeEvent("2", EventType.FILE_IO, 1001.0, 1, 1, "pkg", {}, "frida"),
            RuntimeEvent("3", EventType.NETWORK, 1002.0, 1, 1, "pkg", {}, "frida"),
        ]
        for e in events:
            collector._add_event(e)

        network_events = collector.get_events(event_type=EventType.NETWORK)
        assert len(network_events) == 2

    def test_get_events_filter_by_severity(self):
        from core.dynamic.runtime_collector import RuntimeCollector, RuntimeEvent, EventType
        collector = RuntimeCollector()
        events = [
            RuntimeEvent("1", EventType.NETWORK, 1000.0, 1, 1, "pkg", {}, "frida", "info"),
            RuntimeEvent("2", EventType.FILE_IO, 1001.0, 1, 1, "pkg", {}, "frida", "warning"),
            RuntimeEvent("3", EventType.NETWORK, 1002.0, 1, 1, "pkg", {}, "frida", "critical"),
        ]
        for e in events:
            collector._add_event(e)

        critical = collector.get_events(severity="critical")
        assert len(critical) == 1
        assert critical[0].id == "3"

    def test_get_summary(self):
        from core.dynamic.runtime_collector import RuntimeCollector, RuntimeEvent, EventType
        collector = RuntimeCollector()
        events = [
            RuntimeEvent("1", EventType.NETWORK, 1000.0, 1, 1, "pkg", {}, "frida", "info"),
            RuntimeEvent("2", EventType.NETWORK, 1001.0, 1, 1, "pkg", {}, "frida", "warning"),
            RuntimeEvent("3", EventType.FILE_IO, 1002.0, 1, 1, "pkg", {}, "frida", "critical"),
        ]
        for e in events:
            collector._add_event(e)

        summary = collector.get_summary()
        assert summary["total_events"] == 3
        assert summary["stats"]["network"] == 2
        assert summary["stats"]["file_io"] == 1
        assert summary["stats"]["critical"] == 1
        assert summary["stats"]["warning"] == 1

    def test_export_events_json(self):
        from core.dynamic.runtime_collector import RuntimeCollector, RuntimeEvent, EventType
        collector = RuntimeCollector()
        event = RuntimeEvent(
            "1", EventType.NETWORK, 1000.0, 1, 1, "pkg", {"url": "http://test.com"}, "frida"
        )
        collector._add_event(event)

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = f.name
        try:
            result = collector.export_events(path, format="json")
            assert result is True
            with open(path) as f:
                data = json.load(f)
            assert len(data) == 1
            assert data[0]["event_type"] == "network"
        finally:
            Path(path).unlink(missing_ok=True)

    def test_search_events(self):
        from core.dynamic.runtime_collector import RuntimeCollector, RuntimeEvent, EventType
        collector = RuntimeCollector()
        events = [
            RuntimeEvent("1", EventType.NETWORK, 1000.0, 1, 1, "pkg", {"url": "http://example.com/api"}, "frida"),
            RuntimeEvent("2", EventType.FILE_IO, 1001.0, 1, 1, "pkg", {"path": "/data/data/com.app/file.txt"}, "frida"),
        ]
        for e in events:
            collector._add_event(e)

        results = collector.search_events("example.com")
        assert len(results) == 1
        assert results[0].id == "1"

        results = collector.search_events("file.txt")
        assert len(results) == 1
        assert results[0].id == "2"

    def test_get_timeline(self):
        from core.dynamic.runtime_collector import RuntimeCollector, RuntimeEvent, EventType
        collector = RuntimeCollector()
        base = 1000.0
        events = [
            RuntimeEvent("1", EventType.NETWORK, base, 1, 1, "pkg", {}, "frida"),
            RuntimeEvent("2", EventType.NETWORK, base + 5, 1, 1, "pkg", {}, "frida"),
            RuntimeEvent("3", EventType.FILE_IO, base + 15, 1, 1, "pkg", {}, "frida"),
        ]
        for e in events:
            collector._add_event(e)

        timeline = collector.get_timeline(interval_seconds=10)
        assert len(timeline) == 2  # Two intervals
        assert timeline[0]["event_count"] == 2
        assert timeline[1]["event_count"] == 1


class TestCorrelationEngine:
    """Tests for Correlation Engine."""

    def test_correlation_engine_import(self):
        from core.dynamic.correlation_engine import CorrelationEngine
        engine = CorrelationEngine()
        assert engine is not None

    def test_static_finding_dataclass(self):
        from core.dynamic.correlation_engine import StaticFinding
        finding = StaticFinding(
            id="static_1",
            analyzer="dex_analyzer",
            finding_type="api_call",
            severity="high",
            location={"class": "Ljava/net/URL;", "method": "openConnection"},
            evidence={"urls": ["http://malicious.com"]},
            description="Suspicious URL connection",
        )
        assert finding.id == "static_1"
        assert finding.analyzer == "dex_analyzer"

    def test_dynamic_event_dataclass(self):
        from core.dynamic.correlation_engine import DynamicEvent
        event = DynamicEvent(
            id="dyn_1",
            event_type="network",
            timestamp=1234567890.0,
            data={"url": "http://malicious.com/api", "host": "malicious.com"},
            source="frida",
        )
        assert event.id == "dyn_1"
        assert event.event_type == "network"

    def test_correlation_dataclass(self):
        from core.dynamic.correlation_engine import Correlation, CorrelationType, ConfidenceLevel, StaticFinding, DynamicEvent
        finding = StaticFinding("s1", "a", "t", "high", {}, {}, "desc")
        event = DynamicEvent("e1", "network", 123.0, {}, "frida")
        corr = Correlation(
            id="c1",
            correlation_type=CorrelationType.NETWORK_CONNECTION,
            confidence=ConfidenceLevel.DEFINITE,
            static_finding=finding,
            dynamic_events=[event],
            description="Test correlation",
            evidence={},
            risk_contribution=20.0,
        )
        assert corr.id == "c1"
        assert corr.confidence == ConfidenceLevel.DEFINITE
        assert corr.risk_contribution == 20.0

    def test_load_static_findings_api_calls(self):
        from core.dynamic.correlation_engine import CorrelationEngine
        engine = CorrelationEngine()
        findings = [
            {
                "id": "s1",
                "analyzer": "dex_analyzer",
                "type": "api_call",
                "severity": "high",
                "location": {"class": "Ljavax/crypto/Cipher;", "method": "init"},
                "evidence": {},
                "description": "Crypto init call",
            },
        ]
        engine.load_static_findings(findings)
        assert len(engine.static_findings) == 1
        assert "Ljavax/crypto/Cipher;->init" in engine._api_call_index

    def test_load_static_findings_network(self):
        from core.dynamic.correlation_engine import CorrelationEngine
        engine = CorrelationEngine()
        findings = [
            {
                "id": "s1",
                "analyzer": "network_analyzer",
                "type": "network",
                "severity": "high",
                "location": {},
                "evidence": {"urls": ["http://c2.example.com"], "domains": ["c2.example.com"]},
                "description": "C2 domain",
            },
        ]
        engine.load_static_findings(findings)
        assert "http://c2.example.com" in engine._network_index
        assert "c2.example.com" in engine._network_index

    def test_load_dynamic_events(self):
        from core.dynamic.correlation_engine import CorrelationEngine
        engine = CorrelationEngine()
        events = [
            {"id": "e1", "event_type": "network", "timestamp": 1000.0, "data": {"url": "http://test.com"}, "source": "frida"},
            {"id": "e2", "event_type": "file_io", "timestamp": 1001.0, "data": {"path": "/data/file.txt"}, "source": "frida"},
        ]
        engine.load_dynamic_events(events)
        assert len(engine.dynamic_events) == 2
        assert engine.dynamic_events[0].event_type == "network"

    def test_correlate_network_definite(self):
        from core.dynamic.correlation_engine import CorrelationEngine
        engine = CorrelationEngine()
        engine.load_static_findings([{
            "id": "s1", "analyzer": "net", "type": "network", "severity": "high",
            "location": {}, "evidence": {"urls": ["http://malicious.com/api"]}, "description": "C2"
        }])
        engine.load_dynamic_events([{
            "id": "e1", "event_type": "network", "timestamp": 1000.0,
            "data": {"url": "http://malicious.com/api", "host": "malicious.com"}, "source": "frida"
        }])
        correlations = engine.correlate()
        assert len(correlations) >= 1
        net_corrs = [c for c in correlations if c.correlation_type.name == "NETWORK_CONNECTION"]
        assert len(net_corrs) >= 1
        assert net_corrs[0].confidence.name == "DEFINITE"
        assert net_corrs[0].risk_contribution == 20.0

    def test_correlate_api_call_definite(self):
        from core.dynamic.correlation_engine import CorrelationEngine
        engine = CorrelationEngine()
        engine.load_static_findings([{
            "id": "s1", "analyzer": "dex", "type": "api_call", "severity": "high",
            "location": {"class": "Ljava/net/URL;", "method": "openConnection"}, "evidence": {}, "description": "URL conn"
        }])
        engine.load_dynamic_events([{
            "id": "e1", "event_type": "method_entry", "timestamp": 1000.0,
            "data": {"class": "Ljava/net/URL;", "method": "openConnection"}, "source": "frida"
        }])
        correlations = engine.correlate()
        api_corrs = [c for c in correlations if c.correlation_type.name == "API_CALL_MATCH"]
        assert len(api_corrs) >= 1
        assert api_corrs[0].confidence.name == "DEFINITE"

    def test_correlate_reflection_high(self):
        from core.dynamic.correlation_engine import CorrelationEngine
        engine = CorrelationEngine()
        engine.load_static_findings([{
            "id": "s1", "analyzer": "dex", "type": "reflection", "severity": "high",
            "location": {}, "evidence": {}, "description": "Reflection usage"
        }])
        engine.load_dynamic_events([{
            "id": "e1", "event_type": "reflection", "timestamp": 1000.0,
            "data": {"class": "java.lang.Class", "method": "forName"}, "source": "frida"
        }])
        correlations = engine.correlate()
        refl_corrs = [c for c in correlations if c.correlation_type.name == "REFLECTION_USAGE"]
        assert len(refl_corrs) >= 1
        assert refl_corrs[0].confidence.name == "HIGH"

    def test_correlate_dynamic_loading_high(self):
        from core.dynamic.correlation_engine import CorrelationEngine
        engine = CorrelationEngine()
        engine.load_static_findings([{
            "id": "s1", "analyzer": "dex", "type": "dynamic_loading", "severity": "critical",
            "location": {}, "evidence": {}, "description": "DexClassLoader usage"
        }])
        engine.load_dynamic_events([{
            "id": "e1", "event_type": "dynamic_loading", "timestamp": 1000.0,
            "data": {"class": "dalvik.system.DexClassLoader", "method": "loadClass"}, "source": "frida"
        }])
        correlations = engine.correlate()
        dyn_corrs = [c for c in correlations if c.correlation_type.name == "DYNAMIC_LOADING"]
        assert len(dyn_corrs) >= 1
        assert dyn_corrs[0].confidence.name == "HIGH"
        assert dyn_corrs[0].risk_contribution == 25.0

    def test_correlate_crypto_high(self):
        from core.dynamic.correlation_engine import CorrelationEngine
        engine = CorrelationEngine()
        engine.load_static_findings([{
            "id": "s1", "analyzer": "dex", "type": "crypto", "severity": "high",
            "location": {}, "evidence": {}, "description": "AES encryption"
        }])
        engine.load_dynamic_events([{
            "id": "e1", "event_type": "crypto", "timestamp": 1000.0,
            "data": {"class": "javax.crypto.Cipher", "method": "doFinal"}, "source": "frida"
        }])
        correlations = engine.correlate()
        crypto_corrs = [c for c in correlations if c.correlation_type.name == "CRYPTO_OPERATION"]
        assert len(crypto_corrs) >= 1
        assert crypto_corrs[0].confidence.name == "HIGH"

    def test_correlate_obfuscation_high(self):
        from core.dynamic.correlation_engine import CorrelationEngine
        engine = CorrelationEngine()
        engine.load_static_findings([{
            "id": "s1", "analyzer": "obfuscation", "type": "obfuscation", "severity": "high",
            "location": {}, "evidence": {}, "description": "Packed APK"
        }])
        engine.load_dynamic_events([{
            "id": "e1", "event_type": "anti_analysis", "timestamp": 1000.0,
            "data": {"class": "android.os.Debug", "method": "isDebuggerConnected"}, "source": "frida"
        }])
        correlations = engine.correlate()
        obf_corrs = [c for c in correlations if c.correlation_type.name == "OBFUSCATION_EVIDENCE"]
        assert len(obf_corrs) >= 1
        assert obf_corrs[0].confidence.name == "HIGH"
        assert obf_corrs[0].risk_contribution == 20.0

    def test_get_high_confidence_correlations(self):
        from core.dynamic.correlation_engine import CorrelationEngine, ConfidenceLevel
        engine = CorrelationEngine()
        engine.load_static_findings([{
            "id": "s1", "analyzer": "net", "type": "network", "severity": "high",
            "location": {}, "evidence": {"urls": ["http://test.com"]}, "description": "Test"
        }])
        engine.load_dynamic_events([{
            "id": "e1", "event_type": "network", "timestamp": 1000.0,
            "data": {"url": "http://test.com"}, "source": "frida"
        }])
        engine.correlate()
        high_conf = engine.get_high_confidence_correlations()
        assert len(high_conf) >= 1
        assert all(c.confidence in [ConfidenceLevel.DEFINITE, ConfidenceLevel.HIGH] for c in high_conf)

    def test_get_summary(self):
        from core.dynamic.correlation_engine import CorrelationEngine
        engine = CorrelationEngine()
        engine.load_static_findings([{
            "id": "s1", "analyzer": "net", "type": "network", "severity": "high",
            "location": {}, "evidence": {"urls": ["http://test.com"]}, "description": "Test"
        }])
        engine.load_dynamic_events([{
            "id": "e1", "event_type": "network", "timestamp": 1000.0,
            "data": {"url": "http://test.com"}, "source": "frida"
        }])
        engine.correlate()
        summary = engine.get_summary()
        assert summary["total"] >= 1
        assert "by_type" in summary
        assert "by_confidence" in summary
        assert "total_risk_contribution" in summary
        assert summary["high_confidence_count"] >= 1

    def test_export_correlations(self):
        from core.dynamic.correlation_engine import CorrelationEngine
        engine = CorrelationEngine()
        engine.load_static_findings([{
            "id": "s1", "analyzer": "net", "type": "network", "severity": "high",
            "location": {}, "evidence": {"urls": ["http://test.com"]}, "description": "Test"
        }])
        engine.load_dynamic_events([{
            "id": "e1", "event_type": "network", "timestamp": 1000.0,
            "data": {"url": "http://test.com"}, "source": "frida"
        }])
        engine.correlate()

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = f.name
        try:
            result = engine.export_correlations(path)
            assert result is True
            with open(path) as f:
                data = json.load(f)
            assert len(data) >= 1
            assert "correlation_type" in data[0]
            assert "confidence" in data[0]
        finally:
            Path(path).unlink(missing_ok=True)


class TestDynamicModuleIntegration:
    """Integration tests for dynamic module."""

    def test_module_imports(self):
        from core.dynamic import (
            AVDManager, get_avd_manager,
            FridaBridge, get_frida_bridge,
            MitmproxyIntegration, get_mitmproxy_integration,
            RuntimeCollector, get_runtime_collector,
            CorrelationEngine, get_correlation_engine,
        )
        # All imports should work
        assert AVDManager is not None
        assert FridaBridge is not None
        assert MitmproxyIntegration is not None
        assert RuntimeCollector is not None
        assert CorrelationEngine is not None

    def test_singleton_patterns(self):
        from core.dynamic import (
            get_avd_manager, get_frida_bridge,
            get_mitmproxy_integration, get_runtime_collector,
            get_correlation_engine,
        )
        # Each should return same instance on repeated calls
        assert get_avd_manager() is get_avd_manager()
        assert get_frida_bridge() is get_frida_bridge()
        assert get_mitmproxy_integration() is get_mitmproxy_integration()
        assert get_runtime_collector() is get_runtime_collector()
        assert get_correlation_engine() is get_correlation_engine()

    def test_end_to_end_correlation(self):
        """Test full static-dynamic correlation flow."""
        from core.dynamic.correlation_engine import CorrelationEngine
        from core.dynamic.runtime_collector import RuntimeCollector, RuntimeEvent, EventType

        # Setup correlation engine
        engine = CorrelationEngine()

        # Simulate static findings (from Phase 1-4 analyzers)
        static_findings = [
            {
                "id": "static_1",
                "analyzer": "dex_analyzer",
                "type": "crypto",  # Must be "crypto" for crypto correlation
                "severity": "high",
                "location": {"class": "Ljavax/crypto/Cipher;", "method": "doFinal"},
                "evidence": {},
                "description": "AES encryption detected",
            },
            {
                "id": "static_2",
                "analyzer": "network_analyzer",
                "type": "network",
                "severity": "critical",
                "location": {},
                "evidence": {"urls": ["http://c2.malicious.top/beacon"], "domains": ["c2.malicious.top"]},
                "description": "C2 beacon domain",
            },
            {
                "id": "static_3",
                "analyzer": "advanced_static",
                "type": "dynamic_loading",
                "severity": "critical",
                "location": {},
                "evidence": {},
                "description": "DexClassLoader usage detected",
            },
            {
                "id": "static_4",
                "analyzer": "obfuscation_detector",
                "type": "obfuscation",
                "severity": "high",
                "location": {},
                "evidence": {},
                "description": "APK packed with unknown packer",
            },
        ]
        engine.load_static_findings(static_findings)

        # Simulate dynamic events (from Frida/mitmproxy)
        dynamic_events = [
            {
                "id": "dyn_1",
                "event_type": "crypto",
                "timestamp": 1000000.0,
                "data": {"class": "javax.crypto.Cipher", "method": "doFinal", "args": ["AES"]},
                "source": "frida",
            },
            {
                "id": "dyn_2",
                "event_type": "network",
                "timestamp": 1000001.0,
                "data": {"url": "http://c2.malicious.top/beacon", "host": "c2.malicious.top", "method": "POST"},
                "source": "mitmproxy",
            },
            {
                "id": "dyn_3",
                "event_type": "dynamic_loading",
                "timestamp": 1000002.0,
                "data": {"class": "dalvik.system.DexClassLoader", "method": "loadClass", "args": ["Lcom/malicious/Payload;"]},
                "source": "frida",
            },
            {
                "id": "dyn_4",
                "event_type": "anti_analysis",
                "timestamp": 1000003.0,
                "data": {"class": "android.os.Debug", "method": "isDebuggerConnected"},
                "source": "frida",
            },
        ]
        engine.load_dynamic_events(dynamic_events)

        # Perform correlation
        correlations = engine.correlate()

        # Verify we got correlations for all finding types
        corr_types = {c.correlation_type.name for c in correlations}
        assert "CRYPTO_OPERATION" in corr_types
        assert "NETWORK_CONNECTION" in corr_types
        assert "DYNAMIC_LOADING" in corr_types
        assert "OBFUSCATION_EVIDENCE" in corr_types

        # Verify high confidence correlations
        high_conf = engine.get_high_confidence_correlations()
        assert len(high_conf) >= 4

        # Verify risk contribution
        summary = engine.get_summary()
        assert summary["total_risk_contribution"] > 50  # Significant risk

        # Check definite correlations
        definite = [c for c in correlations if c.confidence.name == "DEFINITE"]
        assert len(definite) >= 1  # Network should be definite


if __name__ == "__main__":
    pytest.main([__file__, "-v"])