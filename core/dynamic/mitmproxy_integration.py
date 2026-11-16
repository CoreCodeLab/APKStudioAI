"""
mitmproxy Integration for APKStudioAI 2.1
HTTP/HTTPS interception, TLS decryption, traffic analysis.
"""
import json
import subprocess
import threading
import time
from pathlib import Path
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass, field
from enum import Enum
from ..config_manager import get_config
from ..logging_setup import get_module_logger

logger = get_module_logger("mitmproxy_integration")


class TrafficType(Enum):
    """Traffic types."""
    HTTP_REQUEST = "http_request"
    HTTP_RESPONSE = "http_response"
    WEBSOCKET = "websocket"
    TLS_HANDSHAKE = "tls_handshake"


@dataclass
class HTTPFlow:
    """HTTP flow record."""
    id: str
    timestamp: float
    client_ip: str
    server_ip: str
    method: str
    url: str
    scheme: str
    host: str
    port: int
    path: str
    request_headers: Dict[str, str]
    request_body: str
    response_headers: Dict[str, str]
    response_body: str
    response_code: int
    response_reason: str
    duration_ms: float
    tls_version: str = ""
    tls_cipher: str = ""


@dataclass
class WebSocketFlow:
    """WebSocket flow record."""
    id: str
    timestamp: float
    client_ip: str
    server_ip: str
    url: str
    messages: List[Dict] = field(default_factory=list)


class MitmproxyIntegration:
    """Integration with mitmproxy for traffic interception."""

    def __init__(self, config: Dict = None):
        self.config = config or get_config().get_all()
        self.mitmproxy_path = self._find_mitmproxy()
        self.mitmdump_path = self._find_mitmdump()
        self.proxy_process: Optional[subprocess.Popen] = None
        self.proxy_port = 8080
        self.ca_cert_path = Path.home() / ".mitmproxy" / "mitmproxy-ca-cert.pem"
        self.flows: List[HTTPFlow] = []
        self.ws_flows: List[WebSocketFlow] = []
        self.callbacks: List[Callable] = []
        self._running = False
        self._script_path = None

    def _find_mitmproxy(self) -> str:
        """Find mitmproxy executable."""
        import shutil
        return shutil.which("mitmproxy") or "mitmproxy"

    def _find_mitmdump(self) -> str:
        """Find mitmdump executable."""
        import shutil
        return shutil.which("mitmdump") or "mitmdump"

    def is_available(self) -> bool:
        """Check if mitmproxy is available."""
        try:
            result = subprocess.run([self.mitmdump_path, "--version"], capture_output=True, timeout=5)
            return result.returncode == 0
        except Exception:
            return False

    def get_version(self) -> Optional[str]:
        """Get mitmproxy version."""
        try:
            result = subprocess.run([self.mitmdump_path, "--version"], capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                return result.stdout.strip()
        except Exception:
            pass
        return None

    def start_proxy(self, port: int = 8080, upstream_proxy: str = None,
                    ssl_insecure: bool = True, scripts: List[str] = None) -> bool:
        """Start mitmproxy in dump mode."""
        if self._running:
            logger.warning("mitmproxy_already_running")
            return True

        self.proxy_port = port

        # Create custom script for flow capture
        self._create_capture_script()

        cmd = [
            self.mitmdump_path,
            "-p", str(port),
            "-s", self._script_path,
            "--set", "block_global=false",
            "--set", "connection_strategy=lazy",
        ]

        if upstream_proxy:
            cmd.extend(["--mode", f"upstream:{upstream_proxy}"])

        if ssl_insecure:
            cmd.extend(["--ssl-insecure"])

        if scripts:
            for script in scripts:
                cmd.extend(["-s", script])

        try:
            self.proxy_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

            # Wait for proxy to start
            time.sleep(3)

            # Check if process is still alive
            if self.proxy_process.poll() is None:
                self._running = True
                logger.info("mitmproxy_started", port=port)
                return True
            else:
                stdout, stderr = self.proxy_process.communicate()
                logger.error("mitmproxy_start_failed", error=stderr.decode() if stderr else "Unknown")
                return False

        except Exception as e:
            logger.error("mitmproxy_start_error", error=str(e))
            return False

    def _create_capture_script(self):
        """Create mitmproxy script for flow capture."""
        import tempfile
        script_content = f'''
import json
import time
from mitmproxy import http, websocket

# Store reference to capture flows
captured_flows = []

class FlowCapture:
    def __init__(self):
        self.flows = []

    def request(self, flow: http.HTTPFlow):
        pass

    def response(self, flow: http.HTTPFlow):
        if flow.request and flow.response:
            flow_data = {{
                "id": flow.id,
                "timestamp": time.time(),
                "client_ip": flow.client_conn.address[0] if flow.client_conn else "",
                "server_ip": flow.server_conn.address[0] if flow.server_conn else "",
                "method": flow.request.method,
                "url": flow.request.url,
                "scheme": flow.request.scheme,
                "host": flow.request.host,
                "port": flow.request.port,
                "path": flow.request.path,
                "request_headers": dict(flow.request.headers),
                "request_body": flow.request.get_text(strict=False) or "",
                "response_headers": dict(flow.response.headers),
                "response_body": flow.response.get_text(strict=False) or "",
                "response_code": flow.response.status_code,
                "response_reason": flow.response.reason,
                "duration_ms": (flow.response.timestamp_end - flow.request.timestamp_start) * 1000 if flow.response.timestamp_end and flow.request.timestamp_start else 0,
            }}

            # TLS info
            if flow.server_conn and flow.server_conn.tls_established:
                flow_data["tls_version"] = flow.server_conn.tls_version.name if flow.server_conn.tls_version else ""
                flow_data["tls_cipher"] = flow.server_conn.cipher_name if flow.server_conn.cipher_name else ""

            self.flows.append(flow_data)

            # Write to file for external consumption
            with open("{tempfile.gettempdir()}/mitmproxy_flows.jsonl", "a") as f:
                f.write(json.dumps(flow_data) + "\\n")

    def websocket_message(self, flow: websocket.WebSocketFlow):
        for msg in flow.messages:
            ws_data = {{
                "id": flow.id,
                "timestamp": time.time(),
                "client_ip": flow.client_conn.address[0] if flow.client_conn else "",
                "server_ip": flow.server_conn.address[0] if flow.server_conn else "",
                "url": flow.request.url if flow.request else "",
                "type": "websocket",
                "from_client": msg.from_client,
                "content": msg.content.decode("utf-8", errors="replace") if isinstance(msg.content, bytes) else str(msg.content),
            }}
            with open("{tempfile.gettempdir()}/mitmproxy_ws.jsonl", "a") as f:
                f.write(json.dumps(ws_data) + "\\n")

addons = [FlowCapture()]
'''

        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(script_content)
            self._script_path = f.name

    def stop_proxy(self) -> bool:
        """Stop mitmproxy."""
        if self.proxy_process:
            try:
                self.proxy_process.terminate()
                self.proxy_process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.proxy_process.kill()
            except Exception:
                pass

        self._running = False
        self.proxy_process = None
        logger.info("mitmproxy_stopped")
        return True

    def get_flows(self, since: float = 0, limit: int = 1000) -> List[HTTPFlow]:
        """Get captured HTTP flows."""
        # Read from JSONL file
        flows_file = Path(tempfile.gettempdir()) / "mitmproxy_flows.jsonl"
        flows = []

        if flows_file.exists():
            with open(flows_file, "r") as f:
                for line in f:
                    try:
                        data = json.loads(line.strip())
                        if data.get("timestamp", 0) > since:
                            flows.append(HTTPFlow(**data))
                    except Exception:
                        pass

        return flows[-limit:]

    def get_websocket_flows(self, since: float = 0, limit: int = 100) -> List[WebSocketFlow]:
        """Get captured WebSocket flows."""
        ws_file = Path(tempfile.gettempdir()) / "mitmproxy_ws.jsonl"
        flows = []

        if ws_file.exists():
            with open(ws_file, "r") as f:
                for line in f:
                    try:
                        data = json.loads(line.strip())
                        if data.get("timestamp", 0) > since:
                            flows.append(WebSocketFlow(**data))
                    except Exception:
                        pass

        return flows[-limit:]

    def clear_flows(self):
        """Clear captured flows."""
        for fname in ["mitmproxy_flows.jsonl", "mitmproxy_ws.jsonl"]:
            fpath = Path(tempfile.gettempdir()) / fname
            if fpath.exists():
                fpath.unlink()

    def export_flows(self, output_path: str, format: str = "json", flows: List[HTTPFlow] = None) -> bool:
        """Export flows to file."""
        if flows is None:
            flows = self.get_flows()

        try:
            if format == "json":
                with open(output_path, "w") as f:
                    json.dump([f.__dict__ for f in flows], f, indent=2)
            elif format == "har":
                self._export_har(flows, output_path)
            elif format == "pcap":
                # Would need mitmproxy pcap export
                pass
            return True
        except Exception as e:
            logger.error("mitmproxy_export_error", error=str(e))
            return False

    def _export_har(self, flows: List[HTTPFlow], output_path: str):
        """Export flows as HAR."""
        har = {
            "log": {
                "version": "1.2",
                "creator": {"name": "APKStudioAI", "version": "2.1"},
                "entries": [],
            }
        }

        for flow in flows:
            entry = {
                "startedDateTime": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(flow.timestamp)),
                "time": flow.duration_ms,
                "request": {
                    "method": flow.method,
                    "url": flow.url,
                    "httpVersion": "HTTP/1.1",
                    "headers": [{"name": k, "value": v} for k, v in flow.request_headers.items()],
                    "queryString": [],
                    "headersSize": -1,
                    "bodySize": len(flow.request_body),
                    "postData": {"mimeType": "", "text": flow.request_body} if flow.request_body else None,
                },
                "response": {
                    "status": flow.response_code,
                    "statusText": flow.response_reason,
                    "httpVersion": "HTTP/1.1",
                    "headers": [{"name": k, "value": v} for k, v in flow.response_headers.items()],
                    "content": {
                        "size": len(flow.response_body),
                        "mimeType": flow.response_headers.get("Content-Type", ""),
                        "text": flow.response_body,
                    },
                    "headersSize": -1,
                    "bodySize": len(flow.response_body),
                },
                "cache": {},
                "timings": {
                    "send": 0,
                    "wait": flow.duration_ms,
                    "receive": 0,
                },
            }
            har["log"]["entries"].append(entry)

        with open(output_path, "w") as f:
            json.dump(har, f, indent=2)

    def get_ca_cert(self) -> Optional[bytes]:
        """Get mitmproxy CA certificate for device installation."""
        if self.ca_cert_path.exists():
            return self.ca_cert_path.read_bytes()
        return None

    def install_ca_on_device(self, device_serial: str) -> bool:
        """Install CA certificate on Android device."""
        cert = self.get_ca_cert()
        if not cert:
            return False

        try:
            # Push cert to device
            import tempfile
            with tempfile.NamedTemporaryFile(suffix=".crt", delete=False) as f:
                f.write(cert)
                cert_path = f.name

            adb = "adb"
            subprocess.run([adb, "-s", device_serial, "push", cert_path, "/sdcard/mitmproxy-ca.crt"], timeout=10)
            subprocess.run([adb, "-s", device_serial, "shell", "su", "-c", "cp /sdcard/mitmproxy-ca.crt /system/etc/security/cacerts/"],
                          timeout=10)

            Path(cert_path).unlink()
            return True
        except Exception as e:
            logger.error("mitmproxy_ca_install_error", error=str(e))
            return False

    def analyze_traffic(self, flows: List[HTTPFlow] = None) -> Dict[str, Any]:
        """Analyze captured traffic for suspicious patterns."""
        if flows is None:
            flows = self.get_flows()

        analysis = {
            "total_requests": len(flows),
            "unique_hosts": set(),
            "suspicious_domains": [],
            "cleartext_requests": 0,
            "certificate_issues": 0,
            "large_responses": 0,
            "potential_c2": [],
            "exfiltration_indicators": [],
            "api_endpoints": [],
        }

        suspicious_tlds = [".top", ".xyz", ".ru", ".cn", ".tk", ".ml", ".ga", ".cf", ".gq"]
        c2_patterns = ["/api/command", "/cmd", "/control", "/beacon", "/heartbeat", "/checkin"]

        for flow in flows:
            analysis["unique_hosts"].add(flow.host)

            # Check for cleartext
            if flow.scheme == "http":
                analysis["cleartext_requests"] += 1

            # Check suspicious TLDs
            for tld in suspicious_tlds:
                if flow.host.endswith(tld):
                    analysis["suspicious_domains"].append(flow.host)

            # Check for C2 patterns
            for pattern in c2_patterns:
                if pattern in flow.path:
                    analysis["potential_c2"].append({
                        "url": flow.url,
                        "pattern": pattern,
                        "method": flow.method,
                    })

            # Check for exfiltration (large POST bodies)
            if flow.method == "POST" and len(flow.request_body) > 10000:
                analysis["exfiltration_indicators"].append({
                    "url": flow.url,
                    "body_size": len(flow.request_body),
                    "method": flow.method,
                })

            # Large responses
            if len(flow.response_body) > 100000:
                analysis["large_responses"] += 1

            # Certificate issues
            if flow.scheme == "https" and not flow.tls_version:
                analysis["certificate_issues"] += 1

            # API endpoints
            if "/api/" in flow.path or "/v1/" in flow.path or "/v2/" in flow.path:
                analysis["api_endpoints"].append(flow.url)

        analysis["unique_hosts"] = list(analysis["unique_hosts"])
        analysis["suspicious_domains"] = list(set(analysis["suspicious_domains"]))
        analysis["api_endpoints"] = list(set(analysis["api_endpoints"]))

        return analysis


_mitmproxy_instance = None


def get_mitmproxy_integration(config: Dict = None) -> MitmproxyIntegration:
    """Get singleton mitmproxy integration instance."""
    global _mitmproxy_instance
    if _mitmproxy_instance is None:
        _mitmproxy_instance = MitmproxyIntegration(config)
    return _mitmproxy_instance


import tempfile