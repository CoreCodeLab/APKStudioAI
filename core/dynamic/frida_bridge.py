"""
Frida Bridge for APKStudioAI 2.1
JavaScript injection, hooking, and runtime instrumentation.
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

logger = get_module_logger("frida_bridge")


class HookType(Enum):
    """Types of Frida hooks."""
    METHOD_ENTRY = "method_entry"
    METHOD_EXIT = "method_exit"
    CONSTRUCTOR = "constructor"
    FIELD_READ = "field_read"
    FIELD_WRITE = "field_write"
    NATIVE = "native"


@dataclass
class Hook:
    """Frida hook definition."""
    id: str
    target_class: str
    target_method: str
    hook_type: HookType = HookType.METHOD_ENTRY
    script: str = ""
    enabled: bool = True
    filters: Dict[str, Any] = field(default_factory=dict)


@dataclass
class FridaSession:
    """Active Frida session."""
    pid: int
    package: str
    device_id: str
    session_id: str
    hooks: List[Hook] = field(default_factory=list)
    events: List[Dict] = field(default_factory=list)
    started_at: float = field(default_factory=time.time)
    process: Optional[subprocess.Popen] = None


class FridaBridge:
    """Bridge for Frida instrumentation."""

    def __init__(self, config: Dict = None):
        self.config = config or get_config().get_all()
        self.frida_path = self._find_frida()
        self.sessions: Dict[str, FridaSession] = {}
        self.event_callbacks: List[Callable] = []
        self._lock = threading.Lock()

    def _find_frida(self) -> str:
        """Find Frida executable."""
        import shutil
        return shutil.which("frida") or "frida"

    def is_available(self) -> bool:
        """Check if Frida is available."""
        try:
            result = subprocess.run([self.frida_path, "--version"], capture_output=True, timeout=5)
            return result.returncode == 0
        except Exception:
            return False

    def get_version(self) -> Optional[str]:
        """Get Frida version."""
        try:
            result = subprocess.run([self.frida_path, "--version"], capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                return result.stdout.strip()
        except Exception:
            pass
        return None

    def list_devices(self) -> List[Dict]:
        """List connected devices."""
        try:
            result = subprocess.run(
                [self.frida_path, "-l"], capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                devices = []
                for line in result.stdout.strip().split("\n"):
                    if line.strip():
                        parts = line.split()
                        if len(parts) >= 2:
                            devices.append({
                                "id": parts[0],
                                "name": " ".join(parts[1:]),
                                "type": "usb" if "usb" in line.lower() else "local",
                            })
                return devices
        except Exception as e:
            logger.error("frida_list_devices_error", error=str(e))
        return []

    def list_processes(self, device_id: str = None) -> List[Dict]:
        """List running processes on device."""
        cmd = [self.frida_path, "ps"]
        if device_id:
            cmd.extend(["-D", device_id])

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                processes = []
                for line in result.stdout.strip().split("\n")[1:]:  # Skip header
                    if line.strip():
                        parts = line.split()
                        if len(parts) >= 3:
                            processes.append({
                                "pid": int(parts[0]),
                                "name": parts[1],
                                "identifier": parts[2] if len(parts) > 2 else "",
                            })
                return processes
        except Exception as e:
            logger.error("frida_list_processes_error", error=str(e))
        return []

    def attach(self, package: str, device_id: str = None, spawn: bool = False) -> Optional[FridaSession]:
        """Attach to a process."""
        # Find PID
        processes = self.list_processes(device_id)
        target = None
        for p in processes:
            if package in p["identifier"] or package in p["name"]:
                target = p
                break

        if not target and spawn:
            # Spawn the app
            target = self._spawn_app(package, device_id)

        if not target:
            logger.error("frida_attach_failed", package=package, reason="Process not found")
            return None

        session_id = f"{package}_{target['pid']}_{int(time.time())}"

        # Create session
        session = FridaSession(
            pid=target["pid"],
            package=package,
            device_id=device_id or "local",
            session_id=session_id,
        )

        self.sessions[session_id] = session
        logger.info("frida_attached", session_id=session_id, pid=target["pid"])

        return session

    def _spawn_app(self, package: str, device_id: str = None) -> Optional[Dict]:
        """Spawn app and return process info."""
        cmd = [self.frida_path, "-f", package]
        if device_id:
            cmd.extend(["-D", device_id])

        try:
            # This would need a more sophisticated approach for actual spawning
            # For now, return mock info
            return {"pid": 0, "identifier": package}
        except Exception:
            return None

    def detach(self, session_id: str) -> bool:
        """Detach from a session."""
        with self._lock:
            session = self.sessions.pop(session_id, None)
            if session and session.process:
                try:
                    session.process.terminate()
                except Exception:
                    pass
            logger.info("frida_detached", session_id=session_id)
            return session is not None

    def inject_script(self, session_id: str, script: str) -> bool:
        """Inject JavaScript into session."""
        session = self.sessions.get(session_id)
        if not session:
            return False

        # Write script to temp file
        import tempfile
        with tempfile.NamedTemporaryFile(mode="w", suffix=".js", delete=False) as f:
            f.write(script)
            script_path = f.name

        try:
            cmd = [self.frida_path, "-p", str(session.pid), script_path]
            if session.device_id != "local":
                cmd.extend(["-D", session.device_id])

            # Run in background
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            session.process = proc

            # Read output in background
            threading.Thread(target=self._read_frida_output, args=(session, proc), daemon=True).start()

            logger.info("frida_script_injected", session_id=session_id)
            return True

        except Exception as e:
            logger.error("frida_inject_error", session_id=session_id, error=str(e))
            return False
        finally:
            try:
                Path(script_path).unlink()
            except Exception:
                pass

    def _read_frida_output(self, session: FridaSession, proc: subprocess.Popen):
        """Read Frida output in background."""
        try:
            for line in iter(proc.stdout.readline, b""):
                line = line.decode("utf-8").strip()
                if line:
                    try:
                        event = json.loads(line)
                        event["session_id"] = session.session_id
                        event["timestamp"] = time.time()
                        session.events.append(event)

                        # Call callbacks
                        for callback in self.event_callbacks:
                            try:
                                callback(event)
                            except Exception:
                                pass
                    except json.JSONDecodeError:
                        # Non-JSON output
                        pass
        except Exception as e:
            logger.error("frida_output_error", session_id=session.session_id, error=str(e))

    def add_hook(self, session_id: str, hook: Hook) -> bool:
        """Add a hook to session."""
        session = self.sessions.get(session_id)
        if not session:
            return False

        # Generate hook script
        script = self._generate_hook_script(hook)
        hook.script = script

        session.hooks.append(hook)
        logger.info("frida_hook_added", session_id=session_id, hook_id=hook.id)
        return True

    def _generate_hook_script(self, hook: Hook) -> str:
        """Generate Frida JavaScript for hook."""
        if hook.hook_type == HookType.METHOD_ENTRY:
            return f"""
Java.perform(function() {{
    var targetClass = Java.use("{hook.target_class}");
    var method = targetClass.{hook.target_method};

    method.implementation = function() {{
        var args = Array.prototype.slice.call(arguments);
        send({{
            type: "method_entry",
            hook_id: "{hook.id}",
            class: "{hook.target_class}",
            method: "{hook.target_method}",
            args: args,
            timestamp: Date.now()
        }});
        return method.apply(this, arguments);
    }};
}});
"""
        elif hook.hook_type == HookType.METHOD_EXIT:
            return f"""
Java.perform(function() {{
    var targetClass = Java.use("{hook.target_class}");
    var method = targetClass.{hook.target_method};

    method.implementation = function() {{
        var result = method.apply(this, arguments);
        var args = Array.prototype.slice.call(arguments);
        send({{
            type: "method_exit",
            hook_id: "{hook.id}",
            class: "{hook.target_class}",
            method: "{hook.target_method}",
            args: args,
            return_value: result,
            timestamp: Date.now()
        }});
        return result;
    }};
}});
"""
        elif hook.hook_type == HookType.CONSTRUCTOR:
            return f"""
Java.perform(function() {{
    var targetClass = Java.use("{hook.target_class}");
    targetClass.$init.implementation = function() {{
        var args = Array.prototype.slice.call(arguments);
        send({{
            type: "constructor",
            hook_id: "{hook.id}",
            class: "{hook.target_class}",
            args: args,
            timestamp: Date.now()
        }});
        return this.$init.apply(this, arguments);
    }};
}});
"""
        elif hook.hook_type == HookType.NATIVE:
            return f"""
Interceptor.attach(Module.findExportByName(null, "{hook.target_method}"), {{
    onEnter: function(args) {{
        send({{
            type: "native_entry",
            hook_id: "{hook.id}",
            function: "{hook.target_method}",
            args: args.map(function(a) {{ return a.toString(); }}),
            timestamp: Date.now()
        }});
    }},
    onLeave: function(retval) {{
        send({{
            type: "native_exit",
            hook_id: "{hook.id}",
            function: "{hook.target_method}",
            retval: retval.toString(),
            timestamp: Date.now()
        }});
    }}
}});
"""

        return ""

    def remove_hook(self, session_id: str, hook_id: str) -> bool:
        """Remove a hook from session."""
        session = self.sessions.get(session_id)
        if not session:
            return False

        session.hooks = [h for h in session.hooks if h.id != hook_id]
        # Would need to reinject scripts without the removed hook
        logger.info("frida_hook_removed", session_id=session_id, hook_id=hook_id)
        return True

    def get_events(self, session_id: str, since: float = 0) -> List[Dict]:
        """Get events from session."""
        session = self.sessions.get(session_id)
        if not session:
            return []

        return [e for e in session.events if e.get("timestamp", 0) > since]

    def register_callback(self, callback: Callable[[Dict], None]):
        """Register event callback."""
        self.event_callbacks.append(callback)

    # Pre-built hook scripts for common analysis tasks
    @staticmethod
    def get_crypto_hooks() -> List[Hook]:
        """Get hooks for cryptographic operations."""
        hooks = []
        crypto_classes = [
            ("javax.crypto.Cipher", "init"),
            ("javax.crypto.Cipher", "doFinal"),
            ("javax.crypto.Cipher", "update"),
            ("javax.crypto.Mac", "init"),
            ("javax.crypto.Mac", "doFinal"),
            ("java.security.MessageDigest", "update"),
            ("java.security.MessageDigest", "digest"),
            ("javax.crypto.spec.SecretKeySpec", "<init>"),
            ("javax.crypto.spec.IvParameterSpec", "<init>"),
        ]
        for i, (cls, method) in enumerate(crypto_classes):
            hooks.append(Hook(
                id=f"crypto_{i}",
                target_class=cls,
                target_method=method,
                hook_type=HookType.METHOD_ENTRY,
            ))
        return hooks

    @staticmethod
    def get_network_hooks() -> List[Hook]:
        """Get hooks for network operations."""
        hooks = []
        net_classes = [
            ("java.net.HttpURLConnection", "connect"),
            ("java.net.HttpURLConnection", "getInputStream"),
            ("java.net.HttpURLConnection", "getOutputStream"),
            ("java.net.URL", "openConnection"),
            ("java.net.Socket", "<init>"),
            ("java.net.Socket", "connect"),
            ("javax.net.ssl.HttpsURLConnection", "connect"),
            ("okhttp3.OkHttpClient", "newCall"),
            ("okhttp3.Call", "execute"),
        ]
        for i, (cls, method) in enumerate(net_classes):
            hooks.append(Hook(
                id=f"network_{i}",
                target_class=cls,
                target_method=method,
                hook_type=HookType.METHOD_ENTRY,
            ))
        return hooks

    @staticmethod
    def get_file_hooks() -> List[Hook]:
        """Get hooks for file operations."""
        hooks = []
        file_classes = [
            ("java.io.FileOutputStream", "<init>"),
            ("java.io.FileInputStream", "<init>"),
            ("java.io.File", "delete"),
            ("java.io.File", "renameTo"),
            ("android.content.Context", "openFileOutput"),
            ("android.content.Context", "openFileInput"),
            ("android.content.Context", "getFilesDir"),
            ("android.content.Context", "getCacheDir"),
        ]
        for i, (cls, method) in enumerate(file_classes):
            hooks.append(Hook(
                id=f"file_{i}",
                target_class=cls,
                target_method=method,
                hook_type=HookType.METHOD_ENTRY,
            ))
        return hooks

    @staticmethod
    def get_reflection_hooks() -> List[Hook]:
        """Get hooks for reflection."""
        hooks = []
        refl_classes = [
            ("java.lang.Class", "forName"),
            ("java.lang.reflect.Method", "invoke"),
            ("java.lang.reflect.Field", "set"),
            ("java.lang.reflect.Constructor", "newInstance"),
            ("java.lang.Class", "getMethod"),
            ("java.lang.Class", "getDeclaredMethod"),
        ]
        for i, (cls, method) in enumerate(refl_classes):
            hooks.append(Hook(
                id=f"reflection_{i}",
                target_class=cls,
                target_method=method,
                hook_type=HookType.METHOD_ENTRY,
            ))
        return hooks

    @staticmethod
    def get_dynamic_loading_hooks() -> List[Hook]:
        """Get hooks for dynamic code loading."""
        hooks = []
        dyn_classes = [
            ("dalvik.system.DexClassLoader", "<init>"),
            ("dalvik.system.DexClassLoader", "loadClass"),
            ("dalvik.system.PathClassLoader", "<init>"),
            ("dalvik.system.PathClassLoader", "loadClass"),
            ("dalvik.system.InMemoryDexClassLoader", "<init>"),
            ("dalvik.system.DexFile", "loadDex"),
        ]
        for i, (cls, method) in enumerate(dyn_classes):
            hooks.append(Hook(
                id=f"dynload_{i}",
                target_class=cls,
                target_method=method,
                hook_type=HookType.METHOD_ENTRY,
            ))
        return hooks

    @staticmethod
    def get_anti_analysis_hooks() -> List[Hook]:
        """Get hooks for anti-analysis detection."""
        hooks = []
        anti_classes = [
            ("android.os.Debug", "isDebuggerConnected"),
            ("android.os.Debug", "waitingForDebugger"),
            ("java.lang.Runtime", "exec"),
            ("java.lang.System", "exit"),
            ("android.app.ActivityManager", "getRunningAppProcesses"),
            ("android.content.pm.PackageManager", "getPackageInfo"),
        ]
        for i, (cls, method) in enumerate(anti_classes):
            hooks.append(Hook(
                id=f"anti_{i}",
                target_class=cls,
                target_method=method,
                hook_type=HookType.METHOD_ENTRY,
            ))
        return hooks

    def get_all_hooks(self) -> List[Hook]:
        """Get all pre-built hooks."""
        hooks = []
        hooks.extend(self.get_crypto_hooks())
        hooks.extend(self.get_network_hooks())
        hooks.extend(self.get_file_hooks())
        hooks.extend(self.get_reflection_hooks())
        hooks.extend(self.get_dynamic_loading_hooks())
        hooks.extend(self.get_anti_analysis_hooks())
        return hooks


_frida_bridge_instance = None


def get_frida_bridge(config: Dict = None) -> FridaBridge:
    """Get singleton Frida bridge instance."""
    global _frida_bridge_instance
    if _frida_bridge_instance is None:
        _frida_bridge_instance = FridaBridge(config)
    return _frida_bridge_instance