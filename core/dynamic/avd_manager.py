"""
AVD Manager for APKStudioAI 2.1
Manages Android Virtual Devices for dynamic analysis.
"""
import json
import subprocess
import time
from pathlib import Path
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from enum import Enum
from ..config_manager import get_config
from ..logging_setup import get_module_logger

logger = get_module_logger("avd_manager")


class AVDState(Enum):
    """AVD states."""
    STOPPED = "stopped"
    STARTING = "starting"
    RUNNING = "running"
    STOPPING = "stopping"
    ERROR = "error"


@dataclass
class AVDConfig:
    """AVD configuration."""
    name: str
    api_level: int = 33
    abi: str = "arm64-v8a"
    device: str = "pixel_6"
    ram_size: str = "2048"
    storage_size: str = "4G"
    snapshot: bool = True
    gpu_mode: str = "auto"
    writable_system: bool = True
    no_window: bool = True  # Headless


@dataclass
class AVDInstance:
    """Running AVD instance."""
    config: AVDConfig
    state: AVDState = AVDState.STOPPED
    pid: Optional[int] = None
    port: int = 5554
    adb_port: int = 5555
    started_at: Optional[float] = None
    emulator_path: str = ""
    last_error: str = ""


class AVDManager:
    """Manages Android Virtual Devices for dynamic analysis."""

    def __init__(self, config: Dict = None):
        self.config = config or get_config().get_all()
        self.android_sdk = self._find_android_sdk()
        self.emulator_path = self._find_emulator()
        self.adb_path = self._find_adb()
        self.avd_dir = Path.home() / ".android" / "avd"
        self.instances: Dict[str, AVDInstance] = {}
        self._base_port = 5554

    def _find_android_sdk(self) -> Optional[Path]:
        """Find Android SDK path."""
        # Check common locations
        candidates = [
            Path.home() / "Android" / "Sdk",
            Path.home() / "Library" / "Android" / "sdk",
            Path("/opt/android-sdk"),
            Path("/usr/local/android-sdk"),
            Path(self.config.get("android_sdk_path", "")),
        ]

        for cand in candidates:
            if cand and cand.exists():
                return cand

        # Check ANDROID_HOME env
        import os
        android_home = os.environ.get("ANDROID_HOME")
        if android_home and Path(android_home).exists():
            return Path(android_home)

        return None

    def _find_emulator(self) -> str:
        """Find emulator executable."""
        if self.android_sdk:
            emulator = self.android_sdk / "emulator" / "emulator"
            if emulator.exists():
                return str(emulator)

        # Check PATH
        import shutil
        return shutil.which("emulator") or "emulator"

    def _find_adb(self) -> str:
        """Find ADB executable."""
        if self.android_sdk:
            adb = self.android_sdk / "platform-tools" / "adb"
            if adb.exists():
                return str(adb)

        import shutil
        return shutil.which("adb") or "adb"

    def list_system_images(self) -> List[Dict]:
        """List available system images."""
        if not self.android_sdk:
            return []

        images = []
        system_images_dir = self.android_sdk / "system-images"
        if system_images_dir.exists():
            for api_dir in system_images_dir.iterdir():
                if api_dir.is_dir():
                    api_level = api_dir.name
                    for arch_dir in api_dir.iterdir():
                        if arch_dir.is_dir():
                            images.append({
                                "api_level": api_level,
                                "abi": arch_dir.name,
                                "path": str(arch_dir),
                            })
        return images

    def create_avd(self, config: AVDConfig) -> bool:
        """Create a new AVD."""
        if not self.android_sdk:
            logger.error("avd_create_failed", error="Android SDK not found")
            return False

        # Check if AVD already exists
        avd_path = self.avd_dir / f"{config.name}.avd"
        if avd_path.exists():
            logger.warning("avd_exists", name=config.name)
            return True

        # Build avdmanager command
        cmd = [
            str(self.android_sdk / "cmdline-tools" / "latest" / "bin" / "avdmanager"),
            "create", "avd", "-n", config.name,
            "-k", f"system-images;android-{config.api_level};default;{config.abi}",
            "--device", config.device,
            "--force",
        ]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            if result.returncode == 0:
                logger.info("avd_created", name=config.name)
                return True
            else:
                logger.error("avd_create_failed", name=config.name, error=result.stderr)
                return False
        except subprocess.TimeoutExpired:
            logger.error("avd_create_timeout", name=config.name)
            return False
        except Exception as e:
            logger.error("avd_create_error", name=config.name, error=str(e))
            return False

    def delete_avd(self, name: str) -> bool:
        """Delete an AVD."""
        avd_path = self.avd_dir / f"{name}.avd"
        ini_path = self.avd_dir / f"{name}.ini"

        try:
            if avd_path.exists():
                import shutil
                shutil.rmtree(avd_path)
            if ini_path.exists():
                ini_path.unlink()
            logger.info("avd_deleted", name=name)
            return True
        except Exception as e:
            logger.error("avd_delete_error", name=name, error=str(e))
            return False

    def list_avds(self) -> List[Dict]:
        """List all AVDs."""
        avds = []
        for ini_file in self.avd_dir.glob("*.ini"):
            name = ini_file.stem
            avd_path = self.avd_dir / f"{name}.avd"
            config_file = avd_path / "config.ini"

            info = {"name": name, "path": str(avd_path), "exists": avd_path.exists()}

            if config_file.exists():
                content = config_file.read_text()
                for line in content.split("\n"):
                    if "=" in line:
                        key, val = line.split("=", 1)
                        info[key.strip()] = val.strip()

            avds.append(info)

        return avds

    def start_avd(self, config: AVDConfig, timeout: int = 120) -> AVDInstance:
        """Start an AVD."""
        # Allocate ports
        port = self._base_port
        self._base_port += 2
        adb_port = port + 1

        instance = AVDInstance(
            config=config,
            state=AVDState.STARTING,
            port=port,
            adb_port=adb_port,
            emulator_path=self.emulator_path,
        )

        # Build emulator command
        cmd = [
            self.emulator_path,
            "-avd", config.name,
            "-port", str(port),
            "-no-window" if config.no_window else "-window",
            "-gpu", config.gpu_mode,
            "-memory", config.ram_size,
            "-partition-size", config.storage_size.replace("G", "000") if "G" in config.storage_size else config.storage_size,
        ]

        if config.writable_system:
            cmd.append("-writable-system")

        if config.snapshot:
            cmd.append("-snapshot")
            cmd.append("default_boot")

        logger.info("avd_starting", name=config.name, port=port)

        try:
            # Start emulator process
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True,
            )

            instance.pid = proc.pid
            instance.started_at = time.time()

            # Wait for boot
            if self._wait_for_boot(instance, timeout):
                instance.state = AVDState.RUNNING
                logger.info("avd_started", name=config.name, pid=proc.pid, port=port)
            else:
                instance.state = AVDState.ERROR
                instance.last_error = "Boot timeout"
                self.stop_avd(instance)
                logger.error("avd_boot_timeout", name=config.name)

        except Exception as e:
            instance.state = AVDState.ERROR
            instance.last_error = str(e)
            logger.error("avd_start_error", name=config.name, error=str(e))

        self.instances[config.name] = instance
        return instance

    def _wait_for_boot(self, instance: AVDInstance, timeout: int) -> bool:
        """Wait for AVD to finish booting."""
        start = time.time()
        while time.time() - start < timeout:
            try:
                # Check boot completed via adb
                result = subprocess.run(
                    [self.adb_path, "-s", f"emulator-{instance.port}", "shell", "getprop", "sys.boot_completed"],
                    capture_output=True, text=True, timeout=10
                )
                if result.stdout.strip() == "1":
                    # Additional wait for stability
                    time.sleep(5)
                    return True
            except Exception:
                pass
            time.sleep(2)
        return False

    def stop_avd(self, instance: AVDInstance) -> bool:
        """Stop an AVD."""
        if instance.pid:
            try:
                import os
                os.killpg(os.getpgid(instance.pid), 9)
            except Exception:
                try:
                    subprocess.run([self.adb_path, "-s", f"emulator-{instance.port}", "emu", "kill"],
                                 capture_output=True, timeout=10)
                except Exception:
                    pass

        instance.state = AVDState.STOPPED
        instance.pid = None
        logger.info("avd_stopped", name=instance.config.name)
        return True

    def get_instance(self, name: str) -> Optional[AVDInstance]:
        """Get AVD instance by name."""
        return self.instances.get(name)

    def list_running(self) -> List[AVDInstance]:
        """List running AVD instances."""
        return [i for i in self.instances.values() if i.state == AVDState.RUNNING]

    def install_apk(self, instance: AVDInstance, apk_path: str) -> bool:
        """Install APK on running AVD."""
        if instance.state != AVDState.RUNNING:
            logger.error("avd_not_running", name=instance.config.name)
            return False

        try:
            result = subprocess.run(
                [self.adb_path, "-s", f"emulator-{instance.port}", "install", "-r", apk_path],
                capture_output=True, text=True, timeout=120
            )
            success = result.returncode == 0
            if success:
                logger.info("apk_installed", avd=instance.config.name, apk=apk_path)
            else:
                logger.error("apk_install_failed", avd=instance.config.name, error=result.stderr)
            return success
        except Exception as e:
            logger.error("apk_install_error", avd=instance.config.name, error=str(e))
            return False

    def start_app(self, instance: AVDInstance, package: str, activity: str = None) -> bool:
        """Start app on AVD."""
        if instance.state != AVDState.RUNNING:
            return False

        try:
            if activity:
                cmd = [self.adb_path, "-s", f"emulator-{instance.port}", "shell", "am", "start", "-n", f"{package}/{activity}"]
            else:
                cmd = [self.adb_path, "-s", f"emulator-{instance.port}", "shell", "monkey", "-p", package, "-c", "android.intent.category.LAUNCHER", "1"]

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            return result.returncode == 0
        except Exception as e:
            logger.error("app_start_error", error=str(e))
            return False

    def take_screenshot(self, instance: AVDInstance, output_path: str) -> bool:
        """Take screenshot from AVD."""
        if instance.state != AVDState.RUNNING:
            return False

        try:
            subprocess.run(
                [self.adb_path, "-s", f"emulator-{instance.port}", "shell", "screencap", "-p", "/sdcard/screen.png"],
                timeout=10
            )
            subprocess.run(
                [self.adb_path, "-s", f"emulator-{instance.port}", "pull", "/sdcard/screen.png", output_path],
                timeout=10
            )
            return True
        except Exception:
            return False

    def execute_shell(self, instance: AVDInstance, command: str) -> Optional[str]:
        """Execute shell command on AVD."""
        if instance.state != AVDState.RUNNING:
            return None

        try:
            result = subprocess.run(
                [self.adb_path, "-s", f"emulator-{instance.port}", "shell", command],
                capture_output=True, text=True, timeout=30
            )
            return result.stdout
        except Exception:
            return None

    def cleanup_all(self):
        """Stop all running AVDs."""
        for instance in self.instances.values():
            if instance.state == AVDState.RUNNING:
                self.stop_avd(instance)


_avd_manager_instance = None


def get_avd_manager(config: Dict = None) -> AVDManager:
    """Get singleton AVD manager instance."""
    global _avd_manager_instance
    if _avd_manager_instance is None:
        _avd_manager_instance = AVDManager(config)
    return _avd_manager_instance