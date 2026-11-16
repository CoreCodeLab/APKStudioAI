#!/usr/bin/env python3
"""
APKStudioAI 2.1 - Python-based Installation Script
Cross-platform installer that works reliably on Windows, Linux, and macOS
"""
import os
import sys
import json
import subprocess
import shutil
import urllib.request
import zipfile
import platform
from pathlib import Path

PROJECT_DIR = Path(__file__).parent.resolve()

def run_cmd(cmd, cwd=None, check=True):
    """Run a command and return result."""
    try:
        result = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, shell=True)
        if check and result.returncode != 0:
            print(f"[ERROR] Command failed: {cmd}")
            print(f"  stdout: {result.stdout}")
            print(f"  stderr: {result.stderr}")
            return False
        return result
    except Exception as e:
        print(f"[ERROR] Exception running command: {e}")
        return False

def print_step(step, total, message):
    print(f"[{step}/{total}] {message}")

def check_python():
    """Check Python version."""
    print_step(1, 8, "Checking Python installation...")
    version = sys.version_info
    if version.major >= 3 and version.minor >= 11:
        print(f"  [OK] Python {version.major}.{version.minor}.{version.micro} found")
        return True
    else:
        print(f"  [ERROR] Python 3.11+ required, found {version.major}.{version.minor}")
        return False

def check_java():
    """Check Java installation."""
    print_step(2, 8, "Checking Java installation...")
    result = run_cmd("java -version", check=False)
    if result and result.returncode == 0:
        print(f"  [OK] Java found")
        # Print version from stderr (java -version outputs to stderr)
        for line in result.stderr.split('\n'):
            if 'version' in line.lower():
                print(f"  {line.strip()}")
                break
        return True
    else:
        print("  [ERROR] Java not found! Please install Java 11+ (JDK recommended)")
        print("         Download from: https://adoptium.net/")
        return False

def create_venv():
    """Create virtual environment."""
    print_step(3, 8, "Creating Python virtual environment...")
    venv_dir = PROJECT_DIR / "venv"
    if venv_dir.exists():
        print("  [OK] Virtual environment already exists")
        return True

    result = run_cmd(f"{sys.executable} -m venv {venv_dir}")
    if result:
        print("  [OK] Virtual environment created")
        return True
    else:
        print("  [ERROR] Failed to create virtual environment")
        return False

def install_deps():
    """Install Python dependencies."""
    print_step(4, 8, "Installing Python dependencies...")
    venv_python = PROJECT_DIR / "venv" / ("Scripts" if platform.system() == "Windows" else "bin") / "python"
    pip_cmd = f'"{venv_python}" -m pip install --upgrade pip'
    run_cmd(pip_cmd, check=False)

    result = run_cmd(f'"{venv_python}" -m pip install -r "{PROJECT_DIR / "requirements.txt"}"')
    if result:
        print("  [OK] Python dependencies installed")
        return True
    else:
        print("  [WARN] Some dependencies may have failed to install")
        return True  # Continue anyway

def download_file(url, dest):
    """Download a file with progress."""
    try:
        print(f"  Downloading {url}...")
        urllib.request.urlretrieve(url, dest)
        return True
    except Exception as e:
        print(f"  [ERROR] Failed to download: {e}")
        return False

def install_jadx():
    """Install JADX."""
    print_step(5, 8, "Checking JADX...")
    jadx_dir = PROJECT_DIR / "tools" / "jadx"
    jadx_bat = jadx_dir / "bin" / ("jadx.bat" if platform.system() == "Windows" else "jadx")

    if jadx_bat.exists():
        print(f"  [OK] JADX already installed at {jadx_bat}")
        return str(jadx_bat)

    print("  [INFO] Downloading JADX 1.5.1...")
    jadx_url = "https://github.com/skylot/jadx/releases/download/v1.5.1/jadx-1.5.1.zip"
    jadx_zip = PROJECT_DIR / "tools" / "jadx.zip"

    if not download_file(jadx_url, jadx_zip):
        print(f"  [WARN] Failed to download JADX automatically")
        print(f"         Please download manually from: {jadx_url}")
        print(f"         Extract to: {jadx_dir}")
        return None

    print("  [INFO] Extracting JADX...")
    try:
        with zipfile.ZipFile(jadx_zip, 'r') as zip_ref:
            zip_ref.extractall(jadx_dir)
        jadx_zip.unlink()
        print("  [OK] JADX extracted")
        return str(jadx_bat)
    except Exception as e:
        print(f"  [ERROR] Failed to extract JADX: {e}")
        return None

def install_apktool():
    """Install Apktool."""
    print_step(6, 8, "Checking Apktool...")
    apktool_jar = PROJECT_DIR / "tools" / "apktool.jar"

    if apktool_jar.exists():
        print(f"  [OK] Apktool already installed at {apktool_jar}")
        return str(apktool_jar)

    print("  [INFO] Downloading Apktool 2.10.0...")
    apktool_url = "https://github.com/iBotPeaches/Apktool/releases/download/v2.10.0/apktool_2.10.0.jar"

    if not download_file(apktool_url, apktool_jar):
        print(f"  [WARN] Failed to download Apktool automatically")
        print(f"         Please download manually from: {apktool_url}")
        print(f"         Save as: {apktool_jar}")
        return None

    print("  [OK] Apktool downloaded")

    # Create wrapper script
    if platform.system() == "Windows":
        wrapper = PROJECT_DIR / "tools" / "apktool.bat"
        wrapper.write_text(f'@echo off\njava -jar "{apktool_jar}" %*')
    else:
        wrapper = PROJECT_DIR / "tools" / "apktool"
        wrapper.write_text(f'#!/bin/bash\njava -jar "{apktool_jar}" "$@"')
        wrapper.chmod(0o755)

    print("  [OK] Apktool wrapper created")
    return str(apktool_jar)

def check_ollama():
    """Check Ollama installation."""
    print_step(7, 8, "Checking Ollama...")

    # Check if ollama is in PATH
    ollama_path = shutil.which("ollama")
    if not ollama_path:
        print("  [WARN] Ollama not found in PATH")
        print("         Install from: https://ollama.ai/")
        print("         Then run: ollama pull qwen2.5-coder:3b")
        return False

    print(f"  [OK] Ollama found at {ollama_path}")

    # Check if model exists
    result = run_cmd("ollama list", check=False)
    if result and "qwen2.5-coder:3b" in result.stdout:
        print("  [OK] Model qwen2.5-coder:3b is available")
        return True
    else:
        print("  [WARN] Model qwen2.5-coder:3b not found")
        print("         Run: ollama pull qwen2.5-coder:3b")
        return False

def update_config(jadx_path, apktool_path):
    """Update config.json with tool paths."""
    print_step(8, 8, "Updating configuration...")
    config_path = PROJECT_DIR / "config.json"

    if not config_path.exists():
        print("  [WARN] config.json not found")
        return False

    try:
        with open(config_path, 'r') as f:
            config = json.load(f)

        config.setdefault("tools", {})
        config["tools"]["jadx_path"] = jadx_path
        config["tools"]["apktool_path"] = apktool_path
        config["tools"]["java_path"] = "java"

        with open(config_path, 'w') as f:
            json.dump(config, f, indent=4)

        print("  [OK] Configuration updated")
        return True
    except Exception as e:
        print(f"  [ERROR] Failed to update config: {e}")
        return False

def main():
    print("=" * 60)
    print("  APKStudioAI 2.1 - Installation")
    print("  Advanced Android Malware Analysis Platform")
    print("=" * 60)
    print()

    # Check admin on Windows
    if platform.system() == "Windows":
        try:
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin()
            if is_admin:
                print("[OK] Running with administrator privileges")
            else:
                print("[WARN] Not running as administrator - some operations may fail")
        except:
            pass

    # Create directories
    print("[0/8] Creating directory structure...")
    dirs = ["tools", "reports", "workspace", "logs", "cache", "analysis", "tests"]
    for d in dirs:
        (PROJECT_DIR / d).mkdir(exist_ok=True)
    print("  [OK] Directories created")
    print()

    # Run installation steps
    steps = [
        check_python,
        check_java,
        create_venv,
        install_deps,
        install_jadx,
        install_apktool,
        check_ollama,
    ]

    results = []
    for step in steps:
        try:
            results.append(step())
        except Exception as e:
            print(f"  [ERROR] Step failed with exception: {e}")
            results.append(False)

    # Update config with results from jadx and apktool
    jadx_path = results[4] if len(results) > 4 else None
    apktool_path = results[5] if len(results) > 5 else None

    if jadx_path and apktool_path:
        update_config(jadx_path, apktool_path)

    # Summary
    print()
    print("=" * 60)
    print("  INSTALLATION SUMMARY")
    print("=" * 60)
    print()
    print(f"Project directory: {PROJECT_DIR}")
    print(f"Virtual env:       {PROJECT_DIR / 'venv'}")
    print(f"JADX:              {jadx_path or 'NOT INSTALLED'}")
    print(f"Apktool:           {apktool_path or 'NOT INSTALLED'}")
    print(f"Reports dir:       {PROJECT_DIR / 'reports'}")
    print(f"Workspace dir:     {PROJECT_DIR / 'workspace'}")
    print(f"Logs dir:          {PROJECT_DIR / 'logs'}")
    print(f"Cache dir:         {PROJECT_DIR / 'cache'}")
    print()

    if jadx_path:
        print("[OK] JADX ready")
    else:
        print("[PENDING] JADX - manual installation required")

    if apktool_path:
        print("[OK] Apktool ready")
    else:
        print("[PENDING] Apktool - manual installation required")

    print()
    print("To start APKStudioAI 2.1 GUI:")
    if platform.system() == "Windows":
        print("  start.bat")
    else:
        print("  ./start.sh")
    print()
    print("To run CLI analysis:")
    if platform.system() == "Windows":
        print("  call venv\\Scripts\\activate.bat")
    else:
        print("  source venv/bin/activate")
    print("  python main.py \"path/to/sample.apk\"")
    print()
    print("For diagnostics:")
    if platform.system() == "Windows":
        print("  diagnostic.bat")
    else:
        print("  ./diagnostic.sh")
    print()
    print("=" * 60)

if __name__ == "__main__":
    main()