#!/bin/bash
# APKStudioAI 2.1 - Diagnostic Script (Linux/macOS)
# Performs comprehensive system and configuration diagnostics

echo "============================================================"
echo "  APKStudioAI 2.1 - Diagnostic Tool"
echo "  Advanced Android Malware Analysis Platform"
echo "============================================================"
echo

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_DIR"

echo "[DIAG] Starting comprehensive diagnostic..."
echo

# ============================================================
echo "[1/10] SYSTEM INFORMATION"
echo "============================================================"
echo "OS:"
uname -a
echo
echo "Architecture:"
uname -m
echo
echo "Memory:"
if command -v free &> /dev/null; then
    free -h
elif command -v sysctl &> /dev/null; then
    sysctl hw.memsize
fi
echo
echo "CPU:"
if command -v lscpu &> /dev/null; then
    lscpu | grep "Model name"
elif command -v sysctl &> /dev/null; then
    sysctl -n machdep.cpu.brand_string
fi
echo

# ============================================================
echo "[2/10] PYTHON ENVIRONMENT"
echo "============================================================"
echo "Python version:"
python3 --version 2>&1
echo
echo "Pip version:"
pip3 --version 2>&1
echo
echo "Virtual environment:"
if [ -d "$PROJECT_DIR/venv" ]; then
    echo "[OK] Virtual environment exists at $PROJECT_DIR/venv"
    source "$PROJECT_DIR/venv/bin/activate" 2>/dev/null
    if [ $? -eq 0 ]; then
        echo "[OK] Virtual environment activates successfully"
        echo "Python (venv):"
        python --version 2>&1
    else
        echo "[ERROR] Virtual environment fails to activate"
    fi
else
    echo "[ERROR] Virtual environment NOT FOUND at $PROJECT_DIR/venv"
    echo "        Run ./install.py to create it"
fi
echo

# ============================================================
echo "[3/10] PYTHON DEPENDENCIES"
echo "============================================================"
echo "Checking required packages..."
python3 -c "
import sys
pkgs = [
    'requests', 'bs4', 'lxml', 'pyelftools', 'capstone',
    'tkinter', 'json', 'hashlib', 'pathlib', 'datetime',
    'threading', 'subprocess', 'tempfile', 'shutil', 'zipfile',
    'xml.etree.ElementTree', 're', 'base64', 'binascii',
    'androguard', 'apkid', 'networkx', 'jsonschema', 'structlog'
]
missing = []
for p in pkgs:
    try:
        __import__(p)
        print(f'  [OK] {p}')
    except ImportError:
        print(f'  [MISSING] {p}')
        missing.append(p)
if missing:
    print(f'\nMissing packages: {missing}')
    sys.exit(1)
else:
    print('\n[OK] All required packages available')
" 2>&1
echo

# ============================================================
echo "[4/10] JAVA ENVIRONMENT"
echo "============================================================"
java -version 2>&1
echo
echo "JAVA_HOME: $JAVA_HOME"
echo

# ============================================================
echo "[5/10] EXTERNAL TOOLS"
echo "============================================================"
echo "Checking JADX..."
JADX_BAT="$PROJECT_DIR/tools/jadx/bin/jadx"
if [ -f "$JADX_BAT" ]; then
    echo "[OK] JADX found at $JADX_BAT"
    "$JADX_BAT" --version 2>&1 | head -1
else
    echo "[ERROR] JADX NOT FOUND at $JADX_BAT"
    echo "        Expected: $PROJECT_DIR/tools/jadx/bin/jadx"
fi
echo

echo "Checking Apktool..."
APKTOOL_JAR="$PROJECT_DIR/tools/apktool.jar"
if [ -f "$APKTOOL_JAR" ]; then
    echo "[OK] Apktool found at $APKTOOL_JAR"
    java -jar "$APKTOOL_JAR" --version 2>&1
else
    echo "[ERROR] Apktool NOT FOUND at $APKTOOL_JAR"
    echo "        Expected: $PROJECT_DIR/tools/apktool.jar"
fi
echo

# ============================================================
echo "[6/10] OLLAMA AI SERVICE"
echo "============================================================"
echo "Checking Ollama..."
if command -v ollama &> /dev/null; then
    echo "[OK] Ollama executable found in PATH"
    ollama --version 2>&1
    echo
    echo "Checking Ollama API..."
    if curl -s http://127.0.0.1:11434/api/tags >/dev/null 2>&1; then
        echo "[OK] Ollama API responding"
        MODELS=$(curl -s http://127.0.0.1:11434/api/tags | python3 -c "
import sys, json
data = json.load(sys.stdin)
found = False
for m in data.get('models', []):
    if 'qwen2.5-coder' in m.get('name', ''):
        print('[OK] Model qwen2.5-coder found:', m['name'])
        found = True
if not found:
    print('[WARN] Model qwen2.5-coder:3b NOT FOUND')
    print('       Run: ollama pull qwen2.5-coder:3b')
" 2>&1)
        echo "$MODELS"
    else
        echo "[ERROR] Ollama API not responding"
        echo "        Make sure Ollama is running: ollama serve"
    fi
else
    echo "[ERROR] Ollama NOT FOUND in PATH"
    echo "        Install from: https://ollama.ai/"
    echo "        Then run: ollama pull qwen2.5-coder:3b"
fi
echo

# ============================================================
echo "[7/10] CONFIGURATION"
echo "============================================================"
CONFIG_FILE="$PROJECT_DIR/config.json"
if [ -f "$CONFIG_FILE" ]; then
    echo "[OK] config.json found"
    echo
    echo "Configuration content:"
    cat "$CONFIG_FILE"
else
    echo "[ERROR] config.json NOT FOUND at $CONFIG_FILE"
fi
echo

# ============================================================
echo "[8/10] PROJECT STRUCTURE"
echo "============================================================"
echo "Checking directory structure..."
DIRS=("core" "analysis" "reports" "workspace" "logs" "cache" "tools" "tests")
for d in "${DIRS[@]}"; do
    if [ -d "$PROJECT_DIR/$d" ]; then
        echo "[OK] $PROJECT_DIR/$d"
    else
        echo "[MISSING] $PROJECT_DIR/$d"
    fi
done
echo

echo "Checking core modules..."
MODULES=("scanner" "archive_analyzer" "manifest_analyzer" "dex_analyzer" "jadx_engine" "apktool_engine" "native_analyzer" "elf_analyzer" "jni_analyzer" "string_analyzer" "permission_analyzer" "behavior_analyzer" "network_analyzer" "malware_detector" "risk_engine" "ollama_client" "utils" "reporter")
for m in "${MODULES[@]}"; do
    if [ -f "$PROJECT_DIR/core/$m.py" ]; then
        echo "[OK] core/$m.py"
    else
        echo "[MISSING] core/$m.py"
    fi
done
echo

echo "Checking analysis rules..."
RULES=("rules.json" "signatures.json" "behavior_rules.json")
for r in "${RULES[@]}"; do
    if [ -f "$PROJECT_DIR/analysis/$r" ]; then
        echo "[OK] analysis/$r"
    else
        echo "[MISSING] analysis/$r"
    fi
done
echo

# ============================================================
echo "[9/10] NETWORK CONNECTIVITY"
echo "============================================================"
echo "Testing local connections..."
# Test Ollama
if curl -s --max-time 3 http://127.0.0.1:11434/api/tags >/dev/null 2>&1; then
    echo "[OK] localhost:11434 (Ollama)"
else
    echo "[FAIL] localhost:11434 (Ollama)"
fi
# Test GitHub
if curl -s --max-time 5 https://api.github.com >/dev/null 2>&1; then
    echo "[OK] github.com"
else
    echo "[WARN] github.com (may affect auto-updates)"
fi
echo

# ============================================================
echo "[10/10] TEST APK FILES"
echo "============================================================"
echo "Checking test APKs..."
MALWARE_DIR="$PROJECT_DIR/MALWARE"
if [ -d "$MALWARE_DIR" ]; then
    echo "[OK] Malware directory found: $MALWARE_DIR"
    count=$(ls "$MALWARE_DIR"/*.apk 2>/dev/null | wc -l)
    echo "     Found $count APK file(s)"
    for f in "$MALWARE_DIR"/*.apk; do
        [ -f "$f" ] && echo "[FOUND] $(basename "$f")"
    done
else
    echo "[WARN] Malware directory NOT FOUND: $MALWARE_DIR"
    echo "       Place test APKs in: $MALWARE_DIR"
fi
echo

# ============================================================
echo "[SUMMARY] DIAGNOSTIC COMPLETE"
echo "============================================================"
echo
echo "Review the output above for any [ERROR] or [MISSING] items."
echo
echo "Common fixes:"
echo "  - Missing Python packages: pip install -r requirements.txt"
echo "  - Missing JADX/Apktool: Run ./install.py (downloads automatically)"
echo "  - Ollama not running: Start 'ollama serve' in a terminal"
echo "  - Model missing: Run 'ollama pull qwen2.5-coder:3b'"
echo "  - Virtual env issues: Delete venv folder and re-run ./install.py"
echo
echo "Logs directory: $PROJECT_DIR/logs"
echo "Reports directory: $PROJECT_DIR/reports"
echo