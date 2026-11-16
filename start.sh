#!/bin/bash
# APKStudioAI 2.1 - Start GUI Script (Linux/macOS)
# Launches the graphical interface

echo "============================================================"
echo "  APKStudioAI 2.1 - Starting GUI"
echo "  Advanced Android Malware Analysis Platform"
echo "============================================================"
echo

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_DIR"

# Check if virtual environment exists
if [ ! -d "$PROJECT_DIR/venv" ]; then
    echo "[ERROR] Virtual environment not found!"
    echo "        Run ./install.py first to set up the environment."
    exit 1
fi

# Activate virtual environment
source "$PROJECT_DIR/venv/bin/activate"
if [ $? -ne 0 ]; then
    echo "[ERROR] Failed to activate virtual environment"
    echo "        Try deleting the venv folder and re-running ./install.py"
    exit 1
fi

echo "[OK] Virtual environment activated"
echo "[INFO] Starting APKStudioAI 2.1 GUI..."
echo

# Start the GUI
python "$PROJECT_DIR/gui.py"

echo
echo "[INFO] APKStudioAI 2.1 GUI closed"