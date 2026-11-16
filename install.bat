@echo off
REM APKStudioAI 2.1 - Installation Script
REM This script sets up the complete environment for APKStudioAI 2.1
REM Run as Administrator for best results

echo ============================================================
echo  APKStudioAI 2.1 - Installation
echo  Advanced Android Malware Analysis Platform
echo ============================================================
echo.

REM Check if running as administrator
net session >nul 2>&1
if %errorLevel% == 0 (
    echo [OK] Running with administrator privileges
) else (
    echo [WARN] Not running as administrator - some operations may fail
    echo        Right-click and select "Run as administrator" for best results
)
echo.

REM Set project directory (handles paths with spaces)
set "PROJECT_DIR=%~dp0"
echo Project directory: %PROJECT_DIR%
echo.

REM Enable delayed expansion for robust variable handling
setlocal EnableDelayedExpansion

REM Create directory structure
echo [1/8] Creating directory structure...
if not exist "%PROJECT_DIR%tools" mkdir "%PROJECT_DIR%tools"
if not exist "%PROJECT_DIR%reports" mkdir "%PROJECT_DIR%reports"
if not exist "%PROJECT_DIR%workspace" mkdir "%PROJECT_DIR%workspace"
if not exist "%PROJECT_DIR%logs" mkdir "%PROJECT_DIR%logs"
if not exist "%PROJECT_DIR%cache" mkdir "%PROJECT_DIR%cache"
if not exist "%PROJECT_DIR%analysis" mkdir "%PROJECT_DIR%analysis"
if not exist "%PROJECT_DIR%tests" mkdir "%PROJECT_DIR%tests"
echo [OK] Directories created
echo.

REM Check Python installation
echo [2/8] Checking Python installation...
python --version >nul 2>&1
if %errorLevel% == 0 (
    for /f "tokens=2" %%i in ('python --version') do set "PY_VER=%%i"
    echo [OK] Python !PY_VER! found
) else (
    echo [ERROR] Python not found! Please install Python 3.11+ from https://python.org
    echo         Make sure to check "Add Python to PATH" during installation
    pause
    exit /b 1
)
echo.

REM Check Java installation
echo [3/8] Checking Java installation...
java -version >nul 2>&1
if %errorLevel% == 0 (
    echo [OK] Java found
    java -version 2>&1 | findstr /r "version"
) else (
    echo [ERROR] Java not found! Please install Java 11+ (JDK recommended)
    echo         Download from: https://adoptium.net/
    pause
    exit /b 1
)
echo.

REM Create virtual environment
echo [4/8] Creating Python virtual environment...
if not exist "%PROJECT_DIR%venv" (
    python -m venv "%PROJECT_DIR%venv"
    if %errorLevel% == 0 (
        echo [OK] Virtual environment created
    ) else (
        echo [ERROR] Failed to create virtual environment
        pause
        exit /b 1
    )
) else (
    echo [OK] Virtual environment already exists
)
echo.

REM Activate virtual environment and install dependencies
echo [5/8] Installing Python dependencies...
call "%PROJECT_DIR%venv\Scripts\activate.bat"
if %errorLevel% == 0 (
    echo [OK] Virtual environment activated
) else (
    echo [ERROR] Failed to activate virtual environment
    pause
    exit /b 1
)

pip install --upgrade pip >nul 2>&1
pip install -r "%PROJECT_DIR%requirements.txt"
if %errorLevel% == 0 (
    echo [OK] Python dependencies installed
) else (
    echo [WARN] Some dependencies may have failed to install
    echo         Check the output above for details
)
echo.

REM Download JADX
echo [6/8] Checking JADX...
set "JADX_URL=https://github.com/skylot/jadx/releases/download/v1.5.1/jadx-1.5.1.zip"
set "JADX_DIR=%PROJECT_DIR%tools\jadx"
set "JADX_BAT=%JADX_DIR%\bin\jadx.bat"
set "JADX_ZIP=%PROJECT_DIR%tools\jadx.zip"

if exist "%JADX_BAT%" (
    echo [OK] JADX already installed at %JADX_BAT%
) else (
    echo [INFO] Downloading JADX 1.5.1...
    powershell -ExecutionPolicy Bypass -Command "Invoke-WebRequest -Uri '%JADX_URL%' -OutFile '%JADX_ZIP%'" 2>nul
    if %errorLevel% == 0 (
        echo [OK] JADX downloaded
        echo [INFO] Extracting JADX...
        powershell -ExecutionPolicy Bypass -Command "Expand-Archive -Path '%JADX_ZIP%' -DestinationPath '%JADX_DIR%' -Force" 2>nul
        if %errorLevel% == 0 (
            echo [OK] JADX extracted
            del "%JADX_ZIP%"
        ) else (
            echo [ERROR] Failed to extract JADX
            echo         Try manually: Expand-Archive -Path '%JADX_ZIP%' -DestinationPath '%JADX_DIR%' -Force
        )
    ) else (
        echo [WARN] Failed to download JADX automatically
        echo         Please download manually from: %JADX_URL%
        echo         Extract to: %JADX_DIR%
    )
)
echo.

REM Download Apktool
echo [7/8] Checking Apktool...
set "APKTOOL_URL=https://github.com/iBotPeaches/Apktool/releases/download/v2.10.0/apktool_2.10.0.jar"
set "APKTOOL_JAR=%PROJECT_DIR%tools\apktool.jar"

if exist "%APKTOOL_JAR%" (
    echo [OK] Apktool already installed at %APKTOOL_JAR%
) else (
    echo [INFO] Downloading Apktool 2.10.0...
    powershell -ExecutionPolicy Bypass -Command "Invoke-WebRequest -Uri '%APKTOOL_URL%' -OutFile '%APKTOOL_JAR%'" 2>nul
    if %errorLevel% == 0 (
        echo [OK] Apktool downloaded
    ) else (
        echo [WARN] Failed to download Apktool automatically
        echo         Please download manually from: %APKTOOL_URL%
        echo         Save as: %APKTOOL_JAR%
    )
)
echo.

REM Create apktool wrapper script
echo @echo off > "%PROJECT_DIR%tools\apktool.bat"
echo java -jar "%APKTOOL_JAR%" %%%* >> "%PROJECT_DIR%tools\apktool.bat"
echo [OK] Apktool wrapper created
echo.

REM Check Ollama
echo [8/8] Checking Ollama...
where ollama >nul 2>&1
if %errorLevel% == 0 (
    echo [OK] Ollama found in PATH
    ollama list | findstr "qwen2.5-coder:3b" >nul 2>&1
    if %errorLevel% == 0 (
        echo [OK] Model qwen2.5-coder:3b is available
    ) else (
        echo [WARN] Model qwen2.5-coder:3b not found
        echo         Run: ollama pull qwen2.5-coder:3b
    )
) else (
    echo [WARN] Ollama not found in PATH
    echo         Install from: https://ollama.ai/
    echo         Then run: ollama pull qwen2.5-coder:3b
)
echo.

REM Update config.json with correct paths using Python (more reliable than PowerShell)
echo [CONFIG] Updating configuration...
set "CONFIG_FILE=%PROJECT_DIR%config.json"
if exist "%CONFIG_FILE%" (
    python -c "
import json, sys
config_path = r'%CONFIG_FILE%'
with open(config_path, 'r') as f:
    config = json.load(f)
config.setdefault('tools', {})
config['tools']['jadx_path'] = r'%JADX_BAT%'
config['tools']['apktool_path'] = r'%APKTOOL_JAR%'
config['tools']['java_path'] = 'java'
with open(config_path, 'w') as f:
    json.dump(config, f, indent=4)
print('[OK] Configuration updated')
" 2>&1
    if %errorLevel% == 0 (
        echo [OK] Configuration updated via Python
    ) else (
        echo [WARN] Could not update config.json automatically
        echo         Please manually edit config.json to set:
        echo         tools.jadx_path = %JADX_BAT%
        echo         tools.apktool_path = %APKTOOL_JAR%
    )
) else (
    echo [WARN] config.json not found
)
echo.

REM Final verification
echo ============================================================
echo  INSTALLATION SUMMARY
echo ============================================================
echo.
echo Project directory: %PROJECT_DIR%
echo Virtual env:       %PROJECT_DIR%venv
echo JADX:              %JADX_BAT%
echo Apktool:           %APKTOOL_JAR%
echo Reports dir:       %PROJECT_DIR%reports
echo Workspace dir:     %PROJECT_DIR%workspace
echo Logs dir:          %PROJECT_DIR%logs
echo Cache dir:         %PROJECT_DIR%cache
echo.

if exist "%JADX_BAT%" (
    echo [OK] JADX ready
) else (
    echo [PENDING] JADX - manual installation required
)

if exist "%APKTOOL_JAR%" (
    echo [OK] Apktool ready
) else (
    echo [PENDING] Apktool - manual installation required
)

echo.
echo To start APKStudioAI 2.1 GUI:
echo   start.bat
echo.
echo To run CLI analysis:
echo   call venv\Scripts\activate.bat
echo   python main.py "path\to\sample.apk"
echo.
echo For diagnostics:
echo   diagnostic.bat
echo.
echo ============================================================
endlocal
pause