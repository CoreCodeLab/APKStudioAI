@echo off
REM APKStudioAI 2.1 - Diagnostic Script
REM Performs comprehensive system and configuration diagnostics

echo ============================================================
echo  APKStudioAI 2.1 - Diagnostic Tool
echo  Advanced Android Malware Analysis Platform
echo ============================================================
echo.

set PROJECT_DIR=%~dp0
cd /d "%PROJECT_DIR%"

echo [DIAG] Starting comprehensive diagnostic...
echo.

REM ============================================================
echo [1/10] SYSTEM INFORMATION
echo ============================================================
echo OS:
ver
echo.
echo Architecture:
wmic os get OSArchitecture /value 2>nul | find "="
echo.
echo Memory:
wmic computersystem get TotalPhysicalMemory /value 2>nul | find "="
echo.
echo CPU:
wmic cpu get Name /value 2>nul | find "="
echo.

REM ============================================================
echo [2/10] PYTHON ENVIRONMENT
echo ============================================================
echo Python version:
python --version 2>&1
echo.
echo Pip version:
pip --version 2>&1
echo.
echo Virtual environment:
if exist "%PROJECT_DIR%venv" (
    echo [OK] Virtual environment exists at %PROJECT_DIR%venv
    call "%PROJECT_DIR%venv\Scripts\activate.bat" >nul 2>&1
    if %errorLevel% == 0 (
        echo [OK] Virtual environment activates successfully
        echo Python (venv):
        python --version 2>&1
    ) else (
        echo [ERROR] Virtual environment fails to activate
    )
) else (
    echo [ERROR] Virtual environment NOT FOUND at %PROJECT_DIR%venv
    echo         Run install.bat to create it
)
echo.

REM ============================================================
echo [3/10] PYTHON DEPENDENCIES
echo ============================================================
echo Checking required packages...
python -c "
import sys
pkgs = [
    'requests', 'bs4', 'lxml', 'pyelftools', 'capstone',
    'tkinter', 'json', 'hashlib', 'pathlib', 'datetime',
    'threading', 'subprocess', 'tempfile', 'shutil', 'zipfile',
    'xml.etree.ElementTree', 're', 'base64', 'binascii'
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
    print(f'\\nMissing packages: {missing}')
    sys.exit(1)
else:
    print('\\n[OK] All required packages available')
" 2>&1
echo.

REM ============================================================
echo [4/10] JAVA ENVIRONMENT
echo ============================================================
java -version 2>&1
echo.
echo JAVA_HOME: %JAVA_HOME%
echo.

REM ============================================================
echo [5/10] EXTERNAL TOOLS
echo ============================================================
echo Checking JADX...
set JADX_BAT=%PROJECT_DIR%tools\jadx\bin\jadx.bat
if exist "%JADX_BAT%" (
    echo [OK] JADX found at %JADX_BAT%
    "%JADX_BAT%" --version 2>&1 | head -1
) else (
    echo [ERROR] JADX NOT FOUND at %JADX_BAT%
    echo         Expected: %PROJECT_DIR%tools\jadx\bin\jadx.bat
)
echo.

echo Checking Apktool...
set APKTOOL_JAR=%PROJECT_DIR%tools\apktool.jar
if exist "%APKTOOL_JAR%" (
    echo [OK] Apktool found at %APKTOOL_JAR%
    java -jar "%APKTOOL_JAR%" --version 2>&1
) else (
    echo [ERROR] Apktool NOT FOUND at %APKTOOL_JAR%
    echo         Expected: %PROJECT_DIR%tools\apktool.jar
)
echo.

REM ============================================================
echo [6/10] OLLAMA AI SERVICE
echo ============================================================
echo Checking Ollama...
where ollama >nul 2>&1
if %errorLevel% == 0 (
    echo [OK] Ollama executable found in PATH
    ollama --version 2>&1
    echo.
    echo Checking Ollama API...
    powershell -Command "
        try {
            \$r = Invoke-WebRequest -Uri 'http://127.0.0.1:11434/api/tags' -TimeoutSec 5 -ErrorAction Stop
            if (\$r.StatusCode -eq 200) {
                Write-Host '[OK] Ollama API responding'
                \$data = \$r.Content | ConvertFrom-Json
                \$found = \$false
                foreach (\$m in \$data.models) {
                    if (\$m.name -like '*qwen2.5-coder*') {
                        Write-Host '[OK] Model qwen2.5-coder found:' \$m.name
                        \$found = \$true
                    }
                }
                if (-\$found) {
                    Write-Host '[WARN] Model qwen2.5-coder:3b NOT FOUND'
                    Write-Host '       Run: ollama pull qwen2.5-coder:3b'
                }
            }
        } catch {
            Write-Host '[ERROR] Ollama API not responding'
            Write-Host '        Make sure Ollama is running: ollama serve'
        }
    " 2>&1
) else (
    echo [ERROR] Ollama NOT FOUND in PATH
    echo         Install from: https://ollama.ai/
    echo         Then run: ollama pull qwen2.5-coder:3b
)
echo.

REM ============================================================
echo [7/10] CONFIGURATION
echo ============================================================
set CONFIG_FILE=%PROJECT_DIR%config.json
if exist "%CONFIG_FILE%" (
    echo [OK] config.json found
    echo.
    echo Configuration content:
    type "%CONFIG_FILE%"
) else (
    echo [ERROR] config.json NOT FOUND at %CONFIG_FILE%
)
echo.

REM ============================================================
echo [8/10] PROJECT STRUCTURE
echo ============================================================
echo Checking directory structure...
set DIRS=core analysis reports workspace logs cache tools tests
for %%d in (%DIRS%) do (
    if exist "%PROJECT_DIR%%%d" (
        echo [OK] %PROJECT_DIR%%%d
    ) else {
        echo [MISSING] %PROJECT_DIR%%%d
    }
)
echo.

echo Checking core modules...
set MODULES=scanner apk_parser archive_analyzer manifest_analyzer dex_analyzer jadx_engine apktool_engine native_analyzer elf_analyzer jni_analyzer string_analyzer permission_analyzer behavior_analyzer network_analyzer malware_detector risk_engine ollama_client utils reporter
for %%m in (%MODULES%) do (
    if exist "%PROJECT_DIR%core\%%m.py" (
        echo [OK] core/%%m.py
    ) else (
        echo [MISSING] core/%%m.py
    )
)
echo.

echo Checking analysis rules...
set RULES=rules.json signatures.json behavior_rules.json
for %%r in (%RULES%) do (
    if exist "%PROJECT_DIR%analysis\%%r" (
        echo [OK] analysis/%%r
    ) else (
        echo [MISSING] analysis/%%r
    )
)
echo.

REM ============================================================
echo [9/10] NETWORK CONNECTIVITY
echo ============================================================
echo Testing local connections...
powershell -Command "
    # Test Ollama
    try { iwr http://127.0.0.1:11434/api/tags -TimeoutSec 3 -OutFile \$null; Write-Host '[OK] localhost:11434 (Ollama)' } catch { Write-Host '[FAIL] localhost:11434 (Ollama)' }
    # Test GitHub (for JADX/Apktool updates)
    try { iwr https://api.github.com -TimeoutSec 5 -OutFile \$null; Write-Host '[OK] github.com' } catch { Write-Host '[WARN] github.com (may affect auto-updates)' }
" 2>&1
echo.

REM ============================================================
echo [10/10] TEST APK FILES
echo ============================================================
echo Checking test APKs...
set MALWARE_DIR=%PROJECT_DIR%MALWARE
if exist "%MALWARE_DIR%" (
    echo [OK] Malware directory found: %MALWARE_DIR%
    dir "%MALWARE_DIR%\*.apk" /b 2>nul | find /c /v ""
    for %%f in ("%MALWARE_DIR%\*.apk") do (
        echo [FOUND] %%~nxf
    )
) else (
    echo [WARN] Malware directory NOT FOUND: %MALWARE_DIR%
    echo         Place test APKs in: %MALWARE_DIR%
    echo         Or update MALWARE_DIR variable in diagnostic.bat
)
echo.

REM ============================================================
echo [SUMMARY] DIAGNOSTIC COMPLETE
echo ============================================================
echo.
echo Review the output above for any [ERROR] or [MISSING] items.
echo.
echo Common fixes:
echo   - Missing Python packages: pip install -r requirements.txt
echo   - Missing JADX/Apktool: Run install.bat (downloads automatically)
echo   - Ollama not running: Start 'ollama serve' in a terminal
echo   - Model missing: Run 'ollama pull qwen2.5-coder:3b'
echo   - Virtual env issues: Delete venv folder and re-run install.bat
echo.
echo Logs directory: %PROJECT_DIR%logs
echo Reports directory: %PROJECT_DIR%reports
echo.
pause