@echo off
REM APKStudioAI 2.1 - Start GUI Script
REM Launches the graphical interface

echo ============================================================
echo  APKStudioAI 2.1 - Starting GUI
echo  Advanced Android Malware Analysis Platform
echo ============================================================
echo.

set "PROJECT_DIR=%~dp0"
cd /d "%PROJECT_DIR%"

REM Enable delayed expansion
setlocal EnableDelayedExpansion

REM Check if virtual environment exists
if not exist "%PROJECT_DIR%venv" (
    echo [ERROR] Virtual environment not found!
    echo         Run install.bat first to set up the environment.
    pause
    exit /b 1
)

REM Activate virtual environment
call "%PROJECT_DIR%venv\Scripts\activate.bat"
if %errorLevel% neq 0 (
    echo [ERROR] Failed to activate virtual environment
    echo         Try deleting the venv folder and re-running install.bat
    pause
    exit /b 1
)

echo [OK] Virtual environment activated
echo [INFO] Starting APKStudioAI 2.1 GUI...
echo.

REM Start the GUI
python "%PROJECT_DIR%gui.py"

echo.
echo [INFO] APKStudioAI 2.1 GUI closed
endlocal
pause