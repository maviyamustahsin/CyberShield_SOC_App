@echo off
setlocal
cd /d "%~dp0"
echo 🛡️ Initializing Maviya's CyberShield SOC Defense System...
powershell -ExecutionPolicy Bypass -File "run_soc.ps1"
if %ERRORLEVEL% neq 0 (
    echo.
    echo ❌ The script failed to run.
    pause
)
