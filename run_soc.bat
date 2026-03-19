@echo off
cd /d "%~dp0"
echo 🛡️ [SYSTEM] Starting CyberShield SOC TITAN v2.3.0...
echo ⏳ Please wait, optimizing AI data cache...
echo.

set PYTHONPATH=%~dp0
.\venv\Scripts\python.exe -m streamlit run src\app.py --server.port 8503

echo.
echo 🚨 [CRITICAL] The SOC Defense System has stopped.
echo 🚨 If you see an importerror above, please tell me!
pause
