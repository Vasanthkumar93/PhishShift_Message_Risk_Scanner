@echo off
title PhishShift Message Risk Scanner
cd /d "%~dp0"
echo ====================================================
echo      PhishShift Message Risk Scanner (Web UI)
echo ====================================================
echo.
echo Installing requirements (if needed)...
pip install -r requirements.txt
echo.
echo Starting Flask Web Application...
start http://127.0.0.1:5000
python app.py
pause
