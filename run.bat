@echo off
cd /d "%~dp0soc-monitoring-system"
echo Starting app from: %CD%
python app.py
pause
