@echo off
cd /d "%~dp0soc-monitoring-system"
echo Installing from: %CD%
pip install -r requirements.txt
pause
