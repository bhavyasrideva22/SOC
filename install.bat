@echo off
cd /d "%~dp0"
echo Installing from: %CD%
pip install -r requirements.txt
pause
