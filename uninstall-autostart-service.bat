@echo off
setlocal
cd /d "%~dp0"
echo ============================================================
echo   Removing NAS-Sentinel Windows Scheduled Task...
echo ============================================================

schtasks /delete /tn "NAS-Sentinel" /f >nul 2>&1
echo [OK] Scheduled Task removed.

call "%~dp0stop-nas-sentinel.bat"
