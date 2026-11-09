@echo off
setlocal
cd /d "%~dp0"
echo ============================================================
echo   Stopping NAS Sentinel Server (Port 8088)...
echo ============================================================

for /f "tokens=5" %%a in ('netstat -aon ^| findstr /r ":8088.*LISTENING"') do (
    echo Terminating PID: %%a ...
    taskkill /f /pid %%a >nul 2>&1
)

echo [OK] NAS Sentinel server stopped.
echo ============================================================
ping 127.0.0.1 -n 3 >nul
