@echo off
setlocal
cd /d "%~dp0"
echo ============================================================
echo   Starting NAS Sentinel Standalone Background Server...
echo   Dashboard URL: http://127.0.0.1:8088
echo ============================================================

where python.exe >nul 2>&1
if errorlevel 1 (
    if not exist "%USERPROFILE%\AppData\Local\Programs\Python\Python312\pythonw.exe" (
        if not exist "%USERPROFILE%\AppData\Local\Programs\Python\Python311\pythonw.exe" (
            if not exist "%USERPROFILE%\AppData\Local\Programs\Python\Python313\pythonw.exe" (
                echo [!] Python 3 not found in PATH or standard AppData directories.
                echo [!] Please install Python from: https://www.python.org/downloads/
                echo [!] (Remember to check "Add Python to PATH" during installation)
                pause
                exit /b 1
            )
        )
    )
)

schtasks /run /tn "NAS-Sentinel" >nul 2>&1
if errorlevel 1 (
    start "" wscript.exe "%~dp0start-nas-sentinel-background.vbs"
)

echo [OK] Server started in background.
echo - Dashboard : http://127.0.0.1:8088
echo - Stop      : stop-nas-sentinel.bat
echo - Autostart : install-autostart-service.bat
echo ============================================================

start "" http://127.0.0.1:8088
ping 127.0.0.1 -n 2 >nul
