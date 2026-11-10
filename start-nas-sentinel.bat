@echo off
setlocal EnableExtensions
cd /d "%~dp0"

echo ============================================================
echo   Starting NAS Sentinel Standalone Background Server...
echo   Dashboard URL: http://127.0.0.1:8088
echo   Novice path  : double-click THIS file (start-nas-sentinel.bat)
echo ============================================================

set "NS_PYTHONW="
set "NS_PYTHON="

rem 1) Portable embed next to the repo (no system Python / PATH needed)
if exist "%~dp0runtime\python\pythonw.exe" set "NS_PYTHONW=%~dp0runtime\python\pythonw.exe"
if exist "%~dp0runtime\python\python.exe"  set "NS_PYTHON=%~dp0runtime\python\python.exe"

rem 2) PATH — skip Windows Store WindowsApps stubs (alias that is not a real Python)
if not defined NS_PYTHONW (
    for /f "delims=" %%P in ('where pythonw 2^>nul') do (
        echo %%P | findstr /i /c:"\WindowsApps\" >nul
        if errorlevel 1 if not defined NS_PYTHONW set "NS_PYTHONW=%%P"
    )
)
if not defined NS_PYTHON (
    for /f "delims=" %%P in ('where python 2^>nul') do (
        echo %%P | findstr /i /c:"\WindowsApps\" >nul
        if errorlevel 1 if not defined NS_PYTHON set "NS_PYTHON=%%P"
    )
)

rem 3) Common per-user installs (no PATH checkbox)
if not defined NS_PYTHONW if exist "%USERPROFILE%\AppData\Local\Programs\Python\Python313\pythonw.exe" set "NS_PYTHONW=%USERPROFILE%\AppData\Local\Programs\Python\Python313\pythonw.exe"
if not defined NS_PYTHONW if exist "%USERPROFILE%\AppData\Local\Programs\Python\Python312\pythonw.exe" set "NS_PYTHONW=%USERPROFILE%\AppData\Local\Programs\Python\Python312\pythonw.exe"
if not defined NS_PYTHONW if exist "%USERPROFILE%\AppData\Local\Programs\Python\Python311\pythonw.exe" set "NS_PYTHONW=%USERPROFILE%\AppData\Local\Programs\Python\Python311\pythonw.exe"
if not defined NS_PYTHONW if exist "%USERPROFILE%\AppData\Local\Programs\Python\Python310\pythonw.exe" set "NS_PYTHONW=%USERPROFILE%\AppData\Local\Programs\Python\Python310\pythonw.exe"

if not defined NS_PYTHON if exist "%USERPROFILE%\AppData\Local\Programs\Python\Python313\python.exe" set "NS_PYTHON=%USERPROFILE%\AppData\Local\Programs\Python\Python313\python.exe"
if not defined NS_PYTHON if exist "%USERPROFILE%\AppData\Local\Programs\Python\Python312\python.exe" set "NS_PYTHON=%USERPROFILE%\AppData\Local\Programs\Python\Python312\python.exe"
if not defined NS_PYTHON if exist "%USERPROFILE%\AppData\Local\Programs\Python\Python311\python.exe" set "NS_PYTHON=%USERPROFILE%\AppData\Local\Programs\Python\Python311\python.exe"
if not defined NS_PYTHON if exist "%USERPROFILE%\AppData\Local\Programs\Python\Python310\python.exe" set "NS_PYTHON=%USERPROFILE%\AppData\Local\Programs\Python\Python310\python.exe"

rem Reject WindowsApps if it slipped in via AppData-style paths; smoke-test console python
if defined NS_PYTHON (
    echo %NS_PYTHON% | findstr /i /c:"\WindowsApps\" >nul
    if not errorlevel 1 set "NS_PYTHON="
)
if defined NS_PYTHONW (
    echo %NS_PYTHONW% | findstr /i /c:"\WindowsApps\" >nul
    if not errorlevel 1 set "NS_PYTHONW="
)

rem Prefer smoke-testing a console interpreter before accepting PATH/AppData
if defined NS_PYTHON (
    echo %NS_PYTHON% | findstr /i /c:"\runtime\python\" >nul
    if errorlevel 1 (
        "%NS_PYTHON%" -c "import sys" >nul 2>&1
        if errorlevel 1 (
            echo [!] Ignoring non-working Python: %NS_PYTHON%
            set "NS_PYTHON="
            set "NS_PYTHONW="
        )
    )
)

if not defined NS_PYTHONW if defined NS_PYTHON set "NS_PYTHONW=%NS_PYTHON%"

if not defined NS_PYTHONW (
    echo [!] No usable Python found ^(Windows Store stubs ignored^).
    echo [!] Fetching official portable embed from python.org...
    echo     ^(SHA-256 pinned in scripts\ensure-portable-python.ps1 — see scripts\PORTABLE-WINDOWS.md^)
    powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\ensure-portable-python.ps1" -RepoRoot "%~dp0."
    if errorlevel 1 (
        echo ============================================================
        echo [!] Portable Python setup failed ^(hash mismatch / network / extract^).
        echo [!] Fix network / retry, OR install Python 3 from:
        echo [!]   https://www.python.org/downloads/
        echo [!] ^(Optional: check "Add Python to PATH"^)
        echo [!] Or pre-zip runtime\python\ for fully offline use.
        echo ============================================================
        pause
        exit /b 1
    )
    if exist "%~dp0runtime\python\pythonw.exe" set "NS_PYTHONW=%~dp0runtime\python\pythonw.exe"
    if exist "%~dp0runtime\python\python.exe"  set "NS_PYTHON=%~dp0runtime\python\python.exe"
    if not defined NS_PYTHONW if defined NS_PYTHON set "NS_PYTHONW=%NS_PYTHON%"
)

if not defined NS_PYTHONW (
    echo [!] Python still not available after portable setup.
    pause
    exit /b 1
)

rem Expose resolved interpreter for the VBS helper (same process tree / schtasks uses VBS path discovery)
set "NAS_SENTINEL_PYTHONW=%NS_PYTHONW%"

schtasks /run /tn "NAS-Sentinel" >nul 2>&1
if errorlevel 1 (
    start "" wscript.exe "%~dp0start-nas-sentinel-background.vbs"
)

echo [OK] Local server started in background.
echo - Python           : %NS_PYTHONW%
echo - Opening Web Wizard: http://127.0.0.1:8088
echo - Unlock            : browser on this PC auto-loads the API token
echo                       ^(loopback only — no need to open api_token.txt^)
echo - Backup token file : nas-sentinel\data\api_token.txt  ^(or API_TOKEN env^)
echo - APIs              : still require Authorization: Bearer ^<token^>
echo - Stop Service      : stop-nas-sentinel.bat
echo - Windows Autostart : install-autostart-service.bat
echo - Portable docs     : scripts\PORTABLE-WINDOWS.md
echo ============================================================

ping 127.0.0.1 -n 2 >nul
start "" http://127.0.0.1:8088
