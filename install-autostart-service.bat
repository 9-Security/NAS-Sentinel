@echo off
setlocal
cd /d "%~dp0"
schtasks /create /tn "NAS-Sentinel" /tr "wscript.exe \"%~dp0start-nas-sentinel-background.vbs\"" /sc onlogon /f
schtasks /run /tn "NAS-Sentinel"
echo [OK] NAS Sentinel Task Registered and Started.
ping 127.0.0.1 -n 3 >nul
