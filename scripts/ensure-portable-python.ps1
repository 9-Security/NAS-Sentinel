#Requires -Version 5.1
<#
.SYNOPSIS
  Download official Windows embeddable Python into runtime\python\ (no installer, no PATH).

.DESCRIPTION
  Used by start-nas-sentinel.bat when no system Python is found.
  Stdlib-only runtime — NAS Sentinel needs no pip packages.
  Does not change Windows PATH or install a system Python.
#>
[CmdletBinding()]
param(
    [string]$RepoRoot = "",
    [string]$Version = "3.12.10"
)

$ErrorActionPreference = "Stop"

if (-not $RepoRoot) {
    $RepoRoot = Split-Path -Parent $PSScriptRoot
}
$RepoRoot = (Resolve-Path $RepoRoot).Path
$RuntimeDir = Join-Path $RepoRoot "runtime\python"
$Marker = Join-Path $RuntimeDir "python.exe"

if (Test-Path $Marker) {
    Write-Host "[OK] Portable Python already present: $RuntimeDir"
    exit 0
}

$arch = $env:PROCESSOR_ARCHITECTURE
switch -Regex ($arch) {
    "ARM64" { $embedArch = "arm64"; break }
    "AMD64|x86_64" { $embedArch = "amd64"; break }
    default {
        # 32-bit process on 64-bit OS still reports x86 — prefer amd64 host when available
        if ($env:PROCESSOR_ARCHITEW6432 -match "AMD64") { $embedArch = "amd64" }
        else { $embedArch = "win32" }
    }
}

$zipName = "python-$Version-embed-$embedArch.zip"
$url = "https://www.python.org/ftp/python/$Version/$zipName"
$staging = Join-Path $RepoRoot "runtime\_staging"
$zipPath = Join-Path $staging $zipName

Write-Host "============================================================"
Write-Host "  NAS Sentinel — first-time portable Python setup"
Write-Host "  Source : python.org embeddable ($Version / $embedArch)"
Write-Host "  Target : $RuntimeDir"
Write-Host "  Note   : no system install, PATH unchanged"
Write-Host "============================================================"

New-Item -ItemType Directory -Force -Path $staging | Out-Null
New-Item -ItemType Directory -Force -Path $RuntimeDir | Out-Null

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Write-Host "[..] Downloading $url"
Invoke-WebRequest -Uri $url -OutFile $zipPath -UseBasicParsing

Write-Host "[..] Extracting..."
Expand-Archive -Path $zipPath -DestinationPath $RuntimeDir -Force

# Embeddable builds isolate sys.path via pythonXY._pth. Enable site and pin app dir.
$pth = Get-ChildItem -Path $RuntimeDir -Filter "python*._pth" | Select-Object -First 1
if (-not $pth) {
    throw "Embeddable package missing python*._pth under $RuntimeDir"
}

$pthLines = @(
    "python$($Version.Split('.')[0])$($Version.Split('.')[1]).zip"
    "."
    "..\..\nas-sentinel"
    "import site"
)
# Prefer keeping the zip name that actually exists in the extract
$zipLib = Get-ChildItem -Path $RuntimeDir -Filter "python*.zip" | Select-Object -First 1
if ($zipLib) {
    $pthLines[0] = $zipLib.Name
}
Set-Content -Path $pth.FullName -Value ($pthLines -join "`r`n") -Encoding ASCII

if (-not (Test-Path (Join-Path $RuntimeDir "python.exe"))) {
    throw "Portable Python extract failed (python.exe missing)."
}

# Cleanup staging zip only (keep runtime)
Remove-Item -Recurse -Force $staging -ErrorAction SilentlyContinue

Write-Host "[OK] Portable Python ready at runtime\python\"
Write-Host "     Double-click start-nas-sentinel.bat again if the browser did not open."
exit 0
