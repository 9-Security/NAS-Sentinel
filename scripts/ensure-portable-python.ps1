#Requires -Version 5.1
<#
.SYNOPSIS
  Download official Windows embeddable Python into runtime\python\ (no installer, no PATH).

.DESCRIPTION
  Used by start-nas-sentinel.bat when no system Python is found.
  Stdlib-only runtime — NAS Sentinel needs no pip packages.
  Does not change Windows PATH or install a system Python.

  Integrity: downloads python-<ver>-embed-<arch>.zip from www.python.org and
  verifies SHA-256 against hashes pinned in this script (fail closed).
  Artifact name is the FTP "-embed-" zip (not the "-embeddable-" JSON alias).
#>
[CmdletBinding()]
param(
    [string]$RepoRoot = "",
    # Only versions present in $PinnedSha256 are accepted.
    [string]$Version = "3.12.10"
)

$ErrorActionPreference = "Stop"

# Pinned SHA-256 for exact FTP artifacts: python-<ver>-embed-<arch>.zip
# Computed 2026-11-10 from https://www.python.org/ftp/python/3.12.10/
$PinnedSha256 = @{
    "3.12.10|amd64" = "4acbed6dd1c744b0376e3b1cf57ce906f9dc9e95e68824584c8099a63025a3c3"
    "3.12.10|arm64" = "3065efc3d382d1cda66757ac71ade11904fa6e350f5a97eb74811acd71ba5532"
    "3.12.10|win32" = "084b9eb24cb848605c895d05b738fbc2572efc8b4c18c415a824065864a2b853"
}

function Clear-Staging {
    param([string]$Path)
    if ($Path -and (Test-Path $Path)) {
        Remove-Item -Recurse -Force $Path -ErrorAction SilentlyContinue
    }
}

function Fail-Closed {
    param(
        [string]$Message,
        [string]$StagingPath = ""
    )
    Clear-Staging -Path $StagingPath
    Write-Host "[!] $Message"
    Write-Host "[!] Portable Python setup aborted (fail closed). Retry or pre-zip runtime\python\."
    exit 1
}

if ($Version -notmatch '^\d+\.\d+\.\d+$') {
    Fail-Closed -Message "Invalid -Version '$Version' (expected x.y.z, e.g. 3.12.10)."
}

if (-not $RepoRoot) {
    $RepoRoot = Split-Path -Parent $PSScriptRoot
}
try {
    $RepoRoot = (Resolve-Path $RepoRoot).Path
} catch {
    Fail-Closed -Message "RepoRoot not found: $RepoRoot"
}

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

$pinKey = "$Version|$embedArch"
if (-not $PinnedSha256.ContainsKey($pinKey)) {
    Fail-Closed -Message "No in-repo SHA-256 pin for Python $Version / $embedArch. Refusing download."
}
$expectedHash = $PinnedSha256[$pinKey].ToLowerInvariant()

# Exact FTP artifact name (NOT python-*-embeddable-*.zip — different file/hash).
$zipName = "python-$Version-embed-$embedArch.zip"
$url = "https://www.python.org/ftp/python/$Version/$zipName"
$staging = Join-Path $RepoRoot "runtime\_staging"
$zipPath = Join-Path $staging $zipName
$extractDir = Join-Path $staging "extract"

Write-Host "============================================================"
Write-Host "  NAS Sentinel — first-time portable Python setup"
Write-Host "  Source : $url"
Write-Host "  SHA256 : $expectedHash (pinned in-repo)"
Write-Host "  Target : $RuntimeDir"
Write-Host "  Note   : no system install, PATH unchanged"
Write-Host "============================================================"

Clear-Staging -Path $staging
New-Item -ItemType Directory -Force -Path $staging | Out-Null
New-Item -ItemType Directory -Force -Path $extractDir | Out-Null

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Write-Host "[..] Downloading $url"
try {
    Invoke-WebRequest -Uri $url -OutFile $zipPath -UseBasicParsing
} catch {
    Fail-Closed -Message "Download failed: $($_.Exception.Message)" -StagingPath $staging
}

if (-not (Test-Path $zipPath)) {
    Fail-Closed -Message "Download produced no file." -StagingPath $staging
}

Write-Host "[..] Verifying SHA-256..."
$actualHash = (Get-FileHash -Path $zipPath -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actualHash -ne $expectedHash) {
    Fail-Closed -Message "SHA-256 mismatch for $zipName.`n    expected $expectedHash`n    actual   $actualHash" -StagingPath $staging
}
Write-Host "[OK] SHA-256 matches pin."

Write-Host "[..] Extracting (path-contained)..."
Add-Type -AssemblyName System.IO.Compression.FileSystem
$extractRootFull = [System.IO.Path]::GetFullPath($extractDir)
if (-not $extractRootFull.EndsWith([System.IO.Path]::DirectorySeparatorChar)) {
    $extractRootFull += [System.IO.Path]::DirectorySeparatorChar
}

$zip = $null
try {
    $zip = [System.IO.Compression.ZipFile]::OpenRead($zipPath)
    foreach ($entry in $zip.Entries) {
        $name = $entry.FullName -replace '/', '\'
        if ([string]::IsNullOrWhiteSpace($name)) { continue }

        $dest = [System.IO.Path]::GetFullPath((Join-Path $extractDir $name))
        if (-not $dest.StartsWith($extractRootFull, [System.StringComparison]::OrdinalIgnoreCase)) {
            throw "Refusing zip entry that escapes extract dir: $($entry.FullName)"
        }

        if ($name.EndsWith('\')) {
            if (-not (Test-Path $dest)) {
                New-Item -ItemType Directory -Force -Path $dest | Out-Null
            }
            continue
        }

        $parent = Split-Path -Parent $dest
        if ($parent -and -not (Test-Path $parent)) {
            New-Item -ItemType Directory -Force -Path $parent | Out-Null
        }
        [System.IO.Compression.ZipFileExtensions]::ExtractToFile($entry, $dest, $true)
    }
} catch {
    if ($zip) { $zip.Dispose(); $zip = $null }
    Fail-Closed -Message "Extract failed: $($_.Exception.Message)" -StagingPath $staging
} finally {
    if ($zip) { $zip.Dispose() }
}

$extractedPython = Join-Path $extractDir "python.exe"
$extractedPythonw = Join-Path $extractDir "pythonw.exe"
if (-not (Test-Path $extractedPython)) {
    Fail-Closed -Message "Embed package missing python.exe after extract." -StagingPath $staging
}

# Promote verified extract into runtime\python (replace empty/partial target).
if (Test-Path $RuntimeDir) {
    Remove-Item -Recurse -Force $RuntimeDir -ErrorAction Stop
}
New-Item -ItemType Directory -Force -Path (Split-Path -Parent $RuntimeDir) | Out-Null
Move-Item -Path $extractDir -Destination $RuntimeDir

# Embeddable builds isolate sys.path via pythonXY._pth. Enable site and pin app dir.
$pth = Get-ChildItem -Path $RuntimeDir -Filter "python*._pth" | Select-Object -First 1
if (-not $pth) {
    Remove-Item -Recurse -Force $RuntimeDir -ErrorAction SilentlyContinue
    Fail-Closed -Message "Embeddable package missing python*._pth under $RuntimeDir" -StagingPath $staging
}

$parts = $Version.Split('.')
$pthLines = @(
    "python$($parts[0])$($parts[1]).zip"
    "."
    "..\..\nas-sentinel"
    "import site"
)
$zipLib = Get-ChildItem -Path $RuntimeDir -Filter "python*.zip" |
    Where-Object { $_.Name -match '^python\d+\.zip$' } |
    Select-Object -First 1
if ($zipLib) {
    $pthLines[0] = $zipLib.Name
}
Set-Content -Path $pth.FullName -Value ($pthLines -join "`r`n") -Encoding ASCII

if (-not (Test-Path (Join-Path $RuntimeDir "python.exe"))) {
    Remove-Item -Recurse -Force $RuntimeDir -ErrorAction SilentlyContinue
    Fail-Closed -Message "Portable Python promote failed (python.exe missing)." -StagingPath $staging
}

Clear-Staging -Path $staging

Write-Host "[OK] Portable Python ready at runtime\python\"
Write-Host "     Double-click start-nas-sentinel.bat again if the browser did not open."
exit 0
