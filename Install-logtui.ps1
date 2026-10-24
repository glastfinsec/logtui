<#
.SYNOPSIS
  One-shot installer for logtui (cross-platform system log viewer).
.PARAMETER Auto
  Unattended mode: accept defaults, no prompts.
#>
param(
    [switch]$Auto,
    [switch]$Uninstall
)

$ErrorActionPreference = "Stop"

function Write-Step($msg) { Write-Host "==> $msg" -ForegroundColor Cyan }

# --- Uninstall ---
if ($Uninstall) {
    Write-Step "Uninstalling logtui"
    python -m pip uninstall -y logtui 2>$null
    $prof = Join-Path $env:APPDATA "logtui"
    if (Test-Path $prof) { Remove-Item -Recurse -Force $prof; Write-Host "Removed $prof" }
    Write-Host "logtui uninstalled." -ForegroundColor Green
    exit 0
}

# --- Python check ---
Write-Step "Checking Python"
$py = Get-Command python -ErrorAction SilentlyContinue
if (-not $py) {
    Write-Host "Python 3.11+ is required. Install from https://www.python.org/downloads/" -ForegroundColor Red
    exit 1
}
$ver = & python -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')"
if ([version]$ver -lt [version]"3.11") {
    Write-Host "Python 3.11+ required (found $ver)." -ForegroundColor Red
    exit 1
}
Write-Host "Python $ver OK"

# --- Install package ---
Write-Step "Installing logtui package"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Push-Location $root
try {
    python -m pip install --upgrade pip 2>&1 | Out-Null
    python -m pip install -e . 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "pip install failed" }
} finally {
    Pop-Location
}
Write-Host "Package installed."

# --- Setup profile ---
Write-Step "Running logtui setup (detecting machine capabilities)"
python -m logtui setup
if ($LASTEXITCODE -ne 0) { throw "setup failed" }

Write-Host ""
Write-Host "logtui installed successfully." -ForegroundColor Green
Write-Host "Run it with:  python -m logtui" -ForegroundColor Yellow
Write-Host "Or, if Scripts is on PATH:  logtui" -ForegroundColor Yellow