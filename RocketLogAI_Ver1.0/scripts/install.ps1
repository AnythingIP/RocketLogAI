# RocketLogAI / LogSentinel - One-click installer for Windows
# Run from an elevated PowerShell prompt (or normal, it will prompt when needed)

$ErrorActionPreference = "Stop"

Write-Host "🚀 RocketLogAI Installer for Windows" -ForegroundColor Cyan
Write-Host "=====================================" -ForegroundColor Cyan

$InstallDir = "D:\logsentinel"
if (-not (Test-Path $InstallDir)) {
    $InstallDir = Read-Host "Enter target directory (default D:\logsentinel)"
    if ([string]::IsNullOrWhiteSpace($InstallDir)) { $InstallDir = "D:\logsentinel" }
}

New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
Set-Location $InstallDir

# Clone or copy? For now we assume the user already has the folder.
# This script focuses on the Python environment + launchers.

Write-Host "`n[1/4] Checking Python..." -ForegroundColor Yellow
try {
    $py = (Get-Command python -ErrorAction Stop).Source
    Write-Host "Found: $py" -ForegroundColor Green
} catch {
    Write-Error "Python 3.10+ is required. Install from https://www.python.org/downloads/windows/ (tick 'Add to PATH')"
    exit 1
}

Write-Host "`n[2/4] Creating virtual environment (recommended)..." -ForegroundColor Yellow
if (-not (Test-Path ".venv")) {
    python -m venv .venv
}
. .\.venv\Scripts\Activate.ps1

Write-Host "`n[3/4] Installing RocketLogAI with full web dashboard + secure auth..." -ForegroundColor Yellow
pip install --upgrade pip setuptools wheel
pip install -e ".[web]"

# Also install the updated requirements just in case
if (Test-Path "requirements.txt") {
    pip install -r requirements.txt
}

Write-Host "`n[4/4] Creating convenient launchers..." -ForegroundColor Yellow

# Create a nice start script
@"
@echo off
cd /d %~dp0
call .venv\Scripts\activate.bat
echo.
echo Starting RocketLogAI...
echo "Web UI addresses (HTTP + HTTPS if enabled) will be printed at startup. Check the log file data/logsentinel.log"
echo.
logsentinel run --web
pause
"@ | Out-File -Encoding ASCII -FilePath "start-rocketlogai.bat"

# Also a PowerShell version
@"
# Quick launcher
Set-Location $PSScriptRoot
. .\.venv\Scripts\Activate.ps1
logsentinel run --web
"@ | Out-File -Encoding UTF8 -FilePath "start-rocketlogai.ps1"

Write-Host "`n✅ Installation complete!" -ForegroundColor Green
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Cyan
Write-Host "  1. (Optional) Edit config.yaml - point LLM at your local model server"
Write-Host "  2. Double-click start-rocketlogai.bat   (or run the .ps1)"
Write-Host "  3. Watch the startup messages (or data/logsentinel.log) for the exact HTTP/HTTPS URLs"
Write-Host "  4. Change the default admin password immediately via the Users page"
Write-Host ""
Write-Host "Your local admin credentials are now stored as a bcrypt hash in the SQLite DB (much safer)." -ForegroundColor Green
Write-Host ""
Write-Host "To move to another machine later: copy the whole folder + the data/ subfolder (contains DB, SSL certs, learned devices, etc.)." -ForegroundColor Yellow
Write-Host ""