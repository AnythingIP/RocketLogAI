# RocketLogAI v2.0 - One-click installer for Windows
# Run from an elevated PowerShell prompt

$ErrorActionPreference = "Stop"

Write-Host "🚀 RocketLogAI Installer for Windows" -ForegroundColor Cyan
Write-Host "=====================================" -ForegroundColor Cyan

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$SourceRoot = Split-Path -Parent $ScriptDir   # RocketLogAI repo root

$InstallDir = "D:\logsentinel"
$InstallDir = Read-Host "Enter target directory (default D:\logsentinel)"
if ([string]::IsNullOrWhiteSpace($InstallDir)) { $InstallDir = "D:\logsentinel" }

New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null

Write-Host "`n[1/5] Checking for Python 3.10+ ..." -ForegroundColor Yellow
$pythonCmd = $null
try {
    $pythonCmd = (Get-Command python -ErrorAction Stop).Source
} catch {
    try {
        $pythonCmd = (Get-Command py -ErrorAction Stop).Source
    } catch {}
}

if (-not $pythonCmd) {
    Write-Host ""
    Write-Host "Python 3.10 or newer was not found." -ForegroundColor Red
    Write-Host "Please download and install it from:" -ForegroundColor Yellow
    Write-Host "https://www.python.org/downloads/windows/" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "During installation, make sure you tick the box:" -ForegroundColor Yellow
    Write-Host "   [x] Add python.exe to PATH" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Then re-run this installer." -ForegroundColor Yellow
    exit 1
}

Write-Host "Found Python at: $pythonCmd" -ForegroundColor Green

Write-Host "`n[2/5] Creating virtual environment..." -ForegroundColor Yellow
python -m venv "$InstallDir\.venv"
. "$InstallDir\.venv\Scripts\Activate.ps1"

Write-Host "`n[3/5] Copying RocketLogAI files..." -ForegroundColor Yellow
robocopy "$SourceRoot\logsentinel" "$InstallDir\logsentinel" /E /NFL /NDL /NJH /NJS | Out-Null
robocopy "$SourceRoot\templates" "$InstallDir\templates" /E /NFL /NDL /NJH /NJS | Out-Null
Copy-Item "$SourceRoot\pyproject.toml" -Destination $InstallDir -Force
Copy-Item "$SourceRoot\requirements.txt" -Destination $InstallDir -Force -ErrorAction SilentlyContinue
Copy-Item "$SourceRoot\example-config.yaml" -Destination $InstallDir -Force -ErrorAction SilentlyContinue
robocopy "$SourceRoot\scripts" "$InstallDir\scripts" /E /NFL /NDL /NJH /NJS | Out-Null

Write-Host "`n[4/5] Installing dependencies..." -ForegroundColor Yellow
pip install --upgrade pip setuptools wheel
Set-Location $InstallDir
pip install ".[web,v2,ai]"

Write-Host "`n[4.5/5] Installing Phase 3/4 AI + Auth extras (open-interpreter for conversational operator, cryptography for encrypted secrets)..." -ForegroundColor Yellow
pip install open-interpreter cryptography

"native" | Out-File -Encoding ascii -FilePath "$InstallDir\.install-type" -Force

Write-Host "`n[5/5] Creating launchers..." -ForegroundColor Yellow

@"
@echo off
cd /d %~dp0
call .venv\Scripts\activate.bat
echo.
echo Starting RocketLogAI...
logsentinel run --web
pause
"@ | Out-File -Encoding ASCII -FilePath "$InstallDir\start-rocketlogai.bat"

@"
# Quick launcher
Set-Location `$PSScriptRoot
. .\.venv\Scripts\Activate.ps1
logsentinel run --web
"@ | Out-File -Encoding UTF8 -FilePath "$InstallDir\start-rocketlogai.ps1"

Write-Host "`n✅ Installation complete!" -ForegroundColor Green
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Cyan
Write-Host "  1. cd $InstallDir"
Write-Host "  2. Copy example-config.yaml to config.yaml and edit it (especially LLM settings)"
Write-Host "  3. Double-click start-rocketlogai.bat"
Write-Host "  4. Open the browser and change the default admin password immediately"
Write-Host ""
Write-Host "New in this build (Phases 1-4):" -ForegroundColor Yellow
Write-Host "  - Powerful AI Assistant powered by Open Interpreter (natural language device ops, plans, confirmations, dynamic tools)." -ForegroundColor Yellow
Write-Host "  - Advanced enterprise auth: AD/LDAP with service accounts + groups, Entra ID, full RBAC (Viewer/Analyst/Operator/Admin) from directory groups." -ForegroundColor Yellow
Write-Host "  - Encrypted secrets for service accounts/Entra, enhanced test tools, RBAC-protected routes." -ForegroundColor Yellow
Write-Host "RocketLogAI v2.0 installed. Full extras: pip install -e '.[web,v2,ai]'" -ForegroundColor Yellow
Write-Host ""
Write-Host "Python download link (if you ever need it again):" -ForegroundColor Cyan
Write-Host "https://www.python.org/downloads/windows/" -ForegroundColor Cyan
Write-Host ""