# RocketLogAI Upgrade Script for Windows (PowerShell)
# Run from an elevated PowerShell prompt, from inside a *new* extracted installer directory.
#
# Usage:
#   .\scripts\upgrade.ps1 -TargetDir "D:\logsentinel"
#
# It stops running instances, copies updated code, upgrades the pip package in the existing venv,
# and restarts.

param(
    [string]$TargetDir = ""
)

$ErrorActionPreference = "Stop"

Write-Host "🔄 RocketLogAI Upgrade (Windows)" -ForegroundColor Cyan
Write-Host "====================================" -ForegroundColor Cyan

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$SourceRoot = Split-Path -Parent $ScriptDir

if ([string]::IsNullOrWhiteSpace($TargetDir)) {
    $TargetDir = Read-Host "Enter path to your EXISTING RocketLogAI installation (e.g. D:\logsentinel)"
}

if (-not (Test-Path $TargetDir)) {
    Write-Host "ERROR: Target directory does not exist: $TargetDir" -ForegroundColor Red
    exit 1
}

Write-Host "Upgrading: $TargetDir"
Write-Host "Using new code from: $SourceRoot"
Write-Host ""

# Detect docker
$IsDocker = $false
if ((Test-Path "$TargetDir\docker-compose.yml") -or (Test-Path "$TargetDir\..\docker-compose.yml")) {
    $IsDocker = $true
    Write-Host "[detected] Docker Compose installation" -ForegroundColor Yellow
}

if ($IsDocker) {
    Write-Host "`n[1/3] Stopping Docker service..." -ForegroundColor Yellow
    try { Push-Location $TargetDir; docker compose down } catch { try { Push-Location (Join-Path $TargetDir ".."); docker compose down } catch {} }

    Write-Host "`n[2/3] Copying updated files for Docker rebuild..." -ForegroundColor Yellow
    if (Test-Path "$TargetDir\logsentinel") {
        robocopy "$SourceRoot\logsentinel" "$TargetDir\logsentinel" /E /NFL /NDL /NJH /NJS | Out-Null
    }
    if (Test-Path "$TargetDir\templates") {
        robocopy "$SourceRoot\templates" "$TargetDir\templates" /E /NFL /NDL /NJH /NJS | Out-Null
    }
    Copy-Item "$SourceRoot\Dockerfile" -Destination $TargetDir -Force -ErrorAction SilentlyContinue
    Copy-Item "$SourceRoot\docker-compose.yml" -Destination $TargetDir -Force -ErrorAction SilentlyContinue
    Copy-Item "$SourceRoot\pyproject.toml" -Destination $TargetDir -Force -ErrorAction SilentlyContinue

    Write-Host "`n[3/3] Rebuilding and restarting container..." -ForegroundColor Yellow
    try { Push-Location $TargetDir; docker compose build --no-cache; docker compose up -d } catch {
        Push-Location (Join-Path $TargetDir "..")
        docker compose build --no-cache
        docker compose up -d
    }

    Write-Host "`n✅ Docker upgrade complete!" -ForegroundColor Green
    exit 0
}

# Native venv upgrade
Write-Host "`n[1/5] Stopping any running RocketLogAI processes..." -ForegroundColor Yellow
Get-Process -Name python -ErrorAction SilentlyContinue | Where-Object { $_.Path -like "*logsentinel*" -or $_.CommandLine -like "*logsentinel*" } | Stop-Process -Force -ErrorAction SilentlyContinue

$VenvDir = Join-Path $TargetDir ".venv"
if (-not (Test-Path $VenvDir)) {
    Write-Host "Looking for venv..." -ForegroundColor Yellow
    $candidates = @($TargetDir, (Join-Path $TargetDir ".."), "D:\logsentinel", "$HOME\logsentinel")
    foreach ($c in $candidates) {
        $test = Join-Path $c ".venv"
        if (Test-Path $test) {
            $VenvDir = $test
            $TargetDir = $c
            Write-Host "Found venv at $VenvDir" -ForegroundColor Green
            break
        }
    }
}

if (-not (Test-Path $VenvDir)) {
    Write-Host "ERROR: Could not locate .venv under $TargetDir" -ForegroundColor Red
    Write-Host "Activate your virtualenv manually and run: pip install -e `".[web]`" --upgrade" -ForegroundColor Yellow
    exit 1
}

Write-Host "`n[2/5] Copying updated code..." -ForegroundColor Yellow
robocopy "$SourceRoot\logsentinel" "$TargetDir\logsentinel" /E /NFL /NDL /NJH /NJS | Out-Null
robocopy "$SourceRoot\templates" "$TargetDir\templates" /E /NFL /NDL /NJH /NJS | Out-Null
Copy-Item "$SourceRoot\pyproject.toml" -Destination $TargetDir -Force -ErrorAction SilentlyContinue
Copy-Item "$SourceRoot\requirements.txt" -Destination $TargetDir -Force -ErrorAction SilentlyContinue
Copy-Item "$SourceRoot\example-config.yaml" -Destination $TargetDir -Force -ErrorAction SilentlyContinue
robocopy "$SourceRoot\scripts" "$TargetDir\scripts" /E /NFL /NDL /NJH /NJS | Out-Null

# Clean pycache
Get-ChildItem -Path $TargetDir -Recurse -Include __pycache__ -Directory | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
Get-ChildItem -Path $TargetDir -Recurse -Include *.pyc -File | Remove-Item -Force -ErrorAction SilentlyContinue

Write-Host "`n[3/5] Activating venv and upgrading package..." -ForegroundColor Yellow
. "$VenvDir\Scripts\Activate.ps1"

pip install --upgrade pip setuptools wheel
Set-Location $TargetDir
pip install -e ".[web]" --upgrade

# Common web deps
pip install fastapi uvicorn[standard] jinja2 itsdangerous bcrypt pyotp qrcode rich click pyyaml openai geoip2 requests ldap3 python-multipart --quiet 2>$null

Write-Host "`n[4/5] Updating launcher scripts..." -ForegroundColor Yellow

@"
@echo off
cd /d %~dp0
call .venv\Scripts\activate.bat
echo.
echo Starting RocketLogAI...
logsentinel run --web
pause
"@ | Out-File -Encoding ASCII -FilePath "$TargetDir\start-rocketlogai.bat" -Force

@"
Set-Location `$PSScriptRoot
. .\.venv\Scripts\Activate.ps1
logsentinel run --web
"@ | Out-File -Encoding UTF8 -FilePath "$TargetDir\start-rocketlogai.ps1" -Force

Write-Host "`n[5/5] Restart guidance..." -ForegroundColor Yellow
Write-Host "If you run RocketLogAI as a scheduled task or service, restart it now."
Write-Host "Or run: cd $TargetDir ; .\start-rocketlogai.ps1"

Write-Host ""
Write-Host "✅ Upgrade complete!" -ForegroundColor Green
Write-Host ""
Write-Host "Your config.yaml and data\ folder were preserved."
Write-Host "New features (Daily Briefing, Ollama fixes, improved LLM config UI) are included."
Write-Host "Open the web UI at http://localhost:8787 and verify your LLM connection still works."
Write-Host ""
