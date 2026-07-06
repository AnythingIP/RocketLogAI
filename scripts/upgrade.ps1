# RocketLogAI Upgrade Script for Windows (PowerShell)
# Run from a git-cloned or extracted RocketLogAI source directory.
#
# Usage:
#   .\scripts\upgrade.ps1 -TargetDir "D:\logsentinel"
#   .\scripts\upgrade.ps1 -TargetDir "D:\logsentinel" -InstallType native
#   .\scripts\upgrade.ps1 -Help

param(
    [string]$TargetDir = "",
    [ValidateSet("", "native", "docker")]
    [string]$InstallType = "",
    [switch]$Help,
    [switch]$Fix
)

$ErrorActionPreference = "Stop"

function Show-Help {
    Write-Host @"
RocketLogAI Upgrade (Windows)

Usage:
  .\scripts\upgrade.ps1 [-TargetDir PATH] [-InstallType native|docker] [-Fix]

Options:
  -TargetDir     Existing installation (default: prompt)
  -InstallType   Force native or docker (auto-detected if omitted)
  -Fix           Run health check repair after upgrade
  -Help          Show this help

Examples:
  .\scripts\upgrade.ps1 -TargetDir D:\logsentinel
  .\scripts\upgrade.ps1 -TargetDir D:\logsentinel -InstallType native -Fix

After upgrade, start with:
  cd D:\logsentinel
  .\start-rocketlogai.ps1
"@
}

if ($Help -or $TargetDir -in @("-h", "--help", "/?")) {
    Show-Help
    exit 0
}

Write-Host "RocketLogAI Upgrade (Windows)" -ForegroundColor Cyan
Write-Host "====================================" -ForegroundColor Cyan

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$SourceRoot = Split-Path -Parent $ScriptDir

if ([string]::IsNullOrWhiteSpace($TargetDir)) {
    $TargetDir = Read-Host "Enter path to your EXISTING RocketLogAI installation (e.g. D:\logsentinel)"
}

if ($TargetDir -in @("-h", "--help", "/?")) {
    Show-Help
    exit 0
}

if (-not (Test-Path $TargetDir)) {
    Write-Host "ERROR: Target directory does not exist: $TargetDir" -ForegroundColor Red
    exit 1
}

$TargetDir = (Resolve-Path $TargetDir).Path

Write-Host "Upgrading: $TargetDir"
Write-Host "Using new code from: $SourceRoot"
Write-Host ""

function Test-DockerDaemon {
    try {
        $null = docker info 2>&1
        return $LASTEXITCODE -eq 0
    } catch {
        return $false
    }
}

function Get-DetectedInstallType {
    param([string]$Dir)

    $marker = Join-Path $Dir ".install-type"
    if (Test-Path $marker) {
        $value = (Get-Content $marker -Raw).Trim().ToLower()
        if ($value -in @("native", "docker")) { return $value }
    }

    if (Test-Path (Join-Path $Dir ".venv")) { return "native" }

    if (Test-DockerDaemon) {
        $containers = docker ps -a --filter "name=rocketlogai" --format "{{.Names}}" 2>$null
        if ($containers -match "rocketlogai") { return "docker" }
    }

    # docker-compose.yml ships with native installs — config/data means native
    if ((Test-Path (Join-Path $Dir "config.yaml")) -or (Test-Path (Join-Path $Dir "data\logsentinel.db"))) {
        return "native"
    }

    if ((Test-Path (Join-Path $Dir "docker-compose.yml")) -and (Test-DockerDaemon)) {
        return "docker"
    }

    return "native"
}

function Copy-UpgradeFiles {
    param([string]$Dest)

    $dirs = @("logsentinel", "templates", "scripts", "helm", "tests")
    foreach ($d in $dirs) {
        $src = Join-Path $SourceRoot $d
        if (Test-Path $src) {
            robocopy $src (Join-Path $Dest $d) /E /NFL /NDL /NJH /NJS /XD __pycache__ .pytest_cache | Out-Null
        }
    }

    $files = @("pyproject.toml", "requirements.txt", "example-config.yaml", "Dockerfile", "docker-compose.yml", "INSTALL.md", "README.md")
    foreach ($f in $files) {
        $src = Join-Path $SourceRoot $f
        if (Test-Path $src) {
            Copy-Item $src -Destination $Dest -Force
        }
    }

    Get-ChildItem -Path $Dest -Recurse -Include __pycache__ -Directory -ErrorAction SilentlyContinue |
        Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
    Get-ChildItem -Path $Dest -Recurse -Include *.pyc -File -ErrorAction SilentlyContinue |
        Remove-Item -Force -ErrorAction SilentlyContinue
}

function Stop-RocketLogAIProcesses {
    Get-Process -Name python, pythonw -ErrorAction SilentlyContinue | ForEach-Object {
        try {
            $cmd = (Get-CimInstance Win32_Process -Filter "ProcessId = $($_.Id)" -ErrorAction SilentlyContinue).CommandLine
            if ($cmd -match "logsentinel") {
                Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
            }
        } catch {}
    }
}

function Ensure-Venv {
    param([string]$Dir)

    $venv = Join-Path $Dir ".venv"
    if (Test-Path (Join-Path $venv "Scripts\python.exe")) {
        return $venv
    }

    Write-Host "No .venv found — creating one (recommended for upgrades)..." -ForegroundColor Yellow
    python -m venv $venv
    if (-not (Test-Path (Join-Path $venv "Scripts\python.exe"))) {
        throw "Failed to create virtual environment at $venv"
    }
    return $venv
}

function Install-NativePackage {
    param([string]$Dir)

    $venv = Ensure-Venv -Dir $Dir
    $python = Join-Path $venv "Scripts\python.exe"

    Write-Host "Upgrading pip and installing RocketLogAI v2 extras..." -ForegroundColor Yellow
    & $python -m pip install --upgrade pip setuptools wheel
    Set-Location $Dir
    & $python -m pip install -e ".[web,v2,ai]" --upgrade
    & $python -m pip install open-interpreter cryptography --upgrade 2>$null

    "native" | Out-File -Encoding ascii -FilePath (Join-Path $Dir ".install-type") -Force

    $batLines = @(
        '@echo off'
        'cd /d %~dp0'
        'call .venv\Scripts\activate.bat'
        'echo.'
        'echo Starting RocketLogAI...'
        'logsentinel run --web'
        'pause'
    )
    $batLines -join "`r`n" | Out-File -Encoding ASCII -FilePath (Join-Path $Dir "start-rocketlogai.bat") -Force

    $ps1Lines = @(
        'Set-Location $PSScriptRoot'
        '. .\.venv\Scripts\Activate.ps1'
        'logsentinel run --web'
    )
    $ps1Lines -join "`n" | Out-File -Encoding UTF8 -FilePath (Join-Path $Dir "start-rocketlogai.ps1") -Force
}

# --- Detect install type ---
if ([string]::IsNullOrWhiteSpace($InstallType)) {
    $InstallType = Get-DetectedInstallType -Dir $TargetDir
}

Write-Host "[detected] Install type: $InstallType" -ForegroundColor Yellow

if ($InstallType -eq "docker") {
    if (-not (Test-DockerDaemon)) {
        Write-Host "ERROR: Docker install detected but Docker daemon is not running." -ForegroundColor Red
        Write-Host "Start Docker Desktop, or re-run with -InstallType native if this is a Python install." -ForegroundColor Yellow
        exit 1
    }

    Write-Host "`n[1/3] Stopping Docker service..." -ForegroundColor Yellow
    Push-Location $TargetDir
    docker compose down
    if ($LASTEXITCODE -ne 0) { throw "docker compose down failed" }

    Write-Host "`n[2/3] Copying updated files..." -ForegroundColor Yellow
    Copy-UpgradeFiles -Dest $TargetDir
    "docker" | Out-File -Encoding ascii -FilePath (Join-Path $TargetDir ".install-type") -Force

    Write-Host "`n[3/3] Rebuilding and restarting container..." -ForegroundColor Yellow
    docker compose build --no-cache
    if ($LASTEXITCODE -ne 0) { throw "docker compose build failed" }
    docker compose up -d
    if ($LASTEXITCODE -ne 0) { throw "docker compose up failed" }
    Pop-Location

    Write-Host "`nDocker upgrade complete!" -ForegroundColor Green
} else {
    Write-Host "`n[1/4] Stopping running RocketLogAI processes..." -ForegroundColor Yellow
    Stop-RocketLogAIProcesses

    Write-Host "`n[2/4] Copying updated code..." -ForegroundColor Yellow
    Copy-UpgradeFiles -Dest $TargetDir

    Write-Host "`n[3/4] Installing/upgrading Python package in .venv..." -ForegroundColor Yellow
    Install-NativePackage -Dir $TargetDir

    Write-Host "`n[4/4] Verifying installation..." -ForegroundColor Yellow
    $venvPython = Join-Path $TargetDir ".venv\Scripts\python.exe"
    & $venvPython -c 'import logsentinel; print("RocketLogAI", logsentinel.__version__)'
    if ($LASTEXITCODE -ne 0) { throw "Post-upgrade import check failed" }

    Write-Host "`nNative upgrade complete!" -ForegroundColor Green
    Write-Host ""
    Write-Host "IMPORTANT: Use the install directory launcher (not global pip):" -ForegroundColor Yellow
    Write-Host "  cd $TargetDir"
    Write-Host "  .\start-rocketlogai.ps1"
    Write-Host ""
    Write-Host "Or activate the venv first:"
    Write-Host "  .\.venv\Scripts\Activate.ps1"
    Write-Host "  logsentinel run --web"
}

if ($Fix) {
    Write-Host "`nRunning health check repair..." -ForegroundColor Yellow
    $hc = Join-Path $SourceRoot "scripts\healthcheck.py"
    if (Test-Path $hc) {
        python $hc $TargetDir --fix
    }
}

Write-Host ""
Write-Host "Your config.yaml and data\ folder were preserved." -ForegroundColor Green
Write-Host "Open http://localhost:8787 and verify the dashboard." -ForegroundColor Green
Write-Host ""