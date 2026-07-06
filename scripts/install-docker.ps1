# RocketLogAI one-click Docker install (Windows)
# Usage: .\scripts\install-docker.ps1 [-InstallDir PATH]

param(
    [string]$InstallDir = "",
    [switch]$Help
)

$ErrorActionPreference = "Stop"

if ($Help) {
    Write-Host "RocketLogAI Docker Install"
    Write-Host "  .\scripts\install-docker.ps1 [-InstallDir PATH]"
    exit 0
}

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$SourceRoot = Split-Path -Parent $ScriptDir

Write-Host ""
Write-Host "RocketLogAI Docker Install" -ForegroundColor Cyan
Write-Host "==========================" -ForegroundColor Cyan
Write-Host "Uses Python 3.12 inside the container (no local Python required)."
Write-Host ""

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    Write-Host "ERROR: Docker not found. Install Docker Desktop:" -ForegroundColor Red
    Write-Host "  https://www.docker.com/products/docker-desktop/" -ForegroundColor Yellow
    exit 1
}

& docker info 1>$null 2>$null
if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: Docker daemon is not running. Start Docker Desktop first." -ForegroundColor Red
    exit 1
}

if ([string]::IsNullOrWhiteSpace($InstallDir)) {
    $InstallDir = Read-Host "Install directory for config and data (default: D:\logsentinel)"
}
if ([string]::IsNullOrWhiteSpace($InstallDir)) {
    $InstallDir = "D:\logsentinel"
}

New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $InstallDir "data") | Out-Null

Write-Host ""
Write-Host "[1/5] Copying Docker files..." -ForegroundColor Yellow
$files = @("Dockerfile", "docker-compose.yml", "pyproject.toml", "requirements.txt", "example-config.yaml")
foreach ($f in $files) {
    $src = Join-Path $SourceRoot $f
    if (Test-Path $src) {
        Copy-Item $src -Destination (Join-Path $InstallDir $f) -Force
    }
}
robocopy (Join-Path $SourceRoot "logsentinel") (Join-Path $InstallDir "logsentinel") /E /NFL /NDL /NJH /NJS | Out-Null
robocopy (Join-Path $SourceRoot "templates") (Join-Path $InstallDir "templates") /E /NFL /NDL /NJH /NJS | Out-Null
robocopy (Join-Path $SourceRoot "scripts") (Join-Path $InstallDir "scripts") /E /NFL /NDL /NJH /NJS | Out-Null

$configPath = Join-Path $InstallDir "config.yaml"
if (-not (Test-Path $configPath)) {
    Copy-Item (Join-Path $InstallDir "example-config.yaml") $configPath
    Write-Host "Created config.yaml from example-config.yaml" -ForegroundColor Green
}

Set-Content -Path (Join-Path $InstallDir ".install-type") -Value "docker" -Encoding ASCII

$cleanupPy = Join-Path $SourceRoot "scripts\rla_cleanup.py"
if (Test-Path $cleanupPy) {
    Write-Host "Cleaning install folder..." -ForegroundColor Yellow
    $py = if (Get-Command python -ErrorAction SilentlyContinue) { "python" } else { "py" }
    & $py $cleanupPy $InstallDir --source $SourceRoot --fix
}

Write-Host ""
Write-Host "[2/5] Backing up any existing data (if present)..." -ForegroundColor Yellow
$backupPy = Join-Path $SourceRoot "scripts\rla_backup.py"
if (Test-Path $backupPy) {
    & python $backupPy $InstallDir --label pre-docker 2>$null
}

Write-Host ""
Write-Host "[3/5] Building Docker image (Python 3.12)..." -ForegroundColor Yellow
Push-Location $InstallDir
try {
    & docker compose build
    if ($LASTEXITCODE -ne 0) { throw "docker compose build failed" }

    Write-Host ""
    Write-Host "[4/5] Starting container..." -ForegroundColor Yellow
    & docker compose up -d
    if ($LASTEXITCODE -ne 0) { throw "docker compose up failed" }
}
finally {
    Pop-Location
}

Write-Host ""
Write-Host "[5/5] Done!" -ForegroundColor Green
Write-Host ""
Write-Host "RocketLogAI is running in Docker." -ForegroundColor Green
Write-Host ("  Web UI:  http://localhost:8787")
Write-Host ("  Data:    " + (Join-Path $InstallDir "data"))
Write-Host ("  Config:  " + $configPath)
Write-Host ""
Write-Host "Default login: admin / admin (change immediately in the UI)"
Write-Host ""
Write-Host "Useful commands (run from install directory):"
Write-Host "  docker compose logs -f"
Write-Host "  docker compose down"
Write-Host "  docker compose up -d --build   # after upgrades"
Write-Host ""