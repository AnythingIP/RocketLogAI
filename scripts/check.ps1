# RocketLogAI Health Check (Windows)
# Usage:
#   .\scripts\check.ps1 [-InstallDir PATH] [-Fix]

param(
    [string]$InstallDir = "",
    [switch]$Fix,
    [switch]$Help
)

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$SourceRoot = Split-Path -Parent $ScriptDir
$Healthcheck = Join-Path $SourceRoot "scripts\healthcheck.py"

if ($Help) {
    Write-Host @"
RocketLogAI Health Check

Usage:
  .\scripts\check.ps1 [-InstallDir PATH] [-Fix]

  -InstallDir   Installation to check (default: current directory or prompt)
  -Fix          Attempt automatic repair (create venv, reinstall deps)
  -Help         Show this help
"@
    exit 0
}

if ([string]::IsNullOrWhiteSpace($InstallDir)) {
    $default = if (Test-Path "config.yaml") { (Get-Location).Path } else { "D:\logsentinel" }
    $InstallDir = Read-Host "Enter RocketLogAI install directory (default: $default)"
    if ([string]::IsNullOrWhiteSpace($InstallDir)) { $InstallDir = $default }
}

if (-not (Test-Path $Healthcheck)) {
    Write-Host "ERROR: healthcheck.py not found at $Healthcheck" -ForegroundColor Red
    exit 1
}

$args = @($Healthcheck, $InstallDir)
if ($Fix) { $args += "--fix" }

python @args
exit $LASTEXITCODE