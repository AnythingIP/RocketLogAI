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
    Write-Host "RocketLogAI Health Check"
    Write-Host ""
    Write-Host "Usage:"
    Write-Host "  .\scripts\check.ps1 [-InstallDir PATH] [-Fix]"
    Write-Host ""
    Write-Host "  -InstallDir   Installation to check (default: current directory or prompt)"
    Write-Host "  -Fix          Attempt automatic repair (create venv, reinstall deps)"
    Write-Host "  -Help         Show this help"
    exit 0
}

if ([string]::IsNullOrWhiteSpace($InstallDir)) {
    $default = "D:\logsentinel"
    if (Test-Path "config.yaml") {
        $default = (Get-Location).Path
    }
    $InstallDir = Read-Host ("Enter RocketLogAI install directory (default: " + $default + ")")
    if ([string]::IsNullOrWhiteSpace($InstallDir)) {
        $InstallDir = $default
    }
}

if (-not (Test-Path $Healthcheck)) {
    Write-Host ("ERROR: healthcheck.py not found at " + $Healthcheck) -ForegroundColor Red
    exit 1
}

$hcArgs = @($Healthcheck, $InstallDir)
if ($Fix) {
    $hcArgs += "--fix"
}

& python @hcArgs
exit $LASTEXITCODE