# RocketLogAI one-click setup wizard (Windows)
# Usage: .\scripts\setup.ps1

param([switch]$Help)

$ErrorActionPreference = "Stop"

function Show-Help {
    Write-Host "RocketLogAI Setup Wizard (Windows)"
    Write-Host ""
    Write-Host "  .\scripts\setup.ps1"
    Write-Host ""
    Write-Host "Guides you through fresh install, Docker install, upgrade, or health check."
}

if ($Help) {
    Show-Help
    exit 0
}

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$SourceRoot = Split-Path -Parent $ScriptDir

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  RocketLogAI v2 Setup Wizard" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Recommended: Python 3.12 for native installs (full AI Operator support)"
Write-Host "Docker installs use Python 3.12 inside the container automatically."
Write-Host ""
Write-Host "What would you like to do?"
Write-Host "  1) Fresh install (Python / native)"
Write-Host "  2) Fresh install (Docker)"
Write-Host "  3) Upgrade existing installation"
Write-Host "  4) Health check / repair"
Write-Host "  5) Restore from backup"
Write-Host ""

$choice = Read-Host "Enter choice [1-5] (default 1)"
if ([string]::IsNullOrWhiteSpace($choice)) { $choice = "1" }

switch ($choice) {
    "1" {
        & (Join-Path $ScriptDir "install.ps1")
    }
    "2" {
        & (Join-Path $ScriptDir "install-docker.ps1")
    }
    "3" {
        $target = Read-Host "Existing install directory (e.g. D:\logsentinel)"
        if ([string]::IsNullOrWhiteSpace($target)) {
            Write-Host "ERROR: Install directory required." -ForegroundColor Red
            exit 1
        }
        & (Join-Path $ScriptDir "upgrade.ps1") -TargetDir $target -InstallType native -Fix
    }
    "4" {
        $target = Read-Host "Install directory to check (e.g. D:\logsentinel)"
        if ([string]::IsNullOrWhiteSpace($target)) { $target = "D:\logsentinel" }
        & (Join-Path $ScriptDir "check.ps1") -InstallDir $target -Fix
    }
    "5" {
        $target = Read-Host "Install directory (e.g. D:\logsentinel)"
        $backup = Read-Host "Backup folder path (under install\backups\...)"
        if ([string]::IsNullOrWhiteSpace($target) -or [string]::IsNullOrWhiteSpace($backup)) {
            Write-Host "ERROR: Both paths required." -ForegroundColor Red
            exit 1
        }
        & python (Join-Path $ScriptDir "rla_backup.py") $target --restore $backup
    }
    default {
        Write-Host "Invalid choice." -ForegroundColor Red
        exit 1
    }
}