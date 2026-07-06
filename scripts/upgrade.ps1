# RocketLogAI Upgrade Script for Windows (PowerShell 5.1+)
# Run from a git-cloned RocketLogAI source directory.
#
# Usage:
#   .\scripts\upgrade.ps1 -TargetDir "D:\logsentinel"
#   .\scripts\upgrade.ps1 -TargetDir "D:\logsentinel" -InstallType native -Fix
#   .\scripts\upgrade.ps1 -Help

param(
    [string]$TargetDir = "",
    [ValidateSet("", "native", "docker")]
    [string]$InstallType = "",
    [switch]$Help,
    [switch]$Fix,
    [switch]$SkipBackup,
    [switch]$RecreateVenv
)

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
. (Join-Path $ScriptDir 'ps-windows.ps1')

function Show-Help {
    Write-Host "RocketLogAI Upgrade (Windows)"
    Write-Host ""
    Write-Host "Usage:"
    Write-Host "  .\scripts\upgrade.ps1 [-TargetDir PATH] [-InstallType native|docker] [-Fix]"
    Write-Host ""
    Write-Host "Options:"
    Write-Host "  -TargetDir     Existing installation (default: prompt)"
    Write-Host "  -InstallType   Force native or docker (auto-detected if omitted)"
    Write-Host "  -Fix           Run health check repair after upgrade"
    Write-Host "  -Help          Show this help"
    Write-Host ""
    Write-Host "Examples:"
    Write-Host "  .\scripts\upgrade.ps1 -TargetDir D:\logsentinel"
    Write-Host "  .\scripts\upgrade.ps1 -TargetDir D:\logsentinel -InstallType native -Fix"
    Write-Host ""
    Write-Host "After upgrade, start with:"
    Write-Host "  cd D:\logsentinel"
    Write-Host "  .\start-rocketlogai.ps1"
}

function Test-DockerDaemon {
    if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
        return $false
    }
    try {
        & docker info 1>$null 2>$null
        return $LASTEXITCODE -eq 0
    }
    catch {
        return $false
    }
}

function Get-DetectedInstallType {
    param([string]$Dir)

    $marker = Join-Path $Dir ".install-type"
    if (Test-Path $marker) {
        $value = (Get-Content $marker -Raw).Trim().ToLower()
        if ($value -eq "native" -or $value -eq "docker") {
            return $value
        }
    }

    if (Test-Path (Join-Path $Dir ".venv")) {
        return "native"
    }

    if (Test-DockerDaemon) {
        $containers = & docker ps -a --filter "name=rocketlogai" --format "{{.Names}}" 2>$null
        if ($containers -match "rocketlogai") {
            return "docker"
        }
    }

    $configPath = Join-Path $Dir "config.yaml"
    $dbPath = Join-Path $Dir "data\logsentinel.db"
    if ((Test-Path $configPath) -or (Test-Path $dbPath)) {
        return "native"
    }

    $composePath = Join-Path $Dir "docker-compose.yml"
    if ((Test-Path $composePath) -and (Test-DockerDaemon)) {
        return "docker"
    }

    return "native"
}

function Copy-UpgradeFiles {
    param(
        [string]$Dest,
        [string]$Source
    )

    $dirs = @("logsentinel", "templates", "scripts", "helm", "tests")
    foreach ($d in $dirs) {
        $src = Join-Path $Source $d
        if (Test-Path $src) {
            $dst = Join-Path $Dest $d
            & robocopy $src $dst /E /NFL /NDL /NJH /NJS /XD __pycache__ .pytest_cache | Out-Null
        }
    }

    $files = @(
        "pyproject.toml",
        "requirements.txt",
        "example-config.yaml",
        "Dockerfile",
        "docker-compose.yml",
        "INSTALL.md",
        "README.md"
    )
    foreach ($f in $files) {
        $src = Join-Path $Source $f
        if (Test-Path $src) {
            Copy-Item $src -Destination (Join-Path $Dest $f) -Force
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
            $proc = Get-CimInstance Win32_Process -Filter ("ProcessId = " + $_.Id) -ErrorAction SilentlyContinue
            if ($null -ne $proc -and $proc.CommandLine -match "logsentinel") {
                Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
            }
        }
        catch {
        }
    }
}

function Invoke-InstallCleanup {
    param([string]$Dir)

    $cleanupPy = Join-Path $SourceRoot "scripts\rla_cleanup.py"
    if (-not (Test-Path $cleanupPy)) {
        Write-Host "WARNING: cleanup script not found, skipping." -ForegroundColor Yellow
        return
    }

    Write-Host "Cleaning install folder (remove junk, sync official layout)..." -ForegroundColor Yellow
    try {
        $runner = Get-DefaultRunnerPython
    }
    catch {
        Write-Host ("WARNING: " + $_.Exception.Message + " Skipping cleanup.") -ForegroundColor Yellow
        return
    }
    Invoke-PythonLauncher -Launcher $runner -PythonArgs $cleanupPy, $Dir, '--source', $SourceRoot, '--fix'
}

function Invoke-InstallBackup {
    param([string]$Dir)

    $backupPy = Join-Path $SourceRoot "scripts\rla_backup.py"
    if (-not (Test-Path $backupPy)) {
        Write-Host "WARNING: backup script not found, skipping backup." -ForegroundColor Yellow
        return
    }
    try {
        $runner = Get-DefaultRunnerPython
        Invoke-PythonLauncher -Launcher $runner -PythonArgs $backupPy, $Dir
    }
    catch {
        Write-Host ("WARNING: Backup skipped - " + $_.Exception.Message) -ForegroundColor Yellow
    }
}

function Get-VenvPythonVersion {
    param([string]$PythonExe)
    if (-not (Test-Path $PythonExe)) { return $null }
    $verCode = 'import sys; print(str(sys.version_info[0]) + chr(46) + str(sys.version_info[1]))'
    return (& $PythonExe -c $verCode).Trim()
}

function Ensure-Venv {
    param([string]$Dir)

    $script:RequirePython312 = $false
    $venv = Join-Path $Dir ".venv"
    $pythonExe = Join-Path $venv "Scripts\python.exe"

    if (Test-Path $pythonExe) {
        $ver = Get-VenvPythonVersion -PythonExe $pythonExe
        $needsRecreate = $RecreateVenv -or ($ver -match '^3\.(1[3-9]|[2-9][0-9])')

        if ($needsRecreate) {
            $selector = Join-Path $SourceRoot "scripts\rla_python.py"
            $has312 = Test-PythonTagAvailable -SelectorScript $selector -Tag '3.12'

            if ($has312) {
                $prompt = "Recreate .venv with Python 3.12 (recommended for full AI Operator)? [Y/n]"
                if ($RecreateVenv) {
                    Write-Host $prompt -ForegroundColor Yellow
                    $ans = "Y"
                }
                else {
                    $ans = Read-Host $prompt
                }
                if ($ans -eq "" -or $ans -eq "y" -or $ans -eq "Y") {
                    Write-Host "Removing old .venv and creating Python 3.12 environment..." -ForegroundColor Yellow
                    Remove-Item -Recurse -Force $venv
                    $script:RequirePython312 = $true
                }
                else {
                    return $venv
                }
            }
            elseif ($RecreateVenv) {
                Write-Python312InstallHelp
                throw 'Python 3.12 required for -RecreateVenv but py -3.12 is not installed'
            }
            else {
                Write-Host ("Keeping existing Python " + $ver + " .venv (AI Operator may be limited).") -ForegroundColor Yellow
                return $venv
            }
        }
        else {
            return $venv
        }
    }

    Write-Host "Creating .venv (default: Python 3.12 if installed)..." -ForegroundColor Yellow
    $selector = Join-Path $SourceRoot "scripts\rla_python.py"
    if (-not (Test-Path $selector)) {
        throw 'Missing scripts\rla_python.py'
    }

    $requireTag = ''
    if ($script:RequirePython312) {
        $requireTag = '3.12'
    }

    try {
        $pyCmd = Invoke-SelectPythonLauncher -SelectorScript $selector -RequireTag $requireTag
        New-PythonVenv -Launcher $pyCmd -VenvPath $venv | Out-Null
    }
    catch {
        Write-Host ("ERROR: " + $_.Exception.Message) -ForegroundColor Red
        if ($requireTag -eq '3.12') {
            Write-Python312InstallHelp
        }
        throw
    }
    return $venv
}

function Install-PythonDependencies {
    param([string]$PythonExe, [string]$Dir)

    Write-Host "Installing core RocketLogAI packages [web,v2]..." -ForegroundColor Yellow
    & $PythonExe -m pip install -e '.[web,v2]' --upgrade
    if ($LASTEXITCODE -ne 0) {
        throw "pip install -e .[web,v2] failed"
    }

    Write-Host "Installing optional AI Operator extras (open-interpreter)..." -ForegroundColor Yellow
    & $PythonExe -m pip install open-interpreter --upgrade
    if ($LASTEXITCODE -ne 0) {
        Write-Host "WARNING: open-interpreter could not be installed (common on Python 3.13+)." -ForegroundColor Yellow
        Write-Host "  RocketLogAI core v2 is installed and will run normally." -ForegroundColor Yellow
        Write-Host "  For full conversational AI Operator, use Python 3.10-3.12 in .venv." -ForegroundColor Yellow
    }
    else {
        Write-Host "AI Operator extras installed." -ForegroundColor Green
    }
}

function Write-LauncherScripts {
    param([string]$Dir)

    $batPath = Join-Path $Dir "start-rocketlogai.bat"
    $batContent = "@echo off`r`ncd /d %~dp0`r`ncall .venv\Scripts\activate.bat`r`necho.`r`necho Starting RocketLogAI...`r`nlogsentinel run --web`r`npause`r`n"
    Set-Content -Path $batPath -Value $batContent -Encoding ASCII

    $ps1Path = Join-Path $Dir "start-rocketlogai.ps1"
    $ps1Content = "Set-Location `$PSScriptRoot`n. .\.venv\Scripts\Activate.ps1`nlogsentinel run --web`n"
    Set-Content -Path $ps1Path -Value $ps1Content -Encoding UTF8
}

function Install-NativePackage {
    param([string]$Dir)

    $venv = Ensure-Venv -Dir $Dir
    $python = Join-Path $venv "Scripts\python.exe"

    Write-Host "Upgrading pip..." -ForegroundColor Yellow
    & $python -m pip install --upgrade pip setuptools wheel
    if ($LASTEXITCODE -ne 0) {
        throw "pip bootstrap failed"
    }

    Push-Location $Dir
    try {
        Install-PythonDependencies -PythonExe $python -Dir $Dir
    }
    finally {
        Pop-Location
    }

    Set-Content -Path (Join-Path $Dir ".install-type") -Value "native" -Encoding ASCII
    Write-LauncherScripts -Dir $Dir
}

function Test-InstalledVersion {
    param([string]$PythonExe)

    $checkScript = Join-Path $env:TEMP ("rla_version_check_" + [guid]::NewGuid().ToString() + ".py")
    $checkLines = @(
        'import logsentinel'
        'print("RocketLogAI", logsentinel.__version__)'
    )
    Set-Content -Path $checkScript -Value $checkLines -Encoding ASCII
    try {
        & $PythonExe $checkScript
        if ($LASTEXITCODE -ne 0) {
            throw "Post-upgrade import check failed"
        }
    }
    finally {
        Remove-Item $checkScript -Force -ErrorAction SilentlyContinue
    }
}

if ($Help -or $TargetDir -eq "-h" -or $TargetDir -eq "--help" -or $TargetDir -eq "/?") {
    Show-Help
    exit 0
}

Write-Host "RocketLogAI Upgrade (Windows)" -ForegroundColor Cyan
Write-Host "====================================" -ForegroundColor Cyan

$SourceRoot = Split-Path -Parent $ScriptDir

if ([string]::IsNullOrWhiteSpace($TargetDir)) {
    $TargetDir = Read-Host "Enter path to your EXISTING RocketLogAI installation (e.g. D:\logsentinel)"
}

if ($TargetDir -eq "-h" -or $TargetDir -eq "--help" -or $TargetDir -eq "/?") {
    Show-Help
    exit 0
}

if (-not (Test-Path $TargetDir)) {
    Write-Host ("ERROR: Target directory does not exist: " + $TargetDir) -ForegroundColor Red
    exit 1
}

$TargetDir = (Resolve-Path $TargetDir).Path

Write-Host ("Upgrading: " + $TargetDir)
Write-Host ("Using new code from: " + $SourceRoot)
Write-Host ""

if ([string]::IsNullOrWhiteSpace($InstallType)) {
    $InstallType = Get-DetectedInstallType -Dir $TargetDir
}

Write-Host ("[detected] Install type: " + $InstallType) -ForegroundColor Yellow

if ($InstallType -eq "docker") {
    if (-not $SkipBackup) {
        Write-Host ""
        Write-Host "[0/4] Backing up config and data..." -ForegroundColor Yellow
        Invoke-InstallBackup -Dir $TargetDir
    }

    if (-not (Test-DockerDaemon)) {
        Write-Host "ERROR: Docker install detected but Docker daemon is not running." -ForegroundColor Red
        Write-Host "Start Docker Desktop, or re-run with -InstallType native if this is a Python install." -ForegroundColor Yellow
        exit 1
    }

    Write-Host ""
    Write-Host "[1/4] Stopping Docker service..." -ForegroundColor Yellow
    Push-Location $TargetDir
    try {
        & docker compose down
        if ($LASTEXITCODE -ne 0) {
            throw "docker compose down failed"
        }

        Write-Host ""
        Write-Host "[2/4] Copying updated files..." -ForegroundColor Yellow
        Copy-UpgradeFiles -Dest $TargetDir -Source $SourceRoot
        Invoke-InstallCleanup -Dir $TargetDir
        Set-Content -Path (Join-Path $TargetDir ".install-type") -Value "docker" -Encoding ASCII

        Write-Host ""
        Write-Host "[3/4] Rebuilding and restarting container (Python 3.12 image)..." -ForegroundColor Yellow
        & docker compose build --no-cache
        if ($LASTEXITCODE -ne 0) {
            throw "docker compose build failed"
        }
        & docker compose up -d
        if ($LASTEXITCODE -ne 0) {
            throw "docker compose up failed"
        }
    }
    finally {
        Pop-Location
    }

    Write-Host ""
    Write-Host "Docker upgrade complete!" -ForegroundColor Green
}
else {
    if (-not $SkipBackup) {
        Write-Host ""
        Write-Host "[0/5] Backing up config and data..." -ForegroundColor Yellow
        Invoke-InstallBackup -Dir $TargetDir
    }

    Write-Host ""
    Write-Host "[1/5] Stopping running RocketLogAI processes..." -ForegroundColor Yellow
    Stop-RocketLogAIProcesses

    Write-Host ""
    Write-Host "[2/5] Copying updated code..." -ForegroundColor Yellow
    Copy-UpgradeFiles -Dest $TargetDir -Source $SourceRoot
    Invoke-InstallCleanup -Dir $TargetDir

    Write-Host ""
    Write-Host "[3/5] Installing/upgrading Python package in .venv..." -ForegroundColor Yellow
    try {
        Install-NativePackage -Dir $TargetDir
    }
    catch {
        Write-Host ''
        Write-Host ('Upgrade failed during Python setup: ' + $_.Exception.Message) -ForegroundColor Red
        Write-Host 'If py -3.12 is missing, install Python 3.12 alongside 3.13, then re-run.' -ForegroundColor Yellow
        exit 1
    }

    Write-Host ""
    Write-Host "[4/5] Verifying installation..." -ForegroundColor Yellow
    $venvPython = Join-Path $TargetDir ".venv\Scripts\python.exe"
    Test-InstalledVersion -PythonExe $venvPython

    Write-Host ""
    Write-Host "Native upgrade complete!" -ForegroundColor Green
    Write-Host ""
    Write-Host "IMPORTANT: Use the install directory launcher (not global pip):" -ForegroundColor Yellow
    Write-Host ("  cd " + $TargetDir)
    Write-Host "  .\start-rocketlogai.ps1"
    Write-Host ""
    Write-Host "Or activate the venv first:"
    Write-Host "  .\.venv\Scripts\Activate.ps1"
    Write-Host "  logsentinel run --web"
}

if ($Fix) {
    Write-Host ""
    Write-Host "Running health check repair..." -ForegroundColor Yellow
    $hc = Join-Path $SourceRoot "scripts\healthcheck.py"
    if (Test-Path $hc) {
        & python $hc $TargetDir --fix
    }
}

Write-Host ""
Write-Host "Your config.yaml and data folder were preserved." -ForegroundColor Green
Write-Host "Open http://localhost:8787 and verify the dashboard." -ForegroundColor Green
Write-Host ""