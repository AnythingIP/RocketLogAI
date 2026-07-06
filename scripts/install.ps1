# RocketLogAI v2.0 - One-click installer for Windows
# Run from an elevated PowerShell prompt

$ErrorActionPreference = "Stop"

Write-Host "RocketLogAI Installer for Windows" -ForegroundColor Cyan
Write-Host "=====================================" -ForegroundColor Cyan

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$SourceRoot = Split-Path -Parent $ScriptDir   # RocketLogAI repo root

$InstallDir = "D:\logsentinel"
$InstallDir = Read-Host "Enter target directory (default D:\logsentinel)"
if ([string]::IsNullOrWhiteSpace($InstallDir)) { $InstallDir = "D:\logsentinel" }

New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null

Write-Host "`n[1/6] Selecting Python (recommended: 3.12)..." -ForegroundColor Yellow
$selector = Join-Path $ScriptDir "rla_python.py"
if (-not (Test-Path $selector)) {
    Write-Host "ERROR: Missing scripts\rla_python.py" -ForegroundColor Red
    exit 1
}

$runner = if (Get-Command python -ErrorAction SilentlyContinue) { @("python") }
          elseif (Get-Command py -ErrorAction SilentlyContinue) { @("py", "-3.12") }
          else { $null }

if (-not $runner) {
    Write-Host "Python 3.10+ not found. Install Python 3.12:" -ForegroundColor Red
    Write-Host "https://www.python.org/downloads/release/python-3120/" -ForegroundColor Cyan
    exit 1
}

$pyJson = & @runner $selector --ask
if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: Could not select Python interpreter." -ForegroundColor Red
    exit 1
}
$pyInfo = $pyJson | ConvertFrom-Json
$pyLauncher = @($pyInfo.command)

if (Test-Path (Join-Path $InstallDir "config.yaml")) {
    Write-Host "`n[1.5/6] Existing install detected - backing up first..." -ForegroundColor Yellow
    & @runner (Join-Path $ScriptDir "rla_backup.py") $InstallDir --label pre-install
}

Write-Host "`n[2/6] Creating virtual environment..." -ForegroundColor Yellow
& @pyLauncher -m venv "$InstallDir\.venv"
. "$InstallDir\.venv\Scripts\Activate.ps1"

Write-Host "`n[3/6] Copying RocketLogAI files..." -ForegroundColor Yellow
robocopy "$SourceRoot\logsentinel" "$InstallDir\logsentinel" /E /NFL /NDL /NJH /NJS | Out-Null
robocopy "$SourceRoot\templates" "$InstallDir\templates" /E /NFL /NDL /NJH /NJS | Out-Null
Copy-Item "$SourceRoot\pyproject.toml" -Destination $InstallDir -Force
Copy-Item "$SourceRoot\requirements.txt" -Destination $InstallDir -Force -ErrorAction SilentlyContinue
Copy-Item "$SourceRoot\example-config.yaml" -Destination $InstallDir -Force -ErrorAction SilentlyContinue
robocopy "$SourceRoot\scripts" "$InstallDir\scripts" /E /NFL /NDL /NJH /NJS | Out-Null

Write-Host "`n[4/6] Installing dependencies..." -ForegroundColor Yellow
pip install --upgrade pip setuptools wheel
Set-Location $InstallDir
pip install ".[web,v2]"
if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: Core install failed." -ForegroundColor Red
    exit 1
}

Write-Host "`n[4.5/6] Installing optional AI Operator (open-interpreter)..." -ForegroundColor Yellow
pip install open-interpreter
if ($LASTEXITCODE -ne 0) {
    Write-Host "WARNING: open-interpreter skipped (common on Python 3.13+)." -ForegroundColor Yellow
    Write-Host "  RocketLogAI core v2 is installed. Use Python 3.10-3.12 for full AI Operator." -ForegroundColor Yellow
}

"native" | Out-File -Encoding ascii -FilePath "$InstallDir\.install-type" -Force

Write-Host "`n[5/6] Creating launchers..." -ForegroundColor Yellow

$batContent = "@echo off`r`ncd /d %~dp0`r`ncall .venv\Scripts\activate.bat`r`necho.`r`necho Starting RocketLogAI...`r`nlogsentinel run --web`r`npause`r`n"
Set-Content -Path "$InstallDir\start-rocketlogai.bat" -Value $batContent -Encoding ASCII

$ps1Content = "Set-Location `$PSScriptRoot`n. .\.venv\Scripts\Activate.ps1`nlogsentinel run --web`n"
Set-Content -Path "$InstallDir\start-rocketlogai.ps1" -Value $ps1Content -Encoding UTF8

Write-Host "`n[6/6] Cleaning install folder..." -ForegroundColor Yellow
$cleanupPy = Join-Path $ScriptDir "rla_cleanup.py"
if (Test-Path $cleanupPy) {
    & @runner $cleanupPy $InstallDir --source $SourceRoot --fix
}

Write-Host ""
Write-Host "Done!" -ForegroundColor Green
Write-Host ""
Write-Host "Tip: Run .\scripts\setup.ps1 anytime for install, upgrade, Docker, or repair." -ForegroundColor Cyan
Write-Host ""
Write-Host "Installation complete!" -ForegroundColor Green
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