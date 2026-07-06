# Validates PowerShell scripts parse without errors.
# Usage: powershell -NoProfile -File scripts\validate-powershell.ps1

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Split-Path -Parent $ScriptDir

$targets = @(
    (Join-Path $ScriptDir "upgrade.ps1"),
    (Join-Path $ScriptDir "install.ps1"),
    (Join-Path $ScriptDir "install-docker.ps1"),
    (Join-Path $ScriptDir "setup.ps1"),
    (Join-Path $ScriptDir "check.ps1"),
    (Join-Path $ScriptDir "validate-powershell.ps1")
)

$failed = $false
foreach ($path in $targets) {
    if (-not (Test-Path $path)) {
        Write-Host ("SKIP missing: " + $path)
        continue
    }
    $errors = $null
    $tokens = $null
    $null = [System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$tokens, [ref]$errors)
    if ($errors -and $errors.Count -gt 0) {
        Write-Host ("FAIL " + $path) -ForegroundColor Red
        foreach ($err in $errors) {
            Write-Host ("  " + $err.ToString())
        }
        $failed = $true
    }
    else {
        Write-Host ("OK   " + $path) -ForegroundColor Green
    }
}

if ($failed) {
    exit 1
}

Write-Host ""
Write-Host "All PowerShell scripts passed syntax validation." -ForegroundColor Green
exit 0