# Shared PowerShell helpers for RocketLogAI Windows scripts (PS 5.1+)
# Dot-source from install.ps1 / upgrade.ps1:
#   . (Join-Path $ScriptDir 'ps-windows.ps1')

function Normalize-PythonLauncher {
    param(
        [Parameter(Mandatory = $true)]
        $Launcher
    )

    if ($null -eq $Launcher) {
        return @()
    }

    if ($Launcher -is [string]) {
        return @($Launcher)
    }

    # Undo accidental nested array: @(,@('py','-3.12'))
    if ($Launcher.Count -eq 1 -and $Launcher[0] -is [System.Array]) {
        $Launcher = $Launcher[0]
    }

    $out = @()
    foreach ($item in @($Launcher)) {
        if ($null -ne $item -and "$item" -ne '') {
            $out += [string]$item
        }
    }
    return $out
}

function Get-PythonLauncherFromJson {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Json
    )

    $info = $Json | ConvertFrom-Json
    $launcher = Normalize-PythonLauncher $info.command
    if ($launcher.Count -eq 0) {
        throw 'Python selector returned an empty launcher command'
    }
    return @{
        Launcher = $launcher
        Version  = [string]$info.version
        Tag      = [string]$info.tag
        AiFull   = [bool]$info.ai_operator_full
    }
}

function Invoke-PythonLauncher {
    param(
        [Parameter(Mandatory = $true)]
        $Launcher,
        [Parameter(ValueFromRemainingArguments = $true)]
        [string[]]$PythonArgs
    )

    $parts = Normalize-PythonLauncher $Launcher
    if ($parts.Count -eq 0) {
        throw 'No Python launcher configured'
    }

    $exe = $parts[0]
    $prefix = @()
    if ($parts.Count -gt 1) {
        $prefix = $parts[1..($parts.Count - 1)]
    }

    & $exe @prefix @PythonArgs
}

function Test-PythonLauncherWorks {
    param(
        [Parameter(Mandatory = $true)]
        $Launcher
    )

    try {
        Invoke-PythonLauncher -Launcher $Launcher '-c', 'import sys'
        return ($LASTEXITCODE -eq 0)
    }
    catch {
        return $false
    }
}

function Get-DefaultRunnerPython {
    # Runner for helper scripts (rla_python.py, cleanup, backup).
    # Use any working Python 3.10+ launcher; do not assume py -3.12 exists.
    $candidates = @(
        @('python'),
        @('py'),
        @('py', '-3.12'),
        @('py', '-3.11'),
        @('py', '-3.10')
    )

    foreach ($candidate in $candidates) {
        $name = $candidate[0]
        if (-not (Get-Command $name -ErrorAction SilentlyContinue)) {
            continue
        }
        if (Test-PythonLauncherWorks -Launcher $candidate) {
            return $candidate
        }
    }

    return @()
}

function Test-PythonTagAvailable {
    param(
        [Parameter(Mandatory = $true)]
        [string]$SelectorScript,
        [Parameter(Mandatory = $true)]
        [string]$Tag
    )

    $runner = Get-DefaultRunnerPython
    if ($runner.Count -eq 0) {
        return $false
    }

    Invoke-PythonLauncher -Launcher $runner -PythonArgs $SelectorScript, '--has', $Tag | Out-Null
    return ($LASTEXITCODE -eq 0)
}

function Invoke-SelectPythonLauncher {
    param(
        [Parameter(Mandatory = $true)]
        [string]$SelectorScript,
        [switch]$Ask,
        [string]$RequireTag = ''
    )

    $runner = Get-DefaultRunnerPython
    if ($runner.Count -eq 0) {
        throw 'Python not found. Install Python 3.12 from https://www.python.org/downloads/windows/'
    }

    $selectorArgs = @($SelectorScript)
    if ($Ask) {
        $selectorArgs += '--ask'
    }

    $json = Invoke-PythonLauncher -Launcher $runner -PythonArgs $selectorArgs
    if ($LASTEXITCODE -ne 0) {
        throw 'Could not find Python 3.10+. Install Python 3.12 from https://www.python.org/downloads/windows/'
    }

    $parsed = Get-PythonLauncherFromJson -Json $json
    $cmdText = $parsed.Launcher -join ' '
    Write-Host ('Selected Python ' + $parsed.Version + ' (' + $cmdText + ')') -ForegroundColor Green
    if (-not $parsed.AiFull) {
        Write-Host '  Note: AI Operator may be limited on this Python version.' -ForegroundColor Yellow
    }

    if (-not (Test-PythonLauncherWorks -Launcher $parsed.Launcher)) {
        $msg = 'Python launcher failed: ' + $cmdText + '.'
        if ($parsed.Tag -ne '3.12') {
            $msg += ' Install Python 3.12 and ensure "py -3.12 -c ""import sys""" works.'
        }
        else {
            $msg += ' Re-run the Python 3.12 installer and enable "py launcher".'
        }
        throw $msg
    }

    if ($RequireTag -and $parsed.Tag -ne $RequireTag) {
        throw (
            'Python ' + $RequireTag + ' is required but only ' + $parsed.Version +
            ' was found (' + $cmdText + '). Install Python ' + $RequireTag +
            ' from https://www.python.org/downloads/release/python-3120/'
        )
    }

    return $parsed.Launcher
}

function New-PythonVenv {
    param(
        [Parameter(Mandatory = $true)]
        $Launcher,
        [Parameter(Mandatory = $true)]
        [string]$VenvPath
    )

    $pythonExe = Join-Path $VenvPath 'Scripts\python.exe'
    if (Test-Path $pythonExe) {
        return $pythonExe
    }

    Invoke-PythonLauncher -Launcher $Launcher '-m', 'venv', $VenvPath
    if ($LASTEXITCODE -ne 0) {
        $cmdText = (Normalize-PythonLauncher $Launcher) -join ' '
        throw ('venv creation failed (exit ' + $LASTEXITCODE + ') using ' + $cmdText)
    }
    if (-not (Test-Path $pythonExe)) {
        $cmdText = (Normalize-PythonLauncher $Launcher) -join ' '
        throw ('Failed to create virtual environment at ' + $VenvPath + ' using ' + $cmdText)
    }
    return $pythonExe
}

function Write-Python312InstallHelp {
    Write-Host ''
    Write-Host 'Python 3.12 is not available via the Windows py launcher.' -ForegroundColor Red
    Write-Host 'Your default "py" command runs Python 3.13, which limits AI Operator extras.' -ForegroundColor Yellow
    Write-Host ''
    Write-Host 'To fix:' -ForegroundColor Cyan
    Write-Host '  1. Download Python 3.12: https://www.python.org/downloads/release/python-3120/' -ForegroundColor Cyan
    Write-Host '  2. Run installer, check "Add python.exe to PATH" and "py launcher"' -ForegroundColor Cyan
    Write-Host '  3. Verify: py -3.12 -c "import sys; print(sys.version)"' -ForegroundColor Cyan
    Write-Host '  4. Re-run this script' -ForegroundColor Cyan
    Write-Host ''
}