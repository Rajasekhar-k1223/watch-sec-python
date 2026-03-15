<#
.SYNOPSIS
WatchSec Agent Launcher
Runs the agent using the embedded Python runtime.
#>

$ScriptDir = $PSScriptRoot
$PythonPath = Join-Path $ScriptDir "pythonw.exe"
$MainScript = Join-Path $ScriptDir "src\main.py"

# Ensure we are in the script directory so relative paths in python work
Set-Location $ScriptDir

if (-not (Test-Path $PythonPath)) {
    # Fallback to python.exe if pythonw.exe is missing (shouldn't happen in embedded)
    $PythonPath = Join-Path $ScriptDir "python.exe"
}

# Run PythonW (no console)
# -I : Isolated mode (ignore user env vars)
# -s : Don't add user site directory to sys.path
Start-Process -FilePath $PythonPath -ArgumentList "-I", "-s", "`"$MainScript`"" -WindowStyle Hidden
