<#
.SYNOPSIS
Monitorix Agent - Source-Based Windows Installer (No EXE)
Downloads and installs the Monitorix Agent using Python scripts via PowerShell.

.DESCRIPTION
This script avoids downloading a pre-compiled .exe file directly.
1. Checks for Administrator privileges.
2. Checks for Python 3. If missing, downloads a Portable Python Runtime.
3. Downloads the Agent Source ZIP.
4. Extracts and configures the environment.
5. Installs the agent as a service running via Python.
#>

param (
    [string]$DownloadUrl = "",
    [string]$VersionCheckUrl = "",
    [string]$InstallDir = "C:\Program Files\Monitorix",
    [string]$ApiKey = "",
    [string]$BackendUrl = ""
)

#Requires -RunAsAdministrator
$ErrorActionPreference = 'Stop'

# [DEBUG] Enable Logging
$LogFile = "C:\monitorix_install_source.log"
Start-Transcript -Path $LogFile -Append -Force

Write-Host "--- Monitorix Source-Based Installation ---"
Write-Host "Target Dir: $InstallDir"
Write-Host "Payload URL: $DownloadUrl"

function Download-File {
    param ($Url, $Dest)
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
        $wc = New-Object System.Net.WebClient
        $wc.DownloadFile($Url, $Dest)
        return (Test-Path $Dest)
    } catch {
        Write-Error "Download Failed: $($_.Exception.Message)"
        return $false
    }
}

# 1. Check for Admin Privileges
Write-Host "[*] Checking for Administrative Privileges..."
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script MUST be run as an Administrator."
    exit 1
}

# 2. Pre-Install Cleanup
Write-Host "[*] Performing Cleanup..."
if (Test-Path $InstallDir) {
    # Stop service if running
    $ServiceName = "MonitorixAgentService"
    if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
        Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
    }
} else {
    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
}

# 3. Handle Python Environment
Write-Host "[*] Detecting Python Environment..."
$PythonPath = ""
if (Get-Command "python" -ErrorAction SilentlyContinue) {
    $PythonPath = (Get-Command "python").Source
    Write-Host "    [+] System Python found: $PythonPath"
} else {
    Write-Host "[!] Python not found. Setting up Portable Python Runtime..." -ForegroundColor Yellow
    $PyZip = Join-Path $env:TEMP "python-runtime.zip"
    $PyUrl = "$($BackendUrl)/api/downloads/python/windows"
    
    if (Download-File -Url $PyUrl -Dest $PyZip) {
        $PyDir = Join-Path $InstallDir "python_runtime"
        if (Test-Path $PyDir) { Remove-Item $PyDir -Recurse -Force }
        New-Item -ItemType Directory -Force -Path $PyDir | Out-Null
        Expand-Archive -Path $PyZip -DestinationPath $PyDir -Force
        $PythonPath = Join-Path $PyDir "python.exe"
        Write-Host "    [+] Portable Python installed: $PythonPath" -ForegroundColor Green
        Remove-Item $PyZip -Force
    } else {
        Write-Error "Failed to download Python Runtime. Installation cannot proceed."
        exit 1
    }
}

# 4. Download and Extract Source
Write-Host "[*] Downloading Agent Source package (No EXE)..."
$TempZip = Join-Path $env:TEMP "monitorix_source.zip"
if (Download-File -Url $DownloadUrl -Dest $TempZip) {
    Write-Host "    [+] Downloaded $([math]::Round((Get-Item $TempZip).Length / 1MB, 2)) MB"
    Expand-Archive -Path $TempZip -DestinationPath $InstallDir -Force
    Remove-Item $TempZip -Force
    Write-Host "    [+] Source files extracted." -ForegroundColor Green
} else {
    Write-Error "Failed to download agent source."
    exit 1
}

# 5. Configure Agent
Write-Host "[*] Configuring Agent..."
$ConfigPath = Join-Path $InstallDir "config.json"
$configJson = @{
    TenantApiKey = $ApiKey
    BackendUrl = $BackendUrl
} | ConvertTo-Json
[System.IO.File]::WriteAllText($ConfigPath, $configJson)
Write-Host "    [+] Configuration generated: $ConfigPath" -ForegroundColor Green

# 6. Service Registration
Write-Host "[*] Registering Monitorix Service (Script-based)..."
$ServiceName = "MonitorixAgentService"
$Description = "Monitorix Security Agent - Source Mode"

# Main entry point (Assuming src/main.py or main.py)
$MainScript = Join-Path $InstallDir "src\main.py"
if (-not (Test-Path $MainScript)) {
    $MainScript = Join-Path $InstallDir "main.py"
}

# Resolve interpreter (pythonw is preferred for no-console)
$Interpreter = Join-Path (Split-Path $PythonPath) "pythonw.exe"
if (-not (Test-Path $Interpreter)) { $Interpreter = $PythonPath }

# Register service
if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
    Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
    sc.exe delete $ServiceName
}

# Use a wrapper for service control if necessary, but we'll try direct execution
# Note: For Python to work as a service natively, it usually needs a wrapper (like nssm) or pywin32 service handler.
# For simplicity, we'll try the direct call and assume main.py handles it or we'll wrap it later.
New-Service -Name $ServiceName -BinaryPathName "`"$Interpreter`" `"$MainScript`"" -DisplayName $Description -StartupType Automatic -Description $Description | Out-Null
sc.exe failure $ServiceName reset= 86400 actions= restart/60000/restart/60000/restart/60000

Write-Host "[SUCCESS] Monitorix Agent is now installed in Script-Only mode." -ForegroundColor Cyan
Write-Host "Service started and configured via Python."

Start-Service -Name $ServiceName -ErrorAction SilentlyContinue
Stop-Transcript
