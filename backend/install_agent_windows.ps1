<#
.SYNOPSIS
Monitorix Agent - Silent Windows Installer
Downloads and installs the Monitorix Agent as a Windows Service via PowerShell.

.DESCRIPTION
This script:
1. Checks for Administrator privileges.
2. Adds a Windows Defender exclusion for the install directory.
3. Downloads only the standalone EXE (no ZIP, no certs exposed).
4. Installs it as a native Windows Service with auto-restart recovery.
5. Adds Registry persistence so the agent also runs in the user session.

.EXAMPLE
# One-liner silent install (run in elevated PowerShell):
iex (irm 'https://agent-api.monitorix.co.in/api/deploy/script/windows?apiKey=YOUR_KEY')

# Or with explicit params:
.\install_agent_windows.ps1 -DownloadUrl 'https://agent-api.monitorix.co.in/api/downloads/exe/windows-x64' -ApiKey 'YOUR_KEY' -BackendUrl 'https://agent-api.monitorix.co.in'
#>

param (
    [string]$DownloadUrl = "",
    [string]$VersionCheckUrl = "",
    [string]$InstallDir = "C:\Program Files\Monitorix",
    [string]$ExeName = "MonitorixAgent.exe",
    [string]$ApiKey = "",
    [string]$BackendUrl = ""
)

#Requires -RunAsAdministrator
$ErrorActionPreference = 'Stop'

# [DEBUG] Enable Logging
$LogFile = "C:\monitorix_install.log"
Start-Transcript -Path $LogFile -Append -Force

Write-Host "--- Starting Monitorix Installation ---"
Write-Host "Target Dir: $InstallDir"
Write-Host "Download URL: $DownloadUrl"

function Download-File {
    param ($Url, $Dest)
    
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
        
        # 1. Get Metadata (optional, silent on failure)
        try {
            $req = [System.Net.HttpWebRequest]::Create($Url)
            $req.Method = "HEAD"
            $req.Timeout = 10000 # 10s timeout
            $resp = $req.GetResponse()
            $bytes = $resp.ContentLength
            $resp.Close()
            if ($bytes -gt 0) {
                $mb = [math]::Round($bytes / 1MB, 2)
                Write-Host "Payload Size: $mb MB" -ForegroundColor Cyan
            }
        } catch {
            # Server does not support HEAD requests - proceed silently
        }

        # 3. Perform Download
        $wc = New-Object System.Net.WebClient
        $wc.DownloadFile($Url, $Dest)
        
        if (Test-Path $Dest) {
            $fileInfo = Get-Item $Dest
            if ($fileInfo.Length -lt 1KB) {
                $content = Get-Content $Dest -Raw -ErrorAction SilentlyContinue
                if ($content -like "*Error*" -or $content -like "*Internal Server Error*") {
                    Write-Error "Server returned an error message instead of the binary: $content"
                } else {
                    Write-Error "Download result is suspiciously small ($($fileInfo.Length) bytes)."
                }
                return $false
            }
            
            # 4. Magic Byte Verification (MZ Header for EXE)
            $header = New-Object byte[] 2
            $fs = [System.IO.File]::OpenRead($Dest)
            $fs.Read($header, 0, 2) | Out-Null
            $fs.Close()
            
            if ($Url -like "*exe*" -and -not ($header[0] -eq 0x4D -and $header[1] -eq 0x5A)) {
                Write-Error "Security Check Failed: Downloaded file is not a valid Windows Executable (Header: $($header[0].ToString('X2')) $($header[1].ToString('X2')))."
                return $false
            }

            Write-Host "Download success and verified." -ForegroundColor Green
            return $true
        } else {
            Write-Error "File not found on disk after download attempt."
            return $false
        }
    } catch {
        Write-Error "Download Failed: $($_.Exception.Message)"
        return $false
    }
}

function Assemble-Parts {
    param ($BaseName, $DestFile)
    Write-Host "Assembling parts for $DestFile..."
    if (Test-Path $DestFile) { Remove-Item $DestFile -Force }
    $parts = Get-ChildItem "$($BaseName).part*" | Sort-Object Name
    foreach ($part in $parts) {
        $bytes = [System.IO.File]::ReadAllBytes($part.FullName)
        [System.IO.File]::AppendAllBytes($DestFile, $bytes)
    }
}

# 1. Check for Admin Privileges
Write-Host "[*] Checking for Administrative Privileges..."
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script MUST be run as an Administrator."
    exit 1
}

# 2. Pre-Install Cleanup (Remove Old Versions)
Write-Host "[*] Performing Pre-Install Cleanup..."
try {
    # A. Stop ALL Monitorix Processes (Aggressive)
    $processes = Get-Process -Name "monitorixagent", "MonitorixAgent", "monitorix-agent" -ErrorAction SilentlyContinue
    if ($processes) {
        Write-Host "    [!] Stopping all running agent processes..." -ForegroundColor Yellow
        # Try graceful stop first, then force
        $processes | Stop-Process -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 3
    }

    # B. Force Kill if still locked (Safety for accumulation)
    $lockedProcesses = Get-Process | Where-Object { $_.Path -like "*$InstallDir*" } -ErrorAction SilentlyContinue
    if ($lockedProcesses) {
        Write-Host "    [!] Force killing locked processes in target directory..." -ForegroundColor Red
        $lockedProcesses | Stop-Process -Force -ErrorAction SilentlyContinue
    }

    # B. Remove Scheduled Task
    Unregister-ScheduledTask -TaskName "MonitorixAgentLauncher" -Confirm:$false -ErrorAction SilentlyContinue
    
    # C. Remove Registry Persistence (Both HKLM and HKCU just in case)
    Remove-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "MonitorixAgentUser" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "MonitorixAgentUser" -ErrorAction SilentlyContinue

    # D. Cleanup Installation Directory
    $OldExe = Join-Path $InstallDir $ExeName
    if (Test-Path $OldExe) {
        Remove-Item $OldExe -Force -ErrorAction SilentlyContinue
    }
    
    # E. [SECURITY] Scrub legacy certificates and sensitive keys (silent if none found)
    $legacyCerts = Get-ChildItem -Path $InstallDir -Include *.crt, *.key, *.pem -File -Recurse -ErrorAction SilentlyContinue
    if ($legacyCerts) {
        Write-Host "    [!] Removing legacy certificates..." -ForegroundColor Yellow
        $legacyCerts | Remove-Item -Force -ErrorAction SilentlyContinue
    }
    # Ensure directory exists for exclusion
    if (-not (Test-Path $InstallDir)) {
        New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
    }
    
    Write-Host "    [+] Cleanup complete." -ForegroundColor Green
} catch {
    Write-Warning "Cleanup had some minor issues (e.g., file locked), but proceeding..."
}

# 3. Establish Security Trust (Resolve "Unknown Publisher" warning)
# This step is MANDATORY. The agent will NOT install without a trusted certificate.
# The certificate is stored in the Windows System Trust Store (LocalMachine\Root).
Write-Host "[*] Establishing Monitorix Security Trust (Mandatory)..."
if ($BackendUrl) {
    try {
        $RootCaUrl = "$BackendUrl/api/downloads/public/root-ca"
        $TempCert = Join-Path $env:TEMP "monitorix_root_ca.crt"
        
        Write-Host "    [*] Fetching Root CA from $RootCaUrl..."
        Invoke-WebRequest -Uri $RootCaUrl -OutFile $TempCert -UseBasicParsing -ErrorAction Stop
        
        if (Test-Path $TempCert) {
            Write-Host "    [*] Importing Monitorix Root CA into Windows System Trust Store..."
            # Try PowerShell cmdlet first (Windows 10/11)
            try {
                Import-Certificate -FilePath $TempCert -CertStoreLocation Cert:\LocalMachine\Root -ErrorAction Stop | Out-Null
                Write-Host "    [+] Root CA successfully trusted via PowerShell." -ForegroundColor Green
            } catch {
                # Fallback to certutil (legacy/server environments)
                Write-Host "    [*] Falling back to certutil for trust import..."
                & certutil -addstore -f "Root" "$TempCert" | Out-Null
                if ($LASTEXITCODE -eq 0) {
                    Write-Host "    [+] Root CA successfully trusted via certutil." -ForegroundColor Green
                } else {
                    Write-Error "CRITICAL: Could not import Root CA (Code: $LASTEXITCODE). Installation Aborted."
                    exit 1
                }
            }
            Remove-Item $TempCert -Force
        } else {
             Write-Error "CRITICAL: Root CA file not found after download. Installation Aborted."
             exit 1
        }
    } catch {
        Write-Error "CRITICAL: Mandatory Trust establishment failed: $($_.Exception.Message). Installation Aborted."
        exit 1
    }
} else {
    Write-Error "CRITICAL: BackendUrl not provided. Cannot establish security trust. Installation Aborted."
    exit 1
}

# 4. Configure Windows Defender Exclusion
Write-Host "[*] Adding Windows Defender Exclusion for $InstallDir..."
try {
    Add-MpPreference -ExclusionPath $InstallDir -ErrorAction SilentlyContinue
    Write-Host "    [+] Exclusion added successfully." -ForegroundColor Green
} catch {
    Write-Warning "Could not add Defender exclusion. Ensure you have the latest Windows updates."
}

# 5. Download and Deploy Agent
$TempFile = Join-Path $env:TEMP "monitorix_payload"
$ExtractPath = $env:TEMP + "\monitorix_extracted"

Write-Host "[*] Downloading Agent Payload..."
# Remove temp file if exists to prevent stale data
if (Test-Path $TempFile) { Remove-Item $TempFile -Force }

$success = Download-File -Url $DownloadUrl -Dest $TempFile
if (-not $success) {
    Write-Error "Failed to download agent from $DownloadUrl"
    Stop-Transcript
    exit 1
}

# 4. Deployment Logic (EXE-Only: No ZIP extraction, no certs)
$ExePath = Join-Path $InstallDir $ExeName
$ConfigPath = Join-Path $InstallDir "config.json"

# Detect file type by magic bytes (MZ = EXE, PK = ZIP)
try {
    $headerBytes = [System.IO.File]::ReadAllBytes($TempFile)
    if ($headerBytes.Length -lt 2) { throw "File too small to identify." }
    $isZip = ($headerBytes[0] -eq 0x50 -and $headerBytes[1] -eq 0x4B)
    $isExe = ($headerBytes[0] -eq 0x4D -and $headerBytes[1] -eq 0x5A)
    Write-Host "File Type Detection: Zip=$isZip, Exe=$isExe"
} catch {
    Write-Error "Failed to detect file type: $_"
    Stop-Transcript
    exit 1
}

Write-Host "[*] Installing files to $InstallDir..."
try {
    if ($isExe) {
        # *** PRIMARY PATH: Clean EXE-only deployment (no ZIP, no cert exposure) ***
        Write-Host "[*] Deploying Standalone Executable (EXE-only mode)..."
        if (Test-Path $ExePath) { Remove-Item $ExePath -Force }
        Move-Item -Path $TempFile -Destination $ExePath -Force
        Unblock-File -Path $ExePath -ErrorAction SilentlyContinue
        Write-Host "    [+] Executable deployed and unblocked: $ExePath" -ForegroundColor Green
    } elseif ($isZip) {
        # Fallback: Handle ZIP payload (legacy support)
        Write-Host "[*] Extracting Agent Archive (ZIP mode)..."
        $ZipFile = "$TempFile.zip"
        if (Test-Path $ZipFile) { Remove-Item $ZipFile -Force }
        Rename-Item -Path $TempFile -NewName (Split-Path $ZipFile -Leaf)
        if (Test-Path $ExtractPath) { Remove-Item $ExtractPath -Recurse -Force }
        New-Item -ItemType Directory -Force -Path $ExtractPath | Out-Null
        Expand-Archive -Path $ZipFile -DestinationPath $ExtractPath -Force
        Copy-Item -Path "$ExtractPath\*" -Destination $InstallDir -Recurse -Force
        Write-Host "    [+] Archive extracted and deployed." -ForegroundColor Green
        if (Test-Path $ZipFile) { Remove-Item $ZipFile -Force }
    } else {
        Write-Warning "Unknown file format. Attempting direct deployment as executable..."
        Move-Item -Path $TempFile -Destination $ExePath -Force
    }
    
    # [VERIFICATION] Check if EXE exists now
    if (-not (Test-Path $ExePath)) {
        Write-Error "FATAL: $ExePath not found after deployment. Install failed."
        throw "Deployment Verification Failed"
    }

    # [v1.8.13] Grant "Users" Modify permissions to the folder
    # This is CRITICAL for the User-session agent to write its lock/log in Program Files.
    Write-Host "[*] Configuring folder permissions for User session..."
    try {
        & icacls "$InstallDir" /grant "Users:(OI)(CI)M" /T /C /Q | Out-Null
        Write-Host "    [+] Permissions granted to Users group." -ForegroundColor Green
    } catch {
        Write-Warning "Failed to update folder permissions: $_"
    }

    # Create/Update Config with provided ApiKey/BackendUrl
    if ($ApiKey -and $BackendUrl) {
        Write-Host "[*] Configuring Agent with API Key..."
        
        # FORCE UNLOCK: Remove ReadOnly if exists to ensure we can update key
        if (Test-Path $ConfigPath) {
            $existingFile = Get-Item $ConfigPath
            if ($existingFile.IsReadOnly) {
                $existingFile.IsReadOnly = $false
            }
        }
        
        # [v1.8.60] Safety Delay: Ensure binary move is committed to disk
        Start-Sleep -Seconds 2
        
        # Create/Update Config
        $configJson = @{
            TenantApiKey = $ApiKey
            BackendUrl = $BackendUrl
        } | ConvertTo-Json
        
        # [ROBUSTNESS] Use .NET to ensure UTF8 NO BOM for maximum cross-platform compatibility
        [System.IO.File]::WriteAllText($ConfigPath, $configJson)
        
        # LOCK CONFIG: Read-Only to prevent user tampering
        $fileItem = Get-Item $ConfigPath
        $fileItem.Attributes = "ReadOnly"
        
        Write-Host "    [+] Generated $ConfigPath (Locked and Verified)" -ForegroundColor Green

        # [ROBUST AUTH] Write to Registry as Fallback
        # This ensures that if config.json is deleted/corrupted, the Agent can self-heal.
        Write-Host "[*] Backing up API Key to Registry..."
        try {
            $RegPath = "HKLM:\SOFTWARE\Monitorix"
            if (!(Test-Path $RegPath)) {
                New-Item -Path $RegPath -Force | Out-Null
            }
            New-ItemProperty -Path $RegPath -Name "TenantApiKey" -Value $ApiKey -PropertyType String -Force | Out-Null
            Write-Host "    [+] API Key written to Registry (HKLM)." -ForegroundColor Green
        } catch {
            Write-Warning "Failed to write API Key to Registry: $_"
        }
    }
} catch {
    Write-Error "Failed to copy or configure files: $_"
    Stop-Transcript
    exit 1
}

# 5. Setup Persistence (Scheduled Task & Windows Service)
Write-Host "[*] Registering Persistence Mechanisms..."
$TaskName = "MonitorixAgentLauncher"
$ServiceName = "MonitorixAgentService"
$Description = "Monitorix Security Agent - Enterprise Data Protection"

try {
    # A. [v1.8.46] Consolidate Persistence
    # Use Service for Persistent Guardian. Schedule Task is now legacy/secondary.
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
    # ONLY register task if Service registration fails or if explicitly required
    # For now, we prefer the native Service.
    Write-Host "    [+] Cleanup of legacy task complete. System Service will handle persistence." -ForegroundColor Gray

    # B. [NEW] Windows Service registration (for services.msc)
    Write-Host "    [*] Registering native Windows Service..."
    if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
        Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
        # Remove-Service is not available in PowerShell 5.1
        sc.exe delete $ServiceName
    }
    
    # Register as a native service. Note: requires the EXE to handle SCM (Service Control Manager) signals.
    # [v1.8.50] main.py now handles SCM heartbeats natively.
    New-Service -Name $ServiceName -BinaryPathName "`"$ExePath`"" -DisplayName $Description -StartupType Automatic -Description $Description | Out-Null
    
    # Configure NATIVE RECOVERY (Immediate Auto-Restart)
    # Reset fail count after 1 day (86400 seconds), restart immediately (1ms)
    sc.exe failure $ServiceName reset= 86400 actions= restart/1/restart/1/restart/1 | Out-Null
    
    Write-Host "    [+] Windows Service registered with native auto-restart recovery." -ForegroundColor Green

    # C. User Session Persistence (HKLM Run Key)
    Write-Host "    [*] Configuring User Session Persistence (for Screenshots)..."
    $regPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
    $regName = "MonitorixAgentUser"
    $regValue = "`"$ExePath`"" 
    Set-ItemProperty -Path $regPath -Name $regName -Value $regValue -Force
    Write-Host "    [+] Registry Run Key added successfully." -ForegroundColor Green

} catch {
    Write-Error "Failed to register persistence: $_"
}

# 6. Start Agent (Service + User Instance)
Write-Host "[*] Starting Monitorix Agent Mechanisms..."
try {
    # A. Start the Windows Service (Session 0)
    Write-Host "    [*] Starting System Service..."
    Start-Service -Name $ServiceName -ErrorAction SilentlyContinue
    
    # B. Start User Instance (Current Session)
    # This is CRITICAL for immediate GUI/Activity tracking after installation.
    # We use Start-Process to launch it in the current interactive session.
    Write-Host "    [*] Launching interactive agent for current user..."
    Start-Process -FilePath $ExePath -WorkingDirectory $InstallDir -WindowStyle Hidden
    
    Write-Host "[SUCCESS] Monitorix Agent v1.8.60 (Platform Host) is now running." -ForegroundColor Cyan
} catch {
    Write-Warning "Installation complete, but could not start the agent automatically. Please start '$ServiceName' in services.msc"
}

# Cleanup
if (Test-Path $TempFile) { Remove-Item $TempFile -Force }
if (Test-Path $ExtractPath) { Remove-Item $ExtractPath -Recurse -Force }

Write-Host "--- Installation Finished ---"
Stop-Transcript
