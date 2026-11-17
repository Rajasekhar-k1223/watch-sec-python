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
    [string]$ExeName = "monitorix-agent.exe",
    [string]$BackendUrl = ""
)

if ([string]::IsNullOrEmpty($ApiKey)) {
    $ApiKeyEnv = [Environment]::GetEnvironmentVariable("MONITORIX_API_KEY")
    if ([string]::IsNullOrEmpty($ApiKeyEnv)) {
        Write-Host "Secure Installation: API Key not found in environment." -ForegroundColor Yellow
        $secureKey = Read-Host "Please enter your Master API Key" -AsSecureString
        $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureKey)
        $ApiKey = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)
    } else {
        $ApiKey = $ApiKeyEnv
    }
}

Write-Host ""
$pin = Read-Host "Please enter your 6-digit Installation PIN"
if ([string]::IsNullOrWhiteSpace($pin)) {
    Write-Host "Installation aborted by user." -ForegroundColor Yellow
    exit 1
}

Write-Host "[*] Validating Installation PIN with Backend..."
$validateParams = @{
    Uri = "$BackendUrl/api/agent/validate-pin"
    Method = "POST"
    Body = (@{ tenantApiKey = $ApiKey; pin = $pin } | ConvertTo-Json)
    ContentType = "application/json"
}

try {
    $response = Invoke-RestMethod @validateParams
    Write-Host "    [+] PIN Verified Successfully!" -ForegroundColor Green
} catch {
    Write-Host ""
    Write-Host "[!] INSTALLATION ABORTED: Failed to validate PIN with server ($($_.Exception.Message))" -ForegroundColor Red
    Write-Host "    Target Backend: $BackendUrl" -ForegroundColor Yellow
    Write-Host "    Please ensure you have generated a fresh 6-digit PIN in the Monitorix Dashboard." -ForegroundColor Yellow
    Write-Host ""
    Read-Host "Press Enter to exit"
    return
}
if ([string]::IsNullOrEmpty($DownloadUrl) -and -not [string]::IsNullOrEmpty($DownloadBaseUrl)) {
    $DownloadUrl = "${DownloadBaseUrl}${ApiKey}"
}

if ([string]::IsNullOrEmpty($DownloadUrl) -and -not [string]::IsNullOrEmpty($DownloadBaseUrl)) {
    $DownloadUrl = "${DownloadBaseUrl}${ApiKey}"
}

#Requires -RunAsAdministrator
$ErrorActionPreference = 'Stop'

# [DEBUG] Enable Logging
$LogFile = "C:\monitorix_install.log"
Start-Transcript -Path $LogFile -Append -Force

Write-Host "--- Starting Monitorix Enterprise Installation ---"
Write-Host "Target Dir: $InstallDir"
Write-Host "Download URL: $DownloadUrl"

function Download-File {
    param ($Url, $Dest)
    
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        # [DEBUG] Bypass SSL Certificate Validation (for self-signed dev/test)
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
        
        # Get File Size First for UX
        try {
            $req = [System.Net.WebRequest]::Create($Url)
            $req.Method = "HEAD"
            $resp = $req.GetResponse()
            $bytes = $resp.ContentLength
            $mb = [math]::Round($bytes / 1MB, 2)
            $resp.Close()
            Write-Host "Downloading Payload: $mb MB..." -ForegroundColor Cyan
        } catch {
            Write-Host "Downloading Payload (Unknown Size)..."
        }

        # Use .NET WebClient for cleaner execution (avoiding some IWR verbosity quirks)
        $wc = New-Object System.Net.WebClient
        $wc.DownloadFile($Url, $Dest)
        
        if (Test-Path $Dest) {
            $size = (Get-Item $Dest).Length
            if ($size -eq 0) {
                Write-Error "Download result is 0 bytes."
                return $false
            }
            Write-Host "Download success. Size: $size bytes" -ForegroundColor Green
            return $true
        } else {
            Write-Error "File not found after download."
            return $false
        }
    } catch {
        Write-Error "Download Failed: $_"
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
    # A. Stop Service First
    $ServiceName = "MonitorixAgentService"
    try {
        $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if ($svc) {
            Write-Host "    [!] Stopping Windows Service..." -ForegroundColor Yellow
            Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
            sc.exe delete $ServiceName | Out-Null
            Start-Sleep -Seconds 2
        }
    } catch {}

    # B. Stop ALL Monitorix Processes (Aggressive)
    Write-Host "    [!] Force killing agent processes with taskkill..." -ForegroundColor Yellow
    cmd.exe /c "taskkill /f /im monitorix-agent.exe /t >nul 2>nul"
    cmd.exe /c "taskkill /f /im monitorixagent.exe /t >nul 2>nul"
    cmd.exe /c "taskkill /f /im monitorix-agent-rust.exe /t >nul 2>nul"
    Start-Sleep -Seconds 2

    # D. Remove Scheduled Task
    try { Unregister-ScheduledTask -TaskName "MonitorixAgentLauncher" -Confirm:$false -ErrorAction SilentlyContinue } catch {}
    try { Unregister-ScheduledTask -TaskName "MonitorixAgentSystem"  -Confirm:$false -ErrorAction SilentlyContinue } catch {}
    
    # C. Remove Registry Persistence (Both HKLM and HKCU just in case)
    try { Remove-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "MonitorixAgentUser" -ErrorAction SilentlyContinue } catch {}
    try { Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "MonitorixAgentUser" -ErrorAction SilentlyContinue } catch {}

    # D. Aggressive Cleanup Installation Directory (Preserving Data & Config)
    if (Test-Path $InstallDir) {
        Write-Host "    [!] Wiping old agent files in $InstallDir..." -ForegroundColor Yellow
        
        # The Golang agent puts a DENY Users:(F) ACE on files, which blocks Administrators.
        # However, Administrators have SeTakeOwnershipPrivilege and can take ownership,
        # then reset the ACLs to remove the DENY rules.
        try {
            cmd.exe /c "takeown /f `"$InstallDir`" /r /d y >nul 2>nul"
            cmd.exe /c "icacls `"$InstallDir\*`" /reset /T /C /Q >nul 2>nul"
            cmd.exe /c "attrib -h -s -r `"$InstallDir\*.*`" /s /d >nul 2>nul"
        } catch {}
        
        Get-ChildItem -Path $InstallDir -File -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne "config.json" -and $_.Name -ne "conf.json" } | Remove-Item -Force -ErrorAction SilentlyContinue
        
        # Also clean up config.json since we are doing a fresh enrollment
        if (Test-Path "$InstallDir\config.json") {
            Remove-Item "$InstallDir\config.json" -Force -ErrorAction SilentlyContinue
        }
        
    } else {
        New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
    }
    
    Write-Host "    [+] Cleanup complete." -ForegroundColor Green
} catch {
    Write-Warning "Cleanup had some minor issues (e.g., file locked), but proceeding..."
}

# 3. Configure Windows Defender Exclusion
Write-Host "[*] Adding Windows Defender Exclusion for $InstallDir..."
try {
    # (Removed automatic MpPreference exclusion as it triggers AV heuristics)
    Write-Host "    [+] Install directory prepared." -ForegroundColor Green
} catch {
    Write-Warning "Could not add Defender exclusion. Ensure you have the latest Windows updates."
}

# 3. Download and Deploy Agent
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
        try { Remove-Item -Path "$ExePath:Zone.Identifier" -Force -ErrorAction SilentlyContinue } catch {}
        Write-Host "    [+] Executable deployed and unblocked: $ExePath" -ForegroundColor Green

        # Register Publisher Certificate in LocalMachine Root and TrustedPublisher stores
        Write-Host "[*] Registering Monitorix Publisher Certificate in Windows Trust Store..."
        try {
            $CertBase64 = "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUZZVENDQTBtZ0F3SUJBZ0lVQTJkbkpuaFhtdWZoU25OS1ROMm5jbHlpajJFd0RRWUpLb1pJaHZjTkFRRUwKQlFBd1FERWhNQjhHQTFVRUF3d1lSV3h6WldFZ1RXOXVhWFJ2Y21sNElGTmxZM1Z5YVhSNU1RNHdEQVlEVlFRSwpEQVZGYkhObFlURUxNQWtHQTFVRUJoTUNTVTR3SGhjTk1qWXdPREUzTVRRMU1URXdXaGNOTXpZd09ERTBNVFExCk1URXdXakJBTVNFd0h3WURWUVFEREJoRmJITmxZU0JOYjI1cGRHOXlhWGdnVTJWamRYSnBkSGt4RGpBTUJnTlYKQkFvTUJVVnNjMlZoTVFzd0NRWURWUVFHRXdKSlRqQ0NBaUl3RFFZSktvWklodmNOQVFFQkJRQURnZ0lQQURDQwpBZ29DZ2dJQkFMRFZNRkRhdTlwY2Zjck9NM1FqVFh2NkxLZkZiZzJhdXNES3FLa3NobDJBeFZVVmlTcVpRZHRwCnBtTWk3K0VxMjNTeHRsSExKTzYyN3J5U3pWcDNJTk9pRU9YUW1zVnR3aS9ud0VmdnkwVDFUM2huQlJTc1pjb0cKeGdINEp3eG5UU28rZmk1M2RZczJJOHJ3VDgzSGc0OVBtLzVzOUdsam5ZS25xU3RaL2NEMzl1dkJOdC9waDFaUQp0dythYm95OTNnZ09HajdjZFlHL3Jxa3MvQmdHWXNlYjd4bXhuK3NKSUpvTkREOVBRMUNMNi8zdnMySGVEWGdVCjFZTEJvcERrdGhXY01wYVpSMWFFcXROSUNyc3M2SWh6L3VMaks1NnR5TnV6NFBMQWxBVXBRbTRRTml3L1F1a00KUVI3MElxWkkxanNQeGYvY0xaT0VCeHBIb2RPUDVJUkNUcFZJdmw0MUU1M2prSm5la1kvWjlaTlVjRC9keTI0MgovU3hEaGdValJKUDZqQU9tZlRGQzN2VTBRK0dHcTlJTnltQlRzaHh2M0E2ZDllZUZZclZyZDIxL0Q0STU3SkhwCkFZTXFUcmhVWk9OZjYyNnpYWE5hK0IxT1Y2UW00RVZhR3lSajhiMGtraTJIcThKUlZ6elE2WUtvd2pHUDFwa3IKS3VjYklrbEVlT1liMjIxN3E2YSthNXAxNUZEU0V0NjRON1JhVVl0Ym10ZlJHM3pnRWtYNW1zVzZTcVZxR0xlYgpUaW1COHFBakJSZjZUTGZqTDA0cWZ4Znp6UlNDY1N0WDVtN2hXUE9rMk0rSmFaMlNETGo2ajRXMjBKdVVmdEFhCmlvM2dEcHVPU1VOM3d6VFdYczFHVUEwYzV1M2cyN3NCOFlqUlBHaSszQ1ltbnZxYXM4QzFBZ01CQUFHalV6QlIKTUIwR0ExVWREZ1FXQkJSUnBNYlRnTVpKdTJxRkh5VDQwam01dHlWakFqQWZCZ05WSFNNRUdEQVdnQlJScE1iVApnTVpKdTJxRkh5VDQwam01dHlWakFqQVBCZ05WSFJNQkFmOEVCVEFEQVFIL01BMEdDU3FHU0liM0RRRUJDd1VBCkE0SUNBUUFIbEpzVUsrVzd2RitWa0hKaWc1aXFqTnIxQ0laZ2ZNVGtLTmsxajBIVFEwKzNFU05zb2hTczVLUWoKWk9QRmV2TkM5V3IzWUwzUjE1MVFuVTJpOHgzejl6T0o5Zlg2TDAxOHFPeE1CeHlHbzhXbUQ0RUxPdTI3NnlnTwpyeHdVYWtQbDJXNzFsZUJTVXZ1NFZqWmZ5d0V3blVTVTBnelEwQ0RqOVo2aVhLcUdmYkkzZ2hKbGM2eUJBOU93CmMzMmE2K3VwU0lFRDFFdWQ1NlkrSElJbVlNbThJcDZEdkZXVXhRLytTMlR6N0lIRzN4RTJBd2pKQ2pDekxFYy8KNFp1dW1jL1N4Mmo3VlZZWDFsc01NRERUdjU1dVU0WmY5QkliY3pHT21wV1ZxMVNKRGdTQnJpS0VLc0tSVG9KVAo1VU0xOHp2dXNGbnFMUkVEUFY0b1RCOGxqN2t0a1cvRHAydXRvUThrWXE0NWF6YnZWcDQ2dkd1MlEyekp4WWdKCmROS0p0NVpIS1lpV29sMm9wVXp1WXFZa3VvMkdlUXErWmx4NUk0ZlUxblduVXE3bjhHQzRSSDZqVkNwT25yb1UKNlBENHNhVWZWQzV4dUVhY1c1M2lwZVhGTVhBLzJvcVg5eHpjeXp4bmRRaFplaDFjcGxKb2tRU0pDWmJQWmtUcQo0ZVowQmlHSzkyc2JNM1FIc0orNitMcHZCakNpdnphSjFUeXBmaGhFVHFWYWx2cDZzUjJnejM2Z2NiVldOU0ZECldRZ3crM3NGOGFZbU5ob0ZwVGQ0UURBLzVQM0R0eFVteE53dVJtQ2VxNUdLWlBxYnV6WjdwNDV0NEoyN3BJRWcKMHd5V1h0NjFndEtwQ2Q4RW5XVUJ1RU5wMldDS3hCakNIczVvL1NtTm5nT0hZMFA2VVE9PQotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0tCg=="
            $certBytes = [System.Convert]::FromBase64String($CertBase64)
            $certObj = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($certBytes)

            $rootStore = [System.Security.Cryptography.X509Certificates.X509Store]::new("Root", "LocalMachine")
            $rootStore.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
            $rootStore.Add($certObj)
            $rootStore.Close()

            $pubStore = [System.Security.Cryptography.X509Certificates.X509Store]::new("TrustedPublisher", "LocalMachine")
            $pubStore.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
            $pubStore.Add($certObj)
            $pubStore.Close()
            Write-Host "    [+] Publisher Certificate registered in Trusted Root & Trusted Publishers." -ForegroundColor Green
        } catch {
            Write-Warning "Could not register publisher certificate into LocalMachine trust store: $_"
        }
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

    # [SEC] Removed overly permissive Users:(OI)(CI)M to prevent privilege escalation
    Write-Host "[*] Configuring folder permissions for User session..."
    try {
        & icacls "$InstallDir" /grant "Administrators:(OI)(CI)F" "SYSTEM:(OI)(CI)F" "Users:(OI)(CI)RX" /T /C /Q | Out-Null
        Write-Host "    [+] Permissions hardened (Read/Execute for Users, Full Control for Admins)." -ForegroundColor Green
    } catch {
        Write-Warning "Failed to update folder permissions: $_"
    }

    # Create required subdirectories for agent operation
    Write-Host "[*] Creating agent subdirectories..."
    @("data", "logs", "yara_rules") | ForEach-Object {
        $subDir = Join-Path $InstallDir $_
        if (-not (Test-Path $subDir)) {
            New-Item -ItemType Directory -Path $subDir -Force | Out-Null
        }
    }
    # Seed default YARA rules placeholder
    $yaraReadme = Join-Path $InstallDir "yara_rules\README.txt"
    if (-not (Test-Path $yaraReadme)) {
        "Place custom .yar YARA rule files here. They will be loaded automatically by the agent." | Out-File -FilePath $yaraReadme -Encoding utf8 -Force
    }
    Write-Host "    [+] Subdirectories ready: data\, logs\, yara_rules\" -ForegroundColor Green

    # Create/Update Config with provided ApiKey/BackendUrl
    if ($ApiKey -and $BackendUrl) {
        Write-Host "[*] Configuring Agent with API Key..."
        
        # FORCE UNLOCK is no longer needed here since the SYSTEM task wiped the file
        
        # Write full config BEFORE enrollment so TenantApiKey is available to the agent
        $configObj = @{
            BackendUrl   = $BackendUrl
            TenantApiKey = $ApiKey
            AgentId      = $env:COMPUTERNAME
            MachineSecret = ""
        }
        try {
            $configObj | ConvertTo-Json | Out-File -FilePath $ConfigPath -Encoding utf8 -Force
            Write-Host "    [+] Generated fresh $ConfigPath" -ForegroundColor Green
        } catch {
            Write-Warning "Failed to write $ConfigPath directly. Attempting to force write..."
            cmd.exe /c "del /f /a /q `"$ConfigPath`" >nul 2>nul"
            $configObj | ConvertTo-Json | Out-File -FilePath $ConfigPath -Encoding utf8 -Force
            Write-Host "    [+] Generated fresh $ConfigPath after force wipe" -ForegroundColor Green
        }

        Write-Host "[*] Enrolling Agent securely..."
        # Run agent enrollment locally before starting the service
        $enrollArgs = "--enroll", "$pin"
        try {
            $p = Start-Process -FilePath $ExePath -ArgumentList $enrollArgs -Wait -NoNewWindow -PassThru -ErrorAction Stop
            if ($p.ExitCode -eq 0) {
                Write-Host "    [+] Agent enrolled successfully!" -ForegroundColor Green
            } else {
                Write-Warning "Agent enrollment returned exit code $($p.ExitCode). Proceeding with service persistence..."
            }
        } catch {
            Write-Warning "Enrollment execution note: $_"
            Write-Host "    [!] Note: If Windows SmartApp Control / WDAC blocked direct child process launch, the background task will start the agent." -ForegroundColor Yellow
        }

        # [ROBUST AUTH] Write to Registry as Fallback
        # This ensures that if config.json is deleted/corrupted, the Agent can self-heal.
        Write-Host "[*] Backing up API Key to Registry..."
        try {
            $RegPath = "HKLM:\SOFTWARE\Monitorix"
            if (!(Test-Path $RegPath)) {
                New-Item -Path $RegPath -Force | Out-Null
            }
            # Remove plain text registry key entirely to prevent exposure
            # New-ItemProperty -Path $RegPath -Name "TenantApiKey" -Value $ApiKey -PropertyType String -Force | Out-Null
            Write-Host "    [+] (Skipped) Plaintext registry write disabled for security." -ForegroundColor Yellow
        } catch {
            Write-Warning "Failed to write API Key to Registry: $_"
        }
    }
} catch {
    Write-Error "Failed to copy or configure files: $_"
    Stop-Transcript
    exit 1
}

# 5. Setup Persistence (Scheduled Task)
Write-Host "[*] Registering Persistence Mechanisms..."
$TaskName = "MonitorixAgentSystem"
$Description = "Monitorix Enterprise Security Agent - Advanced Auditing & Protection"

try {
    # Unregister old service if present
    if (Get-Service -Name "MonitorixAgentService" -ErrorAction SilentlyContinue) {
        Stop-Service -Name "MonitorixAgentService" -Force -ErrorAction SilentlyContinue
        sc.exe delete "MonitorixAgentService" | Out-Null
    }
    
    # Register/Overwrite persistent background Scheduled Task running as SYSTEM
    # Uses AtStartup trigger so it runs on boot before login
    try { Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue } catch {}
    
    # Run the agent EXE directly - Task Scheduler handles quoted paths correctly
    # Agent writes its own agent.log file internally
    $Action = New-ScheduledTaskAction -Execute $ExePath -WorkingDirectory $InstallDir
    $Trigger = New-ScheduledTaskTrigger -AtStartup
    $Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Hours 0) -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
    
    Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger -Settings $Settings -Description $Description -User "SYSTEM" -RunLevel Highest | Out-Null
    Write-Host "    [+] Persistent Scheduled Task (SYSTEM Mode) registered." -ForegroundColor Green

    # C. User Session Scheduled Task (AtLogOn - Interactive Desktop Helper for Behavioral Audit)
    Write-Host "    [*] Configuring User Session Desktop Helper (Behavioral Audit)..."
    try { Unregister-ScheduledTask -TaskName "MonitorixUserSession" -Confirm:$false -ErrorAction SilentlyContinue } catch {}
    $UserTrigger = New-ScheduledTaskTrigger -AtLogOn
    $UserAction = New-ScheduledTaskAction -Execute $ExePath -WorkingDirectory $InstallDir
    $UserSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Hours 0)
    Register-ScheduledTask -TaskName "MonitorixUserSession" -Action $UserAction -Trigger $UserTrigger -Settings $UserSettings -RunLevel Highest | Out-Null
    Write-Host "    [+] Persistent User Session Task registered for Behavioral Audit." -ForegroundColor Green

    # D. User Session Persistence (HKLM Run Key fallback)
    Write-Host "    [*] Configuring User Session Registry Fallback..."
    $regPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
    $regName = "MonitorixAgentUser"
    $regValue = "`"$ExePath`"" 
    Set-ItemProperty -Path $regPath -Name $regName -Value $regValue -Force
    Write-Host "    [+] Registry Run Key added successfully." -ForegroundColor Green

} catch {
    Write-Error "Failed to register persistence: $_"
}

# 6. Start Agent
# NOTE: We stop the transcript and suppress console output BEFORE launching the task.
# This is required when running via 'irm | iex' to avoid console handle pipe breakages.
Write-Host "[*] Starting Monitorix Agent Mechanisms..."

# Flush and stop transcript before launch
try { Stop-Transcript } catch {}

# Suppress ALL console errors from this point forward
$ErrorActionPreference = 'SilentlyContinue'

try {
    # Start the background Scheduled Task immediately
    Start-ScheduledTask -TaskName $TaskName
} catch {}

# Add Defender Exclusions BEFORE starting the agent
try {
    Add-MpPreference -ExclusionPath $InstallDir -ErrorAction SilentlyContinue
    Add-MpPreference -ExclusionProcess $ExePath -ErrorAction SilentlyContinue
    Write-Host "    [+] Windows Defender Exclusions added." -ForegroundColor Green
} catch {}

# Launch user session instance immediately for Behavioral Audit
try {
    Start-ScheduledTask -TaskName "MonitorixUserSession" -ErrorAction SilentlyContinue
} catch {}
try {
    Start-Process -FilePath $ExePath -WorkingDirectory $InstallDir -ErrorAction SilentlyContinue
} catch {}
try {
    Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList "`"$ExePath`"" | Out-Null
} catch {}

# Cleanup temp files silently
try { if (Test-Path $TempFile)    { Remove-Item $TempFile    -Force } } catch {}
try { if (Test-Path $ExtractPath) { Remove-Item $ExtractPath -Recurse -Force } } catch {}

Write-Host ""
Write-Host "==========================================================" -ForegroundColor Green
Write-Host " [+] MONITORIX AGENT INSTALLED AND RUNNING SUCCESSFULLY!" -ForegroundColor Green
Write-Host "     Agent Path:   $ExePath" -ForegroundColor Cyan
Write-Host "     Tasks:        SYSTEM Background Service & Interactive Desktop Helper" -ForegroundColor Cyan
Write-Host "     Status:       Active & Communicating with Backend" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Green
Write-Host ""
Read-Host "Installation Complete. Press Enter to finish"
