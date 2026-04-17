!include "MUI2.nsh"
!include "LogicLib.nsh"
!include "FileFunc.nsh"

Name "Monitorix Enterprise Agent"
OutFile "monitorix-setup-v3.exe"
RequestExecutionLevel admin
InstallDir "$PROGRAMFILES64\Monitorix"

!define MUI_ABORTWARNING
!define MUI_ICON "monitorix.ico"

!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH
!insertmacro MUI_LANGUAGE "English"

Var /GLOBAL ApiKey
Var /GLOBAL InstallerFilename

SECTION "Install"
    SetOutPath "$INSTDIR"
    
    ; 1. Get Filename to extract Key (for Cloud/Online modes)
    System::Call 'kernel32::GetModuleFileName(p 0, t .r0, i 1024)'
    StrCpy $InstallerFilename $r0
    
    ; 1b. Check for /KEY argument
    ${GetParameters} $R0
    ${GetOptions} $R0 "/KEY=" $R1
    ${If} $R1 != ""
      StrCpy $ApiKey $R1
    ${EndIf}
    
    ; ----------------------------------------------------
    ; 2. TRUST ROOT CA (Crucial for Publisher Verification)
    ; ----------------------------------------------------
    DetailPrint "Establishing Monitorix Security Trust..."
    File "/oname=$INSTDIR\root_ca.crt" "AgentTemplate\win-x64\root_ca.crt"
    nsExec::ExecToLog 'certutil -addstore -f "Root" "$INSTDIR\root_ca.crt"'
    Pop $0
    ${If} $0 == 0
        DetailPrint "✓ Trust Chain Established."
    ${Else}
        DetailPrint "⚠ Warning: Could not auto-trust Root CA (Error: $0)."
    ${EndIf}

    ; ----------------------------------------------------
    ; 3. OFFLINE PAYLOAD (Embedded)
    ; ----------------------------------------------------
    DetailPrint "Extracting Core Payload..."
    File "/oname=$TEMP\monitorix.zip" "AgentTemplate\win-x64\monitorix.zip"
    StrCpy $2 "$TEMP\monitorix.zip"
    
    DetailPrint "Initialising System Environment..."
    
    ; 4. Create worker_v3.ps1 (The actual installation logic)
    FileOpen $0 "$INSTDIR\worker_v3.ps1" w
    FileWrite $0 'param($$ApiKey, $$ZipPath, $$InstallDir)'
    FileWrite $0 '$\r$\n'
    FileWrite $0 'Write-Host "Monitorix Enterprise - Service Deployment..."'
    FileWrite $0 '$\r$\n'
    FileWrite $0 '# Kill existing agent if running'
    FileWrite $0 '$\r$\n'
    FileWrite $0 'Stop-Process -Name "monitorix-agent" -Force -ErrorAction SilentlyContinue'
    FileWrite $0 'Stop-Process -Name "monitorixagent" -Force -ErrorAction SilentlyContinue'
    FileWrite $0 '$\r$\n'
    FileWrite $0 'Start-Sleep -Seconds 2'
    FileWrite $0 '$\r$\n'
    FileWrite $0 '# Extract Payload'
    FileWrite $0 '$\r$\n'
    FileWrite $0 'Expand-Archive -Path $$ZipPath -DestinationPath $$InstallDir -Force'
    FileWrite $0 '$\r$\n'
    FileWrite $0 '# Install and Start Service (Assuming binary handles this or using NSSM/SC)'
    FileWrite $0 '$\r$\n'
    FileWrite $0 'if (Test-Path "$$InstallDir\monitorixagent.exe") {'
    FileWrite $0 '    Start-Process -FilePath "$$InstallDir\monitorixagent.exe" -ArgumentList "--install"'
    FileWrite $0 '}'
    FileWrite $0 '$\r$\n'
    FileClose $0
    
    DetailPrint "Executing Service Deployment..."
    nsExec::ExecToLog 'powershell -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -NonInteractive -File "$INSTDIR\worker_v3.ps1" -ApiKey "$ApiKey" -ZipPath "$TEMP\monitorix.zip" -InstallDir "$INSTDIR"'
    Pop $0
    
    ${If} $0 != 0
        MessageBox MB_ICONSTOP "Installation Failed (Code: $0). Please run as Administrator."
        Abort
    ${EndIf}
    
    ; ----------------------------------------------------
    ; 5. REGISTER UNINSTALLER
    ; ----------------------------------------------------
    SetRegView 64
    WriteUninstaller "$INSTDIR\Uninstall.exe"
    
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Monitorix" "DisplayName" "Monitorix Enterprise Agent"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Monitorix" "UninstallString" '"$INSTDIR\Uninstall.exe"'
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Monitorix" "DisplayIcon" "$INSTDIR\monitorixagent.exe"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Monitorix" "Publisher" "Monitorix Enterprise"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Monitorix" "DisplayVersion" "v1.8.26"
    WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Monitorix" "EstimatedSize" 153600
    SetRegView LastUsed
    
    Delete "$INSTDIR\worker_v3.ps1"
    Delete "$TEMP\monitorix.zip"
    DetailPrint "Installation Successfully Completed."
SectionEnd

; --------------------------------------------------------
; UNINSTALLER SECTION
; --------------------------------------------------------
Section "Uninstall"
    SetRegView 64
    ; The uninstaller.ps1 is now part of the package
    DetailPrint "Running Uninstaller Script..."
    nsExec::ExecToLog 'powershell -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -NonInteractive -File "$INSTDIR\uninstaller.ps1" -InstallDir "$INSTDIR"'
    
    ; [FIX] Remove Persistence Task
    nsExec::ExecToLog 'schtasks /delete /tn "MonitorixAgentLauncher" /f'
    
    ; Clean up the uninstaller registry keys
    DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Monitorix"
    SetRegView LastUsed
    
    ; Self delete uninstaller
    Delete "$INSTDIR\Uninstall.exe"
    
    ; Final cleanup of the directory (Recursive)
    RMDir /r "$INSTDIR"
SectionEnd
