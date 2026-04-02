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
    
    ; 1. Get Filename to extract Key
    System::Call 'kernel32::GetModuleFileName(p 0, t .r0, i 1024)'
    StrCpy $InstallerFilename $r0
    
    ; 1b. Check for /KEY argument (Robustness for CLI)
    ${GetParameters} $R0
    DetailPrint "Raw Parameters: $R0"
    ${GetOptions} $R0 "/KEY=" $R1
    ${If} $R1 != ""
      StrCpy $ApiKey $R1
      DetailPrint "API Key provided via command line: $ApiKey"
    ${EndIf}
    
    ; ----------------------------------------------------
    ; OFFLINE INSTALL (Embedded Payload)
    ; ----------------------------------------------------
    DetailPrint "Extracting Embedded Payload..."
    File "/oname=$TEMP\monitorix.zip" "AgentTemplate\win-x64\monitorix.zip"
    StrCpy $2 "$TEMP\monitorix.zip"

    ; OLD DOWNLOAD LOGIC DISABLED
    ; DetailPrint "Connecting to Monitorix Cloud..."
    ; StrCpy $1 "https://agent-api.monitorix.co.in/api/downloads/public/payload?key=$ApiKey&os_type=windows"
    ; ...
    
    DetailPrint "Initializing Installer..."
    
    ; 2. Extract the Worker Script (Inline Creation)
    ; File "build_env/worker_v3.ps1" - REMOVED (File not present in build context)
    
    ; Create worker_v3.ps1 on the fly
    FileOpen $0 "$INSTDIR\worker_v3.ps1" w
    FileWrite $0 'param($$ApiKey, $$ZipPath, $$InstallDir)'
    FileWrite $0 '$\r$\n'
    FileWrite $0 'Write-Host "Starting Update Worker..."'
    FileWrite $0 '$\r$\n'
    FileWrite $0 '# Kill Agent'
    FileWrite $0 '$\r$\n'
    FileWrite $0 'Stop-Process -Name "monitorix-agent" -Force -ErrorAction SilentlyContinue'
    FileWrite $0 '$\r$\n'
    FileWrite $0 'Start-Sleep -Seconds 2'
    FileWrite $0 '$\r$\n'
    FileWrite $0 '# Extract Zip'
    FileWrite $0 '$\r$\n'
    FileWrite $0 'Expand-Archive -Path $$ZipPath -DestinationPath $$InstallDir -Force'
    FileWrite $0 '$\r$\n'
    FileWrite $0 '# Restart Agent'
    FileWrite $0 '$\r$\n'
    FileWrite $0 'Start-Process -FilePath "$$InstallDir\monitorix-agent.exe"'
    FileWrite $0 '$\r$\n'
    FileClose $0

    
    DetailPrint "Execute Installation Logic..."
    ; Run PowerShell with Parameters - Note: Using different quotes to avoid escape issues in nsExec
    nsExec::ExecToLog 'powershell -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -NonInteractive -File "$INSTDIR\worker_v3.ps1" -ApiKey "$ApiKey" -ZipPath "$TEMP\monitorix.zip" -InstallDir "$INSTDIR"'
    Pop $0 ; Return value
    
    ${If} $0 != 0
        MessageBox MB_ICONSTOP "Installation Failed (Code: $0). Please run as Administrator."
        Abort
    ${EndIf}
    
    ; ----------------------------------------------------
    ; REGISTER UNINSTALLER
    ; ----------------------------------------------------
    SetRegView 64
    WriteUninstaller "$INSTDIR\Uninstall.exe"
    
    ; Add to Control Panel (Add/Remove Programs)
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Monitorix" "DisplayName" "Monitorix Enterprise Agent"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Monitorix" "UninstallString" '"$INSTDIR\Uninstall.exe"'
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Monitorix" "DisplayIcon" "$INSTDIR\MonitorixAgent.exe"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Monitorix" "Publisher" "Monitorix Enterprise"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Monitorix" "DisplayVersion" "v1.0-1.1"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Monitorix" "HelpLink" "https://monitorix.co.in/support"
    WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Monitorix" "NoModify" 1
    WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Monitorix" "NoRepair" 1
    
    ; Estimate size (Approx 150MB for full package)
    WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Monitorix" "EstimatedSize" 153600

    SetRegView LastUsed
    
    Delete "$INSTDIR\worker_v3.ps1"
    Delete "$TEMP\monitorix.zip"
    DetailPrint "Installation Complete."
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
