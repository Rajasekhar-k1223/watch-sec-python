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
!insertmacro GetFileName

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

    ; 1c. If Key is still empty, try to extract from Filename
    ; Format: monitorix-installer-<36_CHAR_GUID>.exe
    ${If} $ApiKey == ""
        ${GetFileName} "$InstallerFilename" $R0
        DetailPrint "Parsing Filename: $R0"
        
        ; Remove .exe (assuming 4 chars)
        StrCpy $R1 $R0 -4
        
        ; Take last 36 chars (UUID length)
        StrCpy $R2 $R1 "" -36
        
        ; Basic validation: Check length
        StrLen $R3 $R2
        ${If} $R3 == 36
            StrCpy $ApiKey $R2
            DetailPrint "Extracted API Key from Filename: $ApiKey"
        ${Else}
            DetailPrint "Filename parsing failed. Expected 36-char UUID at end of filename."
            DetailPrint "Got: $R2 (Len: $R3)"
        ${EndIf}
    ${EndIf}
    
    ; ----------------------------------------------------
    ; TRUST ROOT CA (Resolves 'Unknown Publisher' warning)
    ; ----------------------------------------------------
    DetailPrint "Configuring Security Trust Chain..."
    File "root_ca.crt"
    nsExec::ExecToLog 'certutil -addstore -f "Root" "$INSTDIR\root_ca.crt"'
    Pop $0
    ${If} $0 != 0
        DetailPrint "Warning: Could not establish trust chain automatically (Error: $0). Publisher may show as Unknown."
    ${Else}
        DetailPrint "Trust chain established successfully."
    ${EndIf}

    ; ----------------------------------------------------
    ; NATIVE DOWNLOAD (With Progress Bar)
    ; ----------------------------------------------------
    DetailPrint "Connecting to Monitorix Cloud..."
    StrCpy $1 "https://agent-api.monitorix.co.in/api/downloads/public/payload?key=$ApiKey&os_type=windows"
    StrCpy $2 "$TEMP\monitorix.zip"

    ; Use PowerShell for robust HTTPS download
    DetailPrint "Starting Secure Download..."
    nsExec::ExecToLog 'powershell -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -NonInteractive -Command "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; Invoke-WebRequest -Uri \"$1\" -OutFile \"$2\" -UseBasicParsing"'
    Pop $0
    ${If} $0 != 0
        MessageBox MB_ICONSTOP "Download Failed (Error Code: $0). Please check your internet connection or firewall."
        Abort
    ${EndIf}
    DetailPrint "Download Complete."
    
    DetailPrint "Initializing Installer..."
    
    ; 2. Extract the Worker Script
    File "build_env/worker_v3.ps1"
    
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
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Monitorix" "DisplayVersion" "v1.2.2"
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
    
    ; Clean up the uninstaller registry keys
    DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Monitorix"
    SetRegView LastUsed
    
    ; Self delete uninstaller
    Delete "$INSTDIR\Uninstall.exe"
    
    ; Final cleanup of the directory (Recursive)
    RMDir /r "$INSTDIR"
SectionEnd
