
import os # type: ignore
import sys # type: ignore
import platform # type: ignore
import subprocess # type: ignore
import logging # type: ignore
import time # type: ignore

# --- Cross-Platform Compatibility Stubs ---
if platform.system() != "Windows":
    if not hasattr(subprocess, "CREATE_NO_WINDOW"):
        setattr(subprocess, "CREATE_NO_WINDOW", 0)
    if not hasattr(subprocess, "DETACHED_PROCESS"):
        setattr(subprocess, "DETACHED_PROCESS", 0)

class AgentInstaller:
    """
    Handles Self-Healing Persistence and Self-Destruct mechanisms.
    """
    def __init__(self, base_dir, agent_exe):
        self.base_dir = base_dir
        self.agent_exe = agent_exe
        self.logger = logging.getLogger("AgentInstaller")
        # [PHASE 3] Shadow path for self-healing
        if platform.system() == "Windows":
            self.shadow_dir = os.path.join(os.environ.get("ProgramData", "C:\\ProgramData"), "Monitorix")
            self.shadow_exe = os.path.join(self.shadow_dir, "monitorixagent.exe")
        elif platform.system() == "Darwin":
            self.shadow_dir = "/Library/Application Support/Monitorix"
            self.shadow_exe = os.path.join(self.shadow_dir, "monitorix-agent")
        else: # Linux
            self.shadow_dir = "/var/lib/monitorix"
            self.shadow_exe = os.path.join(self.shadow_dir, "monitorix-agent")

    def check_persistence(self):
        """
        Verifies if the agent is set to run on boot.
        """
        if platform.system() == "Windows":
            self._check_windows_persistence()
        elif platform.system() == "Linux":
            self._check_linux_persistence()
        elif platform.system() == "Darwin":
            self._check_macos_persistence()

    def _check_windows_persistence(self):
        """Original Windows persistence logic."""

        # [PHASE 3] Ensure Shadow Copy exists
        self._ensure_shadow_copy()

        # 1. Check Windows Service
        service_name = "MonitorixAgent"
        check_svc = f"sc.exe query {service_name}"
        creation_flags = subprocess.CREATE_NO_WINDOW if platform.system() == "Windows" else 0
        
        svc_result = subprocess.run(check_svc, capture_output=True, shell=True, creationflags=creation_flags)
        if svc_result.returncode != 0:
            self.logger.warning("Persistence missing (Windows Service). Attempting to repair...")
            # Note: Full re-registration usually requires the installer.ps1 
            # for 'New-Service' cmdlets, but we'll log it for now.
            self.logger.error("SYSTEM SERVICE MISSING. Manual reinstall recommended.")
        else:
            self.logger.info("Persistence verified (Windows Service exists).")

        # 2. Check Scheduled Task
        task_name = "MonitorixAgentLauncher"
        check_task = f"schtasks /query /TN \"{task_name}\""
        task_result = subprocess.run(check_task, capture_output=True, shell=True, creationflags=creation_flags)
        
        if task_result.returncode != 0:
            self.logger.warning("Persistence missing (Scheduled Task). Attempting to repair...")
            self._install_task(task_name)
        else:
            self.logger.info("Persistence verified (Scheduled Task exists).")

        # 3. Registry Run Key disabled (Consolidated to Scheduled Task for reliability)
        # self._check_registry_run_key()

    def _check_registry_run_key(self):
        """
        Ensures the HKLM Run key is present to trigger the agent for all user sessions.
        """
        try:
            import winreg # type: ignore
            reg_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
            reg_name = "MonitorixAgentUser"
            
            try:
                # Use getattr to avoid lints on non-Windows
                HKEY_LM = getattr(winreg, "HKEY_LOCAL_MACHINE")
                K_READ = getattr(winreg, "KEY_READ")
                with winreg.OpenKey(HKEY_LM, reg_path, 0, K_READ) as key: # type: ignore
                    val, _ = winreg.QueryValueEx(key, reg_name) # type: ignore
                    if val != f'"{self.agent_exe}"':
                        self.logger.warning("Registry Run Key is incorrect. Repairing...")
                        self._install_run_key(reg_path, reg_name)
                    else:
                        self.logger.info("Persistence verified (Registry Run Key exists).")
            except (FileNotFoundError, AttributeError):
                self.logger.warning("Registry Run Key is missing or inaccessible. Repairing...")
                self._install_run_key(reg_path, reg_name)
        except Exception as e:
            self.logger.error(f"Failed to verify Registry Run Key: {e}")

    def _install_run_key(self, reg_path, reg_name):
        try:
            import winreg # type: ignore
            HKEY_LM = getattr(winreg, "HKEY_LOCAL_MACHINE")
            K_SET = getattr(winreg, "KEY_SET_VALUE")
            R_SZ = getattr(winreg, "REG_SZ")
            with winreg.OpenKey(HKEY_LM, reg_path, 0, K_SET) as key:
                winreg.SetValueEx(key, reg_name, 0, R_SZ, f'"{self.agent_exe}"') # type: ignore
            self.logger.info("Registry Run Key repaired successfully.")
        except Exception as e:
            self.logger.error(f"Failed to repair Registry Run Key: {e}")

    def _ensure_shadow_copy(self):
        """
        Maintains a hidden copy of the agent in ProgramData for self-healing.
        """
        try:
            if not os.path.exists(self.shadow_dir):
                os.makedirs(self.shadow_dir, exist_ok=True)
            
            import shutil # type: ignore
            # If shadow doesn't exist or is different size, update/create it
            if not os.path.exists(self.shadow_exe) or os.path.getsize(self.shadow_exe) != os.path.getsize(self.agent_exe):
                shutil.copy2(self.agent_exe, self.shadow_exe)
                # Hide the directory
                if platform.system() == "Windows":
                    subprocess.run(["attrib", "+H", self.shadow_dir], creationflags=0x08000000) # type: ignore
                self.logger.info(f"Shadow backup created at {self.shadow_exe}")
        except Exception as e:
            self.logger.error(f"Failed to ensure shadow copy: {e}")

    def _install_task(self, task_name):
        # [PHASE 3] Heal-on-Run Logic:
        # The scheduled task action is a PowerShell script that:
        # 1. Checks if the main agent EXE exists.
        # 2. If missing, restores it from the shadow backup.
        # 3. Starts the agent.
        
        heal_script = (
            f"$p = '{self.agent_exe}'; $s = '{self.shadow_exe}'; "
            "if (!(Test-Path $p)) { if (Test-Path $s) { Copy-Item $s $p -Force } }; "
            "if (!(Get-Process -Name 'MonitorixAgent' -ErrorAction SilentlyContinue)) { Start-Process $p }"
        )
        
        # Wrap in a single line for schtasks
        task_action = f"powershell -WindowStyle Hidden -Command \\\"{heal_script}\\\""
        
        # Use ONLOGON + SYSTEM for background repair that doesn't block GUI session
        cmd = (
            f"schtasks /create /tn \"{task_name}\" "
            f"/tr \"{task_action}\" "
            f"/sc ONLOGON /rl HIGHEST /f"
        )
        try:
            creation_flags = 0
            if platform.system() == "Windows":
                creation_flags = subprocess.CREATE_NO_WINDOW # type: ignore
            subprocess.run(cmd, shell=True, check=True, creationflags=creation_flags)
            self.logger.info("Heal-on-Logon Scheduled Task registered.")
        except Exception as e:
            self.logger.error(f"Failed to repair persistence: {e}")

    def _check_linux_persistence(self):
        """Implements systemd service persistence for Linux."""
        service_name = "monitorix-agent.service"
        service_path = f"/etc/systemd/system/{service_name}"
        user_service_path = os.path.expanduser(f"~/.config/systemd/user/{service_name}")
        
        # Determine if we can write to /etc
        is_root = os.geteuid() == 0
        target_path = service_path if is_root else user_service_path
        
        if not os.path.exists(os.path.dirname(target_path)):
            os.makedirs(os.path.dirname(target_path), exist_ok=True)

        service_content = f"""[Unit]
Description=Monitorix Security Agent
After=network.target

[Service]
ExecStart={self.agent_exe}
Restart=always
RestartSec=10

[Install]
WantedBy={'multi-user.target' if is_root else 'default.target'}
"""
        try:
            with open(target_path, "w") as f:
                f.write(service_content)
            
            # Reload and enable
            scope = "--system" if is_root else "--user"
            subprocess.run(["systemctl", scope, "daemon-reload"], check=False)
            subprocess.run(["systemctl", scope, "enable", service_name], check=False)
            subprocess.run(["systemctl", scope, "start", service_name], check=False)
            self.logger.info(f"Linux persistence verified/installed via systemd ({scope}).")
        except Exception as e:
            self.logger.error(f"Failed to install Linux persistence: {e}")

    def _check_macos_persistence(self):
        """Implements launchd persistence for macOS."""
        label = "com.monitorix.agent"
        plist_path = os.path.expanduser(f"~/Library/LaunchAgents/{label}.plist")
        
        plist_content = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{label}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{self.agent_exe}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
</dict>
</plist>
"""
        try:
            if not os.path.exists(os.path.dirname(plist_path)):
                os.makedirs(os.path.dirname(plist_path), exist_ok=True)
                
            with open(plist_path, "w") as f:
                f.write(plist_content)
            
            subprocess.run(["launchctl", "load", plist_path], capture_output=True)
            self.logger.info("macOS persistence verified/installed via launchd.")
        except Exception as e:
            self.logger.error(f"Failed to install macOS persistence: {e}")

    def self_destruct(self):
        """
        Initiates self-uninstallation.
        Since we cannot delete the running executable, we spawn a temporary cleanup script.
        """
        self.logger.info("Initiating Self-Destruct Sequence...")
        
        if platform.system() == "Windows":
            self._self_destruct_windows()
        elif platform.system() == "Darwin":
            self._self_destruct_macos()
        else:
            self._self_destruct_linux()

    def _self_destruct_macos(self):
        label = "com.monitorix.agent"
        plist_path = os.path.expanduser(f"~/Library/LaunchAgents/{label}.plist")
        
        # [v1.8.37] Forensic OS-Cleanup: Overwrite files before deletion
        cleanup_cmd = (
            f"sleep 5; "
            f"launchctl unload '{plist_path}'; "
            f"rm -P '{plist_path}'; " # -P is secure overwrite on BSD/macOS
            f"rm -rfP '{self.shadow_dir}'; "
            f"rm -rfP '{self.base_dir}' &"
        )
        subprocess.Popen(cleanup_cmd, shell=True)
        self.logger.info("macOS Forensic Cleanup sequence initiated.")

    def _self_destruct_windows(self):
        # Create a cleanup .bat file in TEMP
        temp_dir = os.environ.get("TEMP", "C:\\Windows\\Temp")
        cleanup_script = os.path.join(temp_dir, f"cleanup_monitorix_{int(time.time())}.bat")
        
        # Determine the directory to wipe (Base Directory)
        target_dir = self.base_dir
        
        # Batch Script Logic:
        # 1. Wait for Agent exit
        # 2. Forensic wipe of shadow and base directories
        # 3. Remove Scheduled Task
        # 4. Cleanup
        
        script_content = f"""
@echo off
ping 127.0.0.1 -n 6 > nul
:: Forensic Wipe (Naive but better than rd)
for /r "{self.shadow_dir}" %%f in (*) do format %%f /q /y >nul 2>&1
for /r "{target_dir}" %%f in (*) do format %%f /q /y >nul 2>&1
schtasks /delete /tn "MonitorixAgentLauncher" /f >nul 2>&1
rd /s /q "{self.shadow_dir}" >nul 2>&1
rd /s /q "{target_dir}" >nul 2>&1
del "%~f0"
"""
        try:
            with open(cleanup_script, "w") as f:
                f.write(script_content)
            
            # Execute detached
            creation_flags = subprocess.DETACHED_PROCESS # type: ignore
            if platform.system() == "Windows":
                creation_flags |= subprocess.CREATE_NO_WINDOW
            
            # Execute detached and silent via PowerShell hidden window
            # This is more robust than cmd.exe for hiding the window
            ps_cmd = f"Start-Process cmd.exe -ArgumentList '/c \"{cleanup_script}\"' -WindowStyle Hidden"
            
            subprocess.Popen(
                ["powershell", "-Command", ps_cmd], 
                creationflags=0x08000000, # CREATE_NO_WINDOW
                close_fds=True,
                start_new_session=True
            )
            self.logger.info("Cleanup script launched. Exiting.")
        except Exception as e:
            self.logger.error(f"Failed to create cleanup script: {e}")

    def _self_destruct_linux(self):
        # Systemd cleanup + Forensic denial
        service_name = "monitorix-agent.service"
        is_root = os.getuid() == 0
        scope = "--system" if is_root else "--user"
        
        # Use 'shred' if available for forensic wipe
        cleanup_script = (
            f"sleep 5; "
            f"systemctl {scope} stop {service_name}; "
            f"systemctl {scope} disable {service_name}; "
            f"find '{self.base_dir}' -type f -exec shred -u {{}} \\;; "
            f"rm -rf '{self.base_dir}'; "
            f"rm -f '/etc/systemd/system/{service_name}'; "
            f"rm -f ~/.config/systemd/user/{service_name}; "
            f"&"
        )
        subprocess.Popen(cleanup_script, shell=True)
        self.logger.info("Linux Forensic Cleanup sequence initiated.")

    def check_browser_extension(self, agent_id, api_key, backend_url):
        """
        Ensures the Watch-Sec Chrome Extension is deployed and configured.
        """
        if platform.system() != "Windows":
            return 
        
        try:
            # 1. Locate Source
            source_path = None
            if hasattr(sys, '_MEIPASS'):
                # Wrapped in PyInstaller
                source_path = os.path.join(getattr(sys, '_MEIPASS'), "chrome_ext")
            
            # Fallback to installation directory (if extracted from zip)
            if not source_path or not os.path.exists(source_path):
                source_path = os.path.join(self.base_dir, "chrome_ext")
            
            if not os.path.exists(source_path):
                self.logger.warning(f"Chrome Extension source not found (checked _MEIPASS and {self.base_dir}/chrome_ext)")
                return

            # 2. Destination
            # Program Files/Monitorix/Extension
            pf = os.environ.get("ProgramFiles", "C:\\Program Files")
            dest_path = os.path.join(pf, "Monitorix", "Extension")
            
            if not os.path.exists(dest_path):
                os.makedirs(dest_path, exist_ok=True)
                
            # 3. Copy Files (Idempotent-ish)
            import shutil # type: ignore
            for item in os.listdir(source_path):
                s = os.path.join(source_path, item)
                d = os.path.join(dest_path, item)
                if os.path.isfile(s):
                    shutil.copy2(s, d)
            
            self.logger.info(f"Extension files deployed to {dest_path}")
            
            # 4. Inject Config
            config_js = os.path.join(dest_path, "config.js")
            config_content = (
                f"const CONFIG = {{\n"
                f"    BACKEND_URL: \"{backend_url}\",\n"
                f"    TENANT_API_KEY: \"{api_key}\",\n"
                f"    AGENT_ID: \"{agent_id}\"\n"
                f"}};\n"
            )
            with open(config_js, "w") as f:
                f.write(config_content)
                
            # 5. Lockdown Config Permissions (Security Phase 9)
            # Only SYSTEM and Administrators (and Optionally the current user) should read this
            if platform.system() == "Windows":
                 try:
                     # Remove inheritance and all permissions, then grant SYSTEM and Admins Full, and Current User Read
                     import getpass
                     c_user = getpass.getuser()
                     subprocess.run(["icacls", config_js, "/inheritance:r"], creationflags=0x08000000)
                     subprocess.run(["icacls", config_js, "/grant:r", "SYSTEM:(R)"], creationflags=0x08000000)
                     subprocess.run(["icacls", config_js, "/grant:r", "Administrators:(R)"], creationflags=0x08000000)
                     subprocess.run(["icacls", config_js, "/grant:r", f"{c_user}:(R)"], creationflags=0x08000000)
                     self.logger.info(f"Access Control applied to {config_js}")
                 except: pass

            # 6. Update Shortcuts (Force Load)
            self._patch_shortcuts(dest_path)
            
        except Exception as e:
            self.logger.error(f"Extension deployment failed: {e}")

    def _patch_shortcuts(self, ext_path):
        """
        Uses PowerShell to modify Chrome/Edge shortcuts on Desktop and Start Menu.
        Adds --load-extension="C:\..."
        """
        ps_script = f"""
$extPath = "{ext_path}"
$shell = New-Object -COM WScript.Shell
$dirs = @(
    [Environment]::GetFolderPath("Desktop"), 
    [Environment]::GetFolderPath("CommonDesktopDirectory"),
    [Environment]::GetFolderPath("StartMenu"),
    [Environment]::GetFolderPath("CommonStartMenu")
)

$targets = @("Google Chrome.lnk", "Microsoft Edge.lnk", "Brave.lnk")

foreach ($dir in $dirs) {{
    if (Test-Path $dir) {{
        Get-ChildItem -Path $dir -Recurse -Filter *.lnk | ForEach-Object {{
            $lnk = $_
            foreach ($t in $targets) {{
                if ($lnk.Name -eq $t) {{
                    try {{
                        $shortcut = $shell.CreateShortcut($lnk.FullName)
                        $args = $shortcut.Arguments
                        if ($args -notmatch "--load-extension") {{
                            $shortcut.Arguments = "$args --load-extension=`"$extPath`""
                            $shortcut.Save()
                            Write-Output "Patched: $($lnk.FullName)"
                        }}
                    }} catch {{}}
                }}
            }}
        }}
    }}
}}
"""
        try:
            # We encode command to base64 to avoid quote escaping hell
            import base64 # type: ignore
            encoded = base64.b64encode(ps_script.encode('utf-16le')).decode('utf-8')
            cmd = f"powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand {encoded}"
            
            creation_flags = 0
            if platform.system() == "Windows":
                creation_flags = 0x08000000 # CREATE_NO_WINDOW
            
            subprocess.run(cmd, shell=True, capture_output=True, creationflags=creation_flags) # Fire and forget-ish # type: ignore
        except Exception as e:
            self.logger.error(f"Shortcut patching error: {e}")
