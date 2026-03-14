import os # type: ignore
import subprocess # type: ignore
import platform # type: ignore
import logging # type: ignore
import ctypes # type: ignore
import sys # type: ignore
import asyncio # type: ignore

def log_remediation(msg):
    with open("remediation.log", "a") as f:
        from datetime import datetime # type: ignore
        f.write(f"[{datetime.now().isoformat()}] {msg}\n")

class RemediationHandler:
    def __init__(self, agent_id):
        self.agent_id = agent_id

    async def handle_command(self, data):
        """
        Expected data: 
        {
            "action": "KillProcess" | "LockSession" | "SecurityPopup", 
            "params": {"process_name": "chrome.exe", "message": "..."}, 
            "policy_name": "..."
        }
        """
        action = data.get("action")
        params = data.get("params", {})
        policy = data.get("policy_name", "Unknown Policy")

        log_remediation(f"Remediation TRIGGERED: {action} (Policy: {policy})")

        if action == "KillProcess":
            await self._kill_process(params.get("process_name"))
        elif action == "LockSession":
            await self._lock_session()
        elif action == "SecurityPopup":
            await self._show_popup(params.get("message", f"Security violation detected by policy: {policy}"))
        else:
            log_remediation(f"Unknown remediation action received: {action}")

    async def _kill_process(self, process_name):
        if not process_name:
            log_remediation("KillProcess failed: No process_name provided.")
            return
        
        try:
            log_remediation(f"Executing KillProcess: {process_name}")
            if platform.system() == "Windows":
                # /F = Force, /IM = ImageName, /T = Tree (child processes)
                subprocess.run(["taskkill", "/F", "/IM", process_name, "/T"], check=False, capture_output=True)
            else:
                # Linux: pkill -f matches full command line
                subprocess.run(["pkill", "-9", "-f", process_name], check=False, capture_output=True)
            log_remediation(f"Process kill signal sent for '{process_name}'")
        except Exception as e:
            log_remediation(f"Error executing KillProcess {process_name}: {e}")

    async def _lock_session(self):
        try:
            log_remediation("Executing LockSession")
            if platform.system() == "Windows":
                # Native Windows API call
                import ctypes # type: ignore
                ctypes.windll.user32.LockWorkStation() # type: ignore
            else:
                # Linux: Try common lock commands
                lock_commands = [
                    ["xdg-screensaver", "lock"],
                    ["gnome-screensaver-command", "-l"],
                    ["loginctl", "lock-session"]
                ]
                for cmd in lock_commands:
                    try:
                        res = subprocess.run(cmd, check=False, capture_output=True)
                        if res.returncode == 0:
                            log_remediation(f"Session locked using {cmd[0]}")
                            return
                    except:
                        continue
                log_remediation("Failed to lock session: No compatible lock command found.")
        except Exception as e:
            log_remediation(f"Error executing LockSession: {e}")

    async def _show_popup(self, message):
        """Displays a non-blocking alert to the user."""
        try:
            log_remediation(f"Executing SecurityPopup: {message}")
            if platform.system() == "Windows":
                # Using PowerShell to display a message box without extra dependencies
                ps_cmd = (
                    f"Add-Type -AssemblyName System.Windows.Forms; "
                    f"[System.Windows.Forms.MessageBox]::Show('{message}', 'Monitorix Security Alert', 'OK', 'Warning')"
                )
                subprocess.Popen(["powershell", "-WindowStyle", "Hidden", "-Command", ps_cmd])
            else:
                # Linux: notify-send is standard on most desktops
                subprocess.run(["notify-send", "-u", "critical", "Monitorix Security Alert", message], check=False)
        except Exception as e:
            log_remediation(f"Error displaying SecurityPopup: {e}")
