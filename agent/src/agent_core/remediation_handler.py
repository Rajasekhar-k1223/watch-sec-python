import os # type: ignore
import subprocess # type: ignore
import platform # type: ignore
import logging # type: ignore
import ctypes # type: ignore
import sys # type: ignore
import asyncio # type: ignore
import base64
import hmac
import hashlib
import json
from datetime import datetime
from agent_core.privacy_utils import PrivacyRedactor

def log_remediation(msg):
    # [v1.8.32] Privacy: Sanitize remediation logs
    sanitized_msg = PrivacyRedactor.redact_text(msg)
    with open("remediation.log", "a") as f:
        from datetime import datetime # type: ignore
        f.write(f"[{datetime.now().isoformat()}] {sanitized_msg}\n")

class RemediationHandler:
    def __init__(self, agent_id, api_key=None, machine_secret=None, controllers=None):
        self.agent_id = agent_id
        self.api_key = api_key
        self.machine_secret = machine_secret
        self.controllers = controllers or {}

    async def handle_command(self, data):
        """
        Expected data: 
        {
            "action": "...", 
            "params": {...}, 
            "policy_name": "...",
            "signature": "hmac_sha256_here",
            "timestamp": "iso_format"
        }
        """
        action = data.get("action")
        params = data.get("params", {})
        policy = data.get("policy_name", "Unknown Policy")
        signature = data.get("signature")
        timestamp = data.get("timestamp")

        # [v1.8.37] Command Sovereignty: Per-Message Signature Verification
        if not self._verify_signature(data, signature):
            log_remediation(f"SECURITY VIOLATION: Unsigned or invalid command rejected: {action} (Policy: {policy})")
            return

        log_remediation(f"Remediation TRIGGERED: {action} (Policy: {policy})")

        if action == "KillProcess":
            await self._kill_process(params.get("process_name"))
        elif action == "LockSession":
            await self._lock_session()
        elif action == "SecurityPopup":
            await self._show_popup(params.get("message", f"Security violation detected by policy: {policy}"))
        elif action == "IsolateNetwork":
            await self._isolate_network()
        elif action == "WIPE_AGENT":
            await self._self_destruct()
        elif action == "ExecuteCommand":
            await self._execute_command(params.get("command"))
        elif action == "SOVEREIGN_LOCKDOWN":
            # [v2.6.0] High-Sovereignty Lockdown
            unlock_hash = params.get("unlock_hash")
            if not unlock_hash:
                log_remediation("SOVEREIGN_LOCKDOWN failed: Missing unlock hash")
                return
            
            from agent_core.lockdown import lockdown_engine # [v2.6.0]
            # Use a separate thread to avoid blocking the WebSocket while the system freezes
            import threading
            threading.Thread(target=lockdown_engine.apply_lockdown, args=(unlock_hash,), daemon=True).start()
        elif action == "SOVEREIGN_UNLOCK":
            # [v2.6.5] Remote Restoration
            from agent_core.lockdown import lockdown_engine
            lockdown_engine.release_lock()
        elif action == "MemoryForensic":
            await self._memory_forensic_scan()
        else:
            log_remediation(f"Unknown remediation action received: {action}")

    async def _memory_forensic_scan(self):
        """[v2.5.0] Memory Forensic: Scans active process memory for fileless malware patterns."""
        try:
            log_remediation("Initiating Autonomous Memory Forensic Scan...")
            import psutil # type: ignore
            
            # 1. Pattern matching for known fileless IoCs
            suspicious_patterns = [
                r"meterpreter", r"cobaltstrike", r"mimikatz", r"powershell -enc",
                r"base64", r"hidden", r"bypass", r"reflective", r"inject"
            ]
            
            results = []
            for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                try:
                    pinfo = proc.info
                    cmdline = " ".join(pinfo['cmdline'] or [])
                    
                    # Check cmdline for suspicious flags
                    import re
                    for pattern in suspicious_patterns:
                        if re.search(pattern, cmdline.lower()):
                            results.append({
                                "pid": pinfo['pid'],
                                "name": pinfo['name'],
                                "trigger": pattern,
                                "type": "Suspicious Cmdline"
                            })
                            break
                    
                    # [Windows Only] Check for unbacked memory regions (simplified)
                    if platform.system() == "Windows":
                        # Placeholder for advanced memory region scanning
                        pass
                        
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue

            if results:
                log_remediation(f"FORENSIC ALERT: Detected {len(results)} suspicious memory artifacts.")
                # Report back to backend via socket (if available)
                if hasattr(self, 'socket_client') and self.socket_client:
                    await self.socket_client.emit('forensic_result', {
                        "agentId": self.agent_id,
                        "timestamp": datetime.now().isoformat(),
                        "findings": results
                    })
            else:
                log_remediation("Memory forensic scan completed: Nominal. No anomalies detected.")
                
        except Exception as e:
            log_remediation(f"Memory Forensic failed: {e}")

    async def _execute_command(self, command):
        """[v1.8.62] Remote Remediation: Executes a signed command to resolve vulnerabilities."""
        if not command:
            log_remediation("ExecuteCommand failed: No command provided.")
            return

        try:
            log_remediation(f"Executing Remote Remediation Command: {command}")
            # Use subprocess to run the command in the background
            if platform.system() == "Windows":
                # Use powershell for flexibility
                subprocess.Popen(["powershell", "-WindowStyle", "Hidden", "-Command", command], 
                                 creationflags=subprocess.CREATE_NO_WINDOW)
            else:
                subprocess.Popen(["/bin/bash", "-c", command], start_new_session=True)
                
            log_remediation(f"Command dispatched successfully: {command[:20]}...")
        except Exception as e:
            log_remediation(f"Error executing Remote Command: {e}")

    def _verify_signature(self, data, signature):
        """[v1.8.37] Strict Sovereignty: Verifies HMAC-SHA256 signature."""
        if not self.api_key or not self.machine_secret:
            # [SECURITY] Deny-by-Default: If keys aren't loaded, remediation is locked.
            # This prevents bypasses during early boot or initialization failure.
            log_remediation("CRITICAL ERROR: Keys missing for signature verification. Denying command.")
            return False 
        
        if not signature: 
            return False

        try:
            # Reconstruct the message base for signing
            # We sign the action, params, and timestamp to prevent replay/substitution
            msg_parts = [
                str(data.get("action", "")),
                json.dumps(data.get("params", {}), sort_keys=True),
                str(data.get("timestamp", ""))
            ]
            message = "|".join(msg_parts).encode('utf-8')
            
            # Derive HMAC Key
            key = hashlib.sha256(self.api_key.encode() + self.machine_secret).digest()
            
            # Calculate expected signature
            expected = hmac.new(key, message, hashlib.sha256).hexdigest()
            
            return hmac.compare_digest(expected, signature)
        except Exception as e:
            log_remediation(f"Signature Verification Error: {e}")
            return False

    async def _self_destruct(self):
        """Remotely triggered forensic cleanup and uninstallation."""
        try:
            log_remediation("CRITICAL: Self-Destruct Command (WIPE_AGENT) received!")
            import sys # type: ignore
            main_mod = sys.modules.get("__main__")
            if main_mod and hasattr(main_mod, 'tamper_mon') and main_mod.tamper_mon:
                main_mod.tamper_mon.secure_panic_wipe(["config.json", "events.db", "events_user.db"])
            else:
                # Fallback simple delete
                for f in ["config.json", "events.db", "events_user.db"]:
                    try: os.remove(f)
                    except: pass
                os._exit(0)
        except Exception as e:
            log_remediation(f"Self-destruct failed: {e}")

    async def _kill_process(self, process_name):
        if not process_name:
            log_remediation("KillProcess failed: No process_name provided.")
            return

        # [v1.8.37] Remediation Command Sovereignty: Input Validation
        import re
        # Only allow alphanumeric, dots, dashes, and underscores. Block shell metacharacters.
        if not re.match(r"^[a-zA-Z0-9\._\- \(\)]+$", process_name):
            log_remediation(f"SECURITY VIOLATION: Blocked malformed process name (potential injection): {process_name}")
            return

        # [v1.8.37] Remediation Safeguard: Protected Process Shield
        protected = {
            "lsass.exe", "csrss.exe", "wininit.exe", "winlogon.exe", "services.exe",
            "smss.exe", "explorer.exe", "init", "systemd", "btm-agent", "monitorix-agent",
            "avp.exe", "msmpeng.exe", "nssm.exe"
        }
        
        if process_name.lower() in protected:
            log_remediation(f"SECURITY ALERT: Blocked attempt to kill protected process: {process_name}")
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
                # [v1.8.32] ANTI-RCE: Using Base64 EncodedCommand to prevent PowerShell injection
                # We escape single quotes for the PS string, then wrap the whole thing in Base64.
                safe_msg = message.replace("'", "''")
                script = (
                    "Add-Type -AssemblyName System.Windows.Forms; "
                    f"[System.Windows.Forms.MessageBox]::Show('{safe_msg}', 'Monitorix Security Alert', 'OK', 'Warning')"
                )
                encoded_script = base64.b64encode(script.encode('utf-16-le')).decode('ascii')
                subprocess.Popen(["powershell", "-WindowStyle", "Hidden", "-EncodedCommand", encoded_script])
            else:
                # Linux: notify-send is standard on most desktops
                subprocess.run(["notify-send", "-u", "critical", "Monitorix Security Alert", message], check=False)
        except Exception as e:
            log_remediation(f"Error displaying SecurityPopup: {e}")

    async def _isolate_network(self):
        """Emergency Kill-Switch: Disconnects the machine."""
        try:
            log_remediation("Executing IsolateNetwork remediation...")
            # 1. Try via injected controllers (Recommended)
            if self.controllers.get("net"):
                ctrl = self.controllers["net"]
                # If it's a callable (lambda), call it to get the current instance
                if callable(ctrl):
                    ctrl = ctrl()
                if ctrl and hasattr(ctrl, 'isolate_network'):
                    ctrl.isolate_network()
                    return

            # 2. Try via global module access (Fallback)
            try:
                import sys # type: ignore
                main_mod = sys.modules.get("__main__")
                if main_mod and hasattr(main_mod, 'net_mon') and main_mod.net_mon:
                    main_mod.net_mon.isolate_network()
                    return
                
                # Fallback initialize if not running (manual invoke)
                from modules.network_monitor import NetworkMonitor # type: ignore
                nm = NetworkMonitor("REMEDIATION", "NONE", "NONE")
                nm.isolate_network()
            except Exception as ie:
                log_remediation(f"Isolation module access failed: {ie}")
                # Last resort: try to just run a raw command
                if platform.system() == "Linux":
                   # [v1.8.32] Security: Remove shell=True
                   subprocess.run(["ip", "link", "set", "dev", "eth0", "down"], check=False)
        except Exception as e:
            log_remediation(f"Error executing IsolateNetwork: {e}")

    async def _execute_autonomous_action(self, data):
        """[v2.6.0] Internal Trigger: Executes actions from local playbooks."""
        action = data.get("action")
        params = data.get("params", {})
        
        log_remediation(f"AUTONOMOUS ACTION EXECUTING: {action}")
        
        if action == "KillProcess":
            await self._kill_process(params.get("process_name"))
        elif action == "IsolateNetwork":
            await self._isolate_network()
        elif action == "WIPE_AGENT":
            await self._self_destruct()
        elif action == "MemoryForensic":
            await self._memory_forensic_scan()
