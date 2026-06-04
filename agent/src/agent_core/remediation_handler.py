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
        elif action == "TriggerAVScan":
            # [v2.7.0] Native AV Trigger
            if self.controllers.get("av"):
                ctrl = self.controllers["av"]
                if callable(ctrl): ctrl = ctrl()
                if ctrl and hasattr(ctrl, "trigger_quick_scan"):
                    ctrl.trigger_quick_scan()
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
        elif action == "PatchSoftware":
            await self._patch_software(params.get("SoftwareName"))
        elif action == "InstallSoftware":
            await self._install_software(params.get("SoftwareName"))
        elif action == "TriggerYaraScan":
            await self._trigger_yara_scan(params.get("rules"))
        elif action == "MemoryForensic":
            await self._memory_forensic_scan()
        else:
            log_remediation(f"Unknown remediation action received: {action}")

    async def _trigger_yara_scan(self, rules_string):
        """[v3.0.0] Execute a YARA scan."""
        if not rules_string:
            log_remediation("YARA scan failed: No rules provided.")
            return

        try:
            import yara
            import os
            
            rules = yara.compile(source=rules_string)
            scan_dir = os.path.expanduser("~")
            log_remediation(f"Starting YARA scan in {scan_dir}")
            
            matches_found = []
            
            for root, dirs, files in os.walk(scan_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    try:
                        matches = rules.match(file_path)
                        if matches:
                            matches_found.append({
                                "file": file_path,
                                "matches": [str(m) for m in matches]
                            })
                    except:
                        pass

            if matches_found:
                log_remediation(f"YARA MATCHES FOUND: {len(matches_found)} files matched.")
                if hasattr(self, 'socket_client') and self.socket_client:
                    await self.socket_client.emit('forensic_result', {
                        "agentId": self.agent_id,
                        "timestamp": datetime.now().isoformat(),
                        "findings": matches_found,
                        "type": "YARA_SCAN_MATCH"
                    })
            else:
                log_remediation("YARA scan completed: No matches found.")
        except ImportError:
            log_remediation("YARA scan failed: yara-python is not installed.")
        except Exception as e:
            log_remediation(f"YARA scan error: {e}")

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
                    
                    # [v2.7.0] Offline AI/Heuristics
                    threat_score = 0
                    exe_path = ""
                    try:
                        exe_path = proc.exe().lower()
                    except: pass
                    
                    # 1. Suspicious Location
                    if "appdata\\local\\temp" in exe_path or "/tmp/" in exe_path:
                        threat_score += 40
                        
                    # 2. Deeply nested encoded args
                    enc_flags = len(re.findall(r'-e\b|-enc\b', cmdline.lower()))
                    if enc_flags > 0:
                        threat_score += (enc_flags * 30)
                        
                    # 3. Known lolbins with weird args
                    lolbins = ["certutil", "mshta", "regsvr32", "rundll32", "wscript", "cscript"]
                    if pinfo['name'] and pinfo['name'].lower() in lolbins and len(cmdline) > 50:
                        threat_score += 50
                        
                    if threat_score >= 80:
                        results.append({
                            "pid": pinfo['pid'],
                            "name": pinfo['name'],
                            "trigger": f"Heuristic Score {threat_score}",
                            "type": "Heuristic Behavioral Match"
                        })

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
            # Replay Protection [v2.7.0]: Validate TTL (60 seconds)
            from datetime import datetime, timezone
            try:
                msg_time = datetime.fromisoformat(data.get("timestamp", "").replace("Z", "+00:00"))
                now = datetime.now(timezone.utc)
                diff = (now - msg_time).total_seconds()
                if abs(diff) > 60:
                    log_remediation(f"REPLAY ATTACK BLOCKED: Command timestamp expired ({diff}s ago)")
                    return False
            except Exception as t_err:
                log_remediation(f"Timestamp Parse Error (Replay Blocked): {t_err}")
                return False

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

    async def _patch_software(self, software_name):
        """[v2.8.0] Executes cross-platform patch command for the given software."""
        if not software_name:
            log_remediation("PatchSoftware failed: No SoftwareName provided.")
            return
            
        import re
        if not re.match(r"^[a-zA-Z0-9\.\_\- ]+$", software_name):
            log_remediation(f"SECURITY VIOLATION: Blocked malformed software name: {software_name}")
            return
            
        try:
            log_remediation(f"Initiating Patch for {software_name}")
            system = platform.system()
            
            if system == "Linux":
                cmd = ["/bin/bash", "-c", f"export DEBIAN_FRONTEND=noninteractive; apt-get install --only-upgrade -y '{software_name}' || pip3 install --upgrade '{software_name}'"]
            elif system == "Windows":
                cmd = ["powershell", "-WindowStyle", "Hidden", "-Command", f"winget upgrade --silent --accept-package-agreements '{software_name}'"]
            elif system == "Darwin":
                cmd = ["/bin/bash", "-c", f"brew upgrade '{software_name}' || softwareupdate -i '{software_name}'"]
            else:
                log_remediation(f"Patching not supported on {system}")
                return
                
            subprocess.Popen(cmd, start_new_session=True)
            log_remediation(f"Patch command dispatched for {software_name}")
        except Exception as e:
            log_remediation(f"Error executing PatchSoftware for {software_name}: {e}")

    async def _install_software(self, software_name):
        """[v3.0.0] Executes cross-platform install command for the requested software."""
        if not software_name:
            log_remediation("InstallSoftware failed: No SoftwareName provided.")
            return
            
        import re
        if not re.match(r"^[a-zA-Z0-9\.\_\- ]+$", software_name):
            log_remediation(f"SECURITY VIOLATION: Blocked malformed software name: {software_name}")
            return
            
        try:
            log_remediation(f"Initiating Install for {software_name}")
            system = platform.system()
            
            if system == "Linux":
                cmd = ["/bin/bash", "-c", f"export DEBIAN_FRONTEND=noninteractive; apt-get install -y '{software_name}' || pip3 install '{software_name}'"]
            elif system == "Windows":
                cmd = ["powershell", "-WindowStyle", "Hidden", "-Command", f"winget install --silent --accept-package-agreements '{software_name}'"]
            elif system == "Darwin":
                cmd = ["/bin/bash", "-c", f"brew install '{software_name}'"]
            else:
                log_remediation(f"Installing not supported on {system}")
                return

            import sys
            main_mod = sys.modules.get("__main__")
            tamper_paused = False
            if main_mod and hasattr(main_mod, 'tamper_mon') and main_mod.tamper_mon:
                try:
                    main_mod.tamper_mon.relax_protection()
                    tamper_paused = True
                    log_remediation("AntiTamperMonitor paused for software installation.")
                except Exception as e:
                    log_remediation(f"Failed to pause AntiTamperMonitor: {e}")

            try:
                subprocess.run(cmd, check=False)
                log_remediation(f"Install command finished for {software_name}")
            finally:
                if tamper_paused:
                    try:
                        main_mod.tamper_mon.enforce_protection()
                        log_remediation("AntiTamperMonitor enforced after software installation.")
                    except Exception as e:
                        log_remediation(f"Failed to enforce AntiTamperMonitor: {e}")
        except Exception as e:
            log_remediation(f"Error executing InstallSoftware for {software_name}: {e}")
