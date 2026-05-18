import os
import subprocess
import platform
import logging
import time

logger = logging.getLogger("SovereignLockdown")

class LockdownModule:
    """[v2.6.0] Sovereign Lockdown: Forces system into a secure, password-protected state."""

    def __init__(self, log_func=None):
        self.log_func = log_func or logger.info
        self.os_type = platform.system()

    def apply_lockdown(self, unlock_key_hash: str):
        """
        Executes the lockdown sequence: 
        1. Sets the persistent unlock key.
        2. Triggers the OS sleep/hibernate command.
        """
        self.log_func("[SECURITY] Initiating Sovereign Lockdown Sequence...")
        
        # 1. Persist the lockdown state (so it survives reboot)
        self._set_lockdown_marker(unlock_key_hash)
        
        # 2. Trigger OS-specific lock/sleep
        try:
            if self.os_type == "Windows":
                # Force Hibernate (Preserves RAM for forensics)
                subprocess.run(["rundll32.exe", "powrprof.dll,SetSuspendState", "Hibernate", "Force"], check=False)
            elif self.os_type == "Linux":
                # Force Suspend/Hibernate
                subprocess.run(["systemctl", "suspend"], check=False)
            elif self.os_type == "Darwin":
                # macOS sleep
                subprocess.run(["pmset", "sleepnow"], check=False)
                
            self.log_func("[SUCCESS] System is now in Sovereign Lockdown.")
        except Exception as e:
            self.log_func(f"[ERROR] Lockdown trigger failed: {e}")

    def _set_lockdown_marker(self, key_hash: str):
        """Creates a persistent marker that the agent checks on boot."""
        marker_path = os.path.join(os.getcwd(), "data", ".sovereign_lock")
        try:
            import json
            data = {
                "hash": key_hash,
                "created_at": time.time()
            }
            with open(marker_path, "w") as f:
                f.write(json.dumps(data))
            # Hide and protect the file (Windows/Linux)
            if self.os_type == "Windows":
                subprocess.run(["attrib", "+H", "+S", "+R", marker_path], capture_output=True)
            else:
                os.chmod(marker_path, 0o400)
        except: pass

    def request_local_unlock(self) -> str:
        """[v2.6.0] Displays a native OS prompt to the user to enter the unlock key."""
        try:
            if self.os_type == "Windows":
                # PowerShell + VisualBasic interaction for a clean input dialog
                cmd = (
                    "Add-Type -AssemblyName Microsoft.VisualBasic; "
                    "[Microsoft.VisualBasic.Interaction]::InputBox("
                    "'CRITICAL: System in Sovereign Lockdown. Enter Unlock Key to regain access:', "
                    "'Monitorix Sovereign Security', '')"
                )
                res = subprocess.run(["powershell", "-Command", cmd], capture_output=True, text=True)
                return res.stdout.strip()
            
            elif self.os_type == "Darwin":
                # macOS AppleScript password dialog
                cmd = 'display dialog "Sovereign Lockdown Active.\n\nEnter Unlock Key:" default answer "" with title "Monitorix Security" with hidden answer'
                res = subprocess.run(["osascript", "-e", cmd], capture_output=True, text=True)
                # Output format: button returned:OK, text returned:your_pass
                if "text returned:" in res.stdout:
                    return res.stdout.split("text returned:")[1].strip()
            
            elif self.os_type == "Linux":
                # Linux is tricky without zenity. Fallback to a terminal-style input if possible
                pass
                
        except Exception as e:
            self.log_func(f"[ERROR] Local unlock prompt failed: {e}")
        return ""

    def power_off_system(self):
        """[v2.6.0] Forces a hard shutdown of the system (Neutralization)."""
        self.log_func("[SECURITY] Lockdown Timeout. Powering off system...")
        try:
            if self.os_type == "Windows":
                subprocess.run(["shutdown", "/s", "/f", "/t", "0"], check=False)
            elif self.os_type == "Linux" or self.os_type == "Darwin":
                subprocess.run(["shutdown", "-h", "now"], check=False)
        except Exception as e:
            self.log_func(f"[ERROR] Shutdown failed: {e}")

    def verify_unlock(self, provided_key: str):
        """Verifies a provided key against the stored sovereign hash with 5-minute TTL."""
        if not provided_key: return False
        
        marker_path = os.path.join(os.getcwd(), "data", ".sovereign_lock")
        if not os.path.exists(marker_path):
            return True # Not locked
            
        try:
            import hashlib
            import json
            with open(marker_path, "r") as f:
                content = f.read().strip()
                # Support both legacy (plain hash) and new (JSON) formats during migration
                try:
                    data = json.loads(content)
                    stored_hash = data.get("hash")
                    created_at = data.get("created_at", 0)
                except:
                    stored_hash = content
                    created_at = time.time() # Assume fresh if legacy
            
            # Check Expiration (5 Minute TTL from creation)
            if time.time() - created_at > 300:
                self.log_func("[SECURITY] Sovereign Key Expired. Local unlock no longer possible.")
                return False

            provided_hash = hashlib.sha256(provided_key.encode()).hexdigest()
            if provided_hash == stored_hash:
                os.remove(marker_path)
                return True
            return False
        except:
            return False

    def release_lock(self):
        """[v2.6.5] Remotely releases the lockdown by purging the marker file."""
        marker_path = os.path.join(os.getcwd(), "data", ".sovereign_lock")
        try:
            if os.path.exists(marker_path):
                # On Windows, we must strip attributes before deleting
                if self.os_type == "Windows":
                    subprocess.run(["attrib", "-H", "-S", "-R", marker_path], capture_output=True)
                os.remove(marker_path)
                self.log_func("[SECURITY] Sovereign Lockdown Released remotely by Administrator.")
                return True
        except Exception as e:
            self.log_func(f"[ERROR] Failed to release lockdown: {e}")
        return False

# Global instance
lockdown_engine = LockdownModule()
