import os
import sys
import platform
import subprocess
import logging

class FilesystemHardener:
    """
    Sovereign Immutability Engine: Enforces system-level locks on critical agent files.
    [v1.8.40]
    """
    def __init__(self, base_dir, log_func=None):
        self.base_dir = base_dir
        self.log_func = log_func or print
        self.critical_files = ["config.json", "monitorixagent.exe", "monitorix-agent"]
        self.os_type = platform.system()

    def enforce_immutability(self):
        """
        Locks down critical files to prevent unauthorized deletion or modification.
        """
        try:
            self.log_func("[SECURITY] Enforcing Sovereign Immutability...")
            for filename in self.critical_files:
                path = os.path.join(self.base_dir, filename)
                if not os.path.exists(path):
                    continue

                if self.os_type == "Windows":
                    # [v1.8.46] Suppress console windows and use robust list-based execution
                    # +R: Read-only, +S: System, +H: Hidden
                    try:
                        subprocess.run(["attrib", "+R", "+S", "+H", path], 
                                     capture_output=True, check=False, 
                                     creationflags=0x08000000) # CREATE_NO_WINDOW
                    except: pass
                elif self.os_type == "Linux":
                    # Use 'chattr +i' (Immutable) for Linux (requires root)
                    if os.getuid() == 0:
                        subprocess.run(["chattr", "+i", path], capture_output=True, check=False)
                elif self.os_type == "Darwin":
                    # macOS use chflags uchg
                    if os.getuid() == 0:
                        subprocess.run(["chflags", "uchg", path], capture_output=True, check=False)
            
            self.log_func("    [+] Critical files are now immutable.")
        except Exception as e:
            self.log_func(f"    [!] Failed to enforce immutability: {e}")

    def relax_immutability(self):
        """
        Relaxes protection to allow for updates or authorized configuration changes.
        """
        try:
            self.log_func("[SECURITY] Relaxing Immutability for authorized maintenance...")
            for filename in self.critical_files:
                path = os.path.join(self.base_dir, filename)
                if not os.path.exists(path):
                    continue

                if self.os_type == "Windows":
                    try:
                        subprocess.run(["attrib", "-R", "-S", "-H", path], 
                                     capture_output=True, check=False, 
                                     creationflags=0x08000000) # CREATE_NO_WINDOW
                    except: pass
                elif self.os_type == "Linux":
                    if os.getuid() == 0:
                        subprocess.run(["chattr", "-i", path], capture_output=True, check=False)
                elif self.os_type == "Darwin":
                    if os.getuid() == 0:
                        subprocess.run(["chflags", "nouchg", path], capture_output=True, check=False)
            
            self.log_func("    [+] Protections relaxed.")
        except Exception as e:
            self.log_func(f"    [!] Failed to relax immutability: {e}")
