import os # type: ignore
import sys # type: ignore
import platform # type: ignore
import logging # type: ignore
import json # type: ignore
import subprocess # type: ignore

class BrowserEnforcer:
    def __init__(self):
        self.logger = logging.getLogger("BrowserEnforcer")
        self.os_type = platform.system()
        
        # Get absolute path of this file
        current_dir = os.path.dirname(os.path.abspath(__file__))
        # Go up two levels to agent root
        agent_root = os.path.dirname(os.path.dirname(current_dir))
        self.ext_path = os.path.join(agent_root, "chrome_ext")
        
        # Extension ID calculation is complex without key, assuming unpacked path used for now.
        # Ideally we install .crx, but unpacked load requires CLI flags or Policy.
        # Policy requires Extension ID for "ExtensionInstallForcelist".
        # For this implementation, we will stick to CLI flags/Shortcut patching on Windows
        # And Managed Policies on Linux/Mac if checking for unpacked path isn't feasible directly.
        # Actually, "ExtensionInstallLoadList" allows paths on Linux/Mac policies.
        
        self.shortcuts_to_patch = ["Google Chrome.lnk", "Microsoft Edge.lnk", "Brave.lnk"]

    def enforce(self):
        self.logger.info(f"Enforcing Browser Extension from: {self.ext_path}")
        
        if not os.path.exists(self.ext_path):
            self.logger.error(f"Extension path not found: {self.ext_path}")
            return

        if self.os_type == "Windows":
            self._enforce_windows()
        elif self.os_type == "Linux":
            self._enforce_linux()
        elif self.os_type == "Darwin":
            self._enforce_mac()

    def stop(self):
        self.logger.info("Stopping Browser Enforcement.")
        # Currently, browser policies are persistent until overridden.
        # We could potentially remove the policy files here if stricter enforcement is needed.
        pass

    def _enforce_windows(self):
        try:
            from win32com.client import Dispatch # type: ignore
            shell = Dispatch('WScript.Shell')
        except Exception as e:
            self.logger.error(f"Failed to access WScript.Shell: {e}")
            return

        # Define paths to scan dynamically using the shell object
        try:
            paths_to_scan = [
                shell.SpecialFolders("Desktop"),
                os.path.join(os.environ['PUBLIC'], 'Desktop'),
                os.path.join(os.environ['ProgramData'], 'Microsoft', 'Windows', 'Start Menu', 'Programs'),
                os.path.join(os.environ['APPDATA'], 'Microsoft', 'Windows', 'Start Menu', 'Programs'),
                os.path.join(os.environ['APPDATA'], 'Microsoft', 'Internet Explorer', 'Quick Launch', 'User Pinned', 'TaskBar')
            ]
        except Exception as e:
             self.logger.error(f"Error resolving paths: {e}")
             paths_to_scan = []

        for folder in paths_to_scan:
            if not os.path.exists(folder): continue
            for lnk_name in self.shortcuts_to_patch:
                self._patch_shortcut(shell, folder, lnk_name)

    def _patch_shortcut(self, shell, folder, lnk_name):
        lnk_path = os.path.join(folder, lnk_name)
        if not os.path.exists(lnk_path):
            return

        try:
            # self.logger.info(f"Checking Shortcut: {lnk_path}")
            shortcut = shell.CreateShortCut(lnk_path)
            args = shortcut.Arguments
            
            # Check if our extension is already loaded
            if self.ext_path not in args:
                if "--load-extension" in args:
                    # Already has an extension flag
                    pass
                else:
                    new_args = f'{args} --load-extension="{self.ext_path}"'
                    shortcut.Arguments = new_args
                    shortcut.Save()
                    self.logger.info(f"[+] Patched {lnk_name}")
                    print(f"[+] Enforced Extension on: {lnk_name}")
        except Exception as e:
            self.logger.debug(f"Failed to patch {lnk_name}: {e}")

    def _enforce_linux(self):
        # Linux: Use Managed Policies which work nicely on Chrome/Edge
        # Targets:
        # Chrome: /etc/opt/chrome/policies/managed/
        # Edge: /etc/opt/edge/policies/managed/
        # Chromium: /etc/chromium/policies/managed/
        
        policies = {
            "ExtensionSettings": {
                # We can't force install unpacked via ID easily without hosting an Update URL.
                # However, we CAN allow-list it if we had an ID. 
                # For this agent, we will assume the User will install the extension, 
                # but we try to 'Configure' it if installed.
                
                # ALTERNATIVE: Use `ExtensionInstallSources` to allow local file installation
                "*": {
                    "installation_mode": "allowed",
                    "blocked_install_message": "Policy enforced by Monitorix Agent"
                }
            },
            # If we had a CRX hosted on localhost or internal server:
            # "ExtensionInstallForcelist": ["<id>;http://localhost:port/updates.xml"]
        }

        paths = [
            "/etc/opt/chrome/policies/managed",
            "/etc/opt/edge/policies/managed", 
            "/etc/chromium/policies/managed"
        ]

        # Note: This requires Root. If running as User, this will fail.
        # Fallback: Create a Desktop Entry override in ~/.local/share/applications/
        
        if platform.system() != "Windows" and os.geteuid() == 0: # type: ignore
            for path in paths:
                try:
                    if not os.path.exists(path):
                        os.makedirs(path, exist_ok=True)
                    
                    policy_file = os.path.join(path, "monitorix_policy.json")
                    with open(policy_file, "w") as f:
                        json.dump(policies, f, indent=2)
                    self.logger.info(f"Linux Policy written to {policy_file}")
                except Exception as e:
                    self.logger.error(f"Failed to write Linux Policy to {path}: {e}")
        else:
            self.logger.warning("Linux: Not root. Cannot write global browser policies. Attempting User-mode shortcuts...")
            # User-mode: Append flag to ~/.local/share/applications/*.desktopExec
            # Complex, skipping for stability.

    def _enforce_mac(self):
        # macOS: Use 'defaults write' to enforce Managed Preference
        # Target: com.google.Chrome, com.microsoft.Edge
        
        # Like Linux, forcing unpacked is hard. We can force-enable if ID is known.
        # Command: defaults write com.google.Chrome ExtensionInstallSources -array "file:///*"
        
        browsers = ["com.google.Chrome", "com.microsoft.Edge"]
        
        for bundle_id in browsers:
            try:
                # Allow installing from file system (helper for manual install)
                subprocess.run(["defaults", "write", bundle_id, "ExtensionInstallSources", "-array", "file:///*"], capture_output=True)
                
                # If we had an extension ID, we could force it:
                # subprocess.run(["defaults", "write", bundle_id, "ExtensionInstallForcelist", "-array", f"{EXT_ID};file://{self.ext_path}"], ...)
                
                self.logger.info(f"macOS: Updated defaults for {bundle_id}")
            except Exception as e:
                self.logger.error(f"macOS Enforce Error {bundle_id}: {e}")
