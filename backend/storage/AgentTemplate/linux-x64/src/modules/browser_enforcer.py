import os
import sys
import platform
import logging
import json
import subprocess

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
        # Configure Managed Policies for Chrome/Chromium
        # /etc/opt/chrome/policies/managed/monitorix.json
        policy_dir = "/etc/opt/chrome/policies/managed"
        policy_file = os.path.join(policy_dir, "monitorix_policy.json")
        
        # NOTE: ExtensionInstallLoadList allows loading unpacked extensions on Linux
        # BUT it is often restricted to unstable/dev channels unless machine is joined to domain.
        # Fallback to creating a wrapper script for chrome if policy fails? 
        # For now, write the policy.
        
        policy_data = {
            "CommandLineFlagSecurityWarningsEnabled": False,
            "ExtensionInstallForcelist": [
                # Ideally we build a .crx and host it, or submit to webstore. 
                # Unpacked loading via policy 'ExtensionSettings' might be possible.
            ]
        }
        
        # Since we only have unpacked source, we can't easily force install via ID without a CRX.
        # We will fallback to a simpler warning message for now, or try to append flags to launchers.
        # Appending flags to /usr/bin/google-chrome wrapper is risky.
        
        self.logger.info("Linux: Browser Enforcement via Policy requires a packed CRX. Partial support.")

    def _enforce_mac(self):
        # Use defaults write to set policies
        # defaults write com.google.Chrome ExtensionInstallForcelist ...
        self.logger.info("macOS: Browser Enforcement via 'defaults write' requires packed CRX/ID.")
