import os
import sys
import logging
import platform

class BrowserEnforcer:
    def __init__(self):
        self.logger = logging.getLogger("BrowserEnforcer")
        
        # Get absolute path of this file
        current_dir = os.path.dirname(os.path.abspath(__file__))
        # Go up two levels to agent root
        agent_root = os.path.dirname(os.path.dirname(current_dir))
        self.ext_path = os.path.join(agent_root, "chrome_ext")
        
        self.shortcuts_to_patch = ["Google Chrome.lnk", "Microsoft Edge.lnk", "Brave.lnk"]

    def enforce(self):
        if platform.system() != "Windows":
            return

        try:
            from win32com.client import Dispatch
        except ImportError:
            self.logger.warning("win32com not found. Browser enforcement disabled.")
            return

        self.logger.info(f"Enforcing Browser Extension from: {self.ext_path}")
        
        if not os.path.exists(self.ext_path):
            self.logger.error(f"Extension path not found: {self.ext_path}")
            return

        try:
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
                    # Already has an extension flag, complicated to merge. 
                    # For now, skip to avoid breaking existing setups.
                    pass
                else:
                    new_args = f'{args} --load-extension="{self.ext_path}"'
                    shortcut.Arguments = new_args
                    shortcut.Save()
                    self.logger.info(f"[+] Patched {lnk_name}")
                    print(f"[+] Enforced Extension on: {lnk_name}")
            else:
                pass
                # self.logger.debug(f"Shortcut {lnk_name} already authentic.")
        except Exception as e:
            # Downgrade to debug to avoid scary logs for Standard Users
            self.logger.debug(f"Failed to patch {lnk_name}: {e}")
