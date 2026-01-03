
import os
import sys
import winreg
import shutil
from win32com.client import Dispatch

def install_chrome_policy():
    """
    Attempt to enforce extension via Registry (Enterprise Policy).
    Note: unlikely to work for unpacked extensions without Packing it first.
    For local dev, we modify the shortcut.
    """
    print("[*] Chrome Extension Installer (PoC)")
    
    ext_path = os.path.dirname(os.path.abspath(__file__))
    print(f"[*] Extension Path: {ext_path}")

    # Method 1: Modify Desktop Shortcuts to include --load-extension
    try:
        shell = Dispatch('WScript.Shell')
        desktop = shell.SpecialFolders("Desktop")
    except Exception as e:
        print(f"[-] WScript Error: {e}")
        return

    shortcuts_to_patch = ["Google Chrome.lnk", "Microsoft Edge.lnk", "Brave.lnk"]

    for lnk_name in shortcuts_to_patch:
        lnk_path = os.path.join(desktop, lnk_name)
        # Also check Public Desktop for all users
        try:
            public_desktop = os.path.join(os.environ['PUBLIC'], 'Desktop')
            public_lnk_path = os.path.join(public_desktop, lnk_name)
        except:
            public_lnk_path = ""

        target_lnk = None
        if os.path.exists(lnk_path): target_lnk = lnk_path
        elif public_lnk_path and os.path.exists(public_lnk_path): target_lnk = public_lnk_path

        if target_lnk:
            print(f"[*] Found Shortcut: {target_lnk}")
            try:
                shortcut = shell.CreateShortCut(target_lnk)
                target = shortcut.TargetPath
                args = shortcut.Arguments
                
                if "--load-extension" not in args:
                    new_args = f'{args} --load-extension="{ext_path}"'
                    shortcut.Arguments = new_args
                    shortcut.Save()
                    print(f"[+] Updated {lnk_name} to load extension.")
                else:
                    print(f"[-] {lnk_name} already modified.")
            except Exception as e:
                print(f"[-] Failed to modify {lnk_name}: {e}")
        else:
            print(f"[-] {lnk_name} not found on Desktop.")

    print("\n[!] To Apply Immediately: Close all Chrome/Edge windows and re-open using the Desktop Shortcut.")

if __name__ == "__main__":
    try:
        install_chrome_policy()
    except Exception as e:
        print(f"[-] Error: {e}")
