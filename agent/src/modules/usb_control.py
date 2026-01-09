import sys
import platform
import os
import subprocess

class UsbControl:
    def __init__(self):
        self.os_type = platform.system()

    def set_usb_write_protect(self, enable: bool):
        if self.os_type == "Windows":
            return self._set_windows(enable)
        elif self.os_type == "Linux":
            return self._set_linux(enable)
        elif self.os_type == "Darwin":
             return False, "macOS USB Control not supported (Requires System Extension)"
        else:
            return False, f"Unsupported OS: {self.os_type}"

    def _set_windows(self, enable: bool):
        try:
            import winreg
            # Registry Path for USB Storage Policies
            key_path = r"SYSTEM\CurrentControlSet\Control\StorageDevicePolicies"
            
            # Open or Create Key
            try:
                registry_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_WRITE)
            except FileNotFoundError:
                # Create if missing
                registry_key = winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, key_path)
            
            # Set Value (1 = Read Only / Block Write, 0 = Normal)
            val = 1 if enable else 0
            winreg.SetValueEx(registry_key, "WriteProtect", 0, winreg.REG_DWORD, val)
            winreg.CloseKey(registry_key)
            
            action = "Blocked" if enable else "Allowed"
            return True, f"USB Write Access {action}"
            
        except PermissionError:
            return False, "Access Denied (Run as Admin)"
        except ImportError:
             return False, "winreg module missing"
        except Exception as e:
            return False, str(e)

    def _set_linux(self, enable: bool):
        # Using udev rules to block USB storage
        # Rule: ACTION=="add", SUBSYSTEMS=="usb", DRIVERS=="usb-storage", RUN+="/bin/sh -c 'echo 0 > /sys/$env{DEVPATH}/authorized'"
        # Simplified approach: Block loading of usb-storage module or use authorized attribute
        
        rule_file = "/etc/udev/rules.d/99-block-usb-storage.rules"
        # Stronger blocking: authorize = 0 for usb-storage devices
        block_content = 'ACTION=="add", SUBSYSTEM=="usb", DRIVER=="usb-storage", ATTR{authorized}="0"\n'
        
        try:
            if enable:
                # Write rule
                with open(rule_file, "w") as f:
                    f.write(block_content)
                msg = "USB Storage Blocked (udev rule created)"
            else:
                # Remove rule
                if os.path.exists(rule_file):
                    os.remove(rule_file)
                msg = "USB Storage Allowed (udev rule removed)"
            
            # Reload rules
            subprocess.run(["udevadm", "control", "--reload-rules"], check=False)
            subprocess.run(["udevadm", "trigger"], check=False)
            return True, msg
        except PermissionError:
            return False, "Root required for udev rules"
        except Exception as e:
            return False, str(e)

