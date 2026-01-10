import winreg
import sys
import platform

class UsbControl:
    def __init__(self):
        self.os_type = platform.system()

    def set_usb_write_protect(self, enable: bool):
        if self.os_type != "Windows":
            return False, "Only supported on Windows"

        try:
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
        except Exception as e:
            return False, str(e)
