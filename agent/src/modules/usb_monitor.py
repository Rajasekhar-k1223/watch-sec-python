import platform # type: ignore
import os # type: ignore
import subprocess # type: ignore
import logging # type: ignore
import threading # type: ignore
import json # type: ignore
import time # type: ignore
from datetime import datetime # type: ignore

# Platform specific imports
try:
    import wmi # type: ignore
    import pythoncom # type: ignore
    import winreg # type: ignore
except ImportError:
    wmi = None
    pythoncom = None
    winreg = None

class UsbMonitorStrategy:
    def __init__(self, agent_id, api_key, backend_url, interval=5, data_queue=None, on_mount=None, on_unmount=None):
        self.agent_id = agent_id
        self.api_key = api_key
        self.backend_url = backend_url
        self.interval = interval
        self.data_queue = data_queue
        self.on_mount = on_mount 
        self.on_unmount = on_unmount
        self.running = False
        self.logger = logging.getLogger(self.__class__.__name__)
        self.policy = "Allow"
        self.known_devices = set()

    def set_policy(self, policy):
        self.policy = policy
        self.logger.info(f"Policy Updated: {self.policy}")
        self.enforce_policy()

    def enforce_policy(self):
        pass

    def start(self):
        if self.running: return
        self.running = True
        self.thread = threading.Thread(target=self._loop, daemon=True)
        self.thread.start()
        self.logger.info("Monitor Started")

    def stop(self):
        if not self.running: return
        self.running = False
        # Reset policy to Allow on stop to avoid leaving system in blocked state
        self.set_policy("Allow")
        if hasattr(self, 'thread'):
            self.thread.join(timeout=1)
        self.logger.info("Monitor Stopped")

    def _loop(self):
        raise NotImplementedError

    def _send_alert(self, event_type, details):
        payload = {
            "AgentId": self.agent_id,
            "TenantApiKey": self.api_key, # Added
            "Type": event_type,
            "Details": details,
            "Timestamp": datetime.utcnow().isoformat()
        }
        
        if self.data_queue:
            self.data_queue.enqueue("/api/events/report", payload, priority='high')
        else:
            self.logger.error(f"[USB] [ERROR] No DataQueue available to report: {event_type}")

# --- Windows Strategy ---
class WindowsUsbStrategy(UsbMonitorStrategy):
    def enforce_policy(self):
        if not winreg: return
        try:
            # HKLM\SYSTEM\CurrentControlSet\Services\USBSTOR
            # Start = 3 (Enabled), 4 (Disabled)
            req_value = 4 if self.policy == "Block" else 3
            key_path = r"SYSTEM\CurrentControlSet\Services\USBSTOR"
            
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_SET_VALUE) # type: ignore
            winreg.SetValueEx(key, "Start", 0, winreg.REG_DWORD, req_value) # type: ignore
            winreg.CloseKey(key) # type: ignore
            self.logger.info(f"Registry Policy Applied: Start={req_value}")
            self._send_alert("POLICY_APPLIED", f"USB Policy set to: {self.policy}")
            self.logger.info(f"Registry Policy Applied: Start={req_value}")
        except PermissionError:
            curr_state = self._read_current_policy()
            self.logger.warning(f"Failed to set Registry Policy: Access Denied. (Run as Admin). Current System Policy: {curr_state}")
        except Exception as e:
            if "Access is denied" in str(e):
                 curr_state = self._read_current_policy()
                 self.logger.warning(f"Failed to set Registry Policy: Access Denied. (Run as Admin). Current System Policy: {curr_state}")
            else:
                 self.logger.error(f"Failed to set Registry Policy: {e}")
                 self._send_alert("MODULE_ERROR", f"USB Monitor failed to apply policy: {e}")

    def _read_current_policy(self):
        try:
            key_path = r"SYSTEM\CurrentControlSet\Services\USBSTOR"
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_READ) # type: ignore
            val, _ = winreg.QueryValueEx(key, "Start") # type: ignore
            winreg.CloseKey(key) # type: ignore
            # 3 = Enabled (Allowed), 4 = Disabled (Blocked)
            return "BLOCKED" if val == 4 else "ALLOWED"
        except Exception as e:
            return f"Unknown ({e})"

    def _get_connected_drives(self, c):
        devices = []
        try:
            for drive in c.Win32_DiskDrive(InterfaceType="USB"):
                # Find Mount Point (Drive Letter)
                mount_point = None
                try:
                    # Association sequence: DiskDrive -> Partition -> LogicalDisk
                    for partition in drive.associators("Win32_DiskDriveToDiskPartition"):
                        for logical_disk in partition.associators("Win32_LogicalDiskToPartition"):
                            mount_point = logical_disk.DeviceID
                            break
                except: pass
                
                devices.append({
                    "id": drive.DeviceID,
                    "name": drive.Caption,
                    "serial": getattr(drive, 'SerialNumber', 'Unknown'),
                    "mount_point": mount_point
                })
        except: pass
        return devices

    def _loop(self):
        if not wmi or not pythoncom:
            self.logger.error("Windows dependencies missing.")
            return

        pythoncom.CoInitialize() # type: ignore
        c = wmi.WMI() # type: ignore
        
        initial_drives = self._get_connected_drives(c)
        self.known_devices = {d["id"] for d in initial_drives}
        
        while self.running:
            try:
                current_drives = self._get_connected_drives(c)
                current_ids = {d["id"] for d in current_drives}
                
                # Insertions
                new_ids = current_ids - self.known_devices
                for dev_id in new_ids:
                    details = next((d for d in current_drives if d["id"] == dev_id), None)
                    if details:
                        self.logger.info(f"INSERTED: {details['name']} (Mount: {details.get('mount_point')})")
                        self._send_alert("USB_INSERTION", f"Device Connected: {details['name']} at {details.get('mount_point', 'Unknown')}")
                        
                        if details.get("mount_point") and self.on_mount:
                             self.on_mount(details["mount_point"])

                        if self.policy == "Block":
                            self._send_alert("USB_BLOCKED", f"Blocked Policy Prevented Access: {details['name']}")
                            if details.get("mount_point"):
                                self._block_device(details["mount_point"])

                # Removals
                removed_ids = self.known_devices - current_ids
                for dev_id in removed_ids:
                    self.logger.info(f"REMOVED: {dev_id}")
                    self._send_alert("USB_REMOVAL", f"Device Removed: {dev_id}")

                self.known_devices = current_ids
            except Exception as e:
                self.logger.error(f"Loop Error: {e}")
            
            time.sleep(self.interval)
        
        pythoncom.CoUninitialize() # type: ignore

    def _block_device(self, mount_point):
         """Force eject a USB drive on Windows."""
         try:
             self.logger.info(f"Attempting to eject blocked device at {mount_point}...")
             # Use PowerShell COM to Eject safely
             cmd = f'powershell -Command "(New-Object -com Shell.Application).NameSpace(17).ParseName(\'{mount_point}\').InvokeVerb(\'Eject\')"'
             subprocess.run(cmd, shell=True, capture_output=True)
             
             # Fallback: mountvol to dismount if eject fails or isn't enough
             subprocess.run(f"mountvol {mount_point} /D", shell=True, capture_output=True)
             
             self.logger.info(f"Ejection command sent for {mount_point}")
         except Exception as e:
             self.logger.error(f"Ejection failed: {e}")

# --- Linux Strategy ---
class LinuxUsbStrategy(UsbMonitorStrategy):
    def enforce_policy(self):
        # Linux USB Blocking via sysfs
        # /sys/bus/usb/devices/*/authorized = 0
        pass 

    def _get_usb_devices(self):
        devices = []
        try:
            # lsblk -J -o NAME,TRAN,MODEL,SERIAL
            cmd = ["lsblk", "-J", "-o", "NAME,TRAN,MODEL,SERIAL,MOUNTPOINT"]
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode == 0:
                data = json.loads(result.stdout)
                for dev in data.get("blockdevices", []):
                    if dev.get("tran") == "usb":
                        devices.append({
                            "id": dev.get("name"), # sdb
                            "name": f"{dev.get('model')} ({dev.get('name')})",
                            "serial": dev.get("serial"),
                            "mount_point": dev.get("mountpoint")
                        })
        except Exception as e:
            # self.logger.error(f"lsblk error: {e}")
            pass
        return devices

    def _loop(self):
        initial = self._get_usb_devices()
        self.known_devices = {d["id"] for d in initial}
        
        while self.running:
            try:
                current = self._get_usb_devices()
                current_ids = {d["id"] for d in current}
                
                # Insertions
                new_ids = current_ids - self.known_devices
                for dev_id in new_ids:
                    details = next((d for d in current if d["id"] == dev_id), None)
                    if details:
                        self.logger.info(f"INSERTED: {details['name']} (Mount: {details.get('mount_point')})")
                        self._send_alert("USB_INSERTION", f"Device Connected: {details['name']} at {details.get('mount_point', 'Unknown')}")
                        
                        if details.get("mount_point") and self.on_mount:
                             self.on_mount(details["mount_point"])
                        
                        if self.policy == "Block":
                            # Attempt unmount/block
                            self._block_device(dev_id)

                # Removals
                removed_ids = self.known_devices - current_ids
                for dev_id in removed_ids:
                    self.logger.info(f"REMOVED: {dev_id}")
                    self._send_alert("USB_REMOVAL", f"Device Removed: {dev_id}")

                self.known_devices = current_ids
            except Exception as e:
                self.logger.error(f"Loop Error: {e}")
            
            time.sleep(self.interval)

    def _block_device(self, dev_id):
        # Linux Blocking via USB Authorization (Kernel Level)
        # dev_id from lsblk usually is 'sdb'. We need the usb tree path like '2-1'.
        # Easier: Unmount and Remove.
        try:
            self.logger.info(f"Blocking {dev_id} on Linux...")
            
            # 1. Unmount first
            subprocess.run(["umount", f"/dev/{dev_id}"], capture_output=True)
            
            # 2. Find the USB device path to disable 'authorized'
            # This is complex to map 'sdb' -> 'usb1/...'
            # Fallback: 'eject' command which usually sends SCSI Force Eject
            subprocess.run(["eject", f"/dev/{dev_id}"], capture_output=True)
            
            self._send_alert("USB_BLOCKED", f"Ejected/Unmounted Device: {dev_id}")
            self.logger.info(f"Blocked {dev_id} successfully.")
        except Exception as e:
            self.logger.error(f"Linux Block Error: {e}")

# --- macOS Strategy ---
class MacUsbStrategy(UsbMonitorStrategy):
    def enforce_policy(self):
        pass # No global registry switch like Windows

    def _get_external_disks(self):
        devices = []
        try:
            # List only external disks (proxy for removable USB/Thunderbolt)
            cmd = ["diskutil", "list", "-plist", "external"]
            result = subprocess.run(cmd, capture_output=True)
            if result.returncode == 0:
                import plistlib # type: ignore
                data = plistlib.loads(result.stdout)
                
                # Structure: dict with 'AllDisksAndPartitions' -> list of dicts
                for disk in data.get("AllDisksAndPartitions", []):
                     dev_id = disk.get("DeviceIdentifier") # e.g. disk2
                     size = disk.get("Size", 0)
                     mount_point = disk.get("MountPoint")
                     
                     devices.append({
                         "id": dev_id,
                         "name": f"External Disk {dev_id} ({size // (1024*1024)} MB)",
                         "serial": "Unknown",
                         "mount_point": mount_point
                     })
        except Exception as e:
            # self.logger.error(f"Mac detection error: {e}")
            pass
        return devices

    def _loop(self):
        initial = self._get_external_disks()
        self.known_devices = {d["id"] for d in initial}
        
        while self.running:
            try:
                current = self._get_external_disks()
                current_ids = {d["id"] for d in current}
                
                # Insertions
                new_ids = current_ids - self.known_devices
                for dev_id in new_ids:
                     details = next((d for d in current if d["id"] == dev_id), None)
                     if details:
                         self.logger.info(f"INSERTED: {dev_id} (Mount: {details.get('mount_point')})")
                         self._send_alert("USB_INSERTION", f"Device Connected: {dev_id} at {details.get('mount_point', 'Unknown')}")
                         
                         if details.get("mount_point") and self.on_mount:
                             self.on_mount(details["mount_point"])
                     
                     if self.policy == "Block":
                         self._block_device(dev_id)

                # Removals
                removed_ids = self.known_devices - current_ids
                for dev_id in removed_ids:
                     self.logger.info(f"REMOVED: {dev_id}")
                     self._send_alert("USB_REMOVAL", f"Device Removed: {dev_id}")

                self.known_devices = current_ids
            except Exception as e:
                self.logger.error(f"Loop error: {e}")
            
            time.sleep(self.interval) # Slower implementation

    def _block_device(self, dev_id):
        self.logger.info(f"Blocking (Ejecting) {dev_id}...")
        try:
            # force unmount and eject
            subprocess.run(["diskutil", "unmountDisk", "force", f"/dev/{dev_id}"], capture_output=True)
            subprocess.run(["diskutil", "eject", f"/dev/{dev_id}"], capture_output=True)
            self._send_alert("USB_BLOCKED", f"Ejected Device: {dev_id}")
        except Exception as e:
             self.logger.error(f"Eject failed: {e}")

        
# --- Facade ---
class UsbMonitor:
    def __init__(self, agent_id, api_key, backend_url, data_queue=None, interval=5, on_mount=None, on_unmount=None):
        self.strategy = None
        os_type = platform.system()
        
        if os_type == "Windows":
            self.strategy = WindowsUsbStrategy(agent_id, api_key, backend_url, interval, data_queue, on_mount, on_unmount)
        elif os_type == "Linux":
            self.strategy = LinuxUsbStrategy(agent_id, api_key, backend_url, interval, data_queue, on_mount, on_unmount)
        elif os_type == "Darwin":
            self.strategy = MacUsbStrategy(agent_id, api_key, backend_url, interval, data_queue, on_mount, on_unmount)
        else:
            print(f"[UsbMonitor] Unsupported Platform: {os_type}")

    def set_policy(self, policy):
        if self.strategy:
            self.strategy.set_policy(policy)

    @property
    def running(self):
        return self.strategy.running if self.strategy else False

    def start(self):
        if self.strategy:
            self.strategy.start()

    def stop(self):
        if self.strategy:
            self.strategy.stop()
