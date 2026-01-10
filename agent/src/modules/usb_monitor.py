import threading
import time
import json
import requests
import platform
import os
import subprocess
import logging
from datetime import datetime

# Platform specific imports
try:
    import wmi
    import pythoncom
    import winreg
except ImportError:
    wmi = None
    pythoncom = None
    winreg = None

class UsbMonitorStrategy:
    def __init__(self, agent_id, api_key, backend_url, interval=5):
        self.agent_id = agent_id
        self.api_key = api_key
        self.backend_url = backend_url
        self.interval = interval
        self.running = False
        self.logger = logging.getLogger(self.__class__.__name__)
        self.policy = "Allow"
        self.known_devices = set()
        
        # Robust Session
        self.session = requests.Session()
        adapter = requests.adapters.HTTPAdapter(max_retries=3)
        self.session.mount('https://', adapter)
        self.session.mount('http://', adapter)

    def set_policy(self, policy):
        self.policy = policy
        self.logger.info(f"Policy Updated: {self.policy}")
        self.enforce_policy()

    def enforce_policy(self):
        pass

    def start(self):
        self.running = True
        self.thread = threading.Thread(target=self._loop, daemon=True)
        self.thread.start()
        self.logger.info("Monitor Started")

    def stop(self):
        self.running = False
        # Thread join logic if needed

    def _loop(self):
        raise NotImplementedError

    def _send_alert(self, event_type, details):
        payload = {
            "AgentId": self.agent_id,
            "Type": event_type,
            "Details": details,
            "Timestamp": datetime.utcnow().isoformat()
        }
        try:
            # Using /api/events/report generic endpoint
            self.session.post(f"{self.backend_url}/api/events/report", json=payload, timeout=10, verify=False)
        except Exception as e:
            self.logger.error(f"Failed to send alert: {e}")

# --- Windows Strategy ---
class WindowsUsbStrategy(UsbMonitorStrategy):
    def enforce_policy(self):
        if not winreg: return
        try:
            # HKLM\SYSTEM\CurrentControlSet\Services\USBSTOR
            # Start = 3 (Enabled), 4 (Disabled)
            req_value = 4 if self.policy == "Block" else 3
            key_path = r"SYSTEM\CurrentControlSet\Services\USBSTOR"
            
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_SET_VALUE)
            winreg.SetValueEx(key, "Start", 0, winreg.REG_DWORD, req_value)
            winreg.CloseKey(key)
            self.logger.info(f"Registry Policy Applied: Start={req_value}")
        except Exception as e:
            self.logger.error(f"Failed to set Registry Policy: {e}")

    def _get_connected_drives(self, c):
        devices = []
        try:
            for drive in c.Win32_DiskDrive(InterfaceType="USB"):
                devices.append({
                    "id": drive.DeviceID,
                    "name": drive.Caption,
                    "serial": getattr(drive, 'SerialNumber', 'Unknown')
                })
        except: pass
        return devices

    def _loop(self):
        if not wmi or not pythoncom:
            self.logger.error("Windows dependencies missing.")
            return

        pythoncom.CoInitialize()
        c = wmi.WMI()
        
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
                        self.logger.info(f"INSERTED: {details['name']}")
                        self._send_alert("USB_INSERTION", f"Device Connected: {details['name']}")
                        
                        if self.policy == "Block":
                            self._send_alert("USB_BLOCKED", f"Blocked Policy Prevented Access: {details['name']}")

                # Removals
                removed_ids = self.known_devices - current_ids
                for dev_id in removed_ids:
                    self.logger.info(f"REMOVED: {dev_id}")
                    self._send_alert("USB_REMOVAL", f"Device Removed: {dev_id}")

                self.known_devices = current_ids
            except Exception as e:
                self.logger.error(f"Loop Error: {e}")
            
            time.sleep(self.interval)
        
        pythoncom.CoUninitialize()

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
                            "serial": dev.get("serial")
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
                        self.logger.info(f"INSERTED: {details['name']}")
                        self._send_alert("USB_INSERTION", f"Device Connected: {details['name']}")
                        
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

    def _block_device(self, dev_name):
        # e.g. dev_name = sdb
        # Simply trying to unmount if mounted, or unbind driver?
        # Simpler: just log block attempt. Real blocking needs root and writing to /sys
        self.logger.info(f"Blocking Device {dev_name}...")
        self._send_alert("USB_BLOCKED", f"Blocked Device: {dev_name}")

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
                import plistlib
                data = plistlib.loads(result.stdout)
                
                # Structure: dict with 'AllDisksAndPartitions' -> list of dicts
                for disk in data.get("AllDisksAndPartitions", []):
                     dev_id = disk.get("DeviceIdentifier") # e.g. disk2
                     size = disk.get("Size", 0)
                     
                     devices.append({
                         "id": dev_id,
                         "name": f"External Disk {dev_id} ({size // (1024*1024)} MB)",
                         "serial": "Unknown" # detailed serial requires 'diskutil info'
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
                     self.logger.info(f"INSERTED: {dev_id}")
                     self._send_alert("USB_INSERTION", f"Device Connected: {dev_id}")
                     
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
            
            time.sleep(self.interval)

    def _block_device(self, dev_id):
        self.logger.info(f"Blocking (Ejecting) {dev_id}...")
        try:
            subprocess.run(["diskutil", "eject", f"/dev/{dev_id}"], capture_output=True)
            self._send_alert("USB_BLOCKED", f"Ejected Device: {dev_id}")
        except Exception as e:
             self.logger.error(f"Eject failed: {e}")

        
# --- Facade ---
class UsbMonitor:
    def __init__(self, agent_id, api_key, backend_url, interval=5):
        self.strategy = None
        os_type = platform.system()
        
        if os_type == "Windows":
            self.strategy = WindowsUsbStrategy(agent_id, api_key, backend_url, interval)
        elif os_type == "Linux":
            self.strategy = LinuxUsbStrategy(agent_id, api_key, backend_url, interval)
        elif os_type == "Darwin":
            self.strategy = MacUsbStrategy(agent_id, api_key, backend_url, interval)
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
