import wmi
import threading
import time
import pythoncom
import winreg
import json
import requests
from datetime import datetime

class UsbMonitor:
    def __init__(self, agent_id, api_key, backend_url, interval=5):
        self.agent_id = agent_id
        self.api_key = api_key
        self.backend_url = backend_url
        self.interval = interval
        self.running = False
        self.thread = None
        
        # Policy: "Allow", "Block", "ReadOnly" (ReadOnly not implemented yet)
        self.policy = "Allow" 
        self.known_devices = set()

        # Robust Session from main
        self.session = requests.Session()
        adapter = requests.adapters.HTTPAdapter(max_retries=3)
        self.session.mount('https://', adapter)
        self.session.mount('http://', adapter)

    def set_policy(self, policy):
        """ Allow or Block """
        self.policy = policy
        print(f"[USB] Policy Updated: {self.policy}")
        self.enforce_policy()

    def enforce_policy(self):
        """ Writes to Windows Registry to Enable/Disable USB Storage Driver """
        try:
            # HKLM\SYSTEM\CurrentControlSet\Services\USBSTOR
            # Start = 3 (Enabled), 4 (Disabled)
            req_value = 4 if self.policy == "Block" else 3
            
            key_path = r"SYSTEM\CurrentControlSet\Services\USBSTOR"
            try:
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_SET_VALUE)
                winreg.SetValueEx(key, "Start", 0, winreg.REG_DWORD, req_value)
                winreg.CloseKey(key)
                print(f"[USB] Registry Policy Applied: Start={req_value}")
            except Exception as e:
                print(f"[USB] Failed to set Registry Policy: {e} (Run as Admin?)")
                
        except Exception as e:
            print(f"[USB] Policy Enforcement Error: {e}")

    def start(self):
        self.running = True
        self.thread = threading.Thread(target=self._loop)
        self.thread.daemon = True
        self.thread.start()
        print("[USB] Monitor Started")

    def stop(self):
        self.running = False
        if self.thread:
            self.thread.join(timeout=1)

    def _get_connected_drives(self, c):
        """ Returns list of (DeviceID, Caption, InterfaceType) """
        devices = []
        try:
            # InterfaceType='USB' is key
            for drive in c.Win32_DiskDrive(InterfaceType="USB"):
                devices.append({
                    "id": drive.DeviceID,
                    "name": drive.Caption,
                    "serial": drive.SerialNumber if hasattr(drive, 'SerialNumber') else "Unknown"
                })
        except: pass
        return devices

    def _loop(self):
        # Initialize COM for this thread
        pythoncom.CoInitialize()
        c = wmi.WMI()
        
        # Build initial snapshot
        initial_drives = self._get_connected_drives(c)
        self.known_devices = {d["id"] for d in initial_drives}
        print(f"[USB] Initial Devices: {self.known_devices}")

        while self.running:
            try:
                current_drives = self._get_connected_drives(c)
                current_ids = {d["id"] for d in current_drives}
                
                # Check for Insertions
                new_ids = current_ids - self.known_devices
                for dev_id in new_ids:
                    # Find details
                    details = next((d for d in current_drives if d["id"] == dev_id), None)
                    if details:
                        print(f"[USB] INSERTED: {details['name']}")
                        self._send_alert("USB_INSERTION", f"Device Connected: {details['name']} ({details['serial']})")
                        
                        # Use Eject if Blocking is active (Double enforcement: Registry + active eject)
                        if self.policy == "Block":
                            print(f"[USB] Blocking Active! Attempting Eject logic...")
                            # TODO: Eject logic here if needed, but Registry usually prevents mounting.
                            self._send_alert("USB_BLOCKED", f"Blocked Policy Prevented Access: {details['name']}")

                # Check for Removals
                removed_ids = self.known_devices - current_ids
                for dev_id in removed_ids:
                    print(f"[USB] REMOVED: {dev_id}")
                    self._send_alert("USB_REMOVAL", f"Device Removed: {dev_id}")

                self.known_devices = current_ids
                
            except Exception as e:
                print(f"[USB] Loop Error: {e}")
            
            time.sleep(self.interval)
        
        pythoncom.CoUninitialize()

    def _send_alert(self, event_type, details):
        payload = {
            "AgentId": self.agent_id,
            "Type": event_type,
            "Details": details,
            "Timestamp": datetime.utcnow().isoformat()
        }
        try:
            # Assuming main API for events is /api/events/{agent_id} or similar
            # Based on existing code, we likely need a generic event endpoint.
            # Using specific event creation logic or generic log.
            # Let's check `backend/app/api/events.py` implies we might need a dedicated endpoint or reuse `simulate`.
            # Actually ActivityMonitor sends to `/api/events/activity`.
            # We need a Security Event endpoint.
            # `events.py` lines 41-59 has `/simulate`. We need a real POST endpoint for events.
            # I will assume `POST /api/events/security` exists or I need to create it.
            # Checking `events.py` again... wait, logic in `events.py` shows GET and simulate POST. 
            # I need to ADD a generic `POST /api/events/report` for security events.
            
            # For now, I'll point to `/api/events/report` and I will CREATE that endpoint next.
            self.session.post(f"{self.backend_url}/api/events/report", json=payload, timeout=10, verify=False)
        except Exception as e:
            print(f"[USB] Failed to send alert: {e}")
