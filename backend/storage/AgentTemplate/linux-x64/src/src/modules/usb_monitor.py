import logging
import threading
import time
import pythoncom
import wmi
import winreg
import json

class USBMonitor:
    def __init__(self, sio_client, agent_id):
        self.sio = sio_client
        self.agent_id = agent_id
        self.logger = logging.getLogger("USBMonitor")
        self.running = False
        self.thread = None
        self.last_policy_status = None

    def start(self):
        self.running = True
        self.thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.thread.start()
        self.logger.info("USB Monitor Started.")

    def stop(self):
        self.running = False
        if self.thread:
            self.thread.join(timeout=2)

    def _monitor_loop(self):
        # WMI requires COM initialization in a new thread
        pythoncom.CoInitialize()
        c = wmi.WMI()
        watcher = c.Win32_PnPEntity.watch_for(operation="Creation")
        
        # Initial Policy Check
        self._check_usb_policy()

        while self.running:
            try:
                # 1. Real-time Event Monitoring (Blocking Call with timeout logic implied by polling or threads)
                # WMI watch_for is blocking, which makes stopping hard. 
                # Better approach for responsive stop: Polling or specialized async watcher.
                # For simplicity/robustness in threaded agent: Polling active USB hubs/disks or using a non-blocking approach if possible.
                # Actually, `watch_for` without timeout blocks forever.
                # Let's use a polling loop for "Disks" and "Policy" instead to be safe and stoppable.
                
                self._check_new_devices(c)
                self._check_usb_policy()
                time.sleep(2)
                
            except Exception as e:
                self.logger.error(f"USB Monitor Error: {e}")
                time.sleep(5)
        
        pythoncom.CoUninitialize()

    def _check_new_devices(self, wmi_client):
        # This is a simplified poller. For production, listening to raw events is better but complex in Python threading.
        # We'll diff existing list of disks.
        pass # To be implemented via "New Device" logic if desired. 
        # Actually, let's implement the WMI event listener in a way that doesn't block forever or use a shorter timeout if supported.
        # Standard wmi module `watch_for` blocks.
        # Alternative: Poll `Win32_DiskDrive` where InterfaceType='USB'.
        
        try:
            current_disks = [d.Caption for d in wmi_client.Win32_DiskDrive(InterfaceType="USB")]
            # In a real impl, we'd store state and diff. 
            # For now, let's look for *changes*.
            # (Skipping stateful complexity for this step, sticking to Policy check primarily as requested)
        except:
            pass

    def _check_usb_policy(self):
        try:
            key_path = r"SYSTEM\CurrentControlSet\Services\USBSTOR"
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path) as key:
                val, type = winreg.QueryValueEx(key, "Start")
                # 3 = Enabled, 4 = Disabled
                status = "Disabled" if val == 4 else "Enabled"
                
                if status != self.last_policy_status:
                    self.logger.info(f"USB Policy Changed: {status}")
                    self.sio.emit("agent_event", {
                        "agent_id": self.agent_id,
                        "type": "security_alert",
                        "category": "usb_policy",
                        "details": f"USB Storage Policy is now {status}",
                        "severity": "high" if status == "Disabled" else "info",
                        "timestamp": time.time()
                    })
                    self.last_policy_status = status
        except Exception as e:
            # Registry key might not exist on some systems
            pass

class USBEventMonitor(USBMonitor):
    # Specialized version using the raw watcher in a way that we tolerate blocking or just run it.
    def _monitor_loop(self):
        pythoncom.CoInitialize()
        c = wmi.WMI()
        watcher = c.Win32_PnPEntity.watch_for(operation="Creation")
        
        self.logger.info("Listening for PnP Events...")
        
        while self.running:
            try:
                # Check Policy
                self._check_usb_policy()
                
                # Timed wait workaround: WMI doesn't easily support timeout on `watch_for`.
                # We will just do a polling check for USB Disks to avoid blocking forever.
                
                disks = c.Win32_DiskDrive(InterfaceType="USB")
                if not hasattr(self, 'known_disks'):
                    self.known_disks = set(d.DeviceID for d in disks)
                
                current_disks_map = {d.DeviceID: d.Caption for d in disks}
                current_ids = set(current_disks_map.keys())
                
                new_ids = current_ids - self.known_disks
                
                for new_id in new_ids:
                    caption = current_disks_map[new_id]
                    self.logger.warning(f"USB Device Detected: {caption}")
                    self.sio.emit("agent_event", {
                        "agent_id": self.agent_id,
                        "type": "security_alert",
                        "category": "usb_insertion",
                        "details": f"USB Device Inserted: {caption}",
                        "severity": "critical", # USB insertion is often critical in secure envs
                        "timestamp": time.time()
                    })
                
                self.known_disks = current_ids
                time.sleep(1)

            except Exception as e:
                self.logger.error(f"USB Loop Error: {e}")
                time.sleep(2)
        
        pythoncom.CoUninitialize()
