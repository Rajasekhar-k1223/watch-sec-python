import threading
import time
import requests
import json
from datetime import datetime
import platform
import logging

# macOS Imports
try:
    from AppKit import NSWorkspace
    from Quartz import (
        CGWindowListCopyWindowInfo,
        kCGWindowListOptionOnScreenOnly,
        kCGNullWindowID
    )
    HAS_QUARTZ = True
except ImportError:
    HAS_QUARTZ = False
    print("[ActivityMonitor] Warning: pyobjc-framework-Quartz not installed. Activity tracking will be limited.")

class ActivityMonitor:
    def __init__(self, agent_id, api_key, backend_url, interval=2.0):
        self.agent_id = agent_id
        self.api_key = api_key
        self.backend_url = backend_url
        self.interval = interval
        self.running = False
        self._thread = None
        self.current_window = {
            "title": "",
            "process": "",
            "start_time": datetime.utcnow()
        }

    def start(self):
        if not HAS_QUARTZ or platform.system() != "Darwin":
            print("[ActivityMonitor] Skipped: Not on macOS or missing dependencies.")
            return

        self.running = True
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        print("[ActivityMonitor] Started.")

    def stop(self):
        self.running = False
        if self._thread:
            self._thread.join(timeout=2)

    def _get_active_window_macos(self):
        try:
            workspace = NSWorkspace.sharedWorkspace()
            active_app = workspace.frontmostApplication()
            
            if not active_app:
                return "Unknown", "Unknown"
            
            pid = active_app.processIdentifier()
            process_name = active_app.localizedName()
            
            # Get Window Title via Quartz
            options = kCGWindowListOptionOnScreenOnly
            window_list = CGWindowListCopyWindowInfo(options, kCGNullWindowID)
            
            window_title = ""
            
            # Find the first window belonging to the active PID that has a title
            for window in window_list:
                if window.get('kCGWindowOwnerPID') == pid:
                    # Some windows are just overlays/shadows, check for title
                    title = window.get('kCGWindowName', '')
                    if title:
                        window_title = title
                        break
            
            if not window_title:
                window_title = process_name # Fallback
                
            return process_name, window_title
            
        except Exception as e:
            # print(f"[ActivityMonitor] Error: {e}")
            return "Error", str(e)

    def _loop(self):
        last_process = ""
        last_title = ""
        
        while self.running:
            try:
                proc, title = self._get_active_window_macos()
                
                # Check for change
                if proc != last_process or title != last_title:
                    now = datetime.utcnow()
                    
                    # Log PREVIOUS activity (if valid)
                    if last_process:
                        duration = (now - self.current_window["start_time"]).total_seconds()
                        if duration > 1.0: # Filter noise
                            self._send_log(last_process, last_title, duration, self.current_window["start_time"])
                    
                    # Update Current
                    last_process = proc
                    last_title = title
                    self.current_window = {
                        "process": proc,
                        "title": title,
                        "start_time": now
                    }
                    
            except Exception as e:
                print(f"[ActivityMonitor] Loop Error: {e}")
            
            time.sleep(self.interval)

    def _send_log(self, process, title, duration, timestamp):
        payload = {
            "AgentId": self.agent_id,
            "TenantApiKey": self.api_key,
            "ActivityType": "AppFocus",
            "WindowTitle": title,
            "ProcessName": process,
            "Url": "", # Browser URL extraction requires AppleScript/Accessiblity - skipped for now
            "DurationSeconds": float(f"{duration:.2f}"),
            "Timestamp": timestamp.isoformat()
        }
        
        try:
            # Send to Backend
            # Note: We use requests here, could use aiohttp if integrated into main loop better,
            # but threading is fine for this low frequency.
            res = requests.post(f"{self.backend_url}/api/events/activity", json=payload, timeout=5)
            if res.status_code != 200:
                print(f"[ActivityMonitor] Failed to send log: {res.status_code}")
            else:
                # print(f"[Activity] Logged: {process} - {title} ({duration:.1f}s)")
                pass
        except Exception as e:
            print(f"[ActivityMonitor] Net Error: {e}")
