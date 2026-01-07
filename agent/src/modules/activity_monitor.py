import threading
import time
import requests
import json
from datetime import datetime
import platform
import logging
import subprocess

# OS-Specific Imports
HAS_QUARTZ = False
HAS_WIN32 = False
HAS_XLIB = False

SYSTEM_OS = platform.system()

if SYSTEM_OS == "Darwin":
    try:
        from AppKit import NSWorkspace
        from Quartz import (
            CGWindowListCopyWindowInfo,
            kCGWindowListOptionOnScreenOnly,
            kCGNullWindowID
        )
        HAS_QUARTZ = True
        try:
            from ApplicationServices import AXIsProcessTrusted
        except ImportError:
            AXIsProcessTrusted = None
    except ImportError:
        pass

elif SYSTEM_OS == "Windows":
    try:
        import ctypes
        from ctypes import wintypes
        HAS_WIN32 = True
    except ImportError:
        pass

elif SYSTEM_OS == "Linux":
    try:
        from Xlib import display, X
        HAS_XLIB = True
    except ImportError:
        pass

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
        
        # Robust Session initialization
        self.session = requests.Session()
        adapter = requests.adapters.HTTPAdapter(max_retries=3)
        self.session.mount('https://', adapter)
        self.session.mount('http://', adapter)

    def start(self):
        if SYSTEM_OS == "Darwin" and not HAS_QUARTZ:
             print("[ActivityMonitor] Skipped: macOS requires pyobjc-framework-Quartz/ApplicationServices.")
             return
        
        self.running = True
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        print(f"[ActivityMonitor] Started for {SYSTEM_OS}.")
        self._send_log("Usage", "Agent Started", 0.0, datetime.utcnow(), activity_type="System")

        if SYSTEM_OS == "Darwin" and HAS_QUARTZ and AXIsProcessTrusted:
            is_trusted = AXIsProcessTrusted()
            print(f"[ActivityMonitor] Accessibility Permission: {'GRANTED' if is_trusted else 'DENIED (Titles will be hidden!)'}")

    def stop(self):
        self.running = False
        if self._thread:
            self._thread.join(timeout=2)
        self._send_log("Usage", "Agent Stopped", 0.0, datetime.utcnow(), activity_type="System")

    # --- macOS ---
    def _get_active_window_macos(self):
        try:
            workspace = NSWorkspace.sharedWorkspace()
            active_app = workspace.frontmostApplication()
            if not active_app: return "Unknown", "Unknown"
            
            pid = active_app.processIdentifier()
            process_name = active_app.localizedName()
            
            options = kCGWindowListOptionOnScreenOnly
            window_list = CGWindowListCopyWindowInfo(options, kCGNullWindowID)
            
            window_title = ""
            for window in window_list:
                if window.get('kCGWindowOwnerPID') == pid:
                    title = window.get('kCGWindowName', '')
                    if title:
                        window_title = title
                        break
            
            if not window_title: window_title = process_name
            return process_name, window_title
        except Exception:
            return "Error", "Mactracking Error"

    def _get_browser_url_macos(self, process_name):
        script = None
        if "Chrome" in process_name:
            script = 'tell application "Google Chrome" to return URL of active tab of front window'
        elif "Safari" in process_name:
            script = 'tell application "Safari" to return URL of front document'
        
        if script:
            try:
                result = subprocess.run(['osascript', '-e', script], capture_output=True, text=True, timeout=1)
                if result.returncode == 0: return result.stdout.strip()
            except: pass
        return ""

    # --- Windows ---
    def _get_active_window_windows(self):
        if not HAS_WIN32: return "Unknown", "Install pywin32/ctypes"
        try:
            user32 = ctypes.windll.user32
            hwnd = user32.GetForegroundWindow()
            
            # Title
            length = user32.GetWindowTextLengthW(hwnd)
            buff = ctypes.create_unicode_buffer(length + 1)
            user32.GetWindowTextW(hwnd, buff, length + 1)
            title = buff.value
            
            # Process Name (Simplified - real impl requires psutil/getting PID)
            # For brevity/standard lib only, we might just return title twice or generic "WinApp"
            # Ideally use psutil if available
            process = "Windows App" 
            try:
                import psutil
                pid = ctypes.c_ulong()
                user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
                p = psutil.Process(pid.value)
                process = p.name()
            except ImportError:
                pass
                
            return process, title
        except Exception as e:
            return "Error", str(e)

    # --- Linux ---
    def _get_active_window_linux(self):
        # Fallback to xdotool if Xlib not present roughly
        try:
             result = subprocess.run(['xdotool', 'getwindowfocus', 'getwindowname'], capture_output=True, text=True)
             if result.returncode == 0:
                 return "Linux App", result.stdout.strip()
        except: pass
        return "Unknown", "Unknown"

    def _get_active_window(self):
        if SYSTEM_OS == "Darwin": return self._get_active_window_macos()
        if SYSTEM_OS == "Windows": return self._get_active_window_windows()
        if SYSTEM_OS == "Linux": return self._get_active_window_linux()
        return "Unknown", "Unsupported OS"

    def _loop(self):
        last_process = ""
        last_title = ""
        last_url = ""
        
        while self.running:
            try:
                proc, title = self._get_active_window()
                
                # Check for change
                if proc != last_process or title != last_title:
                    now = datetime.utcnow()
                    
                    if last_process:
                        duration = (now - self.current_window["start_time"]).total_seconds()
                        if duration > 1.0: 
                            self._send_log(last_process, last_title, duration, self.current_window["start_time"], last_url)
                    
                    # URL Checking (macOS only currently for easy scripting, Windows needs UI Automation)
                    current_url = ""
                    if SYSTEM_OS == "Darwin":
                        current_url = self._get_browser_url_macos(proc)

                    last_process = proc
                    last_title = title
                    last_url = current_url
                    self.current_window = {
                        "process": proc,
                        "title": title,
                        "start_time": now
                    }
                    
            except Exception as e:
                print(f"[ActivityMonitor] Loop Error: {e}")
            
            time.sleep(self.interval)

    def _send_log(self, process, title, duration, timestamp, url="", activity_type="AppFocus"):
        if url: activity_type = "Web"
        payload = {
            "AgentId": self.agent_id,
            "TenantApiKey": self.api_key,
            "ActivityType": activity_type,
            "WindowTitle": title,
            "ProcessName": process,
            "Url": url,
            "DurationSeconds": float(f"{duration:.2f}"),
            "Timestamp": timestamp.isoformat()
        }
        try:
            self.session.post(f"{self.backend_url}/api/events/activity", json=payload, timeout=10, verify=False)
        except: pass
