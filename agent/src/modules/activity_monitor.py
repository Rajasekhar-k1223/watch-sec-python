import threading # type: ignore
import time # type: ignore
import requests # type: ignore
import json # type: ignore
from datetime import datetime, timezone # type: ignore
from typing import Optional # type: ignore
import platform # type: ignore
import logging # type: ignore
import subprocess # type: ignore
import psutil # type: ignore

# OS-Specific Imports
import ctypes # type: ignore
HAS_QUARTZ = False
HAS_WIN32 = False
HAS_XLIB = False

SYSTEM_OS = platform.system()

if SYSTEM_OS == "Darwin":
    try:
        from AppKit import NSWorkspace # type: ignore
        from Quartz import ( # type: ignore
            CGWindowListCopyWindowInfo,
            kCGWindowListOptionOnScreenOnly,
            kCGNullWindowID
        )
        HAS_QUARTZ = True
        try:
            from ApplicationServices import AXIsProcessTrusted # type: ignore
        except ImportError:
            AXIsProcessTrusted = None
    except ImportError:
        pass

elif SYSTEM_OS == "Windows":
    try:
        import ctypes # type: ignore
        from ctypes import wintypes # type: ignore
        HAS_WIN32 = True

        class LASTINPUTINFO(ctypes.Structure):
            _fields_ = [
                ('cbSize', ctypes.wintypes.UINT), # type: ignore
                ('dwTime', ctypes.wintypes.DWORD), # type: ignore
            ]
    except ImportError:
        pass

elif SYSTEM_OS == "Linux":
    try:
        from Xlib import display, X # type: ignore
        HAS_XLIB = True
    except ImportError:
        pass



class ActivityMonitor:
    def __init__(self, agent_id, api_key, backend_url, data_queue=None, interval=1.0, logger=None):
        self.agent_id = agent_id
        self.api_key = api_key
        self.backend_url = backend_url
        self.data_queue = data_queue
        self.interval = interval
        self.logger = logger
        self.running = False
        self._thread = None
        self.current_window = {
            "title": "",
            "process": "",
            "start_time": datetime.now(timezone.utc),
            "active_seconds": 0.0,
            "idle_seconds": 0.0
        }
        
        # Categorization Rules
        self.categories = {
            "Productive": [
                "visual studio", "code", "pycharm", "intellij", "eclipse", "slack", "teams", "outlook", 
                "word", "excel", "powerpoint", "notion", "jira", "github", "bitbucket", "gitlab", 
                "terminal", "cmd", "powershell", "iterm", "docker", "postman", "figma", "canva", "trello",
                "zoom", "google meet", "webex", "skype"
            ],
            "Unproductive": [
                "steam", "discord", "spotify", "netflix", "youtube", "twitch", "game", "minecraft", 
                "counter-strike", "valorant", "roblox", "fortnite", "facebook", "instagram", "tiktok", "twitter", "x.com"
            ],
            "Neutral": ["chrome", "firefox", "edge", "explorer", "finder", "safari", "brave"]
        }

        # Robust Session initialization
        self.session = requests.Session()
        self.session.headers.update({"X-Tenant-Api-Key": self.api_key})
        adapter = requests.adapters.HTTPAdapter(max_retries=3)
        self.session.mount('https://', adapter)
        self.session.mount('http://', adapter)

    def _get_idle_duration_linux(self):
        try:
            # Use xprintidle if available (standard on many distros or easily installable)
            # Returns idle time in milliseconds
            result = subprocess.run(['xprintidle'], capture_output=True, text=True, timeout=1)
            if result.returncode == 0:
                return float(result.stdout.strip()) / 1000.0
        except:
            pass
        return 0.0

    def _get_idle_duration_mac(self):
        try:
            # Use ioreg to get HIDIdleTime (nanoseconds)
            cmd = "ioreg -c IOHIDSystem | awk '/HIDIdleTime/ {print $NF; exit}'"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=1)
            if result.returncode == 0:
                nanos = int(result.stdout.strip())
                return nanos / 1000000000.0
        except:
            pass
        return 0.0

    def _get_idle_duration(self):
        if SYSTEM_OS == "Windows" and HAS_WIN32:
            lii = LASTINPUTINFO()
            lii.cbSize = ctypes.sizeof(LASTINPUTINFO) # type: ignore
            if ctypes.windll.user32.GetLastInputInfo(ctypes.byref(lii)): # type: ignore
                millis = ctypes.windll.kernel32.GetTickCount() - lii.dwTime # type: ignore
                return millis / 1000.0
        elif SYSTEM_OS == "Linux":
            return self._get_idle_duration_linux()
        elif SYSTEM_OS == "Darwin":
            return self._get_idle_duration_mac()
        return 0.0

    def _get_category(self, process_name, window_title):
        p = process_name.lower()
        t = window_title.lower()
        
        for app in self.categories["Productive"]:
            if app in p or app in t: return "Productive"
        for app in self.categories["Unproductive"]:
            if app in p or app in t: return "Unproductive"
        return "Neutral"

    def start(self):
        if self.running: return
        
        if SYSTEM_OS == "Darwin" and not HAS_QUARTZ:
             print("[ActivityMonitor] Skipped: macOS requires pyobjc-framework-Quartz/ApplicationServices.")
             return
        
        self.running = True
        self._thread = threading.Thread(target=self._loop, daemon=True) # type: ignore
        self._thread.start()
        print(f"[ActivityMonitor] Started for {SYSTEM_OS}.")
        self._send_log("Usage", "Agent Started", 0.0, datetime.now(timezone.utc), activity_type="System")

        if SYSTEM_OS == "Darwin" and HAS_QUARTZ and AXIsProcessTrusted:
            is_trusted = AXIsProcessTrusted()
            print(f"[ActivityMonitor] Accessibility Permission: {'GRANTED' if is_trusted else 'DENIED (Titles will be hidden!)'}")

    def stop(self):
        if not self.running: return
        self.running = False
        if self._thread:
            self._thread.join(timeout=2) # type: ignore
            self._thread = None
        self._send_log("Usage", "Agent Stopped", 0.0, datetime.now(timezone.utc), activity_type="System")

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
            user32 = ctypes.windll.user32 # type: ignore
            hwnd = user32.GetForegroundWindow() # type: ignore
            
            # --- Desktop Mode (Session 1+) ---
            if hwnd: 
                # Title
                length = user32.GetWindowTextLengthW(hwnd)
                if length > 0:
                    buff = ctypes.create_unicode_buffer(length + 1)
                    user32.GetWindowTextW(hwnd, buff, length + 1)
                    title = buff.value
                    
                    # Process Name
                    process = "Windows App" 
                    try:
                        pid = ctypes.c_ulong()
                        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
                        if pid.value > 0:
                            p = psutil.Process(pid.value)
                            process = p.name()
                    except Exception as e:
                        print(f"[ActivityMonitor] PID Error: {e}")
                        pass
                        
                    return process, title

            # --- Service Mode / Session 0 Fallback ---
            return "System Service", "Running as Service (No Desktop Access)"

        except Exception as e:
            return "Error", str(e)

    def _get_browser_url_windows(self, process_name):
        """Attempts to extract URL from common browsers using DDE or basic UI automation hints."""
        # Note: True URL extraction on Windows usually requires UI Automation or Browser Extensions.
        # This is a best-effort implementation for Chrome/Edge.
        if "chrome" not in process_name.lower() and "msedge" not in process_name.lower():
            return ""
            
        try:
            # Simple approach: Check if window title contains a URL or domain hint
            # For deeper tracking, we would need 'pywinauto' or similar which isn't always available.
            # We'll use a placeholder for now as full UI Automation via ctypes is very complex.
            return "" 
        except:
            return ""

    # --- Linux ---
    def _get_active_window_linux(self):
        # 1. Try xdotool (Desktop Environment)
        try:
             result = subprocess.run(['xdotool', 'getwindowfocus', 'getwindowname'], capture_output=True, text=True, timeout=1)
             if result.returncode == 0:
                 title = result.stdout.strip()
                 # Try to get process name via xprop
                 try:
                     wid_res = subprocess.run(['xdotool', 'getwindowfocus'], capture_output=True, text=True, timeout=1)
                     if wid_res.returncode == 0:
                         wid = wid_res.stdout.strip()
                         proc_res = subprocess.run(['xprop', '-id', wid, 'WM_CLASS'], capture_output=True, text=True, timeout=1)
                         if proc_res.returncode == 0:
                             # Output usually: WM_CLASS(STRING) = "name", "Class"
                             parts = proc_res.stdout.split('=')
                             if len(parts) > 1:
                                 name = parts[1].split(',')[0].strip().replace('"', '')
                                 return name, title
                 except: pass
                 return "Linux Desktop", title
        except: pass

        # 2. Fallback: Headless / Server Mode (Top CPU Process)
        try:
            # Use 'ps' to get top CPU process (reliable and stateless)
            cmd = ['/usr/bin/ps', '-eo', 'comm,pcpu,pmem', '--sort=-pcpu', '--no-headers']
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                if lines:
                    top_line = lines[0].strip()
                    parts = top_line.split()
                    if len(parts) >= 3:
                        name = parts[0]
                        cpu = parts[1]
                        mem = parts[2]
                        return name, f"Headless Activity (CPU: {cpu}%, MEM: {mem}%)"
        except:
            pass
            
        return "System Idle", "Waiting for activity..."

    def _get_active_window(self):
        if SYSTEM_OS == "Darwin": return self._get_active_window_macos()
        if SYSTEM_OS == "Windows": return self._get_active_window_windows()
        if SYSTEM_OS == "Linux": return self._get_active_window_linux()
        return "Unknown", "Unsupported OS"

    def _loop(self):
        last_process = ""
        last_title = ""
        last_url = ""
        
        last_flush = time.time()
        
        while self.running:
            try:
                proc, title = self._get_active_window()
                
                # [FIX] Better handle the fallback for Service/Headless
                if proc == "System Service":
                    activity_type = "System" # This will be filtered, but it's accurate
                else:
                    activity_type = "AppFocus"

                # Update Accumulators for CURRENT window
                current_idle = self._get_idle_duration()
                is_idle = current_idle > 60 # Idle threshold 60s
                
                if is_idle:
                    self.current_window["idle_seconds"] += self.interval
                else:
                    self.current_window["active_seconds"] += self.interval

                now_ts = time.time()
                # [OPTIMIZATION] Hybrid Event-Driven + Heartbeat Strategy
                # 1. Trigger immediately on window change (Event-driven)
                # 2. Trigger every 60s for long-running apps (Heartbeat) - Changed from 30s to reduce DB load
                if proc != last_process or title != last_title or (now_ts - last_flush) > 60:
                    now = datetime.now(timezone.utc)
                    
                    if last_process:
                        total_active = self.current_window["active_seconds"]
                        total_idle = self.current_window["idle_seconds"]
                        duration = float(total_active) + float(total_idle) # type: ignore
                        
                        # Only send log if duration is significant (>1s)
                        if duration > 1.0: 
                            category = self._get_category(last_process, last_title)
                            # If it was a periodic flush, we send the log but KEEP the window state (just reset timers)
                            self._send_log(last_process, last_title, duration, self.current_window["start_time"], last_url, category=category, idle_time=total_idle)
                    
                    # URL Checking
                    current_url = ""
                    if SYSTEM_OS == "Darwin":
                        current_url = self._get_browser_url_macos(proc)
                    elif SYSTEM_OS == "Windows":
                        current_url = self._get_browser_url_windows(proc)

                    last_process = proc
                    last_title = title
                    last_url = current_url
                    last_flush = now_ts
                    
                    # Reset accumulators for the window (either NEW window or next slice of CURRENT window)
                    self.current_window = {
                        "process": proc,
                        "title": title,
                        "start_time": now,
                        "active_seconds": 0.0,
                        "idle_seconds": 0.0
                    }
                    
            except Exception as e:
                print(f"[ActivityMonitor] Loop Error: {e}")
            
            time.sleep(self.interval)

    def _send_log(self, process, title, duration, timestamp, url="", activity_type="AppFocus", category="Neutral", idle_time=0.0):
        if url: activity_type = "Web"
        
        score = 0
        if category == "Productive": score = 10
        elif category == "Unproductive": score = -10
        
        payload = {
            "AgentId": self.agent_id,
            "TenantApiKey": self.api_key,
            "ActivityType": activity_type,
            "WindowTitle": title,
            "ProcessName": process,
            "Url": url if url else None, # [FIX] Send None instead of "" for Optional fields
            "DurationSeconds": float(f"{duration:.2f}"),
            "IdleSeconds": float(f"{idle_time:.2f}"),
            "Category": category,
            "ProductivityScore": score,
            "Timestamp": timestamp.isoformat()
        }
        
        if self.data_queue:
            msg = f"[ActivityMonitor] Enqueuing log: {process} - {title} ({duration}s)"
            if self.logger: self.logger(msg)
            else: print(msg)
            self.data_queue.enqueue("/api/events/activity", payload)
        else:
            try:
                msg = f"[ActivityMonitor] Sending log directly: {process} - {title} ({duration}s)"
                if self.logger: self.logger(msg)
                else: print(msg)
                
                response = self.session.post(f"{self.backend_url}/api/events/activity", json=payload, timeout=10, verify=False)
                if response.status_code != 200:
                    err = f"[ActivityMonitor] Backend Rejected: {response.status_code} {response.text}"
                    if self.logger: self.logger(err)
                    else: print(err)
                else:
                    succ = f"[ActivityMonitor] Log Sent Successfully"
                    if self.logger: self.logger(succ)
                    else: print(succ)
            except Exception as e:
                err = f"[ActivityMonitor] Upload Error: {e}"
                if self.logger: self.logger(err)
                else: print(err)
