
import psutil # type: ignore
import threading # type: ignore
import time # type: ignore
from datetime import datetime # type: ignore
from typing import Optional # type: ignore
import os # type: ignore

class AppBlocker:
    def __init__(self, agent_id, api_key, backend_url, data_queue=None, interval=10.0):
        self.agent_id = agent_id
        self.api_key = api_key
        self.backend_url = backend_url
        self.data_queue = data_queue
        self.interval = interval
        self.running = False
        self.thread = None
        self.blocked_apps = [] # List of lowercase process names e.g. ["spotify.exe", "steam.exe"]

    def set_blocked_apps(self, apps):
        """Update the list of blocked apps."""
        if apps:
            self.blocked_apps = [a.lower() for a in apps]
            print(f"[AppBlocker] Warning: Policy updated. Blocking: {self.blocked_apps}")
        else:
            self.blocked_apps = []

    def start(self):
        if self.running: return
        self.running = True
        self.thread = threading.Thread(target=self._loop, daemon=True) # type: ignore
        self.thread.start()
        print("[AppBlocker] Monitoring Started")

    def stop(self):
        if not self.running: return
        self.running = False
        if self.thread:
            self.thread.join(timeout=1) # type: ignore
            self.thread = None
            
    def _loop(self):
        known_pids = {}
        while self.running:
            if not self.blocked_apps:
                time.sleep(self.interval)
                continue
                
            try:
                # O(1) PID caching to prevent 200+ WMI queries every loop
                current_pids = set(psutil.pids())
                new_pids = current_pids - set(known_pids.keys())
                dead_pids = set(known_pids.keys()) - current_pids
                
                for pid in dead_pids:
                    del known_pids[pid]
                    
                for pid in new_pids:
                    try:
                        p = psutil.Process(pid)
                        name = p.name().lower()
                        known_pids[pid] = name
                    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                        pass
                
                # Check known_pids against blocked_apps
                blocked_set = set(self.blocked_apps)
                for pid, pname in list(known_pids.items()):
                    if pname in blocked_set:
                        try:
                            psutil.Process(pid).kill()
                            print(f"[AppBlocker] KILLED: {pname} (PID: {pid})")
                            self._send_alert("APP_BLOCKED", f"Terminated prohibited application: {pname}")
                            del known_pids[pid]
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            pass
                            
            except Exception as e:
                print(f"[AppBlocker] Error: {e}")
                
            time.sleep(self.interval)

    def _send_alert(self, event_type, details):
        payload = {
            "AgentId": self.agent_id,
            "TenantApiKey": self.api_key,
            "Type": event_type,
            "Details": details,
            "Timestamp": datetime.utcnow().isoformat()
        }
        
        if self.data_queue:
            self.data_queue.enqueue("/api/events/report", payload, priority='high')
        else:
            print(f"[AppBlocker] [ERROR] No DataQueue available to report: {event_type}")
