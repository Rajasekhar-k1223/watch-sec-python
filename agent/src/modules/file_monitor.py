import time
import threading
import requests
import os
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from datetime import datetime

class SecurityEventHandler(FileSystemEventHandler):
    def __init__(self, monitor):
        self.monitor = monitor
        self.last_event_time = 0
        self.event_count = 0

    def on_modified(self, event):
        if event.is_directory: return
        # Ignore frequent modifications (log files etc)
        pass 

    def on_created(self, event):
        if event.is_directory: return
        self.monitor.log_event("FILE_CREATED", f"File Created: {event.src_path}")

    def on_deleted(self, event):
        if event.is_directory: return
        
        # Heuristic: Mass Deletion Detection
        now = time.time()
        if now - self.last_event_time < 2.0: # 2 seconds window
            self.event_count += 1
        else:
            self.event_count = 1
        self.last_event_time = now

        if self.event_count >= 5:
            self.monitor.log_event("MASS_DELETION", f"High Velocity Deletion Detected: 5+ files in 2s at {os.path.dirname(event.src_path)}")
            self.event_count = 0 # specific alert sent, reset
        else:
            self.monitor.log_event("FILE_DELETED", f"File Deleted: {event.src_path}")

    def on_moved(self, event):
        if event.is_directory: return
        self.monitor.log_event("FILE_MOVED", f"File Moved: {event.src_path} -> {event.dest_path}")


class FileMonitor:
    def __init__(self, agent_id, api_key, backend_url, path_to_watch=None):
        self.agent_id = agent_id
        self.api_key = api_key
        self.backend_url = backend_url
        self.path_to_watch = path_to_watch if path_to_watch else r"C:\Confidential"
        self.running = False
        self.observer = None
        
        # Robust Session
        self.session = requests.Session()
        adapter = requests.adapters.HTTPAdapter(max_retries=3)
        self.session.mount('https://', adapter)
        self.session.mount('http://', adapter)

    def start(self):
        if not os.path.exists(self.path_to_watch):
            try:
                os.makedirs(self.path_to_watch)
                print(f"[File] Created Monitored Directory: {self.path_to_watch}")
            except:
                print(f"[File] Warning: Directory {self.path_to_watch} does not exist and could not be created.")
                return

        self.running = True
        event_handler = SecurityEventHandler(self)
        self.observer = Observer()
        self.observer.schedule(event_handler, self.path_to_watch, recursive=True)
        self.observer.start()
        print(f"[File] Monitor Started for: {self.path_to_watch}")

    def stop(self):
        self.running = False
        if self.observer:
            self.observer.stop()
            self.observer.join()

    def log_event(self, event_type, details):
        print(f"[File] {event_type}: {details}")
        payload = {
            "AgentId": self.agent_id,
            "TenantApiKey": self.api_key,
            "Type": event_type,
            "Details": details,
            "Timestamp": datetime.utcnow().isoformat()
        }
        try:
            self.session.post(f"{self.backend_url}/api/events/report", json=payload, timeout=10, verify=False)
        except Exception as e:
            print(f"[File] Failed to send alert: {e}")
