from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import time
import threading
import os
import requests
from datetime import datetime

class DlpHandler(FileSystemEventHandler):
    def __init__(self, callback):
        self.callback = callback

    def on_modified(self, event):
        if event.is_directory: return
        self.callback("File Modified", event.src_path)

    def on_created(self, event):
        if event.is_directory: return
        self.callback("File Created", event.src_path)

    def on_deleted(self, event):
        if event.is_directory: return
        self.callback("File Deleted", event.src_path)
        
    def on_moved(self, event):
        if event.is_directory: return
        self.callback("File Moved", f"{event.src_path} -> {event.dest_path}")

class FileIntegrityMonitor:
    def __init__(self, agent_id, api_key, backend_url, sensitive_paths=None):
        self.agent_id = agent_id
        self.api_key = api_key
        self.backend_url = backend_url
        
        # Default Sensitive Paths (Demo: User Documents)
        if not sensitive_paths:
            home = os.path.expanduser("~")
            self.paths = [
                os.path.join(home, "Documents"), 
                os.path.join(home, "Desktop", "Confidential") # specific demo folder
            ]
        else:
            self.paths = sensitive_paths
            
        self.observer = Observer()
        self.is_running = False
        self._dlp_handler = DlpHandler(self._handle_event)

    def start(self):
        if self.is_running: return

        # Ensure folders exist (avoid crash)
        valid_paths = []
        for path in self.paths:
            if os.path.exists(path):
                valid_paths.append(path)
                try:
                    self.observer.schedule(self._dlp_handler, path, recursive=True)
                    print(f"[DLP] Monitoring File System: {path}")
                except Exception as e:
                    print(f"[DLP] Failed to watch {path}: {e}")
        
        if not valid_paths:
            print("[DLP] No valid paths to monitor found.")
            return

        self.observer.start()
        self.is_running = True
        print("[DLP] File Monitoring Started")

    def stop(self):
        if not self.is_running: return
        self.is_running = False
        self.observer.stop()
        self.observer.join()
        print("[DLP] File Monitoring Stopped")

    def _handle_event(self, action, details):
        # Heuristics
        
        # 1. Zip Creation
        if details.endswith(".zip") or details.endswith(".rar") or details.endswith(".7z"):
             if action == "File Created" or action == "File Modified":
                 action = "Data Compression (Risk)"
                 details = f"Compressed Archive Detected: {details} (Potential Exfiltration)"
                 print(f"[DLP ALERT] {details}")
        
        # 2. Sensitive Keyword in Filename (Simple Regex-like)
        lower_details = details.lower()
        sensitive_keywords = ["confidential", "secret", "password", "financial", "salary"]
        if any(k in lower_details for k in sensitive_keywords):
            action = f"{action} [SENSITIVE]"
            
        # Log to Backend
        self._send_log(action, details)

    def _send_log(self, type, details):
        payload = {
            "AgentId": self.agent_id,
            "TenantApiKey": self.api_key,
            "Type": type,
            "Details": details,
            "Timestamp": datetime.utcnow().isoformat()
        }
        try:
            requests.post(f"{self.backend_url}/api/events/report", json=payload, timeout=5, verify=False)
        except: pass
