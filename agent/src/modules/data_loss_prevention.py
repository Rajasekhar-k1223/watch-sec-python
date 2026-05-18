import time # type: ignore
import threading # type: ignore
import os # type: ignore
from watchdog.observers import Observer # type: ignore
from watchdog.events import FileSystemEventHandler # type: ignore
from datetime import datetime # type: ignore
import re # type: ignore

class SecurityEventHandler(FileSystemEventHandler):
    def __init__(self, monitor):
        self.monitor = monitor
        self.last_event_time = 0
        self.event_count = 0

    def on_modified(self, event):
        if event.is_directory: return
        self.monitor.log_event("FILE_MODIFIED", f"File Modified: {event.src_path}")
        # Content Scan for DLP
        self.monitor.scan_file(event.src_path)

    def on_created(self, event):
        if event.is_directory: return
        self.monitor.log_event("FILE_CREATED", f"File Created: {event.src_path}")
        self.monitor.scan_file(event.src_path)

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
    def __init__(self, agent_id, api_key, backend_url, data_queue=None, path_to_watch=None):
        self.agent_id = agent_id
        self.api_key = api_key
        self.backend_url = backend_url
        self.data_queue = data_queue
        # Default to C:\Confidential for security focus, or fallback to current dir
        self.path_to_watch = path_to_watch if path_to_watch else (r"C:\Confidential" if os.name == 'nt' else "confidential_watch")
        self.running = False
        self.observer = None
        
        # DLP Patterns
        self.patterns = {
            "Email": re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"),
            "CreditCard": re.compile(r"\b(?:\d{4}[- ]?){3}\d{4}\b"),
            "SSN": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
            "SensitiveKeywords": re.compile(r"(?i)(confidential|secret|salary|password|invoice|internal only|restriced|project|contract|legal|financial)")
        }

    def start(self):
        if not os.path.exists(self.path_to_watch):
            try:
                os.makedirs(self.path_to_watch)
                print(f"[File] Created Monitored Directory: {self.path_to_watch}")
            except Exception as e:
                print(f"[File] Warning: Directory {self.path_to_watch} could not be created: {e}")
                return

        self.running = True
        event_handler = SecurityEventHandler(self)
        self.observer = Observer()
        self.observer.schedule(event_handler, self.path_to_watch, recursive=True)
        self.observer.start()
        print(f"[File] Monitor Started for: {self.path_to_watch}")

    def stop(self):
        if self.observer:
            self.observer.stop()
            self.observer.join()
            self.observer = None
        self.running = False

    def set_enabled(self, enabled: bool):
        if enabled:
            if not self.running:
                self.start()
        else:
            if self.running:
                self.stop()

    def scan_file(self, file_path):
        """Scans small text files for sensitive patterns (Enterprise DLP)."""
        try:
            if not os.path.exists(file_path): return
            
            # Skip large files for performance (> 5MB)
            if os.path.getsize(file_path) > 5 * 1024 * 1024:
                return

            # Read sample (first 100KB)
            with open(file_path, "r", errors="ignore") as f:
                content = f.read(100000)
            
            hits = []
            for name, pattern in self.patterns.items():
                if pattern.search(content):
                    hits.append(name)
            
            if hits:
                msg = f"DLP POLICY VIOLATION: Sensitive data ({', '.join(hits)}) detected in file: {file_path}"
                self.log_event("FILE_DLP_VIOLATION", msg)

        except Exception as e:
            # print(f"[File] Scan Error: {e}")
            pass

    def log_event(self, event_type, details):
        print(f"[File] {event_type}: {details}")
        payload = {
            "AgentId": self.agent_id,
            # [v1.8.38] Telemetry Stealth: Key suppression enforced.
            # Signing handled by DataQueue.
            "Type": event_type,
            "Details": details,
            "Timestamp": datetime.utcnow().isoformat()
        }
        
        if self.data_queue:
            self.data_queue.enqueue("/api/events/report", payload)
        else:
            # Fallback to console if no queue (should not happen in production)
            print(f"[File] [ERROR] No DataQueue available to report: {event_type}")
