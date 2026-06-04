from watchdog.observers import Observer # type: ignore
from watchdog.events import FileSystemEventHandler # type: ignore
import time # type: ignore
import threading # type: ignore
import os # type: ignore
import os # type: ignore
from datetime import datetime # type: ignore

class DlpHandler(FileSystemEventHandler):
    def __init__(self, callback):
        self.callback = callback
        self.mod_history = []
        self.ransomware_triggered = False

    def _check_ransomware_behavior(self, path):
        if self.ransomware_triggered: return
        now = time.time()
        self.mod_history.append(now)
        self.mod_history = [t for t in self.mod_history if now - t < 5.0]
        if len(self.mod_history) > 20:
            self.ransomware_triggered = True
            self.callback("RansomwareAlert", f"Mass file modification detected near {path}. Triggering lockdown.")

    def on_modified(self, event):
        if event.is_directory: return
        self._check_ransomware_behavior(event.src_path)
        self.callback("File Modified", event.src_path)

    def on_created(self, event):
        if event.is_directory: return
        self.callback("File Created", event.src_path)

    def on_deleted(self, event):
        if event.is_directory: return
        self.callback("File Deleted", event.src_path)
        
    def on_moved(self, event):
        if event.is_directory: return
        self._check_ransomware_behavior(event.dest_path)
        self.callback("File Moved", f"{event.src_path} -> {event.dest_path}")

class FileIntegrityMonitor:
    def __init__(self, agent_id, api_key, backend_url, data_queue=None, sensitive_paths=None):
        self.agent_id = agent_id
        self.api_key = api_key
        self.backend_url = backend_url
        self.data_queue = data_queue
        
        # Default Sensitive Paths (Demo: User Documents)
        if not sensitive_paths:
            home = os.path.expanduser("~")
            self.paths = [
                os.path.join(home, "Documents"), 
                os.path.join(home, "Desktop"),
                os.path.join(home, "Downloads"),
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
                    # [v1.8.64] Memory Optimization: Avoid recursive memory bloat on Windows
                    self.observer.schedule(self._dlp_handler, path, recursive=False)
                    print(f"[DLP] Monitoring File System: {path}")
                except Exception as e:
                    print(f"[DLP] Failed to watch {path}: {e}")
                    self._send_log("MODULE_ERROR", f"FIM failed to watch path {path}: {e}")
        
        if not valid_paths:
            print("[DLP] No valid paths to monitor found.")
            self._send_log("MODULE_ERROR", "FIM failed: No valid paths found.")
            return

        self.observer.start()
        self.is_running = True
        print("[DLP] File Monitoring Started")
        self._send_log("POLICY_APPLIED", f"FIM Monitoring Active on {len(valid_paths)} paths")

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
            
        # 3. Ransomware Alert Action
        if action == "RansomwareAlert":
            print(f"[CRITICAL THREAT] {details}")
            # Isolate network
            try:
                import sys
                main_mod = sys.modules.get("__main__")
                if main_mod and hasattr(main_mod, 'net_mon') and main_mod.net_mon:
                    main_mod.net_mon.isolate_network()
                    details += " Network isolated."
            except Exception as e:
                details += f" Network isolation failed: {e}"

        # Log to Backend
        self._send_log(action, details)

    def _send_log(self, type, details):
        payload = {
            "AgentId": self.agent_id,
            # [v1.8.38] Telemetry Stealth: Key suppression enforced.
            # Signing handled by DataQueue.
            "Type": type,
            "Details": details,
            "Timestamp": datetime.utcnow().isoformat()
        }
        if self.data_queue:
            self.data_queue.enqueue("/api/events/report", payload, priority='high')
        else:
            print(f"[FIM] [ERROR] No DataQueue available to report: {type}")
