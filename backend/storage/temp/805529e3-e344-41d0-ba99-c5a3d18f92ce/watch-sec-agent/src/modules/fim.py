from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import time
import threading

class FIMHandler(FileSystemEventHandler):
    def on_modified(self, event):
        if event.is_directory:
            return
        print(f"[FIM] File Modified: {event.src_path}")

    def on_created(self, event):
        if event.is_directory:
            return
        print(f"[FIM] File Created: {event.src_path}")

    def on_deleted(self, event):
        if event.is_directory:
            return
        print(f"[FIM] File Deleted: {event.src_path}")

class FileIntegrityMonitor:
    def __init__(self, paths_to_watch=None):
        self.paths = paths_to_watch or ["."] # Default to current dir
        self.observer = Observer()
        self.is_running = False

        print("[FIM] Service Stopped")

    def monitor_usb(self):
        import psutil
        known_drives = set()
        
        # Initial Scan
        for p in psutil.disk_partitions():
            if 'removable' in p.opts or 'cdrom' in p.opts:
                known_drives.add(p.device)

        while self.is_running:
            current_drives = set()
            for p in psutil.disk_partitions():
                if 'removable' in p.opts or 'cdrom' in p.opts:
                    current_drives.add(p.device)
            
            new_drives = current_drives - known_drives
            removed_drives = known_drives - current_drives
            
            for drive in new_drives:
                print(f"[DLP] USB Drive Detected: {drive}")
                # Hook FIM to new drive?
                # For now, just logging the event is enough for "Detection"
                # To block: can unmount or raise alert.
            
            for drive in removed_drives:
                print(f"[DLP] USB Drive Removed: {drive}")
            
            known_drives = current_drives
            time.sleep(2)

    def start(self):
        if self.is_running:
            return

        handler = FIMHandler()
        for path in self.paths:
            try:
                self.observer.schedule(handler, path, recursive=True)
                print(f"[FIM] Watching: {path}")
            except Exception as e:
                print(f"[FIM] Failed to watch {path}: {e}")

        self.observer.start()
        self.is_running = True
        
        # Start USB Thread
        self.usb_thread = threading.Thread(target=self.monitor_usb, daemon=True)
        self.usb_thread.start()
        
        print("[FIM] Service Started (with USB DLP)")
