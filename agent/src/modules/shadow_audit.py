
import os # type: ignore
import shutil # type: ignore
import threading # type: ignore
import time # type: ignore
import requests # type: ignore
from datetime import datetime # type: ignore
from watchdog.observers import Observer # type: ignore
from watchdog.events import FileSystemEventHandler # type: ignore
from agent_core.privacy_utils import PrivacyRedactor

class ShadowHandler(FileSystemEventHandler):
    def __init__(self, agent_id, api_key, backend_url, vault_path, data_queue=None):
        self.agent_id = agent_id
        self.api_key = api_key
        self.backend_url = backend_url
        self.vault_path = vault_path
        self.data_queue = data_queue
        # To avoid multiple triggers for the same file write
        self.processed_files = {} # path -> last_processed_time

    def on_created(self, event):
        if event.is_directory: return
        self._shadow_file(event.src_path)

    def on_modified(self, event):
        if event.is_directory: return
        self._shadow_file(event.src_path)

    def _shadow_file(self, src_path):
        # Debounce: ignore multiple events within 2 seconds for the same file
        now = time.time()
        if src_path in self.processed_files:
            if now - self.processed_files[src_path] < 2.0:
                return
        
        self.processed_files[src_path] = now
        
        try:
            # Check if file exists and is not too large (limit to 20MB for forensics)
            if not os.path.exists(src_path): return
            
            # [v1.8.34] Security: Anti-Symlink Trap
            # Do NOT shadow symbolic links to prevent exfiltration of system files 
            # via link trickery (e.g. Doc -> /etc/shadow)
            if os.path.islink(src_path):
                print(f"[Shadow] Blocked (Symlink): {src_path}")
                return

            file_size = os.path.getsize(src_path)
            if file_size > 20 * 1024 * 1024: 
                print(f"[Shadow] Skipping large file: {src_path} ({file_size} bytes)")
                return

            # Wait a tiny bit to ensure write is finished
            time.sleep(0.5)

            # Copy to Vault
            os.makedirs(self.vault_path, exist_ok=True)
            filename = os.path.basename(src_path)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            vault_filename = f"{timestamp}_{filename}"
            vault_file_path = os.path.join(self.vault_path, vault_filename)
            
            shutil.copy2(src_path, vault_file_path)
            
            # [v1.8.31] Privacy: Mask user-identity in paths for logs
            redacted_src = PrivacyRedactor.redact_text(src_path)
            print(f"[Shadow] Intercepted: {redacted_src} -> {vault_file_path}")

            # Upload
            self._upload_shadow(vault_file_path, src_path, delete_on_success=True)

        except Exception as e:
            print(f"[Shadow] Error shadowing {src_path}: {e}")

    def _upload_shadow(self, local_path, original_path, delete_on_success=True):
        import base64
        try:
            filename = os.path.basename(original_path)
            import hashlib # type: ignore
            sha256_hash = hashlib.sha256()
            with open(local_path, 'rb') as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            content_hash = sha256_hash.hexdigest()

            with open(local_path, 'rb') as f:
                file_bytes = f.read()
                
            payload = {
                "agent_id": self.agent_id,
                "filename": filename,
                "content_sha256": content_hash,
                "file_b64": base64.b64encode(file_bytes).decode('utf-8')
            }
            
            if self.data_queue:
                self.data_queue.enqueue("/api/uploads/shadow", payload, priority='normal')
                redacted_name = PrivacyRedactor.redact_text(filename)
                print(f"[Shadow] Queued securely: {redacted_name}")
                if delete_on_success:
                    try:
                        os.remove(local_path)
                    except: pass
            else:
                print(f"[Shadow] Error: No data_queue available")
        except Exception as e:
            redacted_orig = PrivacyRedactor.redact_text(original_path)
            print(f"[Shadow] Upload error for {redacted_orig}: {e}")

class ShadowMonitor:
    def __init__(self, agent_id, api_key, backend_url, vault_path="shadow_vault", data_queue=None):
        self.agent_id = agent_id
        self.api_key = api_key
        self.backend_url = backend_url
        self.vault_path = vault_path
        self.data_queue = data_queue
        self.observer = None
        self.active_watches = {} # drive_path -> watch_info
        self.running = False

    def start(self):
        # ShadowMonitor starts watching drives on-demand when USBs are mounted
        # but we use self.running to control the sync loop.
        if self.running: return
        self.running = True
        threading.Thread(target=self._sync_loop, daemon=True).start()
        print("[ShadowMonitor] Sync Loop Started.")

    def set_watched_paths(self, paths):
        """Standardize on a list of paths to watch."""
        if not paths:
            paths = []
            
        target_paths = set()
        for p in paths:
             # Expand environment variables like %USERPROFILE% or $HOME
             expanded = os.path.expandvars(os.path.expanduser(p))
             if os.path.exists(expanded):
                 target_paths.add(expanded)
        
        # Stop 
        current_paths = set(self.active_watches.keys())
        
        # Remove old
        for p in (current_paths - target_paths):
            self.stop_watching_drive(p)
            
        # Add new
        for p in (target_paths - current_paths):
            self.start_watching_drive(p)

    def start_watching_drive(self, drive_path):
        if drive_path in self.active_watches: return
        
        try:
            print(f"[Shadow] Starting monitor on drive: {drive_path}")
            handler = ShadowHandler(self.agent_id, self.api_key, self.backend_url, self.vault_path, self.data_queue)
            if not self.observer:
                self.observer = Observer()
                self.observer.start()
            
            watch = self.observer.schedule(handler, drive_path, recursive=True)
            self.active_watches[drive_path] = watch

            if not self.running:
                self.running = True
                threading.Thread(target=self._sync_loop, daemon=True).start()
        except Exception as e:
            print(f"[Shadow] Failed to start watch on {drive_path}: {e}")

    def _sync_loop(self):
        while self.running:
            try:
                self.check_pending_uploads()
            except Exception as e:
                print(f"[Shadow] Sync loop error: {e}")
            time.sleep(60) # Sync every minute

    def stop_watching_drive(self, drive_path):
        if drive_path in self.active_watches:
            watch = self.active_watches.pop(drive_path)
            self.observer.unschedule(watch)
            print(f"[Shadow] Stopped monitor on drive: {drive_path}")

    def stop(self):
        if not self.running: return
        self.running = False
        if self.observer:
            try:
                self.observer.stop()
                self.observer.join(timeout=2)
            except: pass
            self.observer = None
        self.active_watches = {}
        print("[ShadowMonitor] Stopped.")

    def check_pending_uploads(self):
        """Retries uploads for files that are in the vault but not yet synced."""
        if not os.path.exists(self.vault_path): return
        
        files = os.listdir(self.vault_path)
        if not files: return
        
        print(f"[Shadow] Checking {len(files)} pending forensic captures...")
        # Simplistic retry: just try to upload all files in vault again
        # Real implementation would track which ones are already uploaded
        # but here we'll assume we delete after success
        for f in files:
            local_path = os.path.join(self.vault_path, f)
            # Vault filename format: Ymd_HMS_filename
            # We reconstruct the original filename by stripping the first 16 chars
            original_filename = f[16:] if len(f) > 16 else f
            
            # We don't have the original full path here easily, 
            # but backend only needs the filename and content.
            self._do_upload(local_path, original_filename)

    def _do_upload(self, local_path, original_filename):
        # Move actual upload logic to a helper for reuse
        handler = ShadowHandler(self.agent_id, self.api_key, self.backend_url, self.vault_path, self.data_queue)
        handler._upload_shadow(local_path, original_filename, delete_on_success=True)

# Update ShadowHandler to support deletion on success
