import requests # type: ignore
import os # type: ignore
import threading # type: ignore
import time # type: ignore
from datetime import datetime # type: ignore
from typing import Optional # type: ignore
from io import BytesIO # type: ignore

class ScreenshotCapture:
    def __init__(self, agent_id, api_key, backend_url, interval=60):
        self.agent_id = agent_id
        self.api_key = api_key
        self.backend_url = backend_url
        self.interval = interval
        self.running = False
        self.enabled = False
        self.paused = False
        self.thread: Optional[threading.Thread] = None
        # Config Defaults
        self.quality = 80
        self.resolution = "Original" 
        self.max_size = 0 # 0 = Unlimited (KB)
        
        # Robust Session
        self.session = requests.Session()
        adapter = requests.adapters.HTTPAdapter(max_retries=3)
        self.session.mount('https://', adapter)
        self.session.mount('http://', adapter)
        self.last_capture_time = 0

    def set_config(self, quality, resolution, max_size, interval=None):
        self.quality = int(quality) if quality is not None else 80
        self.resolution = str(resolution) if resolution is not None else "Original"
        self.max_size = int(max_size) if max_size is not None else 0
        if interval is not None:
             self.interval = int(interval)
        print(f"[Screens] Config Updated: Q={self.quality}, Res={self.resolution}, Max={self.max_size}KB, Int={self.interval}s")

    def start(self):
        if self.running: return
        self.running = True
        
        # [v1.8.21] Re-initialize session if it was purged
        if not hasattr(self, 'session') or self.session is None:
            self.session = requests.Session()
            adapter = requests.adapters.HTTPAdapter(max_retries=3)
            self.session.mount('https://', adapter)
            self.session.mount('http://', adapter)
            if self.api_key:
                self.session.headers.update({"X-Tenant-Api-Key": self.api_key})

        self.thread = threading.Thread(target=self._loop) # type: ignore
        self.thread.daemon = True # type: ignore
        self.thread.start() # type: ignore
        print("[Screens] Module Started (Background Loop)")

    def stop(self):
        if not self.running: return
        self.running = False
        if self.thread:
            self.thread.join(timeout=1) # type: ignore
            self.thread = None
        
        # [v1.8.21] Aggressive Memory Purge
        if hasattr(self, 'session') and self.session:
            try: self.session.close()
            except: pass
            self.session = None
        print("[Screens] Module Stopped (Memory Purged)")

    def set_enabled(self, enabled: bool):
        if self.enabled != enabled:
            self.enabled = enabled
            state_str = "Enabled" if enabled else "Disabled"
            print(f"[Screens] State changed to: {state_str}")
            self._report_audit("POLICY_APPLIED", f"Screenshot Capture is now {state_str}")

    def set_paused(self, paused: bool):
        if self.paused != paused:
            self.paused = paused
            state_str = "Paused (System Locked)" if paused else "Resumed (System Unlocked)"
            print(f"[Screens] {state_str}")

    def _report_audit(self, event_type, details):
        payload = {
            "AgentId": self.agent_id,
            "TenantApiKey": self.api_key,
            "Type": event_type,
            "Details": details,
            "Timestamp": datetime.utcnow().isoformat()
        }
        try:
            self.session.post(f"{self.backend_url}/api/events/report", json=payload, timeout=5, verify=False)
        except: pass

    def _loop(self):
        while self.running:
            if self.enabled and not self.paused:
                self.capture_now()
            
            # [v1.8.19] Reactive Wait: Sleep in 1s increments to respond to interval changes or shutdown
            start_wait = time.time()
            while self.running:
                elapsed = time.time() - start_wait
                if elapsed >= self.interval:
                    break
                time.sleep(1)

    def _create_error_frame(self, text: str) -> bytes:
        from PIL import Image, ImageDraw # type: ignore
        img = Image.new('RGB', (800, 600), color=(15, 15, 15))
        draw = ImageDraw.Draw(img)
        draw.text((50, 300), text, fill=(255, 80, 80))
        bio = BytesIO()
        img.save(bio, format="WEBP", quality=50)
        return bio.getvalue()

    def capture_now(self):
        import mss # type: ignore
        # Don't capture if disabled or if we are paused AND it's not a forced "one-last-shot"
        # Wait, if we are calling capture_now() explicitly (like on lock), we should ignore the pause flag.
        try:
            with mss.mss() as sct:
                # [FIX] Robust monitor detection
                if not sct.monitors:
                    print("[Screens] Error: No monitors detected")
                    return False, "No monitors detected"
                
                # Default to primary monitor (index 1 in mss)
                monitor_idx = 1 if len(sct.monitors) > 1 else 0
                self._capture_and_send(sct, monitor_idx)
                return True, "Screenshot Sent"
        except mss.ScreenShotError:
            print("[Screens] Screen Locked/Secure Desktop - Creating Placeholder")
            self._send_raw_bytes(self._create_error_frame("NO VIDEO SIGNAL\nScreen Locked (mss.ScreenShotError)"))
            return False, "Screen Locked"
        except Exception as e:
            # Check for Session 0 / Headless indicators
            error_msg = str(e)
            if "Windll.user32.GetWindowDC" in error_msg or "failed to get the device context" in error_msg.lower():
                print("[Screens] CRITICAL: Running in Headless/Service Session. Desktop capture impossible.")
                error_msg = "Headless Session (SYSTEM)"
            else:
                print(f"[Screens] Capture failed: {error_msg}")
            
            if self.enabled:
                self._report_audit("CAPTURE_ERROR", error_msg)
            
            self._send_raw_bytes(self._create_error_frame(f"NO VIDEO SIGNAL\n{error_msg}"))
            return False, error_msg

    def _capture_and_send(self, sct, monitor_idx):
        from PIL import Image # type: ignore
        # Capture Monitor
        monitor = sct.monitors[monitor_idx]
        sct_img = sct.grab(monitor)
        
        # Convert to PIL Image
        # [FIX] mss raw data is in BGRA format. On Windows, 
        # ensure it matches the BGRX raw decoder.
        img = Image.frombytes("RGB", sct_img.size, sct_img.bgra, "raw", "BGRX")
        
        # [NEW] Check for 100% black images (locked/headless/minimized RDP)
        extrema = img.convert("L").getextrema()
        if extrema == (0, 0):
            print("[Screens] Image is completely black. Sending placeholder instead.")
            self._send_raw_bytes(self._create_error_frame("NO VIDEO SIGNAL\nDesktop Inaccessible (RDP Minimized / Locked)"))
            return
        
        # 1. Resize Logic
        if self.resolution != "Original":
            w, h = img.size
            new_w = w
            if self.resolution == "720p":
                new_w = 1280
            elif self.resolution == "480p":
                new_w = 854
            
            if new_w < w: # Only downscale
                ratio = new_w / w
                new_h = int(h * ratio)
                img = img.resize((new_w, new_h), Image.Resampling.LANCZOS)

        # 2. Save/Compress Logic with Max Size Constraint
        current_quality = self.quality
        
        bio = BytesIO()
        img.save(bio, format="WEBP", quality=current_quality)
        webp_bytes = bio.getvalue()
        
        # Max Size Check (KB -> Bytes)
        if self.max_size > 0:
            target_bytes = self.max_size * 1024
            while len(webp_bytes) > target_bytes and current_quality > 10:
                print(f"[Screens] Size {len(webp_bytes)} > {target_bytes}. Reducing quality...")
                current_quality -= 10
                bio = BytesIO()
                img.save(bio, format="WEBP", quality=current_quality)
                webp_bytes = bio.getvalue()

        
        # Send to Backend use .webp extension
        self._send_raw_bytes(webp_bytes)
        
    def _send_raw_bytes(self, webp_bytes: bytes):
        now = datetime.utcnow()
        files = {
            'file': (f'screen.webp', webp_bytes, 'image/webp')
        }
        data = {
            'agent_id': self.agent_id,
            'created_at': now.isoformat()
        }
        
        try:
            url = f"{self.backend_url}/api/screenshots/upload"
            resp = self.session.post(url, files=files, data=data, timeout=20, verify=False)
            if resp.status_code == 200:
                print(f"[Screens] Sent Screenshot")
            else:
                print(f"[Screens] Upload Failed: {resp.status_code}")
                raise Exception(f"Upload Failed: {resp.status_code}")
        except Exception as e:
            print(f"[Screens] Network Error: {e}")
            raise
