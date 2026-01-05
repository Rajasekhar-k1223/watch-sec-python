import mss
import mss.tools
import requests
import os
import threading
import time
from datetime import datetime
from io import BytesIO
from PIL import Image

class ScreenshotCapture:
    def __init__(self, agent_id, api_key, backend_url, interval=60):
        self.agent_id = agent_id
        self.api_key = api_key
        self.backend_url = backend_url
        self.interval = interval
        self.running = False
        self.thread = None
        # Config Defaults
        self.quality = 80
        self.resolution = "Original" 
        self.max_size = 0 # 0 = Unlimited (KB)

    def set_config(self, quality, resolution, max_size):
        self.quality = int(quality) if quality else 80
        self.resolution = str(resolution) if resolution else "Original"
        self.max_size = int(max_size) if max_size else 0
        print(f"[Screens] Config Updated: Q={self.quality}, Res={self.resolution}, Max={self.max_size}KB")

    def start(self):
        self.running = True
        self.enabled = False 
        self.thread = threading.Thread(target=self._loop)
        self.thread.daemon = True
        self.thread.start()
        print("[Screens] Module Started (Background Loop)")

    def stop(self):
        self.running = False
        if self.thread:
            self.thread.join(timeout=1)

    def set_enabled(self, enabled: bool):
        if self.enabled != enabled:
            self.enabled = enabled
            state_str = "Enabled" if enabled else "Disabled"
            print(f"[Screens] State changed to: {state_str}")

    def _loop(self):
        while self.running:
            if self.enabled:
                self.capture_now()
            
            # Sleep in chunks to allow quick shutdown
            for _ in range(self.interval):
                if not self.running: 
                    break
                time.sleep(1)

    def capture_now(self):
        with mss.mss() as sct:
            try:
                self._capture_and_send(sct)
                return True, "Screenshot Sent"
            except Exception as e:
                print(f"[Screens] Error: {e}")
                return False, str(e)

    def _capture_and_send(self, sct):
        # Capture Monitor 1
        monitor = sct.monitors[1]
        sct_img = sct.grab(monitor)
        
        # Convert to PIL Image
        img = Image.frombytes("RGB", sct_img.size, sct_img.bgra, "raw", "BGRX")
        
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
            resp = requests.post(url, files=files, data=data, timeout=10)
            if resp.status_code == 200:
                print(f"[Screens] Sent Screenshot")
            else:
                print(f"[Screens] Upload Failed: {resp.status_code}")
                raise Exception(f"Upload Failed: {resp.status_code}")
        except Exception as e:
            print(f"[Screens] Network Error: {e}")
            raise
