import mss
import mss.tools
import requests
import os
import threading
import time
from datetime import datetime
from io import BytesIO

class ScreenshotCapture:
    def __init__(self, agent_id, api_key, backend_url, interval=60):
        self.agent_id = agent_id
        self.api_key = api_key
        self.backend_url = backend_url
        self.interval = interval
        self.running = False
        self.thread = None

    def start(self):
        if self.running: return
        self.running = True
        self.thread = threading.Thread(target=self._loop, daemon=True)
        self.thread.start()
        print("[Screens] Module Started")

    def stop(self):
        self.running = False

    def _loop(self):
        with mss.mss() as sct:
            while self.running:
                try:
                    self._capture_and_send(sct)
                except Exception as e:
                    print(f"[Screens] Error: {e}")
                
                time.sleep(self.interval)

    def _capture_and_send(self, sct):
        # Capture Monitor 1
        monitor = sct.monitors[1]
        
        # Compress Logic (In-memory)
        # sct.grab returns a raw image. We can save to BytesIO.
        sct_img = sct.grab(monitor)
        
        # Convert to PNG bytes
        png_bytes = mss.tools.to_png(sct_img.rgb, sct_img.size)
        
        # Send to Backend
        now = datetime.utcnow()
        files = {
            'file': (f'screen.png', png_bytes, 'image/png')
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
        except Exception as e:
            print(f"[Screens] Network Error: {e}")
