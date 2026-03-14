import threading # type: ignore
import time # type: ignore
import base64 # type: ignore
from io import BytesIO # type: ignore
import asyncio # type: ignore
from typing import Optional # type: ignore

class LiveStreamer:
    def __init__(self, agent_id, sio_client):
        self.agent_id = agent_id
        self.sio = sio_client
        self.running = False
        self.thread: Optional[threading.Thread] = None
        self.stop_event = threading.Event()
        self.frames_sent = 0
        self.loop: Optional[asyncio.AbstractEventLoop] = None

    def start_streaming(self, loop):
        if self.running:
            print("[Stream] Already running.")
            return

        self.loop = loop  # Store the main event loop
        self.running = True
        self.stop_event.clear()
        self.thread = threading.Thread(target=self._stream_loop) # type: ignore
        self.thread.daemon = True # type: ignore
        self.thread.start() # type: ignore
        print("[Stream] Live Streaming Started")

    def stop_streaming(self):
        if not self.running:
            return
        
        self.running = False
        self.stop_event.set()
        # Thread will exit on next loop check
        print("[Stream] Live Streaming Stopped")

    def _stream_loop(self):
        import mss # type: ignore
        from PIL import Image # type: ignore
        with mss.mss() as sct:
            # Monitor 1
            monitor = sct.monitors[1]
            
            while self.running and not self.stop_event.is_set():
                try:
                    start_time = time.time()
                    
                    # 1. Grab Screen
                    sct_img = sct.grab(monitor)
                    img = Image.frombytes("RGB", sct_img.size, sct_img.bgra, "raw", "BGRX")
                    
                    # 2. Resize for Performance (800px width for fluidity)
                    w, h = img.size
                    if w > 800: # Smaller for speed
                        ratio = 800 / w
                        new_h = int(h * ratio)
                        img = img.resize((800, new_h), Image.Resampling.BILINEAR) # Bilinear is faster than Lanczos
                    
                    # 3. Compress to WebP
                    bio = BytesIO()
                    img.save(bio, format="WEBP", quality=50) # Quality 50 for speed
                    b64_data = base64.b64encode(bio.getvalue()).decode('utf-8')
                    
                    if self.frames_sent == 0:
                        print(f"[STREAM_DEBUG] First Frame Captured & Compressed! Size: {len(b64_data)}")
                    self.frames_sent += 1
                    
                    if self.loop and self.loop.is_running(): # type: ignore
                        print(f"[STREAM_DEBUG] Emitting Frame {self.frames_sent} ({len(b64_data)} bytes)")
                        asyncio.run_coroutine_threadsafe(
                            self.sio.emit('stream_frame', {'agentId': self.agent_id, 'image': b64_data}),
                            self.loop # type: ignore
                        )
                    
                    # Cap at ~20 FPS (0.05s)
                    elapsed = time.time() - start_time
                    sleep_time = max(0.05 - elapsed, 0)
                    time.sleep(sleep_time)
                    
                except Exception as e:
                    print(f"[STREAM_ERROR] Capture Loop Failed: {e}")
                    import traceback # type: ignore
                    traceback.print_exc()
                    time.sleep(1) # Backoff
