import threading # type: ignore
import time # type: ignore
import base64 # type: ignore
from io import BytesIO # type: ignore
import asyncio # type: ignore
from typing import Optional, Callable # type: ignore

class LiveStreamer:
    def __init__(self, agent_id, sio_client, log_func: Optional[Callable] = None):
        self.agent_id = agent_id
        self.sio = sio_client
        self.log_func = log_func
        self.running = False
        self.thread: Optional[threading.Thread] = None
        self.stop_event = threading.Event()
        self.frames_sent = 0
        self.loop: Optional[asyncio.AbstractEventLoop] = None
        self.quality = 80
        self.width = 1280

    def start_streaming(self, loop, data=None):
        # Always extract quality settings if provided
        if data and isinstance(data, dict):
            new_width = data.get('width')
            new_quality = data.get('quality')
            
            if new_width: self.width = int(new_width)
            if new_quality: self.quality = int(new_quality)
            
            msg = f"[LiveStream] Settings Applied: Width={self.width}, Quality={self.quality}"
            if self.log_func: self.log_func(msg)
            print(msg)

        if self.running:
            print("[LiveStream] Already running, settings updated.")
            return

        self.loop = loop  # Store the main event loop
        self.running = True
        self.stop_event.clear()
        self.thread = threading.Thread(target=self._stream_loop) # type: ignore
        self.thread.daemon = True # type: ignore
        self.thread.start() # type: ignore
        
        msg = "[LiveStream] Service Started"
        if self.log_func: self.log_func(msg)
        print(msg)

    def stop_streaming(self):
        if not self.running:
            return
        
        self.running = False
        self.stop_event.set()
        # Thread will exit on next loop check
        msg = "[LiveStream] Service Stopped"
        if self.log_func: self.log_func(msg)
        print(msg)

    def _create_error_frame(self, text: str):
        from PIL import Image, ImageDraw # type: ignore
        img = Image.new('RGB', (800, 600), color=(15, 15, 15))
        draw = ImageDraw.Draw(img)
        draw.text((50, 300), text, fill=(255, 80, 80))
        bio = BytesIO()
        img.save(bio, format="JPEG", quality=50)
        return base64.b64encode(bio.getvalue()).decode('utf-8')

    def _stream_loop(self):
        import mss # type: ignore
        from PIL import Image # type: ignore
        
        with mss.mss() as sct:
            # Monitor Detection
            monitors = sct.monitors
            num_monitors = len(monitors) - 1 # mss virtual '0' monitor
            
            msg = f"[LiveStream] Monitored Screens Detected: {num_monitors}"
            if self.log_func: self.log_func(msg)
            print(msg)

            if num_monitors == 0:
                msg = "[LiveStream ERROR] No screens detected! Capture failed."
                if self.log_func: self.log_func(msg)
                print(msg)
                self.running = False
                return

            # Use Monitor 1 (Primary)
            monitor = monitors[1]
            
            while self.running and not self.stop_event.is_set():
                try:
                    start_time = time.time()
                    
                    # 1. Grab Screen
                    sct_img = sct.grab(monitor)
                    if not sct_img:
                        raise Exception("Captured image is empty or null.")

                    img = Image.frombytes("RGB", sct_img.size, sct_img.bgra, "raw", "BGRX")
                    
                    # Check for pure black screen (RDP minimized / headless / locked)
                    extrema = img.convert("L").getextrema()
                    if extrema == (0, 0):
                        raise Exception("Desktop Inaccessible (RDP Minimized or Screen Locked)")
                    
                    # 2. Resize for Performance
                    w, h = img.size
                    target_w = self.width
                    if w > target_w:
                        ratio = target_w / w
                        new_h = int(h * ratio)
                        img = img.resize((target_w, new_h), Image.Resampling.BILINEAR)
                    
                    # 3. Compress
                    bio = BytesIO()
                    img.save(bio, format="JPEG", quality=self.quality)
                    b64_data = base64.b64encode(bio.getvalue()).decode('utf-8')
                    
                    self.frames_sent += 1
                    
                    if self.loop and self.loop.is_running(): # type: ignore
                        if self.frames_sent % 20 == 1: # Log every 20 frames to avoid log bloat
                            print(f"[LiveStream] Emitting Frame {self.frames_sent} ({len(b64_data)} bytes)")
                        
                        asyncio.run_coroutine_threadsafe(
                            self.sio.emit('stream_frame', {'agentId': self.agent_id, 'image': b64_data}),
                            self.loop # type: ignore
                        )
                    
                    # Target ~15-20 FPS
                    elapsed = time.time() - start_time
                    time.sleep(max(0.06 - elapsed, 0))
                    
                except Exception as e:
                    error_msg = str(e)
                    b64_data = self._create_error_frame(f"NO VIDEO SIGNAL\n{error_msg}")
                    if self.loop and self.loop.is_running(): # type: ignore
                        asyncio.run_coroutine_threadsafe(
                            self.sio.emit('stream_frame', {'agentId': self.agent_id, 'image': b64_data}),
                            self.loop # type: ignore
                        )
                    time.sleep(1) # Send error frame at 1 FPS
