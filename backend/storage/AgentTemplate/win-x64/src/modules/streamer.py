import mss
import mss.tools
import threading
import time
import base64
import asyncio

class ScreenStreamer:
    def __init__(self, sio, agent_id):
        self.sio = sio
        self.agent_id = agent_id
        self.running = False
        self.thread = None
        self.fps = 2  # Low FPS to save bandwidth (PNG is heavy)

    def start(self):
        if self.running: return
        self.running = True
        self.thread = threading.Thread(target=self._loop, daemon=True)
        self.thread.start()
        print("[Streamer] Screen Stream Started")

    def stop(self):
        self.running = False
        print("[Streamer] Screen Stream Stopped")

    def _loop(self):
        with mss.mss() as sct:
            while self.running:
                loop_start = time.time()
                try:
                    # Capture Monitor 1
                    monitor = sct.monitors[1]
                    sct_img = sct.grab(monitor)
                    
                    # Convert to PNG (Slow but standard)
                    # For better perf, would need PIL/OpenCV to resize/JPEG
                    png_bytes = mss.tools.to_png(sct_img.rgb, sct_img.size)
                    
                    # Encode Base64
                    b64_str = base64.b64encode(png_bytes).decode('utf-8')
                    
                    # Emit via Socket.IO
                    # run_coroutine_threadsafe is needed because sio is async and we are in a thread
                    asyncio.run_coroutine_threadsafe(
                        self.sio.emit('stream_frame', {'image': b64_str, 'agent_id': self.agent_id}),
                        self.sio.loop
                    )
                    
                except Exception as e:
                    print(f"[Streamer] Capture Error: {e}")

                # FPS Control
                elapsed = time.time() - loop_start
                sleep_time = max(0, (1.0 / self.fps) - elapsed)
                time.sleep(sleep_time)
