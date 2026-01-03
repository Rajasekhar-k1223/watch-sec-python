
import asyncio
import websockets
import json
import logging
import threading
import time
import base64
import io
import mss
from PIL import Image
try:
    import pyautogui
except ImportError:
    pyautogui = None # Handle missing dependency gracefully usually

class RemoteDesktopAgent:
    def __init__(self, api_url, agent_id, api_key):
        self.api_url = api_url.replace("http", "ws") # Ensure ws:// scheme
        self.agent_id = agent_id
        self.api_key = api_key
        self.running = False
        self.logger = logging.getLogger("RemoteDesktop")
        self.thread = None
        
        # Performance Settings
        self.quality = 60 # JPEG Quality
        self.resolution_scale = 0.6 # Scaling factor (0.5 = 50% size)
        self.fps_target = 10

    def start(self):
        if not pyautogui:
            self.logger.error("PyAutoGUI not installed. Remote Control disabled.")
            return

        self.running = True
        self.thread = threading.Thread(target=self._run_async_loop, daemon=True)
        self.thread.start()
        self.logger.info("Remote Desktop Agent Started.")

    def stop(self):
        self.running = False
        if self.thread:
            self.thread.join(timeout=2)

    def _run_async_loop(self):
        # Create a new event loop for this thread
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(self._connect())

    async def _connect(self):
        uri = f"{self.api_url}/api/ws/agent/{self.agent_id}?api_key={self.api_key}"
        self.logger.info(f"Connecting to Remote Hub: {uri}")
        
        while self.running:
            try:
                # Add headers to satisfy CORS and potential future auth requirements
                extra_headers = {
                    "Origin": "http://localhost:5173",
                    "User-Agent": "WatchSec-Agent/1.0"
                }
                async with websockets.connect(uri, extra_headers=extra_headers) as websocket:
                    self.logger.info("Connected to Remote Hub.")
                    
                    # Start Sender and Receiver tasks
                    sender_task = asyncio.create_task(self._stream_screen(websocket))
                    receiver_task = asyncio.create_task(self._handle_input(websocket))
                    
                    done, pending = await asyncio.wait(
                        [sender_task, receiver_task],
                        return_when=asyncio.FIRST_COMPLETED
                    )
                    
                    for task in pending:
                        task.cancel()
                        
            except Exception as e:
                self.logger.error(f"Connection Error: {e}")
                await asyncio.sleep(5) # Retry delay

    async def _stream_screen(self, websocket):
        with mss.mss() as sct:
            # Select first monitor
            monitor = sct.monitors[1] 
            
            while self.running:
                start_time = time.time()
                
                try:
                    # Capture
                    sct_img = sct.grab(monitor)
                    
                    # Convert to PIL
                    img = Image.frombytes("RGB", sct_img.size, sct_img.bgra, "raw", "BGRX")
                    
                    # Resize
                    if self.resolution_scale < 1.0:
                        new_size = (int(img.width * self.resolution_scale), int(img.height * self.resolution_scale))
                        img = img.resize(new_size, Image.Resampling.LANCZOS)
                        
                    # Save to Bytes (JPEG)
                    buffer = io.BytesIO()
                    img.save(buffer, format="JPEG", quality=self.quality, optimize=True)
                    data = buffer.getvalue()
                    
                    # Send Binary
                    await websocket.send(data)
                    
                except Exception as e:
                    self.logger.error(f"Stream Error: {e}")
                    break

                # FPS Control
                elapsed = time.time() - start_time
                delay = max(0, (1.0 / self.fps_target) - elapsed)
                await asyncio.sleep(delay)

    async def _handle_input(self, websocket):
        width, height = pyautogui.size()
        
        while self.running:
            try:
                msg = await websocket.recv()
                command = json.loads(msg)
                
                cmd_type = command.get("type")
                
                if cmd_type == "mousemove":
                    # Coords are normalized 0.0-1.0
                    x = int(command["x"] * width)
                    y = int(command["y"] * height)
                    pyautogui.moveTo(x, y)
                    
                elif cmd_type == "click":
                    x = int(command["x"] * width)
                    y = int(command["y"] * height)
                    button = command.get("button", "left")
                    pyautogui.click(x, y, button=button)
                    
                elif cmd_type == "keypress":
                    key = command.get("key")
                    pyautogui.press(key)
                    
                elif cmd_type == "type":
                    text = command.get("text")
                    pyautogui.typewrite(text)

                elif cmd_type == "lock":
                    try:
                        import ctypes
                        ctypes.windll.user32.LockWorkStation()
                        self.logger.info("Executed Lock Workstation command.")
                    except Exception as e:
                        self.logger.error(f"Failed to lock workstation: {e}")

            except Exception as e:
                self.logger.error(f"Input Error: {e}")
                break
