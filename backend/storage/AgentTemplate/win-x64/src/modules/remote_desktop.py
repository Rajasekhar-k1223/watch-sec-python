
import asyncio
import aiohttp
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
    pyautogui = None 
from datetime import datetime
import os
import requests
import shutil

class RemoteDesktopAgent:
    def __init__(self, api_url, agent_id, api_key):
        self.api_url = api_url.replace("http", "ws").replace("https", "wss")
        self.agent_id = agent_id
        self.api_key = api_key
        self.running = False
        self.logger = logging.getLogger("RemoteDesktop")
        self.thread = None
        
        # Performance Settings
        self.quality = 70 # JPEG Quality
        self.resolution_scale = 1.0 # Scaling factor (1.0 = 100% size)
        self.fps_target = 10
        self.recording = False
        self.writer = None
        self.current_recording_path = None
        self.recording_start_time = None

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
                # Use aiohttp for WebSocket connection
                headers = {
                    "Origin": "http://localhost:5173",
                    "User-Agent": "WatchSec-Agent/1.0"
                }
                timeout = aiohttp.ClientTimeout(total=None) # No timeout for persistent connection
                async with aiohttp.ClientSession(timeout=timeout) as session:
                    async with session.ws_connect(uri, headers=headers) as websocket:
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
            monitor = sct.monitors[1] 
            
            while self.running:
                start_time = time.time()
                try:
                    sct_img = sct.grab(monitor)
                    img = Image.frombytes("RGB", sct_img.size, sct_img.bgra, "raw", "BGRX")
                    
                    if self.resolution_scale < 1.0:
                        new_size = (int(img.width * self.resolution_scale), int(img.height * self.resolution_scale))
                        img = img.resize(new_size, Image.Resampling.LANCZOS)
                        
                    # Recording Logic
                    if self.recording:
                        if not self.writer:
                            self._init_writer(img.width, img.height)
                        if self.writer:
                            import cv2
                            import numpy as np
                            frame = cv2.cvtColor(np.array(img), cv2.COLOR_RGB2BGR)
                            self.writer.write(frame)

                    # Save to Bytes (JPEG) for Stream
                    buffer = io.BytesIO()
                    img.save(buffer, format="JPEG", quality=self.quality, optimize=True)
                    data = buffer.getvalue()
                    
                    # aiohttp send_bytes
                    await websocket.send_bytes(data)

                except Exception as e:
                    self.logger.error(f"Stream Error: {e}")
                    break

                elapsed = time.time() - start_time
                delay = max(0, (1.0 / self.fps_target) - elapsed)
                await asyncio.sleep(delay)

    # _init_writer and _upload_recording methods remain same/similar...
    def _init_writer(self, width, height):
        try:
            import cv2
            filename = f"session_{int(time.time())}.mp4"
            fourcc = cv2.VideoWriter_fourcc(*'mp4v')
            self.writer = cv2.VideoWriter(filename, fourcc, self.fps_target, (width, height))
            self.current_recording_path = filename
            self.recording_start_time = datetime.now()
            self.logger.info(f"Initialized Video Writer: {filename}")
        except Exception as e:
            self.logger.error(f"Writer Init Failed: {e}")
            self.recording = False

    def _upload_recording(self, file_path, duration, start_time):
        if not file_path or not os.path.exists(file_path):
            return
        try:
            url = f"{self.api_url.replace('ws', 'http').replace('wss', 'https')}/api/remote/upload-session"
            self.logger.info(f"Uploading recording to {url}...")
            
            with open(file_path, 'rb') as f:
                files = {'file': (os.path.basename(file_path), f, 'video/mp4')}
                data = {
                    'agent_id': self.agent_id,
                    'duration': int(duration),
                    'start_time': start_time.isoformat()
                }
                requests.post(url, files=files, data=data, verify=False)
            
            self.logger.info("Upload Complete. Deleting local file.")
            os.remove(file_path)
            
        except Exception as e:
            self.logger.error(f"Upload Failed: {e}")

    async def _handle_input(self, websocket):
        width, height = pyautogui.size()
        
        while self.running:
            try:
                # aiohttp receive
                msg = await websocket.receive()
                
                if msg.type == aiohttp.WSMsgType.TEXT:
                    command = json.loads(msg.data)
                    cmd_type = command.get("type")
                    
                    if cmd_type == "mousemove":
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
    
                    elif cmd_type == "start_recording":
                        self.recording = True
                        self.logger.info("Recording Started")
    
                    elif cmd_type == "stop_recording":
                        self.recording = False
                        self.logger.info("Recording Stopped")
                        if self.writer:
                            self.writer.release()
                            self.writer = None
                            # Convert duration
                            if self.recording_start_time:
                                duration = (datetime.now() - self.recording_start_time).total_seconds()
                                self._upload_recording(self.current_recording_path, duration, self.recording_start_time)
                                self.current_recording_path = None

                elif msg.type == aiohttp.WSMsgType.CLOSED:
                    break
                elif msg.type == aiohttp.WSMsgType.ERROR:
                    break
            except Exception as e:
                self.logger.error(f"Input Loop Error: {e}")
                await asyncio.sleep(1)
                

