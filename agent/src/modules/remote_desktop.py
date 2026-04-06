
import asyncio # type: ignore
import aiohttp # type: ignore
import json # type: ignore
import logging # type: ignore
import threading # type: ignore
import time # type: ignore
import base64 # type: ignore
import io # type: ignore
import mss # type: ignore
from PIL import Image # type: ignore
try:
    import pyautogui # type: ignore
except Exception: # ImportError or KeyError: 'DISPLAY'
    pyautogui = None 
from datetime import datetime # type: ignore
import os # type: ignore
import platform # type: ignore
import subprocess # type: ignore
import requests # type: ignore
import shutil # type: ignore
import ctypes # type: ignore
from typing import Any, Optional, Dict # type: ignore

class RemoteDesktopAgent:
    def __init__(self, api_url, agent_id, api_key):
        self.api_url = api_url.replace("http", "ws").replace("https", "wss")
        self.agent_id = agent_id
        self.api_key = api_key
        self.running = False
        self.logger = logging.getLogger("RemoteDesktop")
        self.thread = None
        
        # Performance Settings
        self.quality = 85 # JPEG Quality (Increased for clarity)
        self.resolution_scale = 1.0 # Scaling factor (Removed scaling for crisp text and speed)
        self.fps_target = 30 # Increased for smoother mouse
        self.recording = False
        self.writer: Any = None
        self.current_recording_path: Optional[str] = None
        self.recording_start_time: Optional[datetime] = None
        self.input_blocked = False

        # Set PyAutoGUI for speed
        if pyautogui:
            pyautogui.PAUSE = 0
            pyautogui.MINIMUM_DURATION = 0

    def start(self):
        if not pyautogui:
            self.logger.error("PyAutoGUI not installed. Remote Control disabled.")
            return

        self.running = True
        self.thread = threading.Thread(target=self._run_async_loop, daemon=True) # type: ignore
        self.thread.start() # type: ignore
        self.logger.info("Remote Desktop Agent Started.")

    def stop(self):
        self.running = False
        # Safety: Ensure input is unblocked on stop
        if self.input_blocked:
            self._toggle_input_block(False)
            
        if self.thread:
            self.thread.join(timeout=2) # type: ignore

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
                    "User-Agent": "Monitorix-Agent/1.0"
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
                            import cv2 # type: ignore
                            import numpy as np # type: ignore
                            frame = cv2.cvtColor(np.array(img), cv2.COLOR_RGB2BGR)
                            self.writer.write(frame) # type: ignore

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
                delay = max(0, (1.0 / self.fps_target) - elapsed) # type: ignore
                await asyncio.sleep(delay)

    # _init_writer and _upload_recording methods remain same/similar...
    def _init_writer(self, width, height):
        try:
            import cv2 # type: ignore
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
                headers = {'X-Tenant-Api-Key': self.api_key}
                requests.post(url, files=files, data=data, headers=headers, verify=False)
            
            self.logger.info("Upload Complete. Deleting local file.")
            os.remove(file_path)
            
        except Exception as e:
            self.logger.error(f"Upload Failed: {e}")

    async def _handle_input(self, websocket):
        width, height = (1920, 1080)
        if pyautogui:
            width, height = pyautogui.size()
        
        while self.running:
            try:
                # aiohttp receive
                msg = await websocket.receive()
                
                if msg.type == aiohttp.WSMsgType.TEXT:
                    command = json.loads(msg.data)
                    cmd_type = command.get("type")
                    
                    if cmd_type == "mousemove":
                        if pyautogui:
                            x = int(command["x"] * width)
                            y = int(command["y"] * height)
                            pyautogui.moveTo(x, y) # type: ignore
                        
                    elif cmd_type == "click":
                        if pyautogui:
                            x = int(command["x"] * width)
                            y = int(command["y"] * height)
                            button = command.get("button", "left")
                            pyautogui.click(x, y, button=button) # type: ignore
                        
                    elif cmd_type == "keypress":
                        if pyautogui:
                            key = command.get("key")
                            pyautogui.press(key) # type: ignore
                        
                    elif cmd_type == "type":
                        if pyautogui:
                            text = command.get("text")
                            pyautogui.typewrite(text) # type: ignore
    
                    elif cmd_type == "lock":
                        try:
                            if os.name == 'nt':
                                import ctypes # type: ignore
                                ctypes.windll.user32.LockWorkStation()
                                self.logger.info("Executed Lock Workstation (Windows).")
                            elif platform.system() == "Linux":
                                # Try standard xdg-screensaver
                                subprocess.run(["xdg-screensaver", "lock"], check=False)
                                self.logger.info("Executed Lock Workstation (Linux/XDG).")
                            elif platform.system() == "Darwin":
                                # MacOS Lock
                                cmd = "/System/Library/CoreServices/Menu Extras/User.menu/Contents/Resources/CGSession -suspend"
                                subprocess.run(cmd, shell=True, check=False)
                                self.logger.info("Executed Lock Workstation (macOS).")
                            else:
                                self.logger.info(f"Lock command not implemented for {platform.system()}")
                        except Exception as e:
                            self.logger.error(f"Failed to lock workstation: {e}")
    
                    elif cmd_type == "start_recording":
                        self.recording = True
                        self.logger.info("Recording Started")
    
                            
                    elif cmd_type == "block_input":
                        enabled = command.get("enabled", False)
                        self._toggle_input_block(enabled)
                            
                    elif cmd_type == "stop_recording":
                        self.recording = False
                        self.logger.info("Recording Stopped")
                        if self.writer:
                            self.writer.release()
                            self.writer = None
                            # Convert duration
                            if self.recording_start_time:
                                start_ts: datetime = self.recording_start_time # type: ignore
                                duration = (datetime.now() - start_ts).total_seconds()
                                self._upload_recording(self.current_recording_path, duration, start_ts)
                                self.current_recording_path = None

                elif msg.type == aiohttp.WSMsgType.CLOSED:
                    break
                elif msg.type == aiohttp.WSMsgType.ERROR:
                    break
            except Exception as e:
                self.logger.error(f"Input Loop Error: {e}")
                await asyncio.sleep(1)

    def _toggle_input_block(self, enable):
        """
        Blocks local mouse/keyboard input and turns off monitor to simulate "Curtain Mode"
        """
        try:
            if os.name == 'nt' and hasattr(ctypes, 'windll'):
                # 1. Block Input (Requires Admin)
                windll = getattr(ctypes, 'windll')
                ok = windll.user32.BlockInput(enable)
                
                # 2. Toggle Monitor (2 = Off, -1 = On)
                HWND_BROADCAST = 0xFFFF
                WM_SYSCOMMAND = 0x0112
                SC_MONITORPOWER = 0xF170
                power_setting = 2 if enable else -1
                if hasattr(ctypes, 'windll'):
                    windll = getattr(ctypes, 'windll')
                    windll.user32.SendMessageW(HWND_BROADCAST, WM_SYSCOMMAND, SC_MONITORPOWER, power_setting)
                
                self.logger.info(f"Curtain Mode {'Enabled' if enable else 'Disabled'} (Windows)")
                
            elif platform.system() == 'Linux':
                # Linux Implementation (X11)
                self.input_blocked = enable
                # Monitor Control
                if enable:
                    # Force Monitor Off
                    subprocess.run(["xset", "dpms", "force", "off"], check=False)
                    # Input blocking on Linux usually requires 'xtrlock' or root access to devices
                    # We will log that input blocking is limited without specialized tools
                else:
                    # Force Monitor On
                    subprocess.run(["xset", "dpms", "force", "on"], check=False)
                    subprocess.run(["xset", "s", "reset"], check=False)
                
                self.logger.info(f"Curtain Mode {'Enabled' if enable else 'Disabled'} (Linux - Monitor Power Only)")

            elif platform.system() == 'Darwin':
                # macOS Implementation
                self.input_blocked = enable
                if enable:
                    # sleep display
                    subprocess.run(["pmset", "displaysleepnow"], check=False)
                else:
                    # wake display (simulate user activity or use caffeinate)
                    subprocess.run(["caffeinate", "-u", "-t", "1"], check=False)
                    
                self.logger.info(f"Curtain Mode {'Enabled' if enable else 'Disabled'} (macOS - Monitor Power Only)")
                
            else:
                self.logger.warning(f"Curtain Mode not supported on {platform.system()}")
        except Exception as e:
            self.logger.error(f"Failed to toggle input block: {e}")
