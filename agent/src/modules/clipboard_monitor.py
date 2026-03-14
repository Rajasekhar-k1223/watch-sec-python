
import threading # type: ignore
import time # type: ignore
import requests # type: ignore
import re # type: ignore
import logging # type: ignore
import pyperclip # type: ignore
from datetime import datetime # type: ignore
from typing import Optional # type: ignore

class ClipboardMonitor:
    def __init__(self, agent_id, api_key, backend_url, data_queue=None):
        self.agent_id = agent_id
        self.api_key = api_key
        self.backend_url = backend_url.rstrip('/')
        self.data_queue = data_queue
        self.last_content = ""
        self.running = False
        self._thread: Optional[threading.Thread] = None
        self.logger = logging.getLogger("ClipboardMonitor")
        
        # Regex Patterns for DLP
        self.patterns = {
            "Email": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
            "CreditCard": r"\b(?:\d{4}[- ]?){3}\d{4}\b",
            "SSN": r"\b\d{3}-\d{2}-\d{4}\b",
            "Phone": r"\b\+?[1-9]\d{7,14}\b",
            "SensitiveKeywords": r"(?i)(confidential|secret|salary|password|invoice|internal only|restriced|project|contract|legal|financial)"
        }

    def start(self):
        if self.running: return
        self.running = True
        self._thread = threading.Thread(target=self._loop, daemon=True) # type: ignore
        self._thread.start() # type: ignore
        self.logger.info("Clipboard Monitor Started.")

    def stop(self):
        self.running = False
        if self._thread:
            self._thread.join(timeout=2) # type: ignore
            
    def _loop(self):
        while self.running:
            try:
                try:
                    content = pyperclip.paste()
                except:
                    content = ""

                if content and content != self.last_content:
                    self.last_content = content
                    self._analyze_and_report(content)
                
            except Exception as e:
                self.logger.error(f"Clipboard Loop Error: {e}")
            
            time.sleep(2.0) 

    def _analyze_and_report(self, content):
        risk_level = "Normal"
        flagged_types = []
        
        for rule, pattern in self.patterns.items():
            if re.search(pattern, content):
                flagged_types.append(rule)
                risk_level = "High"

        preview = content[:1000]
        if len(content) > 1000:
            preview += "..."

        event_data = {
            "AgentId": self.agent_id,
            "TenantApiKey": self.api_key,
            "ActivityType": "Clipboard",
            "ProcessName": "Clipboard",
            "WindowTitle": preview, 
            "RiskLevel": risk_level,
            "Category": f"DLP:{','.join(flagged_types)}" if flagged_types else "General",
            "IdleSeconds": 0,
            "DurationSeconds": 0,
            "Timestamp": datetime.utcnow().isoformat()
        }
        
        self._send_log(event_data)

    def _send_log(self, data):
        if self.data_queue:
            # Assuming clipboard logs go to activity for now, or a specific clipboard endpoint?
            # Backend usually handles "ActivityType" = "Clipboard"
            self.data_queue.enqueue("/api/events/activity", data, priority='high')
        else:
            self.logger.error(f"[Clipboard] [ERROR] No DataQueue available to report activity.")
