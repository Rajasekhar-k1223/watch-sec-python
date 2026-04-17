import json # type: ignore
import logging # type: ignore
import asyncio # type: ignore
import requests # type: ignore
from datetime import datetime # type: ignore

class AuditLogger:
    def __init__(self, agent_id, api_key, backend_url, data_queue=None):
        self.agent_id = agent_id
        self.api_key = api_key
        self.backend_url = backend_url
        self.data_queue = data_queue
        # We keep the async queue internally for buffering before DataQueue if needed, 
        # but AuditLogger is mostly used sparingly.
        self.queue = asyncio.Queue()
        self.running = False

    def start(self):
        self.running = True
        asyncio.create_task(self._process_queue())

    def stop(self):
        self.running = False

    def log(self, event_type, details):
        """
        Queues a log entry to be sent to the backend.
        Event Types: 'System', 'Error', 'Security', 'Update', etc.
        """
        entry = {
            "AgentId": self.agent_id,
            # [v1.8.38] Telemetry Stealth: Plaintext Key Suppressed.
            # Signing handled by DataQueue.
            "Type": event_type,
            "Details": str(details)[:1000],  # type: ignore
            "Timestamp": datetime.utcnow().isoformat()
        }
        
        if self.data_queue:
            # Direct enqueue to DataQueue (Stateless & Signed)
            self.data_queue.enqueue("/api/events/report", entry)
        else:
            # Fallback to internal async queue if DataQueue not ready
            try:
                self.queue.put_nowait(entry)
            except:
                pass

    async def _process_queue(self):
        while self.running:
            try:
                # Wait for next log from internal queue (only used if DataQueue was missing at log time)
                entry = await self.queue.get()
                
                if self.data_queue:
                    self.data_queue.enqueue("/api/events/report", entry)
                else:
                    # [SECURITY] Stealth Mode: Forbidden to send plaintext key or unsigned requests.
                    # We discard if DataQueue is not available as direct send is no longer secure.
                    pass
                
                self.queue.task_done()
            except Exception:
                await asyncio.sleep(1)
