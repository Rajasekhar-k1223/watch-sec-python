import json # type: ignore
import logging # type: ignore
import asyncio # type: ignore
import requests # type: ignore
from datetime import datetime # type: ignore

class AuditLogger:
    def __init__(self, agent_id, api_key, backend_url, http_session):
        self.agent_id = agent_id
        self.api_key = api_key
        self.backend_url = backend_url
        self.session = http_session
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
        # Echo to console/local log via main app logic usually, 
        # but here we just queue for remote.
        entry = {
            "AgentId": self.agent_id,
            "TenantApiKey": self.api_key,
            "Type": event_type,
            "Details": str(details)[:1000], # type: ignore
            "Timestamp": datetime.utcnow().isoformat()
        }
        try:
            self.queue.put_nowait(entry)
        except:
            pass

    async def _process_queue(self):
        while self.running:
            try:
                # Wait for next log
                entry = await self.queue.get()
                
                # Attempt to send
                url = f"{self.backend_url}/api/events/report"
                try:
                    await asyncio.to_thread(self.session.post, url, json=entry, timeout=5, verify=False)
                except Exception as e:
                    print(f"[AuditLogger] Failed to upload log: {e}")
                
                self.queue.task_done()
            except Exception:
                await asyncio.sleep(1)
