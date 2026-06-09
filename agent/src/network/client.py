import json
import uuid
import hmac
import hashlib
import logging
import asyncio
from datetime import datetime, timezone
import urllib.request
import urllib.error

logger = logging.getLogger(__name__)

class NetworkClient:
    def __init__(self, base_url="https://api.monitorix.local/api/v2", machine_secret="fallback_secret_key"):
        self.base_url = base_url
        self.machine_secret = machine_secret.encode()
        
    def _generate_hmac(self, payload_str: str) -> str:
        """Layer 3: Generates HMAC-SHA256 signature for offline fallback mode."""
        return hmac.new(self.machine_secret, payload_str.encode(), hashlib.sha256).hexdigest()

    def upload_telemetry_batch(self, events: list, agent_id: str) -> bool:
        """Layer 3: Uploads a batch of telemetry via REST."""
        if not events:
            return True
            
        payload = {
            "agent_id": agent_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "nonce": str(uuid.uuid4()),
            "batch_size": len(events),
            "events": events
        }
        
        payload_json = json.dumps(payload)
        signature = self._generate_hmac(payload_json)
        
        # Mocking the actual HTTP POST to avoid requiring a running backend
        logger.info(f"[NETWORK] POST {self.base_url}/telemetry/ingest | Batch Size: {len(events)} | Sig: {signature[:16]}...")
        
        # Simulate successful upload
        return True

    async def connect_websocket(self, agent_id: str, command_mgr):
        """Layer 3: Persistent WebSocket for SOAR commands."""
        # Using a mock loop to simulate the persistent connection for the prototype
        logger.info(f"[NETWORK] Connecting WebSocket to {self.base_url.replace('https', 'wss')}/ws/agent/{agent_id}...")
        try:
            while True:
                # Simulate listening for commands
                await asyncio.sleep(10)
        except asyncio.CancelledError:
            logger.info("[NETWORK] WebSocket connection closed gracefully.")
