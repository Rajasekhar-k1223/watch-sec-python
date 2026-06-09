import asyncio
import logging
from src.storage.local_db import LocalDB

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
logger = logging.getLogger(__name__)

class MonitorixWorker:
    def __init__(self):
        self.db = LocalDB()
        self.is_running = False

    async def start(self):
        """Initializes the worker loops."""
        logger.info("[WORKER] Starting Monitorix Telemetry Worker...")
        self.is_running = True
        
        # In a full implementation, we would start multiple async tasks here:
        # asyncio.create_task(self._collection_loop())
        # asyncio.create_task(self._sync_loop())
        
        try:
            while self.is_running:
                logger.info("[WORKER] Worker is healthy. Gathering telemetry...")
                
                # Mock collecting a process event
                self.db.queue_event("ProcessCreate", {
                    "process_id": 1024,
                    "image_path": "C:\\Windows\\System32\\cmd.exe",
                    "command_line": "cmd.exe /c whoami"
                })
                
                # Mock flushing the offline buffer to the backend
                pending = self.db.fetch_pending_events(limit=50)
                if pending:
                    logger.info(f"[WORKER] Flushed {len(pending)} events to backend.")
                    self.db.delete_events([e["db_id"] for e in pending])
                    
                await asyncio.sleep(5)
                
        except asyncio.CancelledError:
            logger.info("[WORKER] Worker shutting down gracefully...")
            self.is_running = False

if __name__ == "__main__":
    worker = MonitorixWorker()
    try:
        asyncio.run(worker.start())
    except KeyboardInterrupt:
        pass
