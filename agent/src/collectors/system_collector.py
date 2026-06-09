import asyncio
import logging
import psutil
from src.collectors.base_collector import BaseCollector

logger = logging.getLogger(__name__)

class SystemCollector(BaseCollector):
    async def start(self):
        """Layer 5: Collects OS, CPU, RAM, and Running Services."""
        self.is_running = True
        logger.info("[COLLECTOR] SystemCollector started.")
        
        while self.is_running:
            try:
                # Capture system metrics
                cpu_percent = psutil.cpu_percent(interval=1)
                memory = psutil.virtual_memory()
                disk = psutil.disk_usage('/')
                
                payload = {
                    "cpu_percent": cpu_percent,
                    "ram_percent": memory.percent,
                    "disk_percent": disk.percent,
                    "active_processes": len(psutil.pids())
                }
                
                self.emit("SystemMetrics", payload)
                await asyncio.sleep(60) # Poll every 60 seconds
                
            except Exception as e:
                logger.error(f"[COLLECTOR] SystemCollector error: {e}")
                await asyncio.sleep(5)

    async def stop(self):
        logger.info("[COLLECTOR] SystemCollector stopping.")
        self.is_running = False
