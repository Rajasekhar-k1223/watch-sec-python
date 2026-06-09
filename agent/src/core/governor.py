import psutil
import logging
import asyncio

logger = logging.getLogger(__name__)

class ResourceGovernor:
    def __init__(self, max_cpu_percent=5.0, max_ram_mb=150):
        self.max_cpu = max_cpu_percent
        self.max_ram = max_ram_mb * 1024 * 1024
        self.state = "GREEN"

    async def monitor_resources(self):
        """Layer 13: Continuously monitors the agent's footprint."""
        logger.info(f"[GOVERNOR] Monitoring started. Budget: {self.max_cpu}% CPU, {self.max_ram/1024/1024}MB RAM")
        
        while True:
            try:
                # In prod, this would measure the specific PID of the agent, not the whole system
                # But for the prototype, we simulate the concept.
                current_state = "GREEN"
                
                # Assume agent is within budget
                if self.state != current_state:
                    logger.info(f"[GOVERNOR] State changed: {self.state} -> {current_state}")
                    self.state = current_state
                    
                await asyncio.sleep(5)
            except Exception as e:
                logger.error(f"[GOVERNOR] Monitor error: {e}")
                await asyncio.sleep(5)
                
    def get_current_state(self) -> str:
        return self.state
