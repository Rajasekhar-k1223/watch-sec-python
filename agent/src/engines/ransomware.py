import time
import logging

logger = logging.getLogger(__name__)

class RansomwareShield:
    def __init__(self):
        # Layer 7: Token Bucket Threshold Strategy
        # Maps PID -> {"score": 0, "last_updated": timestamp}
        self.pid_buckets = {}
        
    def evaluate_file_action(self, pid: int, action_type: str, entropy: float = 0.0) -> bool:
        """Layer 7: Evaluates FileWrite/FileRename actions for Ransomware behavior."""
        now = time.time()
        
        if pid not in self.pid_buckets:
            self.pid_buckets[pid] = {"score": 0, "last_updated": now}
            
        bucket = self.pid_buckets[pid]
        
        # Decay score by 1 point per second to avoid triggering on slow, legitimate actions
        time_diff = now - bucket["last_updated"]
        if time_diff > 0:
            bucket["score"] = max(0, bucket["score"] - int(time_diff))
            
        bucket["last_updated"] = now
        
        # Apply heuristics
        if action_type == "HighEntropyWrite" and entropy > 7.5:
            bucket["score"] += 10
        elif action_type == "MassRename":
            bucket["score"] += 15
        elif action_type == "DeleteShadows":
            bucket["score"] += 1000  # Instant trigger
            
        logger.debug(f"[RANSOMWARE_SHIELD] PID {pid} Threat Score: {bucket['score']}")
        
        # Trigger Autonomous Defense if Threshold breached
        if bucket["score"] >= 100:
            logger.critical(f"[RANSOMWARE_SHIELD] THRESHOLD BREACHED FOR PID {pid}! Triggering Quarantine.")
            self._trigger_response(pid)
            return True
            
        return False
        
    def _trigger_response(self, pid: int):
        """Executes safe autonomous response (Kill process, Isolate Network)."""
        logger.critical(f"[RESPONSE] Autonomous action: Terminating Malicious PID {pid}")
        # In a real implementation, this would call psutil.Process(pid).kill()
        pass
