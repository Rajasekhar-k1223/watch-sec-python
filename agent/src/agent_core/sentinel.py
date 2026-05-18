import os
import time
import subprocess
import sys
import logging
import platform
import psutil # type: ignore

logger = logging.getLogger("Sentinel")

class ProcessSentinel:
    """[v2.6.0] Sovereign Sentinel: Ensures the Monitorix Agent process remains immortal."""
    
    def __init__(self, agent_pid: int, binary_path: str):
        self.agent_pid = agent_pid
        self.binary_path = binary_path
        self.os_type = platform.system()

    def start_protection_loop(self):
        """Monitors the main agent and restarts it if it disappears."""
        logger.info(f"Sentinel activated. Guarding PID: {self.agent_pid}")
        
        while True:
            try:
                # Check if the process is still alive
                if not psutil.pid_exists(self.agent_pid):
                    logger.warning("[SECURITY] Main Agent process terminated unexpectedly! Initiating Emergency Recovery...")
                    self.recover_agent()
            except Exception as e:
                logger.error(f"Sentinel monitoring error: {e}")
            
            time.sleep(2) # High-frequency check

    def recover_agent(self):
        """Restarts the agent and updates the tracked PID."""
        try:
            # Start the agent as a new detached process
            if self.os_type == "Windows":
                proc = subprocess.Popen([sys.executable, self.binary_path], 
                                     creationflags=subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.DETACHED_PROCESS)
            else:
                proc = subprocess.Popen([sys.executable, self.binary_path], 
                                     start_new_session=True)
            
            self.agent_pid = proc.pid
            logger.info(f"[RECOVERY] Agent restored with new PID: {self.agent_pid}")
        except Exception as e:
            logger.critical(f"[RECOVERY FAILED] Could not restore agent: {e}")

if __name__ == "__main__":
    # This part is run as a separate process
    if len(sys.argv) < 3:
        sys.exit(1)
        
    target_pid = int(sys.argv[1])
    target_bin = sys.argv[2]
    
    sentinel = ProcessSentinel(target_pid, target_bin)
    sentinel.start_protection_loop()
