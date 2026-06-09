import sys
import time
import subprocess
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
logger = logging.getLogger(__name__)

class AgentSupervisor:
    def __init__(self, worker_script="src/core/worker.py"):
        self.worker_script = worker_script
        self.worker_process = None
        self.running = False

    def start(self):
        """Starts the watchdog loop."""
        logger.info("[SUPERVISOR] Monitorix Agent Supervisor started.")
        self.running = True
        
        while self.running:
            self._ensure_worker_running()
            time.sleep(5)
            
    def _ensure_worker_running(self):
        """Spawns the worker if it isn't running. Restarts it if it crashed."""
        if self.worker_process is None or self.worker_process.poll() is not None:
            if self.worker_process is not None:
                exit_code = self.worker_process.poll()
                logger.warning(f"[SUPERVISOR] Worker crashed with exit code {exit_code}. Restarting...")
                
            logger.info("[SUPERVISOR] Spawning new worker process...")
            # Use sys.executable to ensure we use the same Python interpreter (or virtualenv)
            self.worker_process = subprocess.Popen([sys.executable, self.worker_script])
            
    def stop(self):
        self.running = False
        if self.worker_process and self.worker_process.poll() is None:
            logger.info("[SUPERVISOR] Terminating worker process...")
            self.worker_process.terminate()
            self.worker_process.wait()
            
if __name__ == "__main__":
    supervisor = AgentSupervisor()
    try:
        supervisor.start()
    except KeyboardInterrupt:
        logger.info("[SUPERVISOR] Caught interrupt signal. Shutting down.")
        supervisor.stop()
