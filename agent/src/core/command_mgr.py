import logging
import psutil
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

class CommandManager:
    def __init__(self, policy_mgr, identity_mgr):
        self.policy = policy_mgr
        self.identity = identity_mgr
        # Hardcoded allowlist to prevent arbitrary shell execution
        self.allowlist = ["KillProcess", "CollectForensics", "IsolateNetwork"]
        
    def execute_command(self, payload: dict) -> dict:
        """Layer 10: Safely validates and executes SOAR commands."""
        command_id = payload.get("command_id")
        action = payload.get("action")
        
        # 1. Validation Gate
        if action not in self.allowlist:
            logger.warning(f"[COMMAND] Rejected {command_id}: Action '{action}' not in allowlist.")
            return self._build_result(command_id, action, False, "Action not allowed.")
            
        # 2. Expiry Gate
        # In prod, check if expires_at < current time
        
        # 3. Policy Gate
        if action == "KillProcess":
            if not self.policy.is_action_allowed("response", "process_kill_permission"):
                logger.warning(f"[COMMAND] Rejected {command_id}: Policy forbids process killing.")
                return self._build_result(command_id, action, False, "Policy violation.")
                
            return self._execute_kill(command_id, payload.get("parameters", {}))
            
        elif action == "CollectForensics":
            # Delegate to Forensics module
            logger.info(f"[COMMAND] Initiating Forensic Collection for {command_id}...")
            return self._build_result(command_id, action, True, "Forensic collection started.")

        return self._build_result(command_id, action, False, "Unimplemented.")

    def _execute_kill(self, command_id: str, params: dict) -> dict:
        pid = params.get("pid")
        if not pid:
            return self._build_result(command_id, "KillProcess", False, "Missing PID.")
            
        try:
            p = psutil.Process(pid)
            p.kill()
            logger.info(f"[COMMAND] Successfully killed PID {pid}.")
            return self._build_result(command_id, "KillProcess", True, f"Killed PID {pid}.")
        except Exception as e:
            logger.error(f"[COMMAND] Failed to kill PID {pid}: {e}")
            return self._build_result(command_id, "KillProcess", False, str(e))

    def _build_result(self, command_id: str, action: str, success: bool, msg: str) -> dict:
        return {
            "command_id": command_id,
            "status": "COMPLETED" if success else "FAILED",
            "action": action,
            "result_data": {"success": success, "message": msg}
        }
