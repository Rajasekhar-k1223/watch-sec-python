import logging
import json
import re
from typing import List, Dict, Any

logger = logging.getLogger("PlaybookEngine")

class PlaybookEngine:
    """[v2.6.0] Autonomous Remediation Engine (Edge-Enforced Security Playbooks)."""
    
    def __init__(self, remediation_handler):
        self.remediation_handler = remediation_handler
        self.playbooks = [] # List of { "condition": "...", "action": "..." }

    def sync_playbooks(self, playbooks_json: str):
        """Updates the local playbook cache from the backend."""
        try:
            self.playbooks = json.loads(playbooks_json)
            logger.info(f"Synchronized {len(self.playbooks)} autonomous playbooks.")
        except Exception as e:
            logger.error(f"Failed to sync playbooks: {e}")

    async def evaluate_event(self, event: Dict[str, Any]):
        """Evaluates an event against active playbooks and triggers autonomous remediation."""
        for pb in self.playbooks:
            # [v2.6.1] Support both old (condition/action) and new (if/then) formats
            condition = pb.get("if") or pb.get("condition")
            action_obj = pb.get("then") or {"action": pb.get("action"), "params": pb.get("params", {})}
            
            action = action_obj.get("action")
            params = action_obj.get("params", {})
            
            if self._match_condition(event, condition):
                logger.warning(f"AUTONOMOUS REMEDIATION TRIGGERED: {action} due to condition match.")
                
                cmd_data = {
                    "action": action,
                    "params": params,
                    "policy_name": "Autonomous Playbook",
                    "timestamp": event.get("Timestamp"),
                    "signature": "INTERNAL_BYPASS" 
                }
                
                await self.remediation_handler._execute_autonomous_action(cmd_data)

    def _match_condition(self, event: Dict[str, Any], condition: Any) -> bool:
        """Enhanced condition matcher supporting both strings and structured dicts."""
        try:
            # Case 1: Structured Dict { "risk_level": "Critical" }
            if isinstance(condition, dict):
                for key, val in condition.items():
                    if str(event.get(key)) != str(val):
                        return False
                return True
                
            # Case 2: String expression "Type == 'UsbBlocked'"
            if isinstance(condition, str):
                if "==" in condition:
                    key, val = [s.strip() for s in condition.split("==")]
                    val = val.strip("'").strip('"')
                    return str(event.get(key)) == val
                elif "=~" in condition:
                    key, pattern = [s.strip() for s in condition.split("=~")]
                    pattern = pattern.strip("'").strip('"')
                    return bool(re.search(pattern, str(event.get(key)), re.IGNORECASE))
        except Exception as e:
            logger.error(f"Condition evaluation failed: {e}")
        return False

# Global extension to RemediationHandler to support internal triggers
async def _execute_autonomous_action(self, data):
    action = data.get("action")
    params = data.get("params", {})
    
    # [SECURITY] Autonomous actions are pre-verified by the backend during sync
    if action == "KillProcess":
        await self._kill_process(params.get("process_name"))
    elif action == "IsolateNetwork":
        await self._isolate_network()
    elif action == "WIPE_AGENT":
        await self._self_destruct()
