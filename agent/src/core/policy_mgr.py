import json
import logging
import os

logger = logging.getLogger(__name__)

class PolicyManager:
    def __init__(self, data_dir="data"):
        self.policy_path = os.path.join(data_dir, "policy.json")
        self.current_policy = self._default_policy()
        
    def _default_policy(self) -> dict:
        """Layer 9: Safe default policy if none is loaded."""
        return {
            "telemetry": {"process_events": True, "network_events": True},
            "response": {"process_kill_permission": False, "network_isolation_permission": False},
            "system": {"max_cpu_percent": 5, "update_channel": "stable"}
        }

    def load_policy(self):
        """Layer 9: Loads and parses the hierarchical policy."""
        if os.path.exists(self.policy_path):
            try:
                with open(self.policy_path, "r") as f:
                    self.current_policy = json.load(f)
                logger.info("[POLICY] Loaded local policy.")
            except Exception as e:
                logger.error(f"[POLICY] Failed to load policy: {e}. Using defaults.")
        else:
            logger.info("[POLICY] No local policy found. Using defaults.")
            
    def is_action_allowed(self, action_domain: str, action_key: str) -> bool:
        """Evaluates if an action is permitted by the current policy."""
        domain = self.current_policy.get(action_domain, {})
        return domain.get(action_key, False)
        
    def update_policy(self, new_policy: dict):
        """Updates the local policy cache and saves to disk."""
        self.current_policy = new_policy
        try:
            with open(self.policy_path, "w") as f:
                json.dump(new_policy, f)
            logger.info("[POLICY] Policy successfully updated.")
        except Exception as e:
            logger.error(f"[POLICY] Failed to save updated policy: {e}")
