import re
import logging

logger = logging.getLogger(__name__)

class SigmaLiteEngine:
    def __init__(self):
        # Layer 6: Local Rule Cache for offline detection
        self.rules = [
            {
                "id": "SIGMA-PWSH-001",
                "name": "Suspicious PowerShell Encoded Command",
                "pattern": re.compile(r"powershell.*-enc", re.IGNORECASE),
                "severity": "CRITICAL"
            },
            {
                "id": "SIGMA-LOTL-001",
                "name": "Certutil Network Connection",
                "pattern": re.compile(r"certutil.*-urlcache", re.IGNORECASE),
                "severity": "HIGH"
            }
        ]

    def evaluate_event(self, event_type: str, payload_data: dict) -> dict:
        """Layer 6: Evaluates an event against the local Sigma cache in real-time."""
        if event_type != "ProcessCreate":
            return None
            
        cmdline = payload_data.get("command_line", "")
        
        for rule in self.rules:
            if rule["pattern"].search(cmdline):
                logger.warning(f"[DETECTION] Rule Triggered locally: {rule['name']}")
                
                # Generate a high-priority DetectionAlert schema
                return {
                    "event_type": "DetectionAlert",
                    "severity": rule["severity"],
                    "detection_name": rule["name"],
                    "rule_id": rule["id"],
                    "triggering_event": payload_data,
                    "automated_response": "Pending"
                }
                
        return None
