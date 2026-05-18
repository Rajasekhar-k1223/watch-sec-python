import logging
from typing import List, Dict, Any
from .ai_service import ai_service

logger = logging.getLogger("PolicyAiService")

class PolicyAiService:
    """[v2.6.0] Predictive Policy Engine: Suggests security playbooks based on threat trends."""

    @staticmethod
    async def analyze_trends_and_suggest_playbooks(events: List[Dict[str, Any]]):
        """Analyzes historical events to identify recurring patterns and suggest autonomous playbooks."""
        if not events:
            return []

        suggestions = []
        
        # 1. Detect recurring process-based threats
        critical_procs = [e.get("Details") for e in events if e.get("Severity") == "Critical" and "Process" in e.get("Type", "")]
        if critical_procs:
            # Simplified: Find most common suspicious process
            from collections import Counter
            common = Counter(critical_procs).most_common(1)
            if common and common[0][1] >= 2: # At least twice
                suggestions.append({
                    "name": "Auto-Kill Suspicious Process",
                    "condition": f"Details =~ '{common[0][0]}'",
                    "action": "KillProcess",
                    "params": {"process_name": common[0][0]},
                    "rationale": f"Detected recurring critical threat from process '{common[0][0]}' ({common[0][1]} occurrences)."
                })

        # 2. Detect brute force patterns
        auth_failures = [e for e in events if "Auth" in e.get("Type", "") and "Fail" in e.get("Details", "")]
        if len(auth_failures) >= 5:
            suggestions.append({
                "name": "Rapid Auth Isolation",
                "condition": "Type == 'AuthFailure'",
                "action": "IsolateNetwork",
                "params": {},
                "rationale": "High frequency of authentication failures detected. Autonomous isolation recommended to prevent credential compromise."
            })

        # 3. Detect USB exfiltration patterns
        usb_blocked = [e for e in events if "UsbBlocked" in e.get("Type", "")]
        if len(usb_blocked) >= 3:
            suggestions.append({
                "name": "Strict USB Lockdown",
                "condition": "Type =~ 'USB'",
                "action": "WIPE_AGENT",
                "params": {},
                "rationale": "Repeated unauthorized USB insertion attempts detected. Suggesting high-intensity defense posture."
            })

        return suggestions

# Global singleton
policy_ai_service = PolicyAiService()
