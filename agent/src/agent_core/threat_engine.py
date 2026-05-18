import re
import logging
from typing import Dict, Any, List

logger = logging.getLogger("ThreatEngine")

class ThreatEngine:
    """[v2.6.0] Live Behavioral Threat Engine: Real-time detection of attack patterns."""
    
    def __init__(self, playbook_engine):
        self.playbook_engine = playbook_engine
        # Common attack patterns (Regex-based)
        self.signatures = [
            {"id": "T1059.001", "name": "Suspicious PowerShell", "regex": r"(?i)powershell.*(-enc|-encodedcommand|IEX|Invoke-Expression|downloadstring)"},
            {"id": "T1003", "name": "Credential Dumping Attempt", "regex": r"(?i)(mimikatz|sekurlsa|lsadump|procdump.*lsass)"},
            {"id": "T1027", "name": "Obfuscated Command", "regex": r"(?i)(\^[a-z0-9]|' \+ '|\x[0-9a-f]{2})"},
            {"id": "T1486", "name": "Ransomware-Like Activity", "regex": r"(?i)(vssadmin.*delete shadows|cipher.*/w|wevtutil.*cl)"}
        ]

    async def analyze_process_start(self, process_info: Dict[str, Any]):
        """Analyzes a new process event for real-time threats."""
        cmdline = process_info.get("CommandLine", "")
        if not cmdline: return

        for sig in self.signatures:
            if re.search(sig["regex"], cmdline):
                logger.warning(f"LIVE THREAT DETECTED: {sig['name']} (ID: {sig['id']})")
                
                # Create a high-fidelity alert event
                threat_event = {
                    "Type": "LiveThreatAlert",
                    "Severity": "Critical",
                    "Details": f"Detected {sig['name']} in command line: {cmdline}",
                    "Timestamp": process_info.get("Timestamp"),
                    "TTP": sig["id"]
                }
                
                # 1. Trigger local autonomous remediation if playbooks exist
                await self.playbook_engine.evaluate_event(threat_event)
                
                # 2. Return the event for transmission to backend
                return threat_event
        
        return None

    def analyze_network_connection(self, net_info: Dict[str, Any]):
        """Detects suspicious network patterns (e.g., beaconing)."""
        # Simplified: Check for connections to known malicious ports or ranges
        # In a real build, this would use a TI (Threat Intel) feed
        pass

# Global instance
threat_engine = None
