import logging
from datetime import datetime, timedelta
from typing import List, Dict, Any
from .ai_service import ai_service

logger = logging.getLogger("CorrelationService")

class CorrelationEngine:
    """[v2.5.0] Global Threat Correlation Engine (Multi-node Pattern Recognition)."""

    @staticmethod
    async def analyze_fleet_patterns(events: List[Dict[str, Any]]):
        """Analyzes a window of events across the entire fleet for coordinated attacks."""
        if not events:
            return {"status": "Nominal", "threats": []}

        correlations = []
        
        # 1. Lateral Movement Detection
        # Pattern: Successful login on Node A, followed by network scan or login attempt on Node B within 5 minutes.
        logins = [e for e in events if "Auth" in e.get("Type", "") or "Login" in e.get("Type", "")]
        for i, login_a in enumerate(logins):
            for login_b in logins[i+1:]:
                if login_a.get("AgentId") != login_b.get("AgentId"):
                    # Handle both datetime and string timestamps
                    ts_a = login_a.get("Timestamp")
                    ts_b = login_b.get("Timestamp")
                    
                    if isinstance(ts_a, str): ts_a = datetime.fromisoformat(ts_a.replace('Z', '+00:00'))
                    if isinstance(ts_b, str): ts_b = datetime.fromisoformat(ts_b.replace('Z', '+00:00'))
                    
                    time_diff = abs((ts_a - ts_b).total_seconds())
                    if time_diff < 300: # 5 minutes
                        correlations.append({
                            "type": "Potential Lateral Movement",
                            "severity": "High",
                            "nodes": [login_a.get("AgentId"), login_b.get("AgentId")],
                            "description": f"Rapid sequential login detected across nodes {login_a.get('AgentId')} and {login_b.get('AgentId')}."
                        })

        # 2. Coordinated Brute Force
        # Pattern: Failed logins across 3+ nodes from the same subnet or within the same timeframe.
        failed_logins = [e for e in events if "Fail" in e.get("Details", "") and ("Auth" in e.get("Type", "") or "Login" in e.get("Type", ""))]
        unique_nodes = set([e.get("AgentId") for e in failed_logins])
        if len(unique_nodes) >= 3:
            correlations.append({
                "type": "Coordinated Brute Force",
                "severity": "Critical",
                "nodes": list(unique_nodes),
                "description": f"Failed login attempts detected across {len(unique_nodes)} different nodes simultaneously."
            })

        # 3. Data Exfiltration Cluster
        # Pattern: Multiple nodes reporting high network volume or USB insertions within a small window.
        dlp_events = [e for e in events if "DLP" in e.get("Type", "") or "USB" in e.get("Type", "")]
        if len(dlp_events) >= 2:
            correlations.append({
                "type": "Distributed Data Exfiltration",
                "severity": "Critical",
                "nodes": list(set([e.get("AgentId") for e in dlp_events])),
                "description": "Coordinated sensitive data movement detected across multiple endpoints."
            })

        return {
            "status": "Threat Detected" if correlations else "Nominal",
            "correlations": correlations,
            "tactical_narrative": ai_service.generate_tactical_narrative(events) if correlations else "No fleet-wide anomalies detected."
        }

# Global singleton
correlation_engine = CorrelationEngine()
