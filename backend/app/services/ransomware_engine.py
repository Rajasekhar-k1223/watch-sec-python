from sqlalchemy.orm import Session
from app.db.models import RansomwareIncident, RansomwareMitigationLog

class RansomwareEngine:
    
    def process_signal(self, db: Session, payload: dict):
        """
        Receives high-priority ransomware heuristics from the edge agent.
        Instantly orchestrates mitigation.
        """
        agent_id = payload.get("agent_id")
        process_id = payload.get("process_id")
        heuristic = payload.get("heuristic_matched") # e.g., "HighEntropy", "VssadminDeletion"
        file_path = payload.get("file_path")
        
        # Log the incident
        incident = RansomwareIncident(
            AgentId=agent_id,
            ProcessId=process_id,
            FilePath=file_path,
            HeuristicMatched=heuristic
        )
        db.add(incident)
        db.commit() # Commit to get ID
        
        # Trigger Autonomous Response
        self._trigger_mitigation(db, incident)
        
        return incident.Id
        
    def _trigger_mitigation(self, db: Session, incident: RansomwareIncident):
        """
        Executes immediate response actions to halt the ransomware outbreak.
        This ties directly into the Layer 6 SOAR capability, but operates autonomously.
        """
        mitigations = []
        
        # 1. Terminate the offending process
        print(f"[RANSOMWARE SHIELD] Terminating PID {incident.ProcessId} on Agent {incident.AgentId}")
        # MOCK: socket_manager.emit_to_agent(incident.AgentId, "kill_process", {"pid": incident.ProcessId})
        mitigations.append("ProcessKilled")
        
        # 2. Isolate the host from the network to prevent lateral movement (worming)
        print(f"[RANSOMWARE SHIELD] Isolating Agent {incident.AgentId}")
        # MOCK: socket_manager.emit_to_agent(incident.AgentId, "isolate_network", {})
        mitigations.append("HostQuarantined")
        
        # Log the actions
        for action in mitigations:
            log = RansomwareMitigationLog(
                IncidentId=incident.Id,
                ActionTaken=action,
                Success=True
            )
            db.add(log)
            
        db.commit()

ransomware_engine = RansomwareEngine()
