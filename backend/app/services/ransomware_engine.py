from sqlalchemy.ext.asyncio import AsyncSession
from app.db.models import RansomwareIncident, RansomwareMitigationLog

class RansomwareEngine:

    async def process_signal(self, db: AsyncSession, payload: dict):
        agent_id = payload.get("agent_id")
        
        # Determine heuristics based on Golang agent payload or legacy payload
        event_type = payload.get("EventType")
        
        if event_type == "RansomwareAlert":
            heuristic = f"HighEntropy: {payload.get('Entropy')}"
            file_path = payload.get("FilePath")
            process_id = 0 # Go agent currently doesn't map PID for fsnotify writes
        elif event_type == "ShadowCopyDeletion":
            heuristic = f"VssadminDeletion: {payload.get('OldCount')} -> {payload.get('NewCount')}"
            file_path = "Volume Shadow Copy"
            process_id = 0
        else:
            # Legacy Python Agent
            heuristic = payload.get("heuristic_matched")
            file_path = payload.get("file_path")
            process_id = payload.get("process_id", 0)

        incident = RansomwareIncident(
            AgentId=agent_id,
            ProcessId=process_id,
            FilePath=file_path,
            HeuristicMatched=heuristic
        )
        db.add(incident)
        await db.commit()

        await self._trigger_mitigation(db, incident)
        return incident.Id

    async def _trigger_mitigation(self, db: AsyncSession, incident: RansomwareIncident):
        from app.services.soar_engine import soar_engine
        
        print(f"[RANSOMWARE SHIELD] Triggering SOAR Playbook for Agent {incident.AgentId}")
        
        # Trigger Playbook ID 1 (Critical Mitigation) via SOAR Engine
        action_params = None
        if incident.ProcessId and incident.ProcessId > 0:
            action_params = {"TargetPID": str(incident.ProcessId)}
            
        await soar_engine.trigger_playbook(
            db, 
            playbook_id=1, 
            target_agent_id=incident.AgentId,
            action_params=action_params
        )

ransomware_engine = RansomwareEngine()
