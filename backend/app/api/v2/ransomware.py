from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import desc
from app.db.session import get_db
from app.db.models import RansomwareIncident, RansomwareMitigationLog, User
from app.services.ransomware_engine import ransomware_engine
from app.api.deps import get_current_user, verify_agent_signature
from pydantic import BaseModel

router = APIRouter()

class RansomwareSignal(BaseModel):
    agent_id: str
    process_id: int
    heuristic_matched: str
    file_path: str = None

@router.post("/detect")
async def ingest_signal(payload: RansomwareSignal, db: Session = Depends(get_db), agent_sig: str = Depends(verify_agent_signature)):
    """
    High-priority endpoint for edge agents to report suspected ransomware.
    Instantly triggers backend orchestration.
    """
    incident_id = ransomware_engine.process_signal(db, payload.model_dump())
    return {"status": "success", "incident_id": incident_id, "action": "mitigating"}

@router.get("/incidents")
async def get_incidents(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    """Fetch recent ransomware outbreaks."""
    incidents = db.query(RansomwareIncident).order_by(desc(RansomwareIncident.Timestamp)).limit(50).all()
    
    results = []
    for inc in incidents:
        mitigations = db.query(RansomwareMitigationLog).filter(RansomwareMitigationLog.IncidentId == inc.Id).all()
        
        results.append({
            "id": inc.Id,
            "agent_id": inc.AgentId,
            "process_id": inc.ProcessId,
            "heuristic": inc.HeuristicMatched,
            "timestamp": inc.Timestamp,
            "mitigations": [{"action": m.ActionTaken, "success": m.Success} for m in mitigations]
        })
        
    return results
