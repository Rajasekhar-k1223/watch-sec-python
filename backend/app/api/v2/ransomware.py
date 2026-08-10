from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
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
async def ingest_signal(payload: RansomwareSignal, db: AsyncSession = Depends(get_db), agent_sig: str = Depends(verify_agent_signature)):
    incident_id = await ransomware_engine.process_signal(db, payload.model_dump())
    return {"status": "success", "incident_id": incident_id, "action": "mitigating"}

@router.get("/incidents")
async def get_incidents(db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    incidents = (await db.execute(
        select(RansomwareIncident).order_by(desc(RansomwareIncident.Timestamp)).limit(50)
    )).scalars().all()

    results = []
    for inc in incidents:
        mitigations = (await db.execute(
            select(RansomwareMitigationLog).where(RansomwareMitigationLog.IncidentId == inc.Id)
        )).scalars().all()

        results.append({
            "id": inc.Id,
            "agent_id": inc.AgentId,
            "process_id": inc.ProcessId,
            "heuristic": inc.HeuristicMatched,
            "timestamp": inc.Timestamp,
            "mitigations": [{"action": m.ActionTaken, "success": m.Success} for m in mitigations]
        })

    return results
