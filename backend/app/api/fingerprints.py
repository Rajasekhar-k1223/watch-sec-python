from fastapi import APIRouter, Depends, HTTPException, Body
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from typing import List
from datetime import datetime

from ..db.session import get_db
from ..db.models import DigitalFingerprint, User, Agent
from .deps import get_current_user

router = APIRouter()

@router.get("/fingerprints", response_model=List[dict])
async def get_fingerprints(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    result = await db.execute(select(DigitalFingerprint).order_by(DigitalFingerprint.LastSeen.desc()))
    fps = result.scalars().all()
    
    # Enrich with Hostname if possible (simple join logic simulation)
    # Ideally use a join, but for simplicity:
    enriched = []
    for fp in fps:
        # Fetch agent hostname
        res_agent = await db.execute(select(Agent).where(Agent.AgentId == fp.AgentId))
        agent = res_agent.scalars().first()
        hostname = agent.Hostname if agent else "Unknown"
        
        enriched.append({
            "id": fp.Id,
            "agentId": fp.AgentId,
            "hostname": hostname,
            "hardwareId": fp.HardwareId,
            "os": fp.OS,
            "status": fp.Status,
            "firstSeen": fp.FirstSeen,
            "lastSeen": fp.LastSeen
        })
        
    return enriched

@router.post("/fingerprints/{id}/status")
async def set_fingerprint_status(
    id: int,
    status: str = Body(..., embed=True), # Authorized, Revoked
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    res = await db.execute(select(DigitalFingerprint).where(DigitalFingerprint.Id == id))
    fp = res.scalars().first()
    if not fp:
        raise HTTPException(status_code=404, detail="Fingerprint not found")
        
    fp.Status = status
    await db.commit()
    return {"status": "Updated", "newStatus": status}
