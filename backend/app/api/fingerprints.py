from fastapi import APIRouter, Depends, HTTPException, Body # type: ignore
from sqlalchemy.ext.asyncio import AsyncSession # type: ignore
from sqlalchemy.future import select # type: ignore
from typing import List # type: ignore
from datetime import datetime # type: ignore

from ..db.session import get_db # type: ignore
from ..db.models import DigitalFingerprint, User, Agent # type: ignore
from .deps import get_current_user # type: ignore

router = APIRouter()

@router.get("/fingerprints", response_model=List[dict])
async def get_fingerprints(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    query = select(DigitalFingerprint)
    if current_user.Role != "SuperAdmin":
        query = query.where(DigitalFingerprint.TenantId == current_user.TenantId)
        
    result = await db.execute(query.order_by(DigitalFingerprint.LastSeen.desc()))
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
        
    # [SECURITY] Check Ownership
    if current_user.Role != "SuperAdmin" and fp.TenantId != current_user.TenantId:
        raise HTTPException(status_code=403, detail="Access denied")
        
    fp.Status = status
    await db.commit()
    return {"status": "Updated", "newStatus": status}
