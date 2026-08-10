from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy import desc
from app.db.session import get_db
from app.db.models import DeviceRiskProfile, Agent, User
from app.services.risk_engine import calculate_risk_score
from app.api.deps import get_current_user

router = APIRouter()

@router.get("/agent/{agent_id}")
async def get_agent_risk(agent_id: str, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    profile = (await db.execute(select(DeviceRiskProfile).where(DeviceRiskProfile.AgentId == agent_id))).scalars().first()
    if not profile:
        profile = await calculate_risk_score(db, agent_id)
        if not profile:
            raise HTTPException(status_code=404, detail="Agent not found")

    return {
        "agent_id": profile.AgentId,
        "total_score": profile.TotalRiskScore,
        "level": profile.RiskLevel,
        "vectors": {
            "threat_intel": profile.ThreatIntelRiskScore,
            "behavioral": profile.BehavioralRiskScore,
            "process": profile.ProcessRiskScore,
            "network": profile.NetworkRiskScore,
            "user": profile.UserRiskScore,
            "device": profile.DeviceRiskScore
        },
        "last_calculated": profile.LastCalculatedAt
    }

@router.get("/tenant")
async def get_tenant_risk(tenant_id: int = 1, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    profiles = (await db.execute(
        select(DeviceRiskProfile)
        .where(DeviceRiskProfile.TenantId == tenant_id)
        .order_by(desc(DeviceRiskProfile.TotalRiskScore))
        .limit(100)
    )).scalars().all()

    return [
        {
            "agent_id": p.AgentId,
            "total_score": p.TotalRiskScore,
            "level": p.RiskLevel,
            "last_calculated": p.LastCalculatedAt
        } for p in profiles
    ]

@router.post("/evaluate/{agent_id}")
async def force_evaluate_risk(agent_id: str, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    profile = await calculate_risk_score(db, agent_id)
    if not profile:
        raise HTTPException(status_code=404, detail="Agent not found")

    return {
        "status": "success",
        "agent_id": profile.AgentId,
        "new_score": profile.TotalRiskScore,
        "new_level": profile.RiskLevel
    }
