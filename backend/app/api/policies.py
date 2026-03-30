from fastapi import APIRouter, Depends, HTTPException, status # type: ignore
from sqlalchemy.ext.asyncio import AsyncSession # type: ignore
from sqlalchemy.future import select # type: ignore
from pydantic import BaseModel # type: ignore
from typing import Optional, List # type: ignore
from datetime import datetime # type: ignore

from ..db.session import get_db # type: ignore
from ..db.models import Policy, User, Agent # type: ignore
from .deps import get_current_user # type: ignore
from ..socket_instance import sio # type: ignore
import json # type: ignore

router = APIRouter()

class PolicyDto(BaseModel):
    Id: Optional[int]
    Name: str
class PolicyDto(BaseModel):
    id: Optional[int] = None
    name: str
    rulesJson: str
    actions: str
    isActive: bool
    tenantId: int
    blockedAppsJson: str
    blockedWebsitesJson: str
    remediationJson: str
    bandwidthJson: str = "{}" # [NEW]
    screenshotInterval: Optional[int] = 60
    screenshotQuality: Optional[int] = 80
    screenshotsEnabled: Optional[bool] = False
    activityMonitorEnabled: Optional[bool] = True

@router.get("/", response_model=List[PolicyDto])
async def get_policies(
    current_user: User = Depends(get_current_user), 
    db: AsyncSession = Depends(get_db)
):
    query = select(Policy)
    if current_user.Role != "SuperAdmin":
        if not current_user.TenantId:
            return []
        query = query.where(Policy.TenantId == current_user.TenantId)
        
    result = await db.execute(query)
    policies = result.scalars().all()
    
    return [
        PolicyDto(
            id=p.Id,
            name=p.Name,
            rulesJson=p.RulesJson,
            actions=p.Actions,
            isActive=p.IsActive,
            blockedAppsJson=p.BlockedAppsJson,
            blockedWebsitesJson=p.BlockedWebsitesJson,
            remediationJson=p.RemediationJson,
            bandwidthJson=p.BandwidthJson,
            screenshotInterval=p.ScreenshotInterval,
            screenshotQuality=p.ScreenshotQuality or 80,
            screenshotsEnabled=p.ScreenshotsEnabled,
            activityMonitorEnabled=p.ActivityMonitorEnabled
        ) for p in policies
    ]

@router.post("/")
async def create_policy(
    dto: PolicyDto,
    current_user: User = Depends(get_current_user), 
    db: AsyncSession = Depends(get_db)
):
    if not current_user.TenantId:
         raise HTTPException(status_code=403, detail="User must belong to a tenant")

    if current_user.Role not in ["SuperAdmin", "TenantAdmin"]:
        raise HTTPException(status_code=403, detail="Not authorized")

    new_policy = Policy(
        TenantId=current_user.TenantId,
        Name=dto.name,
        RulesJson=dto.rulesJson,
        Actions=dto.actions,
        IsActive=dto.isActive,
        BlockedAppsJson=dto.blockedAppsJson,
        BlockedWebsitesJson=dto.blockedWebsitesJson,
        RemediationJson=dto.remediationJson,
        BandwidthJson=dto.bandwidthJson,
        ScreenshotInterval=dto.screenshotInterval or 60,
        ScreenshotQuality=dto.screenshotQuality or 80,
        ScreenshotsEnabled=dto.screenshotsEnabled or False,
        ActivityMonitorEnabled=dto.activityMonitorEnabled or True,
        CreatedAt=datetime.utcnow()
    )
    
    db.add(new_policy)
    
    # [AUDIT]
    from ..db.models import AuditLog # type: ignore
    audit = AuditLog(
        TenantId=current_user.TenantId or 0,
        Actor=current_user.Username,
        Action="Create Policy",
        Target=new_policy.Name,
        Details=f"Policy created with actions: {new_policy.Actions}",
        Timestamp=datetime.utcnow()
    )
    db.add(audit)
    
    await db.commit()
    await db.refresh(new_policy)
    
    return new_policy

@router.put("/{id}")
async def update_policy(
    id: int,
    dto: PolicyDto,
    current_user: User = Depends(get_current_user), 
    db: AsyncSession = Depends(get_db)
):
    result = await db.execute(select(Policy).where(Policy.Id == id))
    policy = result.scalars().first()
    
    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found")
        
    if current_user.Role != "SuperAdmin" and policy.TenantId != current_user.TenantId:
        raise HTTPException(status_code=403, detail="Not authorized")

    if current_user.Role not in ["SuperAdmin", "TenantAdmin"]:
        raise HTTPException(status_code=403, detail="Not authorized (ReadOnly)")

    policy.Name = dto.name
    policy.RulesJson = dto.rulesJson
    policy.Actions = dto.actions
    policy.IsActive = dto.isActive
    policy.BlockedAppsJson = dto.blockedAppsJson
    policy.BlockedWebsitesJson = dto.blockedWebsitesJson
    policy.RemediationJson = dto.remediationJson
    policy.BandwidthJson = dto.bandwidthJson
    policy.ScreenshotInterval = dto.screenshotInterval if dto.screenshotInterval is not None else 60
    policy.ScreenshotQuality = dto.screenshotQuality if dto.screenshotQuality is not None else 80
    policy.ScreenshotsEnabled = dto.screenshotsEnabled if dto.screenshotsEnabled is not None else False
    policy.ActivityMonitorEnabled = dto.activityMonitorEnabled if dto.activityMonitorEnabled is not None else True
    
    # [REAL-TIME SYNC] Notify Agents assigned to this policy
    agent_query = select(Agent).where(Agent.PolicyId == id)
    agent_res = await db.execute(agent_query)
    agents = agent_res.scalars().all()
    
    for agent in agents:
        try:
            # Emit to agent's specific room
            await sio.emit('UpdateConfig', {
                "ScreenshotInterval": policy.ScreenshotInterval,
                "ScreenshotQuality": policy.ScreenshotQuality,
                "ScreenshotsEnabled": policy.ScreenshotsEnabled,
                "ActivityMonitorEnabled": policy.ActivityMonitorEnabled,
                "BandwidthConfig": json.loads(policy.BandwidthJson) if policy.BandwidthJson else {}
            }, room=agent.AgentId)
            print(f"[Policy Sync] Pushed v1.8.20 config to Agent: {agent.AgentId}")
        except Exception as e:
            print(f"[Policy Sync] Failed to push to {agent.AgentId}: {e}")

    # [AUDIT]
    from ..db.models import AuditLog # type: ignore
    audit = AuditLog(
        TenantId=current_user.TenantId or 0,
        Actor=current_user.Username,
        Action="Update Policy",
        Target=policy.Name,
        Details=f"Policy updated (Quality: {policy.ScreenshotQuality}, Interval: {policy.ScreenshotInterval})",
        Timestamp=datetime.utcnow()
    )
    db.add(audit)
    
    await db.commit()
    return policy

@router.delete("/{id}")
async def delete_policy(
    id: int,
    current_user: User = Depends(get_current_user), 
    db: AsyncSession = Depends(get_db)
):
    result = await db.execute(select(Policy).where(Policy.Id == id))
    policy = result.scalars().first()
    
    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found")
        
    if current_user.Role != "SuperAdmin" and policy.TenantId != current_user.TenantId:
        raise HTTPException(status_code=403, detail="Not authorized")

    if current_user.Role not in ["SuperAdmin", "TenantAdmin"]:
        raise HTTPException(status_code=403, detail="Not authorized (ReadOnly)")
        
    await db.delete(policy)
    
    # [AUDIT]
    from ..db.models import AuditLog # type: ignore
    audit = AuditLog(
        TenantId=current_user.TenantId or 0,
        Actor=current_user.Username,
        Action="Delete Policy",
        Target=policy.Name,
        Details="Policy permanently removed",
        Timestamp=datetime.utcnow()
    )
    db.add(audit)
    
    await db.commit()
    return status.HTTP_204_NO_CONTENT
