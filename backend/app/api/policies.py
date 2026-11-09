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
    id: Optional[int] = None
    name: str
    rulesJson: Optional[str] = "{}"
    actions: Optional[str] = ""
    isActive: Optional[bool] = True
    tenantId: Optional[int] = 1
    blockedAppsJson: Optional[str] = "[]"
    blockedWebsitesJson: Optional[str] = "[]"
    remediationJson: Optional[str] = "{}"
    bandwidthJson: Optional[str] = "{}"
    screenshotInterval: Optional[int] = 60
    screenshotQuality: Optional[int] = 80
    screenshotsEnabled: Optional[bool] = False
    activityMonitorEnabled: Optional[bool] = True
    geolocationEnabled: Optional[bool] = True # [NEW] v1.8.27
    autonomousRemediationEnabled: Optional[bool] = False # [v2.6.8]
    threatScoreThreshold: Optional[int] = 90 # [v2.6.8]
    exclusionsJson: Optional[str] = "[]" # [v2.6.9]
    productivityJson: Optional[str] = "{}" # [v2.7.5]

@router.get("", response_model=List[PolicyDto])
@router.get("/", response_model=List[PolicyDto], include_in_schema=False)
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
            name=p.Name or "Default Policy",
            rulesJson=p.RulesJson or "{}",
            actions=p.Actions or "",
            isActive=p.IsActive if p.IsActive is not None else True,
            tenantId=p.TenantId or 1,
            blockedAppsJson=p.BlockedAppsJson or "[]",
            blockedWebsitesJson=p.BlockedWebsitesJson or "[]",
            remediationJson=p.RemediationJson or "{}",
            bandwidthJson=p.BandwidthJson or "{}",
            screenshotInterval=getattr(p, "ScreenshotInterval", 60) or 60,
            screenshotQuality=getattr(p, "ScreenshotQuality", 80) or 80,
            screenshotsEnabled=getattr(p, "ScreenshotsEnabled", False) if getattr(p, "ScreenshotsEnabled", None) is not None else False,
            activityMonitorEnabled=getattr(p, "ActivityMonitorEnabled", True) if getattr(p, "ActivityMonitorEnabled", None) is not None else True,
            geolocationEnabled=getattr(p, "GeolocationEnabled", True) if getattr(p, "GeolocationEnabled", None) is not None else True,
            autonomousRemediationEnabled=getattr(p, "AutonomousRemediationEnabled", False) if getattr(p, "AutonomousRemediationEnabled", None) is not None else False,
            threatScoreThreshold=getattr(p, "ThreatScoreThreshold", 90) or 90,
            exclusionsJson=getattr(p, "ExclusionsJson", "[]") or "[]",
            productivityJson=getattr(p, "ProductivityJson", "{}") or "{}"
        ) for p in policies
    ]

@router.post("")
@router.post("/", include_in_schema=False)
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
        GeolocationEnabled=dto.geolocationEnabled if dto.geolocationEnabled is not None else True,
        AutonomousRemediationEnabled=dto.autonomousRemediationEnabled or False,
        ThreatScoreThreshold=dto.threatScoreThreshold or 90,
        ExclusionsJson=dto.exclusionsJson or "[]",
        ProductivityJson=dto.productivityJson or "{}",
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
    policy.GeolocationEnabled = dto.geolocationEnabled if dto.geolocationEnabled is not None else True # [NEW]
    policy.AutonomousRemediationEnabled = dto.autonomousRemediationEnabled if dto.autonomousRemediationEnabled is not None else False
    policy.ThreatScoreThreshold = dto.threatScoreThreshold if dto.threatScoreThreshold is not None else 90
    policy.ExclusionsJson = dto.exclusionsJson if dto.exclusionsJson is not None else "[]"
    policy.ProductivityJson = dto.productivityJson if dto.productivityJson is not None else "{}"
    
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
                "GeolocationEnabled": policy.GeolocationEnabled,
                "BandwidthConfig": json.loads(policy.BandwidthJson) if policy.BandwidthJson else {},
                "BlockedApps": json.loads(policy.BlockedAppsJson) if policy.BlockedAppsJson else [],
                "BlockedWebsites": json.loads(policy.BlockedWebsitesJson) if policy.BlockedWebsitesJson else [],
                "AutonomousPlaybooks": json.loads(policy.RemediationJson) if policy.RemediationJson else []
            }, room=agent.AgentId)
            print(f"[Policy Sync] Pushed Full Governance config to Agent: {agent.AgentId}")
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
