from fastapi import APIRouter, Depends, HTTPException, status # type: ignore
from sqlalchemy.ext.asyncio import AsyncSession # type: ignore
from sqlalchemy.future import select # type: ignore
from pydantic import BaseModel # type: ignore
from typing import Optional, List # type: ignore
from datetime import datetime # type: ignore

from ..db.session import get_db # type: ignore
from ..db.models import Policy, User # type: ignore
from .deps import get_current_user # type: ignore
import json # type: ignore

router = APIRouter()

class PolicyDto(BaseModel):
    Id: Optional[int]
    Name: str
    RulesJson: str
    Actions: str
    IsActive: bool
    BlockedAppsJson: str
    BlockedWebsitesJson: str
    RemediationJson: str
    BandwidthJson: str = "{}" # [NEW]

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
            Id=p.Id,
            Name=p.Name,
            RulesJson=p.RulesJson,
            Actions=p.Actions,
            IsActive=p.IsActive,
            BlockedAppsJson=p.BlockedAppsJson,
            BlockedWebsitesJson=p.BlockedWebsitesJson,
            RemediationJson=p.RemediationJson,
            BandwidthJson=p.BandwidthJson
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
        Name=dto.Name,
        RulesJson=dto.RulesJson,
        Actions=dto.Actions,
        IsActive=dto.IsActive,
        BlockedAppsJson=dto.BlockedAppsJson,
        BlockedWebsitesJson=dto.BlockedWebsitesJson,
        RemediationJson=dto.RemediationJson,
        BandwidthJson=dto.BandwidthJson, # [NEW]
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

    policy.Name = dto.Name
    policy.RulesJson = dto.RulesJson
    policy.Actions = dto.Actions
    policy.IsActive = dto.IsActive
    policy.BlockedAppsJson = dto.BlockedAppsJson
    policy.BlockedWebsitesJson = dto.BlockedWebsitesJson
    policy.RemediationJson = dto.RemediationJson
    policy.BandwidthJson = dto.BandwidthJson # [NEW]
    
    # [AUDIT]
    from ..db.models import AuditLog # type: ignore
    audit = AuditLog(
        TenantId=current_user.TenantId or 0,
        Actor=current_user.Username,
        Action="Update Policy",
        Target=policy.Name,
        Details="Policy settings updated",
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
