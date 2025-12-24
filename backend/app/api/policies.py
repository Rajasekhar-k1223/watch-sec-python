from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime

from ..db.session import get_db
from ..db.models import Policy, User
from .deps import get_current_user
import json

router = APIRouter()

class PolicyDto(BaseModel):
    Id: Optional[int]
    Name: str
    RulesJson: str
    Actions: str
    IsActive: bool
    BlockedAppsJson: str
    BlockedWebsitesJson: str

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
            BlockedWebsitesJson=p.BlockedWebsitesJson
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

    new_policy = Policy(
        TenantId=current_user.TenantId,
        Name=dto.Name,
        RulesJson=dto.RulesJson,
        Actions=dto.Actions,
        IsActive=dto.IsActive,
        BlockedAppsJson=dto.BlockedAppsJson,
        BlockedWebsitesJson=dto.BlockedWebsitesJson,
        CreatedAt=datetime.utcnow()
    )
    
    db.add(new_policy)
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

    policy.Name = dto.Name
    policy.RulesJson = dto.RulesJson
    policy.Actions = dto.Actions
    policy.IsActive = dto.IsActive
    policy.BlockedAppsJson = dto.BlockedAppsJson
    policy.BlockedWebsitesJson = dto.BlockedWebsitesJson
    
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
        
    await db.delete(policy)
    await db.commit()
    return status.HTTP_204_NO_CONTENT
