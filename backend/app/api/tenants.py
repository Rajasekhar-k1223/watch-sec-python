from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from pydantic import BaseModel
from typing import Optional
import uuid

from ..db.session import get_db
from ..db.models import Tenant, User
from .deps import get_current_user

router = APIRouter()

class CreateTenantDto(BaseModel):
    Name: str
    Plan: Optional[str] = "Starter"

@router.get("/")
async def get_tenants(
    current_user: User = Depends(get_current_user), 
    db: AsyncSession = Depends(get_db)
):
    query = select(Tenant)
    
    if current_user.Role != "SuperAdmin":
        if not current_user.TenantId:
            return []
        query = query.where(Tenant.Id == current_user.TenantId)
        
    result = await db.execute(query)
    tenants = result.scalars().all()
    return tenants

@router.post("/")
async def create_tenant(
    dto: CreateTenantDto, 
    current_user: User = Depends(get_current_user), 
    db: AsyncSession = Depends(get_db)
):
    if current_user.Role != "SuperAdmin":
        raise HTTPException(status_code=403, detail="Not authorized")
        
    if not dto.Name:
        raise HTTPException(status_code=400, detail="Name is required")

    new_tenant = Tenant(
        Name=dto.Name,
        Plan=dto.Plan,
        ApiKey=str(uuid.uuid4())
    )
    
    db.add(new_tenant)
    await db.commit()
    await db.refresh(new_tenant)
    
    return new_tenant
