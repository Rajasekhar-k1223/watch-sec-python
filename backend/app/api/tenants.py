from fastapi import APIRouter, Depends, HTTPException, status # type: ignore
from sqlalchemy.ext.asyncio import AsyncSession # type: ignore
from sqlalchemy.future import select # type: ignore
from pydantic import BaseModel # type: ignore
from typing import Optional, List # type: ignore
import uuid # type: ignore
import json # type: ignore

from ..db.session import get_db # type: ignore
from ..db.models import Tenant, User # type: ignore
from .deps import get_current_user # type: ignore

router = APIRouter()

class CreateTenantDto(BaseModel):
    Name: str
    Plan: Optional[str] = "Starter"

class MaintenanceWindowDto(BaseModel):
    enabled: bool = False
    days: List[int] = [0, 1, 2, 3, 4, 5, 6] # 0=Monday
    startTime: str = "00:00"
    endTime: str = "23:59"
    timezone: str = "UTC"

@router.get("")
@router.get("/", include_in_schema=False)
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

@router.get("/api-key")
async def get_my_api_key(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    if not current_user.TenantId:
        raise HTTPException(status_code=400, detail="No Tenant")
        
    result = await db.execute(select(Tenant).where(Tenant.Id == current_user.TenantId))
    tenant = result.scalars().first()
    
    if not tenant:
         raise HTTPException(status_code=404, detail="Tenant not found")
         
    return {"apiKey": tenant.ApiKey}

@router.get("/{tenant_id}")
async def get_tenant(
    tenant_id: int,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    if current_user.Role != "SuperAdmin":
        if current_user.TenantId != tenant_id:
            raise HTTPException(status_code=403, detail="Not authorized")
            
    result = await db.execute(select(Tenant).where(Tenant.Id == tenant_id))
    tenant = result.scalars().first()
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")
    return tenant

@router.post("")
@router.post("/", include_in_schema=False)
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
    
    # [AUDIT]
    from datetime import datetime # type: ignore
    from ..db.models import AuditLog # type: ignore
    audit = AuditLog(
        TenantId=current_user.TenantId or 1, # System level
        Actor=current_user.Username,
        Action="Create Tenant",
        Target=new_tenant.Name,
        Details=f"Manual tenant creation. Plan: {new_tenant.Plan}",
        Timestamp=datetime.utcnow()
    )
    db.add(audit)
    
    await db.commit()
    await db.refresh(new_tenant)
    
    return new_tenant


@router.get("/{tenant_id}/maintenance-window", response_model=MaintenanceWindowDto)
async def get_tenant_maintenance_window(
    tenant_id: int,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    if current_user.Role != "SuperAdmin" and (current_user.TenantId != tenant_id):
        raise HTTPException(status_code=403, detail="Not authorized")
        
    result = await db.execute(select(Tenant).where(Tenant.Id == tenant_id))
    tenant = result.scalars().first()
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")
        
    try:
        data = json.loads(tenant.MaintenanceWindowJson or "{}")
        # Ensure default values if empty
        return {
            "enabled": data.get("enabled", False),
            "days": data.get("days", [0, 1, 2, 3, 4, 5, 6]),
            "startTime": data.get("startTime", "00:00"),
            "endTime": data.get("endTime", "23:59"),
            "timezone": data.get("timezone", "UTC")
        }
    except:
        return MaintenanceWindowDto()

@router.put("/{tenant_id}/maintenance-window")
async def update_tenant_maintenance_window(
    tenant_id: int,
    dto: MaintenanceWindowDto,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    if current_user.Role != "SuperAdmin" and (current_user.TenantId != tenant_id):
        raise HTTPException(status_code=403, detail="Not authorized")
        
    result = await db.execute(select(Tenant).where(Tenant.Id == tenant_id))
    tenant = result.scalars().first()
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")
        
    tenant.MaintenanceWindowJson = json.dumps(dto.dict())
    
    # [AUDIT]
    from datetime import datetime # type: ignore
    from ..db.models import AuditLog # type: ignore
    audit = AuditLog(
        TenantId=tenant.Id,
        Actor=current_user.Username,
        Action="Update Maintenance Window",
        Target=tenant.Name,
        Details=f"Updates enabled: {dto.enabled}. Window: {dto.startTime}-{dto.endTime}",
        Timestamp=datetime.utcnow()
    )
    db.add(audit)
    
    await db.commit()
    return {"status": "success"}

@router.put("/{tenant_id}")
async def update_tenant(
    tenant_id: int,
    dto: CreateTenantDto,
    agent_limit: Optional[int] = None,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    if current_user.Role != "SuperAdmin":
        raise HTTPException(status_code=403, detail="Not authorized")
        
    result = await db.execute(select(Tenant).where(Tenant.Id == tenant_id))
    tenant = result.scalars().first()
    
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")
        
    if dto.Name:
        tenant.Name = dto.Name
    if dto.Plan:
        tenant.Plan = dto.Plan
    if agent_limit is not None:
        tenant.AgentLimit = agent_limit
        
    await db.commit()
    return tenant

