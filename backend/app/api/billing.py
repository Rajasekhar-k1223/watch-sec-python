from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from pydantic import BaseModel

from ..db.session import get_db
from ..db.models import Tenant, User
from .deps import get_current_user

router = APIRouter()

class PlanDto(BaseModel):
    TenantId: int
    Plan: str
    AgentLimit: int
    NextBillingDate: str
    AmountDue: float

class UpgradeRequest(BaseModel):
    NewPlan: str

@router.get("/", response_model=PlanDto)
async def get_billing_info(
    current_user: User = Depends(get_current_user), 
    db: AsyncSession = Depends(get_db)
):
    if not current_user.TenantId:
        raise HTTPException(status_code=400, detail="No Tenant")
        
    result = await db.execute(select(Tenant).where(Tenant.Id == current_user.TenantId))
    tenant = result.scalars().first()
    
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")
        
    amounts = {"Starter": 0.0, "Pro": 49.99, "Enterprise": 299.99}
    
    return PlanDto(
        TenantId=tenant.Id,
        Plan=tenant.Plan,
        AgentLimit=tenant.AgentLimit,
        NextBillingDate=tenant.NextBillingDate.isoformat(),
        AmountDue=amounts.get(tenant.Plan, 0.0)
    )

@router.post("/upgrade")
async def upgrade_plan(
    req: UpgradeRequest,
    current_user: User = Depends(get_current_user), 
    db: AsyncSession = Depends(get_db)
):
    if current_user.Role != "TenantAdmin":
        raise HTTPException(status_code=403, detail="Only Tenant Admins can upgrade.")
        
    result = await db.execute(select(Tenant).where(Tenant.Id == current_user.TenantId))
    tenant = result.scalars().first()
    
    # Mock Upgrade Logic
    limits = {"Starter": 5, "Pro": 50, "Enterprise": 1000}
    
    tenant.Plan = req.NewPlan
    tenant.AgentLimit = limits.get(req.NewPlan, 5)
    
    await db.commit()
    
    return {"message": f"Plan upgraded to {req.NewPlan}", "NewLimit": tenant.AgentLimit}
