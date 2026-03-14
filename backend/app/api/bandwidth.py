from fastapi import APIRouter, Depends, HTTPException # type: ignore
from sqlalchemy.ext.asyncio import AsyncSession # type: ignore
from sqlalchemy.future import select # type: ignore
from ..db.session import get_db # type: ignore
from ..db.models import Tenant # type: ignore
from .deps import get_current_user # type: ignore
from ..socket_instance import sio # type: ignore

router = APIRouter()

@router.get("/tenants/{tenant_id}/bandwidth/config")
async def get_bandwidth_config(
    tenant_id: int, 
    db: AsyncSession = Depends(get_db), 
    current_user: dict = Depends(get_current_user)
):
    """Get bandwidth configuration for a tenant"""
    result = await db.execute(select(Tenant).where(Tenant.Id == tenant_id))
    tenant = result.scalars().first()
    
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")
    
    # Return default if not set
    if not tenant.bandwidth_config:
        return {
            "max_rate_kbps": 0,
            "business_hours": {"enabled": False, "start": "09:00", "end": "17:00", "throttle_percent": 30},
            "compression_enabled": True,
            "min_available_bandwidth_mbps": 5
        }
        
    return tenant.bandwidth_config

@router.put("/tenants/{tenant_id}/bandwidth/config")
async def update_bandwidth_config(
    tenant_id: int, 
    config: dict, 
    db: AsyncSession = Depends(get_db), 
    current_user: dict = Depends(get_current_user)
):
    """Update bandwidth configuration with Plan enforcement"""
    result = await db.execute(select(Tenant).where(Tenant.Id == tenant_id))
    tenant = result.scalars().first()
    
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")
    
    # [NEW] Plan Enforcement Logic
    plan = (tenant.Plan or "Starter").lower()
    
    # 1. Business Hours Enforcement
    if config.get("business_hours", {}).get("enabled", False):
        if plan == "starter":
            raise HTTPException(
                status_code=403, 
                detail="Business Hours throttling requires Professional or Enterprise plan."
            )

    # 2. Min Available Bandwidth Enforcement
    # Starter plan is locked to default 5Mbps to ensure safety
    if "min_available_bandwidth_mbps" in config:
        if plan == "starter" and config["min_available_bandwidth_mbps"] != 5:
             raise HTTPException(
                status_code=403, 
                detail="Custom network sensitivity requires Professional plan."
            )

    # Validate config (basic validation)
    if not isinstance(config, dict):
         raise HTTPException(status_code=400, detail="Invalid configuration format")

    tenant.bandwidth_config = config
    await db.commit()
    
    # Broadcast update to all tenant agents
    await sio.emit('UpdateBandwidthConfig', config, room=f'tenant_{tenant_id}')
    
    return {"status": "updated", "config": config}

@router.post("/tenants/{tenant_id}/bandwidth/pause")
async def pause_uploads(
    tenant_id: int, 
    duration_minutes: int, 
    db: AsyncSession = Depends(get_db), 
    current_user: dict = Depends(get_current_user)
):
    """Pause uploads for all agents of a tenant (Enterprise Only)"""
    result = await db.execute(select(Tenant).where(Tenant.Id == tenant_id))
    tenant = result.scalars().first()
    
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")
        
    # [NEW] Plan Enforcement
    plan = (tenant.Plan or "Starter").lower()
    
    if plan != "enterprise":
        raise HTTPException(
            status_code=403, 
            detail="Manual global pause requires Enterprise plan."
        )
        
    # Broadcast pause command
    await sio.emit('PauseUploads', {
        'duration_minutes': duration_minutes,
        'reason': f"Manual pause by {current_user.Username}"
    }, room=f'tenant_{tenant_id}')
    
    return {"status": "paused", "duration_minutes": duration_minutes}
