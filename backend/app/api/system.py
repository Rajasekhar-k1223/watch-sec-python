from fastapi import APIRouter, Depends, HTTPException # type: ignore
from sqlalchemy.ext.asyncio import AsyncSession # type: ignore
from sqlalchemy.future import select # type: ignore
from sqlalchemy import update # type: ignore
from typing import List, Dict, Any # type: ignore
from pydantic import BaseModel # type: ignore
from app.db.session import get_db # type: ignore
from app.db.models import SystemSetting, User # type: ignore
from app.api.deps import get_current_user # type: ignore

router = APIRouter()

class SettingDto(BaseModel):
    Key: str
    Value: str
    Category: str = "General"
    Description: str = None

@router.get("/system/settings")
async def get_settings(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    # Only Admin? Let's check role or assume TenantAdmin for now
    if current_user.Role != 'TenantAdmin':
        raise HTTPException(status_code=403, detail="Insufficient permissions")

    result = await db.execute(select(SystemSetting))
    settings = result.scalars().all()
    
    # If empty, seed defaults
    defaults = {
        "DataRetentionDays": ("90", "General", "Days to keep activity logs"),
        "LogLevel": ("INFO", "General", "System logging level"),
        "EnableGlobalLockdown": ("false", "Auth", "Lock all agents"),
        "TrustedIps": ("", "Auth", "Comma-separated whitelist IPs")
    }
    
    if not settings:
        for k, v in defaults.items():
            new_setting = SystemSetting(Key=k, Value=v[0], Category=v[1], Description=v[2])
            db.add(new_setting)
        await db.commit()
        # Re-fetch
        result = await db.execute(select(SystemSetting))
        settings = result.scalars().all()

    # Group by category
    grouped = {}
    for s in settings:
        if s.Category not in grouped: grouped[s.Category] = []
        grouped[s.Category].append({"Key": s.Key, "Value": s.Value, "Description": s.Description})
        
    return grouped

@router.post("/system/settings")
async def update_settings(
    settings: List[SettingDto],
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    if current_user.Role != 'TenantAdmin':
        raise HTTPException(status_code=403, detail="Insufficient permissions")

    for s in settings:
        stmt = select(SystemSetting).where(SystemSetting.Key == s.Key)
        res = await db.execute(stmt)
        existing = res.scalar_one_or_none()
        
        if existing:
            existing.Value = s.Value
        else:
            new_s = SystemSetting(Key=s.Key, Value=s.Value, Category=s.Category, Description=s.Description)
            db.add(new_s)
            
    # [AUDIT]
    from app.db.models import AuditLog # type: ignore
    from datetime import datetime # type: ignore
    audit = AuditLog(
        TenantId=current_user.TenantId or 0,
        Actor=current_user.Username,
        Action="Update System Settings",
        Target="System Config",
        Details=f"Updated {len(settings)} system settings",
        Timestamp=datetime.utcnow()
    )
    db.add(audit)
    
    await db.commit()
    return {"status": "updated"}
