from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy import update
from typing import List, Dict, Any
from pydantic import BaseModel
from app.db.session import get_db
from app.db.models import SystemSetting, User
from app.api.deps import get_current_user

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
            
    await db.commit()
    return {"status": "updated"}
