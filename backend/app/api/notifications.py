from fastapi import APIRouter, Depends, HTTPException # type: ignore
from sqlalchemy.ext.asyncio import AsyncSession # type: ignore
from sqlalchemy.future import select # type: ignore
from sqlalchemy import update, delete # type: ignore
from typing import List, Optional # type: ignore
from datetime import datetime # type: ignore

from ..db.session import get_db # type: ignore
from ..db.models import Notification, User # type: ignore
from .deps import get_current_user # type: ignore

router = APIRouter()

@router.get("/notifications")
async def list_notifications(
    limit: int = 50,
    only_unread: bool = False,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    query = select(Notification).order_by(Notification.CreatedAt.desc()).limit(limit)
    
    if current_user.Role != "SuperAdmin":
        query = query.where(Notification.TenantId == current_user.TenantId)
        
    if only_unread:
        query = query.where(Notification.IsRead == False)
        
    result = await db.execute(query)
    notifs = result.scalars().all()
    
    return notifs

@router.post("/notifications/read-all")
async def mark_all_as_read(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    query = update(Notification).where(Notification.IsRead == False)
    if current_user.Role != "SuperAdmin":
        query = query.where(Notification.TenantId == current_user.TenantId)
        
    await db.execute(query.values(IsRead=True))
    await db.commit()
    return {"status": "success"}

@router.delete("/notifications/clear")
async def clear_notifications(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    query = delete(Notification)
    if current_user.Role != "SuperAdmin":
        query = query.where(Notification.TenantId == current_user.TenantId)
        
    await db.execute(query)
    await db.commit()
    return {"status": "success"}
