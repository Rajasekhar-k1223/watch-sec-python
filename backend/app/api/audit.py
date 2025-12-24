from fastapi import APIRouter, Depends, HTTPException
from typing import List, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy import desc

from ..db.session import get_db
from ..db.models import AuditLog, User
from .deps import get_current_user

router = APIRouter()

@router.get("/")
async def get_audit_logs(
    tenantId: Optional[int] = None,
    limit: int = 100,
    current_user: User = Depends(get_current_user), 
    db: AsyncSession = Depends(get_db)
):
    query = select(AuditLog)
    
    # RBAC & Filtering
    if current_user.Role == "SuperAdmin":
        if tenantId:
             query = query.where(AuditLog.TenantId == tenantId)
    elif current_user.Role == "TenantAdmin":
        # Force own tenant
        query = query.where(AuditLog.TenantId == current_user.TenantId)
    else:
         # Regular user sees nothing or only own? For Audit, usually Admin only.
         raise HTTPException(status_code=403, detail="Not authorized")
         
    query = query.order_by(desc(AuditLog.Timestamp)).limit(limit)
    
    result = await db.execute(query)
    logs = result.scalars().all()
    
    return logs
