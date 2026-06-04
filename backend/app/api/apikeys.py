import secrets
import hashlib
from datetime import datetime, timedelta
from typing import List, Optional
from pydantic import BaseModel
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from ..db.session import get_db
from ..db.models import ApiKey, User
from .deps import get_current_active_user

router = APIRouter()

class ApiKeyCreate(BaseModel):
    name: str
    expires_in_days: Optional[int] = None # None = never expires

class ApiKeyResponse(BaseModel):
    id: int
    name: str
    prefix: str
    raw_key: Optional[str] = None # Added for full key copy
    created_at: datetime
    expires_at: Optional[datetime]
    last_used_at: Optional[datetime]

class ApiKeyCreateResponse(ApiKeyResponse):
    raw_key: str # Only returned once upon creation

@router.post("/", response_model=ApiKeyCreateResponse)
async def create_api_key(
    payload: ApiKeyCreate,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    if current_user.Role not in ["TenantAdmin", "SuperAdmin"]:
        raise HTTPException(status_code=403, detail="Only Admins can create API Keys")

    # Generate the raw key
    # Format: mk_ + 32 chars of random hex
    raw_key = "mk_" + secrets.token_hex(16)
    key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
    prefix = raw_key[:7] # e.g. mk_a1b2

    expires_at = None
    if payload.expires_in_days:
        expires_at = datetime.utcnow() + timedelta(days=payload.expires_in_days)

    new_key = ApiKey(
        TenantId=current_user.TenantId,
        Name=payload.name,
        KeyHash=key_hash,
        Prefix=prefix,
        RawKey=raw_key,
        CreatedAt=datetime.utcnow(),
        ExpiresAt=expires_at
    )
    
    db.add(new_key)
    await db.commit()
    await db.refresh(new_key)

    return {
        "id": new_key.Id,
        "name": new_key.Name,
        "prefix": new_key.Prefix,
        "raw_key": raw_key,
        "created_at": new_key.CreatedAt,
        "expires_at": new_key.ExpiresAt,
        "last_used_at": new_key.LastUsedAt
    }

@router.get("/", response_model=List[ApiKeyResponse])
async def list_api_keys(
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    if current_user.Role not in ["TenantAdmin", "SuperAdmin", "Analyst"]:
        raise HTTPException(status_code=403, detail="Access denied")

    result = await db.execute(select(ApiKey).where(ApiKey.TenantId == current_user.TenantId))
    api_keys = result.scalars().all()
    return [
        {
            "id": k.Id,
            "name": k.Name,
            "prefix": k.Prefix,
            "raw_key": k.RawKey,
            "created_at": k.CreatedAt,
            "expires_at": k.ExpiresAt,
            "last_used_at": k.LastUsedAt
        } for k in api_keys
    ]

@router.delete("/{key_id}")
async def revoke_api_key(
    key_id: int,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    if current_user.Role not in ["TenantAdmin", "SuperAdmin"]:
        raise HTTPException(status_code=403, detail="Only Admins can revoke API Keys")

    result = await db.execute(select(ApiKey).where(ApiKey.Id == key_id, ApiKey.TenantId == current_user.TenantId))
    api_key = result.scalars().first()
    
    if not api_key:
        raise HTTPException(status_code=404, detail="API Key not found")
        
    await db.delete(api_key)
    await db.commit()
    
    return {"status": "success", "message": "API Key revoked"}
