from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from typing import List, Optional
from pydantic import BaseModel
from datetime import datetime

from ..db.session import get_db
from ..db.models import HashBank, User
from .deps import get_current_user

router = APIRouter()

class HashBankDto(BaseModel):
    Hash: str
    Type: str = "SHA256"
    Reputation: str = "Malicious"
    Description: Optional[str] = None
    Source: str = "Manual"

@router.get("/hashbank", response_model=List[dict])
async def get_hashes(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    result = await db.execute(select(HashBank).order_by(HashBank.CreatedAt.desc()))
    hashes = result.scalars().all()
    return [
        {
            "id": h.Id,
            "hash": h.Hash,
            "type": h.Type,
            "reputation": h.Reputation,
            "description": h.Description,
            "source": h.Source,
            "addedBy": h.AddedBy,
            "createdAt": h.CreatedAt
        }
        for h in hashes
    ]

@router.post("/hashbank")
async def add_hash(
    dto: HashBankDto,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    # Check duplicate
    res = await db.execute(select(HashBank).where(HashBank.Hash == dto.Hash))
    if res.scalars().first():
        raise HTTPException(status_code=400, detail="Hash already exists in bank.")

    new_entry = HashBank(
        Hash=dto.Hash,
        Type=dto.Type,
        Reputation=dto.Reputation,
        Description=dto.Description,
        Source=dto.Source,
        AddedBy=current_user.Username,
        CreatedAt=datetime.utcnow()
    )
    
    db.add(new_entry)
    await db.commit()
    return {"status": "Added", "id": new_entry.Id}

@router.delete("/hashbank/{id}")
async def delete_hash(
    id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    res = await db.execute(select(HashBank).where(HashBank.Id == id))
    entry = res.scalars().first()
    if not entry:
        raise HTTPException(status_code=404, detail="Entry not found")
        
    await db.delete(entry)
    await db.commit()
    return {"status": "Deleted"}
