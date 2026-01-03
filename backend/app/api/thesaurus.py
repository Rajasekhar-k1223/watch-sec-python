from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy.future import select
from sqlalchemy.ext.asyncio import AsyncSession
from typing import List, Optional
from pydantic import BaseModel
import json
from datetime import datetime

from ..db.session import get_db
from ..db.models import ThesaurusEntry, User
from ..api.deps import get_current_user

router = APIRouter()

class ThesaurusDto(BaseModel):
    keyword: str
    synonyms: List[str]
    category: str = "General"

@router.get("/thesaurus")
async def get_entries(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    result = await db.execute(select(ThesaurusEntry).order_by(ThesaurusEntry.Keyword.asc()))
    entries = result.scalars().all()
    
    response_data = []
    for entry in entries:
        response_data.append({
            "id": entry.Id,
            "keyword": entry.Keyword,
            "synonyms": json.loads(entry.Synonyms) if entry.Synonyms else [],
            "category": entry.Category
        })
    return response_data

@router.post("/thesaurus")
async def add_entry(
    entry_data: ThesaurusDto,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    # Check if keyword exists
    stmt = select(ThesaurusEntry).where(ThesaurusEntry.Keyword == entry_data.keyword)
    res = await db.execute(stmt)
    existing = res.scalar_one_or_none()
    
    if existing:
        # Update
        existing.Synonyms = json.dumps(entry_data.synonyms)
        existing.Category = entry_data.category
    else:
        # Create
        new_entry = ThesaurusEntry(
            Keyword=entry_data.keyword,
            Synonyms=json.dumps(entry_data.synonyms),
            Category=entry_data.category
        )
        db.add(new_entry)
        
    await db.commit()
    return {"status": "saved", "keyword": entry_data.keyword}

@router.delete("/thesaurus/{entry_id}")
async def delete_entry(
    entry_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    entry = await db.get(ThesaurusEntry, entry_id)
    if not entry:
        raise HTTPException(status_code=404, detail="Entry not found")
        
    await db.delete(entry)
    await db.commit()
    return {"status": "deleted"}
