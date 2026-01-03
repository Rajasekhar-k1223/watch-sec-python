from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from typing import List
from pydantic import BaseModel
from datetime import datetime

from ..db.session import get_db
from ..db.models import SavedSearch, User
from .deps import get_current_user

router = APIRouter()

class SavedSearchDto(BaseModel):
    Name: str
    QueryJson: str
    Category: str = "General"

@router.get("/searches", response_model=List[dict])
async def get_searches(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    result = await db.execute(select(SavedSearch).order_by(SavedSearch.CreatedAt.desc()))
    searches = result.scalars().all()
    return [{"id": s.Id, "name": s.Name, "query": s.QueryJson, "category": s.Category, "createdAt": s.CreatedAt} for s in searches]

@router.post("/searches")
async def create_search(
    dto: SavedSearchDto,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    new_search = SavedSearch(Name=dto.Name, QueryJson=dto.QueryJson, Category=dto.Category)
    db.add(new_search)
    await db.commit()
    return {"status": "Created", "id": new_search.Id}

@router.delete("/searches/{id}")
async def delete_search(
    id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    res = await db.execute(select(SavedSearch).where(SavedSearch.Id == id))
    search = res.scalars().first()
    if not search:
        raise HTTPException(status_code=404, detail="Search not found")
        
    await db.delete(search)
    await db.commit()
    return {"status": "Deleted"}
