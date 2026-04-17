from fastapi import APIRouter, Depends, HTTPException # type: ignore
from sqlalchemy.ext.asyncio import AsyncSession # type: ignore
from sqlalchemy.future import select # type: ignore
from typing import List # type: ignore
from pydantic import BaseModel # type: ignore
from datetime import datetime # type: ignore

from ..db.session import get_db # type: ignore
from ..db.models import SavedSearch, User # type: ignore
from .deps import get_current_user # type: ignore

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
    query = select(SavedSearch)
    if current_user.Role != "SuperAdmin":
        query = query.where(SavedSearch.TenantId == current_user.TenantId)
        
    result = await db.execute(query.order_by(SavedSearch.CreatedAt.desc()))
    searches = result.scalars().all()
    return [{"id": s.Id, "name": s.Name, "query": s.QueryJson, "category": s.Category, "createdAt": s.CreatedAt} for s in searches]

@router.post("/searches")
async def create_search(
    dto: SavedSearchDto,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    new_search = SavedSearch(
        Name=dto.Name, 
        QueryJson=dto.QueryJson, 
        Category=dto.Category,
        TenantId=current_user.TenantId
    )
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
        
    # [SECURITY] Check Ownership
    if current_user.Role != "SuperAdmin" and search.TenantId != current_user.TenantId:
        raise HTTPException(status_code=403, detail="Access denied")
        
    await db.delete(search)
    await db.commit()
    return {"status": "Deleted"}
