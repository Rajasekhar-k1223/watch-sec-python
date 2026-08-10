from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from app.db.session import get_db
from app.db.models import UebaBaseline, User
from app.services.ueba_engine import ueba_engine
from app.api.deps import get_current_user
import json

router = APIRouter()

@router.get("/baselines/{entity_id}")
async def get_baseline(entity_id: str, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    baseline = (await db.execute(select(UebaBaseline).where(UebaBaseline.EntityId == entity_id))).scalars().first()
    if not baseline:
        raise HTTPException(status_code=404, detail="Baseline not found for this entity.")

    return {
        "entity_id": baseline.EntityId,
        "entity_type": baseline.EntityType,
        "profile": json.loads(baseline.ProfileDataJson),
        "last_updated": baseline.LastUpdated
    }

@router.post("/rebuild")
async def rebuild_baselines(background_tasks: BackgroundTasks, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    background_tasks.add_task(ueba_engine.build_baselines, db)
    return {"status": "success", "message": "UEBA baseline rebuilding task queued."}

@router.post("/evaluate")
async def test_evaluation(payload: dict, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    entity_id = payload.get("entity_id")
    if not entity_id:
        raise HTTPException(status_code=400, detail="Missing entity_id")

    result = await ueba_engine.evaluate_event(db, entity_id, payload)
    return result
