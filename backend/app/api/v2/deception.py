from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy import desc
from app.db.session import get_db
from app.db.models import DeceptionCampaign, DeceptionAlert, User
from app.services.deception_engine import deception_engine
from app.api.deps import get_current_user, verify_agent_signature
from pydantic import BaseModel

router = APIRouter()

class CampaignRequest(BaseModel):
    name: str
    token_type: str
    payload_template: str

class TriggerPayload(BaseModel):
    agent_id: str
    token_path: str
    process_id: int
    action: str

@router.get("/campaigns")
async def list_campaigns(db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    return (await db.execute(select(DeceptionCampaign))).scalars().all()

@router.post("/campaigns")
async def create_campaign(request: CampaignRequest, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    camp = DeceptionCampaign(
        Name=request.name,
        Type=request.token_type,
        PayloadTemplate=request.payload_template
    )
    db.add(camp)
    await db.commit()
    return {"status": "success", "campaign_id": camp.Id}

@router.get("/tokens/{agent_id}")
async def fetch_honey_tokens(agent_id: str, db: AsyncSession = Depends(get_db), agent_sig: str = Depends(verify_agent_signature)):
    tokens = await deception_engine.get_tokens_for_agent(db, agent_id)
    return {"agent_id": agent_id, "tokens": tokens}

@router.post("/trigger")
async def trigger_alert(payload: TriggerPayload, db: AsyncSession = Depends(get_db), agent_sig: str = Depends(verify_agent_signature)):
    success, result = await deception_engine.process_trigger(db, payload.model_dump())
    if not success:
        raise HTTPException(status_code=400, detail=result)
    return {"status": "alert_logged", "alert_id": result}

@router.get("/alerts")
async def get_alerts(db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    alerts = (await db.execute(
        select(DeceptionAlert).order_by(desc(DeceptionAlert.Timestamp)).limit(100)
    )).scalars().all()
    return alerts
