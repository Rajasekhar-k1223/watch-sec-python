from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import desc
from app.db.session import get_db
from app.db.models import DeceptionCampaign, DeceptionAlert, User
from app.services.deception_engine import deception_engine
from app.api.deps import get_current_user, verify_agent_signature
from pydantic import BaseModel

router = APIRouter()

class CampaignRequest(BaseModel):
    name: str
    token_type: str # File, Credential, NetworkShare
    payload_template: str

class TriggerPayload(BaseModel):
    agent_id: str
    token_path: str
    process_id: int
    action: str

@router.get("/campaigns")
async def list_campaigns(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    return db.query(DeceptionCampaign).all()

@router.post("/campaigns")
async def create_campaign(request: CampaignRequest, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    camp = DeceptionCampaign(
        Name=request.name,
        Type=request.token_type,
        PayloadTemplate=request.payload_template
    )
    db.add(camp)
    db.commit()
    return {"status": "success", "campaign_id": camp.Id}

@router.get("/tokens/{agent_id}")
async def fetch_honey_tokens(agent_id: str, db: Session = Depends(get_db), agent_sig: str = Depends(verify_agent_signature)):
    """
    Endpoint for agents to pull down their assigned Honey Tokens
    so they can place them on disk or in memory.
    """
    tokens = deception_engine.get_tokens_for_agent(db, agent_id)
    return {"agent_id": agent_id, "tokens": tokens}

@router.post("/trigger")
async def trigger_alert(payload: TriggerPayload, db: Session = Depends(get_db), agent_sig: str = Depends(verify_agent_signature)):
    """
    High-priority endpoint for an agent to report an attacker interacting with a Honey Token.
    """
    success, result = deception_engine.process_trigger(db, payload.model_dump())
    if not success:
        raise HTTPException(status_code=400, detail=result)
        
    return {"status": "alert_logged", "alert_id": result}

@router.get("/alerts")
async def get_alerts(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    """Dashboard endpoint to view high-fidelity deception alerts."""
    alerts = db.query(DeceptionAlert).order_by(desc(DeceptionAlert.Timestamp)).limit(100).all()
    return alerts
