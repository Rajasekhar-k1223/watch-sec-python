from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy import desc
from app.db.session import get_db
from app.db.models import DeceptionCampaign, DeceptionAlert, HoneyToken, User
from app.services.deception_engine import deception_engine
from typing import Optional, List, Dict, Any
from pydantic import BaseModel
import uuid
import hashlib

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

class DeployTokenRequest(BaseModel):
    campaign_id: int
    agent_id: str
    token_path: Optional[str] = None

@router.get("/overview")
async def get_overview(db: AsyncSession = Depends(get_db)):
    """Retrieve full Honeypots & Deception Technology posture and live status."""
    return await deception_engine.get_overview(db)

@router.get("/agents")
async def list_deception_agents(db: AsyncSession = Depends(get_db)):
    """List active endpoints available for honeytoken deployment without hard auth barriers."""
    from app.db.models import Agent
    agents = (await db.execute(select(Agent))).scalars().all()
    return [
        {
            "AgentId": a.AgentId,
            "agent_id": a.AgentId,
            "Hostname": a.Hostname or a.AgentId,
            "hostname": a.Hostname or a.AgentId,
            "status": a.Status or "Online"
        }
        for a in agents
    ]

@router.get("/campaigns")
async def list_campaigns(db: AsyncSession = Depends(get_db)):
    await deception_engine.ensure_seed_data(db)
    campaigns = (await db.execute(select(DeceptionCampaign))).scalars().all()
    return [
        {
            "id": c.Id,
            "name": c.Name,
            "type": c.Type,
            "payload_template": c.PayloadTemplate,
            "is_active": c.IsActive
        }
        for c in campaigns
    ]

@router.post("/campaigns")
async def create_campaign(request: CampaignRequest, db: AsyncSession = Depends(get_db)):
    camp = DeceptionCampaign(
        Name=request.name,
        Type=request.token_type,
        PayloadTemplate=request.payload_template,
        IsActive=True
    )
    db.add(camp)
    await db.commit()
    await db.refresh(camp)
    return {
        "status": "success",
        "campaign_id": camp.Id,
        "campaign": {
            "id": camp.Id,
            "name": camp.Name,
            "type": camp.Type,
            "payload_template": camp.PayloadTemplate,
            "is_active": camp.IsActive
        }
    }

@router.get("/tokens")
async def list_tokens(db: AsyncSession = Depends(get_db)):
    await deception_engine.ensure_seed_data(db)
    tokens = (await db.execute(select(HoneyToken))).scalars().all()
    camps = (await db.execute(select(DeceptionCampaign))).scalars().all()
    camp_map = {c.Id: c for c in camps}
    return [
        {
            "id": t.Id,
            "agent_id": t.AgentId,
            "token_path": t.TokenPath,
            "campaign_id": t.CampaignId,
            "campaign_name": camp_map[t.CampaignId].Name if t.CampaignId in camp_map else "Decoy Campaign",
            "token_type": camp_map[t.CampaignId].Type if t.CampaignId in camp_map else "File",
            "token_hash": t.TokenHash,
            "deployed_at": t.DeployedAt.isoformat() if t.DeployedAt else None
        }
        for t in tokens
    ]

@router.get("/tokens/{agent_id}")
async def fetch_honey_tokens(agent_id: str, db: AsyncSession = Depends(get_db)):
    tokens = await deception_engine.get_tokens_for_agent(db, agent_id)
    return {"agent_id": agent_id, "tokens": tokens}

@router.post("/tokens/deploy")
async def deploy_token(request: DeployTokenRequest, db: AsyncSession = Depends(get_db)):
    camp = (await db.execute(select(DeceptionCampaign).where(DeceptionCampaign.Id == request.campaign_id))).scalars().first()
    if not camp:
        raise HTTPException(status_code=404, detail="Campaign not found")

    path = request.token_path or (
        f"/var/log/backup/prod_db_{uuid.uuid4().hex[:6]}.sql" if camp.Type == "Database"
        else f"/home/admin/.aws/credentials_backup_{uuid.uuid4().hex[:4]}" if camp.Type == "Credential"
        else f"/opt/shares/confidential/financial_q3_{uuid.uuid4().hex[:4]}.xlsx"
    )
    token = HoneyToken(
        CampaignId=camp.Id,
        AgentId=request.agent_id,
        TokenPath=path,
        TokenHash=hashlib.sha256(path.encode()).hexdigest()
    )
    db.add(token)
    await db.commit()
    await db.refresh(token)
    return {"status": "deployed", "token_id": token.Id, "path": token.TokenPath}

@router.post("/trigger")
async def trigger_alert(payload: TriggerPayload, db: AsyncSession = Depends(get_db)):
    success, result = await deception_engine.process_trigger(db, payload.model_dump())
    if not success:
        raise HTTPException(status_code=400, detail=result)
    return {"status": "alert_logged", "alert_id": result}

@router.get("/alerts")
async def get_alerts(db: AsyncSession = Depends(get_db)):
    await deception_engine.ensure_seed_data(db)
    alerts = (await db.execute(
        select(DeceptionAlert).order_by(desc(DeceptionAlert.Timestamp)).limit(100)
    )).scalars().all()
    tokens = (await db.execute(select(HoneyToken))).scalars().all()
    camps = (await db.execute(select(DeceptionCampaign))).scalars().all()
    tok_map = {t.Id: t for t in tokens}
    camp_map = {c.Id: c for c in camps}

    return [
        {
            "id": a.Id,
            "agent_id": a.AgentId,
            "process_id": a.ProcessId,
            "action": a.Action,
            "token_path": tok_map[a.TokenId].TokenPath if a.TokenId in tok_map else "C:\\Users\\Public\\Documents\\financial_Q3_report.xlsx",
            "campaign_name": camp_map[tok_map[a.TokenId].CampaignId].Name if (a.TokenId in tok_map and tok_map[a.TokenId].CampaignId in camp_map) else "Decoy Intrusion Alert",
            "token_type": camp_map[tok_map[a.TokenId].CampaignId].Type if (a.TokenId in tok_map and tok_map[a.TokenId].CampaignId in camp_map) else "File",
            "timestamp": a.Timestamp.isoformat() if a.Timestamp else None,
            "severity": "CRITICAL",
            "containment_status": "AUTO_CONTAINED"
        }
        for a in alerts
    ]
