from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy import desc
from app.db.session import get_db
from app.db.models import DetectionRule, DetectionAlert, User
from app.services.detection_engine import detection_engine
from app.api.deps import get_current_user, verify_agent_signature
from pydantic import BaseModel

router = APIRouter()

class RuleRequest(BaseModel):
    name: str
    rule_type: str = "Sigma"
    category: str
    mitre_tactic: str
    mitre_technique: str
    severity: str = "High"
    content: str

class TelemetryPayload(BaseModel):
    agent_id: str
    process_name: str
    cmdline: str
    log_id: int = 0

@router.get("/rules")
async def list_rules(tactic: str = None, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    query = select(DetectionRule)
    if tactic:
        query = query.where(DetectionRule.MitreTactic == tactic)
    return (await db.execute(query)).scalars().all()

@router.post("/rules")
async def create_rule(request: RuleRequest, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    rule = DetectionRule(
        Name=request.name,
        Type=request.rule_type,
        Category=request.category,
        MitreTactic=request.mitre_tactic,
        MitreTechnique=request.mitre_technique,
        Severity=request.severity,
        RuleContent=request.content
    )
    db.add(rule)
    await db.commit()

    await detection_engine.load_rules(db)
    return {"status": "success", "rule_id": rule.Id}

@router.get("/alerts")
async def get_alerts(status: str = "New", db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    alerts = (await db.execute(
        select(DetectionAlert)
        .where(DetectionAlert.Status == status)
        .order_by(desc(DetectionAlert.Timestamp))
        .limit(100)
    )).scalars().all()
    return alerts

@router.post("/evaluate")
async def evaluate_payload(payload: TelemetryPayload, db: AsyncSession = Depends(get_db), agent_sig: str = Depends(verify_agent_signature)):
    alerts = await detection_engine.evaluate_telemetry(db, payload.dict(), payload.agent_id)
    return {
        "status": "evaluated",
        "alerts_triggered": len(alerts),
        "alert_ids": [a.Id for a in alerts]
    }
