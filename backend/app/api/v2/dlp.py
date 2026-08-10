from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy import desc
from app.db.session import get_db
from app.db.models import DlpRule, DlpPolicy, DlpPolicyRuleLink, DlpViolation, User
from app.services.dlp_engine import dlp_engine
from app.api.deps import get_current_user, verify_agent_signature
from pydantic import BaseModel
import json

router = APIRouter()

class RuleRequest(BaseModel):
    name: str
    category: str
    pattern: str

class PolicyRequest(BaseModel):
    name: str
    channels: list
    action: str
    rule_ids: list

class EvaluationPayload(BaseModel):
    agent_id: str
    channel: str
    content: str

@router.get("/rules")
async def list_rules(db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    return (await db.execute(select(DlpRule))).scalars().all()

@router.post("/rules")
async def create_rule(request: RuleRequest, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    rule = DlpRule(
        Name=request.name,
        Category=request.category,
        Pattern=request.pattern
    )
    db.add(rule)
    await db.commit()
    await dlp_engine.load_policies(db)
    return {"status": "success", "rule_id": rule.Id}

@router.get("/policies")
async def list_policies(db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    return (await db.execute(select(DlpPolicy))).scalars().all()

@router.post("/policies")
async def create_policy(request: PolicyRequest, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    policy = DlpPolicy(
        Name=request.name,
        TargetChannelsJson=json.dumps(request.channels),
        Action=request.action
    )
    db.add(policy)
    await db.commit()

    for rid in request.rule_ids:
        link = DlpPolicyRuleLink(PolicyId=policy.Id, RuleId=rid)
        db.add(link)

    await db.commit()
    await dlp_engine.load_policies(db)
    return {"status": "success", "policy_id": policy.Id}

@router.post("/evaluate")
async def evaluate_payload(payload: EvaluationPayload, db: AsyncSession = Depends(get_db), agent_sig: str = Depends(verify_agent_signature)):
    action, violation_ids = await dlp_engine.evaluate_payload(
        db, payload.agent_id, payload.channel, payload.content
    )
    return {
        "status": "evaluated",
        "enforcement_action": action,
        "violations_logged": len(violation_ids)
    }

@router.get("/violations")
async def list_violations(db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    violations = (await db.execute(
        select(DlpViolation).order_by(desc(DlpViolation.Timestamp)).limit(100)
    )).scalars().all()
    return violations
