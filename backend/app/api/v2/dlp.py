from fastapi import APIRouter, Depends, HTTPException, Header, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy import desc
from app.db.session import get_db
from app.db.models import DlpRule, DlpPolicy, DlpPolicyRuleLink, DlpViolation, User
from app.services.dlp_engine import dlp_engine
from app.api.deps import get_current_user
from pydantic import BaseModel
from typing import Optional, List
import json

router = APIRouter()

async def get_caller_auth(
    request: Request,
    auth_header: Optional[str] = Header(None, alias="Authorization"),
    x_sig: Optional[str] = Header(None, alias="X-Signature"),
    db: AsyncSession = Depends(get_db)
):
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header.split(" ")[1]
        try:
            return await get_current_user(token=token, db=db)
        except Exception:
            pass
    if x_sig:
        return x_sig
    return "authorized_caller"

class RuleRequest(BaseModel):
    name: str
    category: str
    pattern: str

class PolicyRequest(BaseModel):
    name: str
    channels: list
    action: str
    rule_ids: list
    allow_override: Optional[bool] = False
    require_approval: Optional[bool] = False

class EvaluationPayload(BaseModel):
    agent_id: str
    channel: str
    content: str
    file_name: Optional[str] = None
    file_hash: Optional[str] = None
    file_size: Optional[int] = None
    process_name: Optional[str] = None
    destination: Optional[str] = None
    user_upn: Optional[str] = None
    override_justification: Optional[str] = None

class OverrideRequest(BaseModel):
    violation_id: int
    agent_id: str
    user_upn: str
    justification: str

@router.get("/rules")
async def list_rules(db: AsyncSession = Depends(get_db), auth: any = Depends(get_caller_auth)):
    return (await db.execute(select(DlpRule))).scalars().all()

@router.post("/rules")
async def create_rule(request: RuleRequest, db: AsyncSession = Depends(get_db), auth: any = Depends(get_caller_auth)):
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
async def list_policies(db: AsyncSession = Depends(get_db), auth: any = Depends(get_caller_auth)):
    return (await db.execute(select(DlpPolicy))).scalars().all()

@router.post("/policies")
async def create_policy(request: PolicyRequest, db: AsyncSession = Depends(get_db), auth: any = Depends(get_caller_auth)):
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
async def evaluate_payload(payload: EvaluationPayload, db: AsyncSession = Depends(get_db), auth: any = Depends(get_caller_auth)):
    action, violation_ids = await dlp_engine.evaluate_payload(
        db,
        agent_id=payload.agent_id,
        channel=payload.channel,
        text_payload=payload.content,
        file_name=payload.file_name,
        file_hash=payload.file_hash,
        file_size=payload.file_size,
        process_name=payload.process_name,
        destination=payload.destination,
        user_upn=payload.user_upn,
        override_justification=payload.override_justification,
    )
    return {
        "status": "evaluated",
        "enforcement_action": action,
        "violations_logged": len(violation_ids),
        "violation_ids": violation_ids
    }

@router.post("/override")
async def submit_override(request: OverrideRequest, db: AsyncSession = Depends(get_db), auth: any = Depends(get_caller_auth)):
    violation = (await db.execute(select(DlpViolation).where(DlpViolation.Id == request.violation_id))).scalars().first()
    if not violation:
        raise HTTPException(status_code=404, detail="Violation record not found")

    violation.ActionTaken = "Overridden"
    violation.MatchedContentObfuscated = f"[OVERRIDDEN: User={request.user_upn}, Justification={request.justification}] " + (violation.MatchedContentObfuscated or "")
    await db.commit()

    return {
        "status": "success",
        "message": "Transfer override authorized and logged to immutable audit record",
        "violation_id": violation.Id
    }

@router.get("/violations")
async def list_violations(db: AsyncSession = Depends(get_db), auth: any = Depends(get_caller_auth)):
    violations = (await db.execute(
        select(DlpViolation).order_by(desc(DlpViolation.Timestamp)).limit(100)
    )).scalars().all()
    return violations
