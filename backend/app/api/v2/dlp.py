from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
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
    channel: str # e.g. "Clipboard", "USB", "Email"
    content: str # The text payload to scan

@router.get("/rules")
async def list_rules(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    return db.query(DlpRule).all()

@router.post("/rules")
async def create_rule(request: RuleRequest, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    rule = DlpRule(
        Name=request.name,
        Category=request.category,
        Pattern=request.pattern
    )
    db.add(rule)
    db.commit()
    dlp_engine.load_policies(db) # Hot reload
    return {"status": "success", "rule_id": rule.Id}

@router.get("/policies")
async def list_policies(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    return db.query(DlpPolicy).all()

@router.post("/policies")
async def create_policy(request: PolicyRequest, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    policy = DlpPolicy(
        Name=request.name,
        TargetChannelsJson=json.dumps(request.channels),
        Action=request.action
    )
    db.add(policy)
    db.commit()
    
    for rid in request.rule_ids:
        link = DlpPolicyRuleLink(PolicyId=policy.Id, RuleId=rid)
        db.add(link)
        
    db.commit()
    dlp_engine.load_policies(db) # Hot reload
    return {"status": "success", "policy_id": policy.Id}

@router.post("/evaluate")
async def evaluate_payload(payload: EvaluationPayload, db: Session = Depends(get_db), agent_sig: str = Depends(verify_agent_signature)):
    """
    Endpoint called by the agent when it intercepts a clipboard copy or file transfer.
    Returns the enforcement action (Block/Allow).
    """
    action, violation_ids = dlp_engine.evaluate_payload(
        db, payload.agent_id, payload.channel, payload.content
    )
    
    return {
        "status": "evaluated",
        "enforcement_action": action, # "Block", "Alert", "Allow"
        "violations_logged": len(violation_ids)
    }

@router.get("/violations")
async def list_violations(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    violations = db.query(DlpViolation).order_by(desc(DlpViolation.Timestamp)).limit(100).all()
    return violations
