from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from pydantic import BaseModel
from typing import List

from ..db.session import get_db
from ..db.models import YaraRule, Agent, Tenant
from .deps import get_current_user
from ..socket_instance import sio
from datetime import datetime

router = APIRouter()

class YaraRuleCreate(BaseModel):
    name: str
    rule_content: str

class YaraRuleResponse(BaseModel):
    id: int
    name: str
    rule_content: str
    created_at: datetime

@router.get("/rules", response_model=List[YaraRuleResponse])
async def list_yara_rules(
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    result = await db.execute(select(YaraRule).where(YaraRule.TenantId == current_user["tenantId"]))
    rules = result.scalars().all()
    return [{"id": r.Id, "name": r.Name, "rule_content": r.RuleContent, "created_at": r.CreatedAt} for r in rules]

@router.post("/rules", response_model=YaraRuleResponse)
async def create_yara_rule(
    rule: YaraRuleCreate,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    new_rule = YaraRule(
        TenantId=current_user["tenantId"],
        Name=rule.name,
        RuleContent=rule.rule_content,
        CreatedAt=datetime.utcnow()
    )
    db.add(new_rule)
    await db.commit()
    await db.refresh(new_rule)
    
    return {
        "id": new_rule.Id,
        "name": new_rule.Name,
        "rule_content": new_rule.RuleContent,
        "created_at": new_rule.CreatedAt
    }

@router.delete("/rules/{rule_id}")
async def delete_yara_rule(
    rule_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    result = await db.execute(select(YaraRule).where(YaraRule.Id == rule_id, YaraRule.TenantId == current_user["tenantId"]))
    rule = result.scalars().first()
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
        
    await db.delete(rule)
    await db.commit()
    return {"status": "success"}

@router.post("/scan/{agent_id}")
async def trigger_yara_scan(
    agent_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    # Verify agent belongs to tenant
    result = await db.execute(select(Agent).where(Agent.AgentId == agent_id, Agent.TenantId == current_user["tenantId"]))
    agent = result.scalars().first()
    
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
        
    # Get all YARA rules for this tenant
    rule_result = await db.execute(select(YaraRule).where(YaraRule.TenantId == current_user["tenantId"]))
    rules = rule_result.scalars().all()
    
    if not rules:
        raise HTTPException(status_code=400, detail="No YARA rules found for this tenant")
        
    combined_rules = "\n".join([r.RuleContent for r in rules])
    
    # Emit socket event
    await sio.emit('remote_command', {
        'command': 'TriggerYaraScan',
        'args': {'rules': combined_rules}
    }, room=agent_id)
    
    return {"status": "Scan triggered"}
