from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime

from ..db.session import get_db
from ..db.models import YaraRule, Agent, Tenant, User
from .deps import get_current_user
from ..socket_instance import sio

router = APIRouter()

def get_user_tenant_id(user) -> Optional[int]:
    if isinstance(user, dict):
        return user.get("tenantId") or user.get("TenantId")
    return getattr(user, "TenantId", None)

def is_super_admin(user) -> bool:
    if isinstance(user, dict):
        return user.get("role") == "SuperAdmin" or user.get("Role") == "SuperAdmin"
    return getattr(user, "Role", None) == "SuperAdmin"

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
    current_user: User = Depends(get_current_user)
):
    query = select(YaraRule)
    tenant_id = get_user_tenant_id(current_user)
    if not is_super_admin(current_user) and tenant_id is not None:
        query = query.where(YaraRule.TenantId == tenant_id)
    result = await db.execute(query)
    rules = result.scalars().all()
    return [{"id": r.Id, "name": r.Name, "rule_content": r.RuleContent, "created_at": r.CreatedAt} for r in rules]

@router.post("/rules", response_model=YaraRuleResponse)
async def create_yara_rule(
    rule: YaraRuleCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    tenant_id = get_user_tenant_id(current_user) or 1
    new_rule = YaraRule(
        TenantId=tenant_id,
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
    current_user: User = Depends(get_current_user)
):
    query = select(YaraRule).where(YaraRule.Id == rule_id)
    tenant_id = get_user_tenant_id(current_user)
    if not is_super_admin(current_user) and tenant_id is not None:
        query = query.where(YaraRule.TenantId == tenant_id)
    result = await db.execute(query)
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
    current_user: User = Depends(get_current_user)
):
    # Verify agent belongs to tenant
    agent_query = select(Agent).where(Agent.AgentId == agent_id)
    tenant_id = get_user_tenant_id(current_user)
    if not is_super_admin(current_user) and tenant_id is not None:
        agent_query = agent_query.where(Agent.TenantId == tenant_id)
    result = await db.execute(agent_query)
    agent = result.scalars().first()
    
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
        
    # Get all YARA rules for this tenant
    rule_query = select(YaraRule)
    if not is_super_admin(current_user) and tenant_id is not None:
        rule_query = rule_query.where(YaraRule.TenantId == tenant_id)
    rule_result = await db.execute(rule_query)
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
