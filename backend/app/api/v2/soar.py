from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy import desc
from app.db.session import get_db
from app.db.models import SoarPlaybook, SoarApprovalQueue, SoarActionExecution, User
from app.services.soar_engine import soar_engine
from app.api.deps import get_current_user
from pydantic import BaseModel
import json

router = APIRouter()

class PlaybookRequest(BaseModel):
    name: str
    trigger_condition: str
    actions: list
    requires_approval: bool = False

@router.get("/playbooks")
async def list_playbooks(db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    return (await db.execute(select(SoarPlaybook))).scalars().all()

@router.post("/playbooks")
async def create_playbook(request: PlaybookRequest, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    playbook = SoarPlaybook(
        Name=request.name,
        TriggerCondition=request.trigger_condition,
        ActionsJson=json.dumps(request.actions),
        RequiresApproval=request.requires_approval
    )
    db.add(playbook)
    await db.commit()
    return {"status": "success", "playbook_id": playbook.Id}

@router.get("/approvals")
async def list_pending_approvals(db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    approvals = (await db.execute(
        select(SoarApprovalQueue).where(SoarApprovalQueue.Status == "Pending")
    )).scalars().all()
    return approvals

@router.post("/approvals/{approval_id}/approve")
async def approve_action(approval_id: int, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    success, msg = await soar_engine.approve_action(db, approval_id, current_user.Username)
    if not success:
        raise HTTPException(status_code=400, detail=msg)
    return {"status": "success", "message": msg}

@router.get("/audit")
async def get_audit_trail(db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    executions = (await db.execute(
        select(SoarActionExecution).order_by(desc(SoarActionExecution.CreatedAt)).limit(100)
    )).scalars().all()
    return executions
