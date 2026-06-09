from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
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
async def list_playbooks(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    playbooks = db.query(SoarPlaybook).all()
    return playbooks

@router.post("/playbooks")
async def create_playbook(request: PlaybookRequest, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    playbook = SoarPlaybook(
        Name=request.name,
        TriggerCondition=request.trigger_condition,
        ActionsJson=json.dumps(request.actions),
        RequiresApproval=request.requires_approval
    )
    db.add(playbook)
    db.commit()
    return {"status": "success", "playbook_id": playbook.Id}

@router.get("/approvals")
async def list_pending_approvals(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    approvals = db.query(SoarApprovalQueue).filter(SoarApprovalQueue.Status == "Pending").all()
    return approvals

@router.post("/approvals/{approval_id}/approve")
async def approve_action(approval_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    admin_id = current_user.Username
    success, msg = soar_engine.approve_action(db, approval_id, admin_id)
    if not success:
        raise HTTPException(status_code=400, detail=msg)
    return {"status": "success", "message": msg}

@router.get("/audit")
async def get_audit_trail(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    executions = db.query(SoarActionExecution).order_by(desc(SoarActionExecution.CreatedAt)).limit(100).all()
    return executions
