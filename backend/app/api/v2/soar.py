from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy import desc, or_, and_
from app.db.session import get_db
from app.db.models import SoarPlaybook, SoarApprovalQueue, SoarActionExecution, User, Agent
from app.services.soar_engine import soar_engine
from app.api.deps import get_current_user
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
import json
import logging

logger = logging.getLogger("SoarAPI")

router = APIRouter()

# ── RBAC Authorization Helpers ───────────────────────────────────────────────

def normalize_role(role: Optional[str]) -> str:
    return (role or "").lower().replace("_", "").replace(" ", "")

def is_superadmin(user: User) -> bool:
    return user.Role == "SuperAdmin" or normalize_role(user.Role) == "superadmin"

def is_tenantadmin(user: User) -> bool:
    if is_superadmin(user):
        return True
    nr = normalize_role(user.Role)
    return user.Role == "TenantAdmin" or nr in ("tenantadmin", "admin")

def can_execute_playbook(user: User) -> bool:
    """SuperAdmin, TenantAdmin, Analyst, and SOC Operator can execute operational workflows."""
    if is_tenantadmin(user):
        return True
    nr = normalize_role(user.Role)
    return nr in ("analyst", "securityanalyst", "socoperator", "operator")

def enforce_mutation_access(user: User):
    """Only SuperAdmin and TenantAdmin can create, update, delete, enable, or disable playbooks."""
    if not is_tenantadmin(user):
        raise HTTPException(
            status_code=403,
            detail=f"Access denied: Role '{user.Role}' is not authorized to mutate SOAR playbooks. Requires TenantAdmin or SuperAdmin."
        )

def enforce_approval_access(user: User):
    """Only SuperAdmin and TenantAdmin can approve or reject actions."""
    if not is_tenantadmin(user):
        raise HTTPException(
            status_code=403,
            detail=f"Access denied: Role '{user.Role}' is not authorized to approve or reject SOAR actions. Requires TenantAdmin or SuperAdmin."
        )

# ── Pydantic Request Models ──────────────────────────────────────────────────

class PlaybookRequest(BaseModel):
    name: str
    trigger_condition: Optional[str] = None
    trigger_type: Optional[str] = None
    actions: Optional[list] = None
    definition: Optional[dict] = None
    description: Optional[str] = None
    requires_approval: bool = True
    tenant_id: Optional[int] = None

    def get_trigger(self) -> str:
        return self.trigger_condition or self.trigger_type or "alert.created"

    def get_actions(self) -> list:
        if self.actions is not None:
            return self.actions
        if self.definition and isinstance(self.definition, dict) and "steps" in self.definition:
            return self.definition["steps"]
        return []

class PlaybookExecuteRequest(BaseModel):
    playbook_id: int
    target_agent_id: str
    action_params: dict = {}

class RejectRequest(BaseModel):
    reason: Optional[str] = "Rejected by administrator"

# ── Endpoints ────────────────────────────────────────────────────────────────

@router.get("/playbooks")
async def list_playbooks(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Lists playbooks with strict tenant isolation.
    SuperAdmin views all; other roles view only playbooks scoped to their TenantId.
    """
    if is_superadmin(current_user):
        q = select(SoarPlaybook)
    else:
        q = select(SoarPlaybook).where(
            or_(
                SoarPlaybook.TenantId == current_user.TenantId,
                SoarPlaybook.TenantId == None
            )
        )
    return (await db.execute(q)).scalars().all()

@router.post("/playbooks")
async def create_playbook(
    request: PlaybookRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Creates a new SOAR playbook. Restricted to SuperAdmin and TenantAdmin.
    """
    enforce_mutation_access(current_user)

    assigned_tenant_id = (
        request.tenant_id if (is_superadmin(current_user) and request.tenant_id)
        else current_user.TenantId
    )

    playbook = SoarPlaybook(
        TenantId=assigned_tenant_id,
        Name=request.name,
        TriggerCondition=request.get_trigger(),
        ActionsJson=json.dumps(request.get_actions()),
        RequiresApproval=request.requires_approval,
        IsActive=True
    )
    db.add(playbook)
    await db.commit()
    return {"status": "success", "playbook_id": playbook.Id, "id": playbook.Id, "tenant_id": playbook.TenantId}

@router.put("/playbooks/{playbook_id}")
async def update_playbook(
    playbook_id: int,
    request: PlaybookRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Updates an existing playbook with RBAC and cross-tenant guardrails.
    """
    enforce_mutation_access(current_user)

    pb = (await db.execute(select(SoarPlaybook).where(SoarPlaybook.Id == playbook_id))).scalars().first()
    if not pb:
        raise HTTPException(status_code=404, detail="Playbook not found")

    if not is_superadmin(current_user) and pb.TenantId and pb.TenantId != current_user.TenantId:
        raise HTTPException(status_code=403, detail="Cross-tenant modification prohibited")

    pb.Name = request.name
    pb.TriggerCondition = request.get_trigger()
    pb.ActionsJson = json.dumps(request.get_actions())
    pb.RequiresApproval = request.requires_approval
    if is_superadmin(current_user) and request.tenant_id is not None:
        pb.TenantId = request.tenant_id

    await db.commit()
    await db.refresh(pb)
    return {"status": "success", "playbook": pb, "name": pb.Name}

@router.delete("/playbooks/{playbook_id}")
async def delete_playbook(
    playbook_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Deletes a playbook with RBAC and tenant isolation.
    """
    enforce_mutation_access(current_user)

    pb = (await db.execute(select(SoarPlaybook).where(SoarPlaybook.Id == playbook_id))).scalars().first()
    if not pb:
        raise HTTPException(status_code=404, detail="Playbook not found")

    if not is_superadmin(current_user) and pb.TenantId and pb.TenantId != current_user.TenantId:
        raise HTTPException(status_code=403, detail="Cross-tenant deletion prohibited")

    await db.delete(pb)
    await db.commit()
    return {"status": "success", "message": f"Playbook #{playbook_id} deleted"}

@router.patch("/playbooks/{playbook_id}/enable")
async def enable_playbook(
    playbook_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Enables an active playbook."""
    enforce_mutation_access(current_user)

    pb = (await db.execute(select(SoarPlaybook).where(SoarPlaybook.Id == playbook_id))).scalars().first()
    if not pb:
        raise HTTPException(status_code=404, detail="Playbook not found")

    if not is_superadmin(current_user) and pb.TenantId and pb.TenantId != current_user.TenantId:
        raise HTTPException(status_code=403, detail="Cross-tenant operation prohibited")

    pb.IsActive = True
    await db.commit()
    return {"status": "success", "message": f"Playbook #{playbook_id} enabled", "is_active": True}

@router.patch("/playbooks/{playbook_id}/disable")
async def disable_playbook(
    playbook_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Disables a playbook from automated or manual execution."""
    enforce_mutation_access(current_user)

    pb = (await db.execute(select(SoarPlaybook).where(SoarPlaybook.Id == playbook_id))).scalars().first()
    if not pb:
        raise HTTPException(status_code=404, detail="Playbook not found")

    if not is_superadmin(current_user) and pb.TenantId and pb.TenantId != current_user.TenantId:
        raise HTTPException(status_code=403, detail="Cross-tenant operation prohibited")

    pb.IsActive = False
    await db.commit()
    return {"status": "success", "message": f"Playbook #{playbook_id} disabled", "is_active": False}

@router.post("/playbooks/execute")
async def execute_playbook(
    request: PlaybookExecuteRequest, 
    db: AsyncSession = Depends(get_db), 
    current_user: User = Depends(get_current_user)
):
    """
    Executes a SOAR playbook. Permitted for SuperAdmin, TenantAdmin, Analyst, and SOC Operator.
    Enforces active state and tenant boundaries.
    """
    if not can_execute_playbook(current_user):
        raise HTTPException(
            status_code=403,
            detail=f"Access denied: User role '{current_user.Role}' is not permitted to execute SOAR playbooks."
        )

    pb = (await db.execute(select(SoarPlaybook).where(SoarPlaybook.Id == request.playbook_id))).scalars().first()
    if not pb:
        raise HTTPException(status_code=404, detail="Playbook not found")

    if pb.IsActive is False:
        raise HTTPException(status_code=400, detail="Cannot execute inactive or disabled playbook")

    if not is_superadmin(current_user) and pb.TenantId and pb.TenantId != current_user.TenantId:
        raise HTTPException(status_code=403, detail="Cross-tenant playbook execution prohibited")

    # Verify target agent belongs to tenant
    if not is_superadmin(current_user):
        target_agent = (await db.execute(select(Agent).where(Agent.AgentId == request.target_agent_id))).scalars().first()
        if target_agent and target_agent.TenantId and target_agent.TenantId != current_user.TenantId:
            raise HTTPException(status_code=403, detail="Cross-tenant target execution prohibited")

    success, msg = await soar_engine.trigger_playbook(
        db, 
        request.playbook_id, 
        request.target_agent_id, 
        request.action_params
    )
    if not success:
        raise HTTPException(status_code=400, detail=msg)
    return {"status": "success", "message": msg}

@router.get("/approvals")
async def list_pending_approvals(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Lists pending approval queue items.
    SuperAdmin views all; TenantAdmin and Analysts view only their tenant's actions.
    """
    if is_superadmin(current_user):
        q = select(SoarApprovalQueue).where(SoarApprovalQueue.Status == "Pending")
    else:
        q = select(SoarApprovalQueue).join(
            SoarActionExecution, SoarApprovalQueue.ExecutionId == SoarActionExecution.Id
        ).join(
            SoarPlaybook, SoarActionExecution.PlaybookId == SoarPlaybook.Id, isouter=True
        ).where(
            and_(
                SoarApprovalQueue.Status == "Pending",
                or_(
                    SoarPlaybook.TenantId == current_user.TenantId,
                    SoarPlaybook.TenantId == None
                )
            )
        )
    return (await db.execute(q)).scalars().all()

@router.post("/approvals/{approval_id}/approve")
async def approve_action(
    approval_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Approves a queued action. Restricted to SuperAdmin and TenantAdmin.
    """
    enforce_approval_access(current_user)

    approval = (await db.execute(select(SoarApprovalQueue).where(SoarApprovalQueue.Id == approval_id))).scalars().first()
    if not approval:
        raise HTTPException(status_code=404, detail="Approval not found")

    if not is_superadmin(current_user):
        execution = (await db.execute(select(SoarActionExecution).where(SoarActionExecution.Id == approval.ExecutionId))).scalars().first()
        if execution and execution.PlaybookId:
            pb = (await db.execute(select(SoarPlaybook).where(SoarPlaybook.Id == execution.PlaybookId))).scalars().first()
            if pb and pb.TenantId and pb.TenantId != current_user.TenantId:
                raise HTTPException(status_code=403, detail="Cross-tenant approval prohibited")

    success, msg = await soar_engine.approve_action(db, approval_id, current_user.Username)
    if not success:
        raise HTTPException(status_code=400, detail=msg)
    return {"status": "success", "message": msg}

@router.post("/approvals/{approval_id}/reject")
async def reject_action(
    approval_id: int,
    request: Optional[RejectRequest] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Rejects a queued action. Restricted to SuperAdmin and TenantAdmin.
    """
    enforce_approval_access(current_user)

    approval = (await db.execute(select(SoarApprovalQueue).where(SoarApprovalQueue.Id == approval_id))).scalars().first()
    if not approval:
        raise HTTPException(status_code=404, detail="Approval not found")

    if not is_superadmin(current_user):
        execution = (await db.execute(select(SoarActionExecution).where(SoarActionExecution.Id == approval.ExecutionId))).scalars().first()
        if execution and execution.PlaybookId:
            pb = (await db.execute(select(SoarPlaybook).where(SoarPlaybook.Id == execution.PlaybookId))).scalars().first()
            if pb and pb.TenantId and pb.TenantId != current_user.TenantId:
                raise HTTPException(status_code=403, detail="Cross-tenant rejection prohibited")

    reason_str = request.reason if request and request.reason else "Rejected by administrator"
    success, msg = await soar_engine.reject_action(db, approval_id, current_user.Username, reason_str)
    if not success:
        raise HTTPException(status_code=400, detail=msg)
    return {"status": "success", "message": msg}

@router.get("/audit")
async def get_audit_trail(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Returns recent SOAR execution history with tenant filtering.
    """
    if is_superadmin(current_user):
        q = select(SoarActionExecution).order_by(desc(SoarActionExecution.CreatedAt)).limit(100)
    else:
        q = select(SoarActionExecution).join(
            SoarPlaybook, SoarActionExecution.PlaybookId == SoarPlaybook.Id, isouter=True
        ).where(
            or_(
                SoarPlaybook.TenantId == current_user.TenantId,
                SoarPlaybook.TenantId == None
            )
        ).order_by(desc(SoarActionExecution.CreatedAt)).limit(100)
    return (await db.execute(q)).scalars().all()
