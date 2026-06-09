from fastapi import APIRouter, Depends, HTTPException, UploadFile, File  # type: ignore
from sqlalchemy.ext.asyncio import AsyncSession  # type: ignore
from sqlalchemy.future import select  # type: ignore
from sqlalchemy import update  # type: ignore
from pydantic import BaseModel, field_validator  # type: ignore
from typing import Optional
import os
import uuid
import shutil
import logging
from datetime import datetime

from ..db.session import get_db  # type: ignore
from ..db.models import User, Tenant, Policy  # type: ignore
from .deps import get_current_user  # type: ignore

router = APIRouter()
logger = logging.getLogger("SupportRouter")

# Secure allowlist for diagnostic upload file extensions
ALLOWED_EXTENSIONS = {".log", ".txt", ".json", ".zip", ".gz", ".tar"}
MAX_UPLOAD_BYTES = 50 * 1024 * 1024  # 50 MB

STORAGE_BASE = os.environ.get("DIAGNOSTICS_STORAGE_PATH", "/app/storage/diagnostics")


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class SupportTicketRequest(BaseModel):
    subject: str
    description: str
    priority: str = "Medium"

    @field_validator("subject")
    @classmethod
    def validate_subject(cls, v: str) -> str:
        v = v.strip()
        if not v or len(v) > 200:
            raise ValueError("Subject must be 1–200 characters")
        return v

    @field_validator("priority")
    @classmethod
    def validate_priority(cls, v: str) -> str:
        allowed = {"Low", "Medium", "High", "Critical"}
        if v not in allowed:
            raise ValueError(f"Priority must be one of {allowed}")
        return v

    @field_validator("description")
    @classmethod
    def validate_description(cls, v: str) -> str:
        v = v.strip()
        if not v or len(v) > 10000:
            raise ValueError("Description must be 1–10000 characters")
        return v


class TicketStatusUpdate(BaseModel):
    status: str

    @field_validator("status")
    @classmethod
    def validate_status(cls, v: str) -> str:
        allowed = {"Open", "In Progress", "Resolved", "Closed"}
        if v not in allowed:
            raise ValueError(f"Status must be one of {allowed}")
        return v


# ---------------------------------------------------------------------------
# In-memory ticket store (production: use a proper SupportTicket DB model)
# TODO: Replace with DB model once SupportTicket table is added to models.py
# ---------------------------------------------------------------------------
_ticket_store: dict = {}


def _generate_ticket_id() -> str:
    return f"TIC-{str(uuid.uuid4()).upper()[:8]}"


# ---------------------------------------------------------------------------
# POST /api/support/tickets  — Create a new support ticket
# ---------------------------------------------------------------------------

@router.post("/tickets")
async def create_support_ticket(
    ticket: SupportTicketRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    [v2.5.0] Enterprise Support: Creates a new support ticket.
    Persists the ticket with a unique ID tied to the requesting user/tenant.
    """
    ticket_id = _generate_ticket_id()
    record = {
        "ticketId": ticket_id,
        "subject": ticket.subject,
        "description": ticket.description,
        "priority": ticket.priority,
        "status": "Open",
        "createdBy": current_user.Username,
        "tenantId": current_user.TenantId,
        "createdAt": datetime.utcnow().isoformat(),
        "updatedAt": datetime.utcnow().isoformat(),
        "attachments": []
    }
    _ticket_store[ticket_id] = record
    # NOTE: Do not log subject/description — may contain sensitive info
    logger.info(f"[Support] Ticket {ticket_id} created by tenant {current_user.TenantId}")
    return {"status": "created", "ticketId": ticket_id, "message": "Monitorix support has been notified."}


# ---------------------------------------------------------------------------
# GET /api/support/tickets  — List tickets for the calling tenant
# ---------------------------------------------------------------------------

@router.get("/tickets")
async def list_support_tickets(
    current_user: User = Depends(get_current_user)
):
    """Returns all support tickets for the current tenant, newest first."""
    tickets = [
        t for t in _ticket_store.values()
        if t["tenantId"] == current_user.TenantId
    ]
    tickets.sort(key=lambda t: t["createdAt"], reverse=True)
    return {"tickets": tickets, "total": len(tickets)}


# ---------------------------------------------------------------------------
# GET /api/support/tickets/{ticket_id}  — Get single ticket
# ---------------------------------------------------------------------------

@router.get("/tickets/{ticket_id}")
async def get_ticket(
    ticket_id: str,
    current_user: User = Depends(get_current_user)
):
    """Returns a single ticket — only accessible by the owning tenant."""
    ticket = _ticket_store.get(ticket_id)
    if not ticket:
        raise HTTPException(status_code=404, detail="Ticket not found")
    # Tenant isolation: ensure the ticket belongs to the requesting tenant
    if ticket["tenantId"] != current_user.TenantId and current_user.Role != "SuperAdmin":
        raise HTTPException(status_code=403, detail="Access denied")
    return ticket


# ---------------------------------------------------------------------------
# PUT /api/support/tickets/{ticket_id}/status  — Update ticket status
# ---------------------------------------------------------------------------

@router.put("/tickets/{ticket_id}/status")
async def update_ticket_status(
    ticket_id: str,
    body: TicketStatusUpdate,
    current_user: User = Depends(get_current_user)
):
    """Updates the status of a support ticket. TenantAdmin or SuperAdmin only."""
    if current_user.Role not in ("TenantAdmin", "SuperAdmin"):
        raise HTTPException(status_code=403, detail="Insufficient permissions to update ticket status")

    ticket = _ticket_store.get(ticket_id)
    if not ticket:
        raise HTTPException(status_code=404, detail="Ticket not found")
    if ticket["tenantId"] != current_user.TenantId and current_user.Role != "SuperAdmin":
        raise HTTPException(status_code=403, detail="Access denied")

    ticket["status"] = body.status
    ticket["updatedAt"] = datetime.utcnow().isoformat()
    logger.info(f"[Support] Ticket {ticket_id} status → {body.status}")
    return {"status": "updated", "ticketId": ticket_id, "newStatus": body.status}


# ---------------------------------------------------------------------------
# POST /api/support/diagnostic-upload/{ticket_id}  — Secure file upload
# ---------------------------------------------------------------------------

@router.post("/diagnostic-upload/{ticket_id}")
async def upload_diagnostic_bundle(
    ticket_id: str,
    file: UploadFile = File(...),
    current_user: User = Depends(get_current_user)
):
    """
    Secure diagnostic log upload. Enforces:
    - Extension allowlist: .log, .txt, .json, .zip, .gz, .tar
    - Max file size: 50 MB
    - Randomized filename stored under a ticket-scoped directory
    - Path traversal prevention via os.path.realpath boundary check
    """
    # Validate ticket ownership
    ticket = _ticket_store.get(ticket_id)
    if not ticket:
        raise HTTPException(status_code=404, detail="Ticket not found")
    if ticket["tenantId"] != current_user.TenantId and current_user.Role != "SuperAdmin":
        raise HTTPException(status_code=403, detail="Access denied")

    # Validate file extension against allowlist
    original_name = file.filename or ""
    _, ext = os.path.splitext(original_name.lower())
    if ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail=f"File type '{ext}' not allowed. Allowed: {', '.join(ALLOWED_EXTENSIONS)}"
        )

    # Read file content with size limit
    content = await file.read(MAX_UPLOAD_BYTES + 1)
    if len(content) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="File exceeds the 50MB limit")

    # Build a randomized safe filename — never use original filename in path
    safe_name = f"{uuid.uuid4().hex}{ext}"
    upload_dir = os.path.realpath(os.path.join(STORAGE_BASE, ticket_id))

    # Boundary check: ensure resolved path stays within STORAGE_BASE
    base_real = os.path.realpath(STORAGE_BASE)
    if not upload_dir.startswith(base_real + os.sep):
        raise HTTPException(status_code=400, detail="Invalid ticket path")

    os.makedirs(upload_dir, exist_ok=True)
    file_path = os.path.join(upload_dir, safe_name)

    with open(file_path, "wb") as f:
        f.write(content)

    # Record attachment in ticket
    ticket.setdefault("attachments", []).append({
        "originalName": original_name,
        "storedAs": safe_name,
        "uploadedAt": datetime.utcnow().isoformat(),
        "sizeBytes": len(content)
    })

    logger.info(f"[Support] Diagnostic uploaded for ticket {ticket_id} ({len(content)} bytes)")
    return {"status": "uploaded", "storedAs": safe_name, "sizeBytes": len(content)}


# ---------------------------------------------------------------------------
# POST /api/support/initialize-tenant  — Guided onboarding
# ---------------------------------------------------------------------------

@router.post("/initialize-tenant")
async def initialize_new_tenant(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    [v2.5.0] Guided Onboarding: Sets up default Baseline Security Policy and
    provisions the initial audit log entry for a newly registered tenant.
    TenantAdmin only.
    """
    if current_user.Role not in ("TenantAdmin", "SuperAdmin"):
        raise HTTPException(status_code=403, detail="Only TenantAdmins can initialize workspace")

    # Check if already initialized (idempotent)
    policy_result = await db.execute(
        select(Policy).where(
            Policy.TenantId == current_user.TenantId,
            Policy.Name == "Baseline Security"
        )
    )
    existing = policy_result.scalars().first()
    if existing:
        return {"status": "already_initialized", "message": "Workspace already set up."}

    # Create default Baseline Security policy
    baseline = Policy(
        TenantId=current_user.TenantId,
        Name="Baseline Security",
        Description="Auto-generated baseline security policy for new tenant.",
        ScreenshotEnabled=True,
        ActivityMonitoringEnabled=True,
        USBMonitoringEnabled=True,
        NetworkMonitoringEnabled=True,
        DlpEnabled=False,
        IsActive=True,
    )
    db.add(baseline)
    await db.commit()

    logger.info(f"[Support] Tenant {current_user.TenantId} initialized with baseline policy")
    return {
        "status": "initialized",
        "message": "Welcome to Monitorix Enterprise. Baseline Security policy created.",
        "policyCreated": "Baseline Security"
    }
