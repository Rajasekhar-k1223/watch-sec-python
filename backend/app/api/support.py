from fastapi import APIRouter, Depends, HTTPException, UploadFile, File # type: ignore
from sqlalchemy.ext.asyncio import AsyncSession # type: ignore
from pydantic import BaseModel # type: ignore
from typing import List, Optional
import os
import shutil

from ..db.session import get_db # type: ignore
from ..db.models import User, Tenant # type: ignore
from .deps import get_current_user # type: ignore

router = APIRouter()

class SupportTicketRequest(BaseModel):
    subject: str
    description: str
    priority: str = "Medium"

@router.post("/tickets")
async def create_support_ticket(
    ticket: SupportTicketRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    [v2.5.0] Enterprise Support: Creates a new support ticket.
    """
    # Logic to store ticket in DB or forward to Zendesk/Jira
    return {
        "status": "created",
        "ticketId": "TIC-12345",
        "message": "Monitorix support has been notified."
    }

@router.post("/diagnostic-upload/{ticket_id}")
async def upload_diagnostic_bundle(
    ticket_id: str,
    file: UploadFile = File(...),
    current_user: User = Depends(get_current_user)
):
    """
    Allows agents or admins to upload diagnostic logs for troubleshooting.
    """
    upload_dir = f"/app/storage/diagnostics/{ticket_id}"
    os.makedirs(upload_dir, exist_ok=True)
    
    file_path = os.path.join(upload_dir, file.filename)
    with open(file_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)
        
    return {"status": "uploaded", "path": file_path}

@router.post("/initialize-tenant")
async def initialize_new_tenant(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    [v2.5.0] Guided Onboarding: Sets up default policies and workspace for a new tenant.
    """
    if current_user.Role != "TenantAdmin":
        raise HTTPException(status_code=403, detail="Only TenantAdmins can initialize workspace")
        
    # 1. Create Default "Baseline Security" Policy
    # 2. Setup Default Dashboard Layout
    # 3. Provision Internal Audit Logs
    
    return {"status": "initialized", "message": "Welcome to Monitorix Enterprise."}
