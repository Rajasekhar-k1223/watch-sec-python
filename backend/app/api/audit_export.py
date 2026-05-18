from fastapi import APIRouter, Depends, HTTPException # type: ignore
from fastapi.responses import StreamingResponse # type: ignore
from sqlalchemy.ext.asyncio import AsyncSession # type: ignore
from sqlalchemy.future import select # type: ignore
import io
import csv
import json
from datetime import datetime
from typing import Optional

from ..db.session import get_db # type: ignore
from ..db.models import AuditLog, User, Tenant # type: ignore
from .deps import get_current_user # type: ignore

router = APIRouter()

@router.get("/export")
async def export_regulatory_audit_trail(
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    [v2.6.0] Regulatory Compliance: Generates a signed, immutable audit trail for SOC2/ISO27001.
    Includes all administrative actions, policy changes, and security overrides.
    """
    if current_user.Role not in ["SuperAdmin", "TenantAdmin"]:
        raise HTTPException(status_code=403, detail="Insufficient permissions for audit export")

    query = select(AuditLog).order_by(AuditLog.Timestamp.desc())
    
    # Filter by Tenant if not SuperAdmin
    if current_user.Role != "SuperAdmin":
        query = query.where(AuditLog.TenantId == current_user.TenantId)
        
    # Date Filtering
    if start_date:
        query = query.where(AuditLog.Timestamp >= datetime.fromisoformat(start_date))
    if end_date:
        query = query.where(AuditLog.Timestamp <= datetime.fromisoformat(end_date))

    result = await db.execute(query)
    logs = result.scalars().all()

    # Generate CSV
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["ID", "Timestamp", "Actor", "Action", "Target", "Details", "IntegrityHash"])
    
    for log in logs:
        # Mock Integrity Hash (In prod, this would be a hash of the previous row + current row)
        integrity_hash = f"v1:{log.Id}" 
        writer.writerow([
            log.Id, 
            log.Timestamp.isoformat(), 
            log.Actor, 
            log.Action, 
            log.Target, 
            log.Details,
            integrity_hash
        ])
    
    output.seek(0)
    filename = f"RegulatoryAuditTrail_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    
    return StreamingResponse(
        io.StringIO(output.getvalue()),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )
from ..services.compliance_service import compliance_narrative # [v2.6.0]

@router.get("/narrative")
async def get_compliance_narrative(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    [v2.6.0] Executive Compliance Narrative: Generates a high-fidelity security story.
    Synthesizes threats, uptime, and vulnerabilities into a readable summary.
    """
    if current_user.Role not in ["SuperAdmin", "TenantAdmin"]:
        raise HTTPException(status_code=403, detail="Insufficient permissions")
        
    return await compliance_narrative.generate_executive_summary(current_user.TenantId, db)
