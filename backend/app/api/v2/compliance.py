"""
[v2.6.0] Executive Compliance API — V2
Endpoints for automated regulatory checks and executive narratives.
"""
from fastapi import APIRouter, Depends, HTTPException # type: ignore
from sqlalchemy.ext.asyncio import AsyncSession # type: ignore
import logging

from ...db.session import get_db # type: ignore
from ...db.models import User # type: ignore
from ...services.compliance_service import compliance_engine # type: ignore
from ..deps import get_current_user # type: ignore

router = APIRouter()
logger = logging.getLogger("ComplianceAPI")

# ---------------------------------------------------------------------------
# GET /api/v2/compliance/run
# Executes all automated compliance checks
# ---------------------------------------------------------------------------
@router.get("/run")
async def run_compliance_checks(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Executes automated checks for GDPR, HIPAA, and SOC2 against the tenant's current posture.
    Returns the full detailed findings.
    """
    if current_user.Role not in ("TenantAdmin", "SuperAdmin", "Analyst"):
        raise HTTPException(status_code=403, detail="Insufficient permissions")
        
    results = await compliance_engine.run_all_checks(current_user.TenantId, db)
    return results

# ---------------------------------------------------------------------------
# GET /api/v2/compliance/summary
# Returns the overall compliance score and summary
# ---------------------------------------------------------------------------
@router.get("/summary")
async def get_compliance_summary(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Returns the aggregated compliance score (0-100) and high-level counts.
    """
    results = await compliance_engine.run_all_checks(current_user.TenantId, db)
    
    return {
        "overall_score": results["overall_score"],
        "total_checks": results["total_checks"],
        "passed": results["passed"],
        "warnings": results["warnings"],
        "failures": results["failures"]
    }

# ---------------------------------------------------------------------------
# GET /api/v2/compliance/executive-report
# Returns the synthesized executive narrative
# ---------------------------------------------------------------------------
@router.get("/executive-report")
async def get_executive_report(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Generates a human-readable narrative report for executive and regulatory review.
    """
    report = await compliance_engine.generate_executive_summary(current_user.TenantId, db)
    return report
