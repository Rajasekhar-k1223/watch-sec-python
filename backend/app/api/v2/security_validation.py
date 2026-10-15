"""
[v3.0.0] Feature 59: Monitorix Security Validation & Penetration Testing API
Endpoints for running platform self-penetration testing, OWASP API Top 10 auditing,
and fetching platform security posture certifications.
"""

from fastapi import APIRouter, Depends, HTTPException
from typing import Dict, Any

from app.db.models import User
from app.api.deps import get_current_user
from app.services.security_validation_suite import security_suite

router = APIRouter()

@router.post("/run")
async def run_security_validation_audit(
    current_user: User = Depends(get_current_user)
):
    """
    Executes live penetration testing audit across BOLA, SQLi, JWT tampering,
    signature verification, rate limiting, and RBAC privilege separation.
    """
    report = await security_suite.run_platform_security_audit()
    return report

@router.get("/report")
async def get_latest_security_report(
    current_user: User = Depends(get_current_user)
):
    """
    Retrieves the latest platform security validation and penetration audit report.
    """
    return security_suite.get_latest_report()
