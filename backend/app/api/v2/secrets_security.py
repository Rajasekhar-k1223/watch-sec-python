"""
[v18.6.0] Monitorix Secrets Security API Router
================================================
Provides RESTful endpoints for:
- GET  /api/v2/secrets/overview      - Secrets posture score, counts, breakdown
- GET  /api/v2/secrets/incidents     - Detected exposed secrets with severity/status
- GET  /api/v2/secrets/targets       - Scanned repos, hosts, containers, CI/CD
- GET  /api/v2/secrets/vaults        - Vault integrations & sync telemetry
- POST /api/v2/secrets/scan          - Real-time code/file secret inspection
- POST /api/v2/secrets/remediate     - 1-Click revocation & vault rotation
- POST /api/v2/secrets/targets/scan  - On-demand target discovery scan
"""

from typing import Optional, List, Dict, Any
from fastapi import APIRouter, Depends, Query, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db
from app.services.secrets_security_service import MonitorixSecretsSecurityService

router = APIRouter()

# ---------------------------------------------------------------------------
# Request Models
# ---------------------------------------------------------------------------

class ScanContentRequest(BaseModel):
    content: str = Field(..., example="export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nstripe_key = 'sk_live_123456789012345678901234'")
    filename: Optional[str] = Field(default="source_code.py", example="server.py")

class RemediateIncidentRequest(BaseModel):
    incident_id: str = Field(..., example="SEC-INC-001")
    action: Optional[str] = Field(default="REVOKE_AND_ROTATE", example="REVOKE_AND_ROTATE")

class ScanTargetRequest(BaseModel):
    target_id: str = Field(..., example="TGT-REPO-PAYMENT-SVC")

# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("/overview")
async def get_secrets_overview(db: AsyncSession = Depends(get_db)):
    """Retrieve holistic Secrets Security posture and risk telemetry."""
    return await MonitorixSecretsSecurityService.get_overview(db)

@router.get("/incidents")
async def get_secrets_incidents(
    severity: Optional[str] = Query(None, description="Filter by CRITICAL, HIGH, MEDIUM"),
    status: Optional[str] = Query(None, description="Filter by OPEN, REVOKED, ROTATED"),
    secret_type: Optional[str] = Query(None, description="Filter by AWS_ACCESS_KEY, STRIPE_SECRET_KEY, etc."),
    db: AsyncSession = Depends(get_db)
):
    """List exposed secret incidents with line-level telemetry."""
    return await MonitorixSecretsSecurityService.get_incidents(
        db,
        severity=severity,
        status=status,
        secret_type=secret_type
    )

@router.get("/targets")
async def get_secrets_targets(
    target_type: Optional[str] = Query(None, description="Filter by GIT_REPO, HOST_FILESYSTEM, DOCKER_IMAGE, CI_CD_PIPELINE"),
    db: AsyncSession = Depends(get_db)
):
    """List scanned repositories, hosts, and pipeline targets."""
    return await MonitorixSecretsSecurityService.get_targets(db, target_type=target_type)

@router.get("/vaults")
async def get_secrets_vaults(db: AsyncSession = Depends(get_db)):
    """List enterprise vault integrations and secret synchronization status."""
    return await MonitorixSecretsSecurityService.get_vaults(db)

@router.post("/scan")
async def scan_content(req: ScanContentRequest):
    """Real-time regex and Shannon entropy secret scanner for code samples."""
    return MonitorixSecretsSecurityService.scan_content_sample(req.content, req.filename)

@router.post("/remediate")
async def remediate_secret_incident(
    req: RemediateIncidentRequest,
    db: AsyncSession = Depends(get_db)
):
    """1-Click automated revocation or vault rotation of an exposed secret."""
    return await MonitorixSecretsSecurityService.remediate_incident(
        db,
        incident_id=req.incident_id,
        action=req.action
    )

@router.post("/targets/scan")
async def trigger_target_scan(
    req: ScanTargetRequest,
    db: AsyncSession = Depends(get_db)
):
    """Trigger on-demand discovery scan on a target repository or host."""
    return await MonitorixSecretsSecurityService.trigger_target_scan(db, req.target_id)
