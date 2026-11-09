"""
[v18.5.0] Monitorix DSPM API Router (Data Security Posture Management)
======================================================================
Provides RESTful endpoints for:
- GET  /api/v2/dspm/overview       - Data security posture score, volume, sensitive counts
- GET  /api/v2/dspm/datastores     - Data stores inventory with cloud and shadow filters
- GET  /api/v2/dspm/assets         - Files and tables catalog with sensitive types
- GET  /api/v2/dspm/findings       - Sensitive data exposure findings (PCI, PII, PHI)
- GET  /api/v2/dspm/compliance     - GDPR, HIPAA, PCI-DSS compliance frameworks
- POST /api/v2/dspm/classify       - Real-time payload content classification
- POST /api/v2/dspm/remediate      - 1-Click automated exposure remediation
- POST /api/v2/dspm/scan           - On-demand discovery scan on target datastore
"""

from typing import Optional, List, Dict, Any
from fastapi import APIRouter, Depends, Query, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db
from app.services.dspm_service import MonitorixDspmService

router = APIRouter()

# ---------------------------------------------------------------------------
# Request Models
# ---------------------------------------------------------------------------

class ClassifyTextRequest(BaseModel):
    text_sample: str = Field(..., example="Customer SSN: 123-45-6789 and Visa card 4532015012348912")

class RemediateFindingRequest(BaseModel):
    finding_id: str = Field(..., example="DSPM-FIND-001")
    action_taken: Optional[str] = Field(default="REVOKE_PUBLIC_ACCESS", example="REVOKE_PUBLIC_ACCESS")

class TriggerScanRequest(BaseModel):
    store_id: str = Field(..., example="STORE-AZURE-BLOB-ANALYTICS")

# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("/overview")
async def get_dspm_overview(db: AsyncSession = Depends(get_db)):
    """Retrieve holistic Data Security Posture Overview and KPI scores."""
    return await MonitorixDspmService.get_overview(db)

@router.get("/datastores")
async def get_dspm_datastores(
    cloud_provider: Optional[str] = Query(None, description="Filter by cloud provider (AWS, AZURE, GCP, ON_PREMISE)"),
    is_shadow_only: Optional[bool] = Query(None, description="Filter unmanaged shadow datastores"),
    is_public_only: Optional[bool] = Query(None, description="Filter publicly exposed datastores"),
    db: AsyncSession = Depends(get_db)
):
    """List managed and shadow data stores across hybrid clouds."""
    return await MonitorixDspmService.get_datastores(
        db,
        cloud_provider=cloud_provider,
        is_shadow_only=is_shadow_only,
        is_public_only=is_public_only
    )

@router.get("/assets")
async def get_dspm_assets(
    store_id: Optional[str] = Query(None, description="Filter by parent store ID"),
    is_shadow_only: Optional[bool] = Query(None, description="Filter shadow data files"),
    db: AsyncSession = Depends(get_db)
):
    """List data assets (tables, blobs, files) containing sensitive data."""
    return await MonitorixDspmService.get_data_assets(
        db,
        store_id=store_id,
        is_shadow_only=is_shadow_only
    )

@router.get("/findings")
async def get_dspm_findings(
    severity: Optional[str] = Query(None, description="Filter by CRITICAL, HIGH, MEDIUM, LOW"),
    category: Optional[str] = Query(None, description="Filter by PCI_DSS, PII_PERSONAL, PHI_HEALTH, CREDENTIALS_KEYS"),
    status: Optional[str] = Query(None, description="Filter by OPEN, REMEDIATED"),
    db: AsyncSession = Depends(get_db)
):
    """List sensitive data exposure and posture violation findings."""
    return await MonitorixDspmService.get_findings(
        db,
        severity=severity,
        category=category,
        status=status
    )

@router.get("/compliance")
async def get_dspm_compliance(db: AsyncSession = Depends(get_db)):
    """Retrieve GDPR, HIPAA, PCI-DSS compliance frameworks ledger."""
    return await MonitorixDspmService.get_compliance_posture(db)

@router.post("/classify")
async def classify_text_sample(req: ClassifyTextRequest):
    """Real-time content scanner for text samples (PII, PCI, PHI, Secrets)."""
    return MonitorixDspmService.classify_text_payload(req.text_sample)

@router.post("/remediate")
async def remediate_dspm_finding(
    req: RemediateFindingRequest,
    db: AsyncSession = Depends(get_db)
):
    """1-Click automated remediation of sensitive data exposure finding."""
    return await MonitorixDspmService.remediate_finding(
        db,
        finding_id=req.finding_id,
        action_taken=req.action_taken
    )

@router.post("/scan")
async def trigger_datastore_scan(
    req: TriggerScanRequest,
    db: AsyncSession = Depends(get_db)
):
    """Trigger on-demand discovery scan on a target data store."""
    return await MonitorixDspmService.run_discovery_scan(db, req.store_id)
