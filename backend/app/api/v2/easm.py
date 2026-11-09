"""
[v18.3.0] Monitorix EASM API Router (External Attack Surface Management)
========================================================================
API Endpoints:
- GET  /api/v2/easm/overview      - Perimeter health score, asset counts, exposed ports summary
- GET  /api/v2/easm/assets        - Discovered external assets (domains, subdomains, public IPs)
- GET  /api/v2/easm/ports         - Listening network ports & service banners
- GET  /api/v2/easm/certificates  - SSL/TLS certificate inventory, expiry, and grades
- GET  /api/v2/easm/findings      - Perimeter exposure findings (subdomain takeover, open RDP)
- POST /api/v2/easm/discover      - Automated perimeter asset discovery scan
- POST /api/v2/easm/remediate     - 1-click automated remediation for exposure findings
- POST /api/v2/easm/evaluate      - Real-time exposure evaluation for external telemetry
"""

from fastapi import APIRouter, Depends, HTTPException, Query, Body, status
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any

from app.db.session import get_db
from app.services.easm_service import MonitorixEasmService

router = APIRouter()

# ---------------------------------------------------------------------------
# Request Models
# ---------------------------------------------------------------------------

class TriggerDiscoveryRequest(BaseModel):
    root_domain: Optional[str] = Field(default="monitorix.co.in", example="monitorix.co.in")

class CreateEasmAssetRequest(BaseModel):
    value: str = Field(..., example="elsea.co.in")
    asset_type: str = Field(default="DOMAIN", example="DOMAIN") # DOMAIN, SUBDOMAIN, IP_ADDRESS, CLOUD_EDGE
    root_domain: Optional[str] = Field(default=None, example="elsea.co.in")
    protection_scope: Optional[str] = Field(default="AUTO", example="FULL_DOMAIN") # AUTO, FULL_DOMAIN, PARTICULAR_SUBDOMAIN
    hosting_provider: Optional[str] = Field(default="CLOUDFLARE", example="CLOUDFLARE")
    ip_address: Optional[str] = Field(default=None, example="104.21.48.11")
    risk_score: Optional[float] = Field(default=15.0, example=15.0)

class RemediateEasmFindingRequest(BaseModel):
    finding_id: str = Field(..., example="EASM-FIND-001")
    action: str = Field(default="AUTO_REMEDIATE", example="AUTO_REMEDIATE")

class EvaluateExposureRequest(BaseModel):
    domain: Optional[str] = Field(default="test-sub.monitorix.co.in", example="test-sub.monitorix.co.in")
    cname: Optional[str] = Field(default=None, example="subdomain.s3-website-us-east-1.amazonaws.com")
    port: Optional[int] = Field(default=None, example=3389)
    service: Optional[str] = Field(default=None, example="RDP")

# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("/overview")
async def get_easm_overview(db: AsyncSession = Depends(get_db)):
    """Retrieve perimeter health score, shadow asset counts, and exposed port summaries."""
    return await MonitorixEasmService.get_overview(db)

@router.get("/assets")
async def get_easm_assets(
    asset_type: Optional[str] = Query(None, description="DOMAIN, SUBDOMAIN, IP_ADDRESS, CLOUD_EDGE"),
    is_shadow: Optional[bool] = Query(None, description="Filter shadow or unmonitored assets"),
    min_risk: Optional[float] = Query(None, description="Minimum risk score filter"),
    search: Optional[str] = Query(None, description="Search domain, subdomain, or IP"),
    db: AsyncSession = Depends(get_db)
):
    """List discovered external attack surface assets."""
    return await MonitorixEasmService.get_assets(
        db,
        asset_type=asset_type,
        is_shadow=is_shadow,
        min_risk=min_risk,
        search=search
    )

@router.get("/ports")
async def get_easm_ports(
    is_exposed_only: Optional[bool] = Query(None, description="Filter dangerous/exposed ports only"),
    asset_id: Optional[str] = Query(None, description="Filter by asset ID"),
    db: AsyncSession = Depends(get_db)
):
    """List open perimeter network ports and banner intelligence."""
    return await MonitorixEasmService.get_ports(
        db,
        is_exposed_only=is_exposed_only,
        asset_id=asset_id
    )

@router.get("/certificates")
async def get_easm_certificates(
    is_expiring_soon: Optional[bool] = Query(None, description="Filter certificates expiring in <=30 days"),
    tls_grade: Optional[str] = Query(None, description="Filter by SSL Labs grade (A+, A, B, F)"),
    db: AsyncSession = Depends(get_db)
):
    """List monitored SSL/TLS certificates and cryptographic grades."""
    return await MonitorixEasmService.get_certificates(
        db,
        is_expiring_soon=is_expiring_soon,
        tls_grade=tls_grade
    )

@router.get("/findings")
async def get_easm_findings(
    severity: Optional[str] = Query(None, description="CRITICAL, HIGH, MEDIUM, LOW"),
    status_filter: Optional[str] = Query(None, description="OPEN, REMEDIATED, SUPPRESSED"),
    db: AsyncSession = Depends(get_db)
):
    """List perimeter exposure & vulnerability findings (subdomain takeover, open ports)."""
    return await MonitorixEasmService.get_findings(
        db,
        severity=severity,
        status_filter=status_filter
    )

@router.post("/discover")
async def trigger_easm_discovery(
    req: TriggerDiscoveryRequest = Body(default=TriggerDiscoveryRequest()),
    db: AsyncSession = Depends(get_db)
):
    """Trigger automated perimeter asset discovery scan."""
    return await MonitorixEasmService.trigger_discovery(db, req.root_domain)

@router.post("/remediate")
async def remediate_easm_finding(
    req: RemediateEasmFindingRequest,
    db: AsyncSession = Depends(get_db)
):
    """Execute 1-click remediation for an attack surface exposure finding."""
    return await MonitorixEasmService.remediate_finding(db, req.finding_id, req.action)

@router.post("/evaluate")
async def evaluate_asset_exposure(
    req: EvaluateExposureRequest,
    db: AsyncSession = Depends(get_db)
):
    """Evaluate external asset telemetry against exposure heuristics."""
    return await MonitorixEasmService.evaluate_asset_exposure(db, req.dict())

@router.post("/assets")
async def create_easm_asset(
    req: CreateEasmAssetRequest,
    db: AsyncSession = Depends(get_db)
):
    """Manually register and begin monitoring a new external domain or perimeter asset."""
    return await MonitorixEasmService.create_asset(db, req.dict())

@router.delete("/assets/{asset_id}")
async def delete_easm_asset(
    asset_id: str,
    db: AsyncSession = Depends(get_db)
):
    """Remove a perimeter asset from monitoring."""
    return await MonitorixEasmService.delete_asset(db, asset_id)

