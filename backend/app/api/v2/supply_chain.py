"""
[v18.9.0] Monitorix Software Supply-Chain Security & SBOM API (v2)
==================================================================
Exposes sovereign Supply-Chain Security and SBOM Governance endpoints:
- GET /overview: Holistic supply-chain score, SBOM component count, threat telemetry
- GET /projects: Monitored repos and CI/CD targets (PyPI, npm, Go, Cargo, Maven)
- GET /components: Software package inventory with license and vulnerability telemetry
- GET /findings: Real-time supply-chain alerts (typosquatting, dependency confusion, postinstall)
- GET /policies: CI/CD build gate policies and SLSA provenance guardrails
- POST /evaluate-manifest: CI/CD build gate sandbox scanning dependencies
- POST /quarantine-component: 1-Click active package quarantine & upstream blocking
"""

import logging
from typing import Optional, Dict, Any, List
from fastapi import APIRouter, Depends, Query, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db
from app.services.supply_chain_service import MonitorixSupplyChainService

router = APIRouter()

# ---------------------------------------------------------------------------
# Request Models
# ---------------------------------------------------------------------------

class EvaluateManifestRequest(BaseModel):
    manifest_text: str = Field(..., example="requests==2.28.1\nrequsts==2.28.1\nfastapi==0.100.0")
    ecosystem: Optional[str] = Field(default="PYPI", example="PYPI")
    project_name: Optional[str] = Field(default="target-app", example="payment-service")

class QuarantineComponentRequest(BaseModel):
    component_id: Optional[str] = Field(default=None, example="COMP-REQUESTS-TYPO")
    finding_id: Optional[str] = Field(default=None, example="SC-FIND-001")
    action: Optional[str] = Field(default="BLOCK_PACKAGE", example="BLOCK_PACKAGE")

# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("/overview")
async def get_supply_chain_overview(db: AsyncSession = Depends(get_db)):
    """Retrieve holistic Software Supply-Chain and SBOM governance overview."""
    return await MonitorixSupplyChainService.get_overview(db)

@router.get("/projects")
async def get_supply_chain_projects(
    ecosystem: Optional[str] = Query(None, description="Filter by ecosystem: PYPI, NPM, GO, CARGO, MAVEN"),
    db: AsyncSession = Depends(get_db)
):
    """List monitored software projects, SLSA provenance, and dependency counts."""
    return await MonitorixSupplyChainService.get_projects(db, ecosystem=ecosystem)

@router.get("/components")
async def get_supply_chain_components(
    is_malicious: Optional[bool] = Query(None, description="Filter malicious packages (typosquats, trojans)"),
    is_vulnerable: Optional[bool] = Query(None, description="Filter packages with known CVEs"),
    ecosystem: Optional[str] = Query(None, description="Filter by package ecosystem"),
    db: AsyncSession = Depends(get_db)
):
    """List software package inventory across all repositories and SBOMs."""
    return await MonitorixSupplyChainService.get_components(
        db,
        is_malicious=is_malicious,
        is_vulnerable=is_vulnerable,
        ecosystem=ecosystem
    )

@router.get("/findings")
async def get_supply_chain_findings(
    severity: Optional[str] = Query(None, description="Filter by CRITICAL, HIGH, MEDIUM, LOW"),
    status: Optional[str] = Query(None, description="Filter by OPEN, QUARANTINED, RESOLVED"),
    db: AsyncSession = Depends(get_db)
):
    """List active and historical supply-chain security alerts and gate violations."""
    return await MonitorixSupplyChainService.get_findings(
        db,
        severity=severity,
        status=status
    )

@router.get("/policies")
async def get_supply_chain_policies(db: AsyncSession = Depends(get_db)):
    """List active CI/CD build gate policies and artifact verification rules."""
    return await MonitorixSupplyChainService.get_policies(db)

@router.post("/evaluate-manifest")
async def evaluate_supply_chain_manifest(
    req: EvaluateManifestRequest,
    db: AsyncSession = Depends(get_db)
):
    """CI/CD build gate sandbox scanning manifests for typosquats, malware, and CVEs."""
    return await MonitorixSupplyChainService.evaluate_manifest(
        db,
        manifest_text=req.manifest_text,
        ecosystem=req.ecosystem or "PYPI",
        project_name=req.project_name or "target-app"
    )

@router.post("/quarantine-component")
async def quarantine_supply_chain_component(
    req: QuarantineComponentRequest,
    db: AsyncSession = Depends(get_db)
):
    """1-Click active response to quarantine a malicious package or dependency."""
    if not req.component_id and not req.finding_id:
        raise HTTPException(status_code=400, detail="Must provide either component_id or finding_id")
    return await MonitorixSupplyChainService.quarantine_component(
        db,
        component_id=req.component_id,
        finding_id=req.finding_id,
        action=req.action or "BLOCK_PACKAGE"
    )
