"""
[v18.3.0] Monitorix CNAPP API Router (Cloud Security & Posture Management)
==========================================================================
API Endpoints:
- GET  /api/v2/cnapp/overview           - Multi-cloud posture score, asset tallies, benchmark summary
- GET  /api/v2/cnapp/accounts           - AWS, Azure, GCP accounts with compliance ratings
- GET  /api/v2/cnapp/resources          - Discovered cloud workloads, storage buckets, IAM roles
- GET  /api/v2/cnapp/misconfigurations  - CSPM findings against CIS / SOC2 / PCI-DSS
- GET  /api/v2/cnapp/threats            - Cloud Detection & Response (CDR) active threats
- GET  /api/v2/cnapp/paths              - Multi-cloud attack paths from internet to crown jewels
- POST /api/v2/cnapp/evaluate           - Real-time cloud event ingestion & threat evaluation
- POST /api/v2/cnapp/remediate          - 1-click automated remediation for CSPM findings
- POST /api/v2/cnapp/scan               - On-demand CIS benchmark posture scan
"""

from fastapi import APIRouter, Depends, HTTPException, Query, Body, status
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any

from app.db.session import get_db
from app.services.cnapp_service import MonitorixCnappService

router = APIRouter()

# ---------------------------------------------------------------------------
# Request Models
# ---------------------------------------------------------------------------

class EvaluateCloudEventRequest(BaseModel):
    event_name: str = Field(..., example="PutBucketAcl", description="PutBucketAcl, StopLogging, CreateAccessKey, RunInstances")
    provider: Optional[str] = Field(default="AWS", example="AWS")
    account_id: Optional[str] = Field(default="aws-112233445566", example="aws-112233445566")
    principal_arn: Optional[str] = Field(default="arn:aws:iam::112233445566:user/devops", example="arn:aws:iam::112233445566:user/devops")
    source_ip: Optional[str] = Field(default="198.51.100.44", example="198.51.100.44")
    resource_name: Optional[str] = Field(default="corp-customer-backups-2026", example="corp-customer-backups-2026")
    grant: Optional[str] = Field(default=None, example="http://acs.amazonaws.com/groups/global/AllUsers")
    instance_type: Optional[str] = Field(default=None, example="p3.16xlarge")

class RemediateFindingRequest(BaseModel):
    finding_id: str = Field(..., example="CSPM-FIND-AWS-001")
    action: str = Field(default="ENABLE_BLOCK_PUBLIC_ACCESS", example="ENABLE_BLOCK_PUBLIC_ACCESS")

class TriggerScanRequest(BaseModel):
    account_id: Optional[str] = Field(default=None, example="aws-112233445566")

# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("/overview")
async def get_cnapp_overview(db: AsyncSession = Depends(get_db)):
    """Retrieve high-level cloud security posture score, exposed assets, and finding counts."""
    return await MonitorixCnappService.get_overview(db)

@router.get("/accounts")
async def get_cloud_accounts(
    provider: Optional[str] = Query(None, description="AWS, AZURE, GCP"),
    db: AsyncSession = Depends(get_db)
):
    """List connected multi-cloud accounts and compliance scores."""
    return await MonitorixCnappService.get_accounts(db, provider=provider)

@router.get("/resources")
async def get_cloud_resources(
    provider: Optional[str] = Query(None, description="AWS, AZURE, GCP"),
    resource_type: Optional[str] = Query(None, description="S3_BUCKET, EC2_INSTANCE, K8S_CLUSTER, IAM_ROLE, AZURE_BLOB, GCS_BUCKET"),
    is_exposed: Optional[bool] = Query(None, description="Filter publicly exposed resources"),
    db: AsyncSession = Depends(get_db)
):
    """List discovered multi-cloud assets across storage, compute, and IAM."""
    return await MonitorixCnappService.get_resources(
        db,
        provider=provider,
        resource_type=resource_type,
        is_exposed=is_exposed
    )

@router.get("/misconfigurations")
async def get_misconfigurations(
    provider: Optional[str] = Query(None, description="AWS, AZURE, GCP"),
    severity: Optional[str] = Query(None, description="CRITICAL, HIGH, MEDIUM, LOW"),
    status_filter: Optional[str] = Query(None, description="OPEN, REMEDIATED, SUPPRESSED"),
    db: AsyncSession = Depends(get_db)
):
    """List CSPM compliance audit findings against CIS benchmarks."""
    return await MonitorixCnappService.get_misconfigurations(
        db,
        provider=provider,
        severity=severity,
        status_filter=status_filter
    )

@router.get("/threats")
async def get_cloud_threats(
    provider: Optional[str] = Query(None, description="AWS, AZURE, GCP"),
    status_filter: Optional[str] = Query(None, description="ACTIVE, INVESTIGATING, CONTAINED"),
    db: AsyncSession = Depends(get_db)
):
    """List active Cloud Detection & Response (CDR) threat detections."""
    return await MonitorixCnappService.get_threats(
        db,
        provider=provider,
        status_filter=status_filter
    )

@router.get("/paths")
async def get_cloud_attack_paths(db: AsyncSession = Depends(get_db)):
    """Retrieve multi-cloud attack paths from internet exposure to crown jewels."""
    return await MonitorixCnappService.get_attack_paths(db)

@router.post("/evaluate")
async def evaluate_cloud_event(
    req: EvaluateCloudEventRequest,
    db: AsyncSession = Depends(get_db)
):
    """Evaluate streaming CloudTrail / Activity Log / Cloud Audit telemetry."""
    return await MonitorixCnappService.evaluate_cloud_event(db, req.dict())

@router.post("/remediate")
async def remediate_misconfiguration(
    req: RemediateFindingRequest,
    db: AsyncSession = Depends(get_db)
):
    """Execute 1-click automated remediation for a cloud misconfiguration."""
    return await MonitorixCnappService.remediate_misconfiguration(db, req.finding_id, req.action)

@router.post("/scan")
async def trigger_cspm_scan(
    req: TriggerScanRequest = Body(default=TriggerScanRequest()),
    db: AsyncSession = Depends(get_db)
):
    """Trigger an on-demand CIS benchmark posture scan across cloud accounts."""
    return await MonitorixCnappService.trigger_scan(db, req.account_id)
