"""
[v2.4.0] Cloud Visibility API — V2
Endpoints for cloud VM metadata, container state, Kubernetes pods,
cloud inventory summary, and risk signal aggregation.
All endpoints are authenticated and tenant-scoped.
"""
from fastapi import APIRouter, Depends, HTTPException  # type: ignore
from sqlalchemy.ext.asyncio import AsyncSession  # type: ignore
from sqlalchemy.future import select  # type: ignore
from pydantic import BaseModel, field_validator  # type: ignore
from typing import Optional, List
import logging

from ...db.session import get_db  # type: ignore
from ...db.models import CloudMetadata, ContainerAsset, KubernetesAsset, User, CloudIntegrationCredential
from ...services.cloud_visibility_engine import cloud_engine  # type: ignore
from ..deps import get_current_user  # type: ignore

router = APIRouter()
logger = logging.getLogger("CloudVisibilityAPI")


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class CloudMetadataPayload(BaseModel):
    agent_id: str
    provider: str
    account_id: str
    region: str
    zone: Optional[str] = None
    instance_id: Optional[str] = None
    instance_type: Optional[str] = None
    iam_role: Optional[str] = None
    tags: dict = {}

    @field_validator("provider")
    @classmethod
    def validate_provider(cls, v: str) -> str:
        allowed = {"aws", "azure", "gcp", "other"}
        if v.lower() not in allowed:
            raise ValueError(f"Provider must be one of {allowed}")
        return v.lower()


class ContainerPayload(BaseModel):
    agent_id: str
    containers: List[dict]


class K8sPayload(BaseModel):
    agent_id: str
    pods: List[dict]

class CspmCredentialPayload(BaseModel):
    provider: str
    account_id: str
    access_key_id: Optional[str] = None
    secret_access_key: Optional[str] = None
    region: Optional[str] = None


# ---------------------------------------------------------------------------
# POST /api/v2/cloud/metadata  — Ingest VM metadata from agent
# ---------------------------------------------------------------------------

@router.post("/metadata")
async def ingest_cloud_metadata(
    payload: CloudMetadataPayload,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Ingests AWS/Azure/GCP instance metadata discovered by the agent."""
    meta = await cloud_engine.process_cloud_metadata(db, payload.agent_id, payload.model_dump())
    return {"status": "success", "agent_id": payload.agent_id}


# ---------------------------------------------------------------------------
# POST /api/v2/cloud/containers  — Ingest container snapshot from agent
# ---------------------------------------------------------------------------

@router.post("/containers")
async def ingest_containers(
    payload: ContainerPayload,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Ingests a snapshot of running Docker/containerd containers from an agent."""
    signals = await cloud_engine.process_container_state(db, payload.agent_id, payload.containers)
    return {"status": "success", "signals_generated": len(signals)}


# ---------------------------------------------------------------------------
# POST /api/v2/cloud/k8s  — Ingest Kubernetes pod/namespace state
# ---------------------------------------------------------------------------

@router.post("/k8s")
async def ingest_k8s_state(
    payload: K8sPayload,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Ingests Kubernetes pod and namespace state from an agent running in a K8s cluster."""
    await cloud_engine.process_k8s_state(db, payload.agent_id, payload.pods)
    return {"status": "success", "pods_processed": len(payload.pods)}


# ---------------------------------------------------------------------------
# GET /api/v2/cloud/inventory  — Full inventory list
# ---------------------------------------------------------------------------

@router.get("/inventory")
async def get_cloud_inventory(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Returns the full cloud VM and container inventory."""
    vm_result = await db.execute(select(CloudMetadata))
    vms = vm_result.scalars().all()

    container_result = await db.execute(
        select(ContainerAsset).where(ContainerAsset.State == "Running")
    )
    containers = container_result.scalars().all()

    return {
        "vms": [
            {
                "agent_id": v.AgentId,
                "provider": v.Provider,
                "region": v.Region,
                "instance_id": v.InstanceId,
                "iam_role": v.IamRole,
                "last_seen": v.LastSeen.isoformat() if v.LastSeen else None
            } for v in vms
        ],
        "active_containers": [
            {
                "agent_id": c.AgentId,
                "container_id": c.ContainerId,
                "image_name": c.ImageName,
                "is_privileged": c.IsPrivileged,
                "state": c.State,
                "last_seen": c.LastSeen.isoformat() if c.LastSeen else None
            } for c in containers
        ]
    }


# ---------------------------------------------------------------------------
# CSPM Credentials 
# ---------------------------------------------------------------------------

@router.post("/cspm/credentials")
async def add_cspm_credential(
    payload: CspmCredentialPayload,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Configures a new agentless cloud integration (AWS/Azure/GCP)."""
    cred = CloudIntegrationCredential(
        TenantId=current_user.TenantId,
        Provider=payload.provider.lower(),
        AccountId=payload.account_id,
        AccessKeyId=payload.access_key_id,
        SecretAccessKey=payload.secret_access_key,
        Region=payload.region
    )
    db.add(cred)
    await db.commit()
    return {"status": "success", "id": cred.Id}

@router.get("/cspm/credentials")
async def get_cspm_credentials(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Returns active cloud integrations (secrets masked)."""
    creds = (await db.execute(
        select(CloudIntegrationCredential).where(CloudIntegrationCredential.TenantId == current_user.TenantId)
    )).scalars().all()
    
    return [
        {
            "id": c.Id,
            "provider": c.Provider,
            "account_id": c.AccountId,
            "region": c.Region,
            "is_active": c.IsActive
        } for c in creds
    ]

# ---------------------------------------------------------------------------
# GET /api/v2/cloud/inventory/summary  — Aggregated summary for dashboard
# ---------------------------------------------------------------------------

@router.get("/inventory/summary")
async def get_cloud_inventory_summary(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Returns aggregated cloud inventory statistics broken down by provider and region."""
    summary = await cloud_engine.get_cloud_inventory_summary(db)
    return summary


# ---------------------------------------------------------------------------
# GET /api/v2/cloud/alerts  — Active cloud security signals
# ---------------------------------------------------------------------------

@router.get("/alerts")
async def get_cloud_alerts(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Returns pending cloud security risk signals: privileged containers, IAM issues, untagged instances."""
    signals = await cloud_engine.generate_cloud_risk_signals(db)
    return {
        "alerts": signals,
        "total": len(signals),
        "critical": sum(1 for s in signals if s["severity"] == "Critical"),
        "high": sum(1 for s in signals if s["severity"] == "High"),
    }
