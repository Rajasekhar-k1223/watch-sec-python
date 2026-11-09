"""
[v18.8.0] Monitorix Kubernetes & Container Workload Security API (v2)
====================================================================
Exposes sovereign KSPM and CWPP endpoints:
- GET /overview: Cluster stats, KSPM score, pod inventory, threat telemetry
- GET /clusters: Multi-cloud K8s cluster catalog (EKS, GKE, AKS, Self-Hosted)
- GET /workloads: Container workloads, privileged flags, risk metrics
- GET /findings: Real-time security alerts & posture misconfigurations
- GET /policies: PSS & RBAC admission guardrail definitions
- POST /evaluate-manifest: Admission control sandbox evaluating Pod specs
- POST /inspect-runtime: CWPP runtime detection (breakout, reverse shell, etc.)
- POST /quarantine-pod: 1-Click active pod isolation via NetworkPolicy
"""

import logging
from typing import Optional, Dict, Any, List
from fastapi import APIRouter, Depends, Query, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db
from app.services.k8s_security_service import MonitorixK8sSecurityService

router = APIRouter()

# ---------------------------------------------------------------------------
# Request Models
# ---------------------------------------------------------------------------

class EvaluateManifestRequest(BaseModel):
    manifest_text: str = Field(..., example="apiVersion: v1\nkind: Pod\nspec:\n  containers:\n  - name: app\n    securityContext:\n      privileged: true")
    namespace: Optional[str] = Field(default="default", example="production")

class InspectRuntimeRequest(BaseModel):
    cluster_id: str = Field(default="K8S-EKS-PROD-PRIMARY", example="K8S-EKS-PROD-PRIMARY")
    pod_name: str = Field(..., example="payment-gateway-7b94cf9b-xk29s")
    namespace: str = Field(default="prod", example="prod")
    event_type: str = Field(default="PROCESS_EXEC", example="PROCESS_EXEC")
    process_path: str = Field(default="/bin/bash", example="/usr/bin/nsenter")
    command_line: str = Field(..., example="nsenter --mount=/proc/1/ns/mnt sh")

class QuarantinePodRequest(BaseModel):
    finding_id: Optional[str] = Field(default=None, example="K8S-FIND-001")
    workload_id: Optional[str] = Field(default=None, example="WKLD-ROGUED-JOB")
    action: Optional[str] = Field(default="ISOLATE_NETWORK", example="ISOLATE_NETWORK")

# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("/overview")
async def get_k8s_security_overview(db: AsyncSession = Depends(get_db)):
    """Retrieve holistic Kubernetes & Container Security posture overview."""
    return await MonitorixK8sSecurityService.get_overview(db)

@router.get("/clusters")
async def get_k8s_clusters(
    provider: Optional[str] = Query(None, description="Filter by cloud provider: EKS, GKE, AKS, SELF_HOSTED"),
    db: AsyncSession = Depends(get_db)
):
    """List monitored Kubernetes clusters with CIS benchmark postures."""
    return await MonitorixK8sSecurityService.get_clusters(db, provider=provider)

@router.get("/workloads")
async def get_k8s_workloads(
    namespace: Optional[str] = Query(None, description="Filter by namespace: prod, default, monitoring"),
    is_privileged: Optional[bool] = Query(None, description="Filter privileged pods"),
    db: AsyncSession = Depends(get_db)
):
    """List container workloads, pod specifications, and security context telemetry."""
    return await MonitorixK8sSecurityService.get_workloads(
        db,
        namespace=namespace,
        is_privileged=is_privileged
    )

@router.get("/findings")
async def get_k8s_findings(
    severity: Optional[str] = Query(None, description="Filter by CRITICAL, HIGH, MEDIUM, LOW"),
    status: Optional[str] = Query(None, description="Filter by OPEN, QUARANTINED, RESOLVED"),
    db: AsyncSession = Depends(get_db)
):
    """List active and historical Kubernetes security findings and runtime threats."""
    return await MonitorixK8sSecurityService.get_findings(
        db,
        severity=severity,
        status=status
    )

@router.get("/policies")
async def get_k8s_policies(db: AsyncSession = Depends(get_db)):
    """List Pod Security Standards and admission control guardrails."""
    return await MonitorixK8sSecurityService.get_policies(db)

@router.post("/evaluate-manifest")
async def evaluate_k8s_manifest(
    req: EvaluateManifestRequest,
    db: AsyncSession = Depends(get_db)
):
    """Admission control sandbox testing YAML/JSON manifests against security policies."""
    return await MonitorixK8sSecurityService.evaluate_manifest(
        db,
        manifest_text=req.manifest_text,
        namespace=req.namespace or "default"
    )

@router.post("/inspect-runtime")
async def inspect_k8s_runtime_event(
    req: InspectRuntimeRequest,
    db: AsyncSession = Depends(get_db)
):
    """Real-time CWPP runtime detection for container escapes, reverse shells, and malicious processes."""
    return await MonitorixK8sSecurityService.inspect_runtime_event(
        db,
        cluster_id=req.cluster_id,
        pod_name=req.pod_name,
        namespace=req.namespace,
        event_type=req.event_type,
        process_path=req.process_path,
        command_line=req.command_line
    )

@router.post("/quarantine-pod")
async def quarantine_k8s_pod(
    req: QuarantinePodRequest,
    db: AsyncSession = Depends(get_db)
):
    """1-Click active response to quarantine a pod via NetworkPolicy denial."""
    if not req.finding_id and not req.workload_id:
        raise HTTPException(status_code=400, detail="Must provide either finding_id or workload_id")
    return await MonitorixK8sSecurityService.quarantine_pod(
        db,
        finding_id=req.finding_id,
        workload_id=req.workload_id,
        action=req.action or "ISOLATE_NETWORK"
    )
