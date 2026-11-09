"""
[v3.10.0] Phase 16: Monitorix Security Research & Innovation Lab API Router
============================================================================
Endpoints:
- GET  /api/v2/research/overview
- GET  /api/v2/research/experiments
- GET  /api/v2/research/experiments/{experiment_id}
- POST /api/v2/research/experiments
- POST /api/v2/research/experiments/{experiment_id}/advance
- POST /api/v2/research/experiments/{experiment_id}/security-review
- POST /api/v2/research/experiments/{experiment_id}/performance-test
- POST /api/v2/research/experiments/{experiment_id}/regression-test
- POST /api/v2/research/experiments/{experiment_id}/rollback-strategy
- POST /api/v2/research/experiments/{experiment_id}/canary
- POST /api/v2/research/experiments/{experiment_id}/promote
- POST /api/v2/research/experiments/{experiment_id}/rollback
- GET  /api/v2/research/datasets
- GET  /api/v2/research/prototypes
- GET  /api/v2/research/notes
- POST /api/v2/research/notes
"""

from fastapi import APIRouter, Depends, HTTPException, Query, Body, Header, Request, status
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any

from app.db.session import get_db
from app.db.models import User
from app.api.deps import get_current_user
from app.services.security_research_service import SecurityResearchService

router = APIRouter()

# ---------------------------------------------------------------------------
# Request Models
# ---------------------------------------------------------------------------

class CreateExperimentRequest(BaseModel):
    title: str = Field(..., example="Zero-Copy eBPF Ringbuffer Kernel Telemetry")
    domain: str = Field(default="ENDPOINT", example="ENDPOINT", description="ENDPOINT, NETWORK, IDENTITY, CLOUD, AI_SECURITY, DETECTION")
    subdomain: str = Field(default="Kernel Telemetry", example="Kernel Telemetry")
    hypothesis: str = Field(..., example="Hooking LSM syscall probes with eBPF achieves sub-microsecond latency.")
    methodology: str = Field(default="", example="Stream synthetic events through kernel eBPF ring buffer.")
    dataset_id: Optional[str] = Field(default=None, example="DS-EP-KERNEL-01")
    prototype_id: Optional[str] = Field(default=None, example="PROTO-EBPF-01")
    lead_researcher: Optional[str] = Field(default="Security Lab Fellow", example="Dr. Aris Thorne")
    metrics: Optional[Dict[str, Any]] = Field(default=None)

class AdvanceStageRequest(BaseModel):
    target_stage: str = Field(..., example="PROTOTYPE", description="RESEARCH, PROTOTYPE, LAB_VALIDATION, REGRESSION_TESTING, SECURITY_REVIEW, CANARY, PRODUCTION")

class SecurityReviewRequest(BaseModel):
    reviewer: str = Field(default="Principal Security Architect", example="Principal Security Architect")
    risk_level: str = Field(default="Low", example="Low", description="Low, Medium, High")
    mitigations: str = Field(default="Verified in sandboxed eBPF verifier.", example="Verified in sandboxed eBPF verifier.")
    notes: str = Field(default="Approved for staging progression.", example="Approved for staging progression.")

class PerformanceTestRequest(BaseModel):
    p99_latency_ms: float = Field(default=1.2, example=1.2)
    cpu_pct: float = Field(default=0.8, example=0.8)
    memory_mb: float = Field(default=15.0, example=15.0)
    passed: bool = Field(default=True, example=True)

class RegressionTestRequest(BaseModel):
    test_suite_name: str = Field(default="Detection_Baseline_Suite_v1", example="Detection_Baseline_Suite_v1")

class RollbackStrategyRequest(BaseModel):
    rollback_trigger: str = Field(..., example="Latency exceeds 10ms or unhandled kernel fault")
    recovery_action: str = Field(..., example="Detaches bytecode hook via bpf_link__destroy() and restores baseline")
    snapshot_ref: Optional[str] = Field(default=None, example="SNAP-KRN-V310")

class CanaryRequest(BaseModel):
    percentage: float = Field(..., example=10.0, description="Canary traffic percentage (0.0 to 100.0)")

class RollbackProductionRequest(BaseModel):
    reason: str = Field(default="Manual safety intervention", example="Latency spike detected on canary cluster")

class AddNoteRequest(BaseModel):
    title: str = Field(..., example="Analysis of Indirect Prompt Injections in Multi-Turn Agents")
    content: str = Field(..., example="# Findings\nDelimiter sanitization stops 98% of injection vectors.")
    domain: str = Field(default="AI_SECURITY", example="AI_SECURITY")
    experiment_id: Optional[str] = Field(default=None, example="EXP-2026-AI01")
    author: Optional[str] = Field(default="Security Researcher", example="Dr. Maya Lin")
    tags: Optional[List[str]] = Field(default=["ai", "prompt-injection"])

# ---------------------------------------------------------------------------
# API Endpoints
# ---------------------------------------------------------------------------

@router.get("/overview", summary="Retrieve complete Security Research Lab overview & KPIs")
async def get_lab_overview(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    return await SecurityResearchService.get_lab_overview(db)

@router.get("/experiments", summary="List research experiments")
async def list_experiments(
    domain: Optional[str] = Query(default=None),
    stage: Optional[str] = Query(default=None),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    return await SecurityResearchService.list_experiments(db, domain=domain, stage=stage)

@router.get("/experiments/{experiment_id}", summary="Get detailed research experiment")
async def get_experiment(
    experiment_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    return await SecurityResearchService.get_experiment(db, experiment_id)

@router.post("/experiments", summary="Create a new isolated research experiment")
async def create_experiment(
    req: CreateExperimentRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    return await SecurityResearchService.create_experiment(db, req.dict())

@router.post("/experiments/{experiment_id}/advance", summary="Advance experiment through pipeline stage")
async def advance_stage(
    experiment_id: str,
    req: AdvanceStageRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    return await SecurityResearchService.advance_stage(db, experiment_id, req.target_stage)

@router.post("/experiments/{experiment_id}/security-review", summary="Complete formal security review for experiment")
async def submit_security_review(
    experiment_id: str,
    req: SecurityReviewRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    return await SecurityResearchService.submit_security_review(
        db, experiment_id, req.reviewer, req.risk_level, req.mitigations, req.notes
    )

@router.post("/experiments/{experiment_id}/performance-test", summary="Record performance benchmark test results")
async def record_performance_test(
    experiment_id: str,
    req: PerformanceTestRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    return await SecurityResearchService.record_performance_test(
        db, experiment_id, req.p99_latency_ms, req.cpu_pct, req.memory_mb, req.passed
    )

@router.post("/experiments/{experiment_id}/regression-test", summary="Execute regression testing against baseline detections")
async def run_regression_test(
    experiment_id: str,
    req: RegressionTestRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    return await SecurityResearchService.run_regression_test(db, experiment_id, req.test_suite_name)

@router.post("/experiments/{experiment_id}/rollback-strategy", summary="Define automated rollback strategy and snapshot reference")
async def define_rollback_strategy(
    experiment_id: str,
    req: RollbackStrategyRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    return await SecurityResearchService.define_rollback_strategy(
        db, experiment_id, req.rollback_trigger, req.recovery_action, req.snapshot_ref or ""
    )

@router.post("/experiments/{experiment_id}/canary", summary="Deploy experiment to canary traffic percentage")
async def set_canary(
    experiment_id: str,
    req: CanaryRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    return await SecurityResearchService.set_canary_percentage(db, experiment_id, req.percentage)

@router.post("/experiments/{experiment_id}/promote", summary="Promote experimental capability to production (Enforces all 4 safety gates)")
async def promote_to_production(
    experiment_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    return await SecurityResearchService.promote_to_production(db, experiment_id)

@router.post("/experiments/{experiment_id}/rollback", summary="Execute emergency rollback of production-promoted capability")
async def rollback_production(
    experiment_id: str,
    req: RollbackProductionRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    return await SecurityResearchService.rollback_production(db, experiment_id, req.reason)

@router.get("/datasets", summary="List lab synthetic and anonymized datasets")
async def list_datasets(
    domain: Optional[str] = Query(default=None),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    return await SecurityResearchService.list_datasets(db, domain=domain)

@router.get("/prototypes", summary="List experimental detection prototypes")
async def list_prototypes(
    domain: Optional[str] = Query(default=None),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    return await SecurityResearchService.list_prototypes(db, domain=domain)

@router.get("/notes", summary="List research lab notes and academic findings")
async def list_notes(
    domain: Optional[str] = Query(default=None),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    return await SecurityResearchService.list_notes(db, domain=domain)

@router.post("/notes", summary="Add a new research lab note")
async def add_note(
    req: AddNoteRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    return await SecurityResearchService.add_note(db, req.dict())
