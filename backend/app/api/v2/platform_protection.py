"""
Monitorix Platform Self-Protection & Tamper Defense API Router (Wave 1.11)
===========================================================================
100% Sovereign Monitorix Architecture. Zero external dependencies.
"""

from typing import Optional, List, Dict, Any
from fastapi import APIRouter, Depends, Query, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db
from app.services.platform_protection_service import PlatformProtectionService

router = APIRouter()


class ReportTamperRequest(BaseModel):
    component_type: str = Field(..., description="AGENT, API_GATEWAY, DATABASE, KAFKA, REDIS, MINIO_STORAGE, QDRANT_VECTOR, SOAR_ENGINE")
    target_identifier: str = Field(..., description="Unique target identifier (e.g. srv-prod-agent-01, postgres:5432)")
    tamper_type: str = Field(..., description="SERVICE_TERMINATION_ATTEMPT, PROCESS_INJECTION, DLL_HIJACK, UNHOOKING_ATTEMPT, DATABASE_HASH_CHAIN_MISMATCH, REDIS_CACHE_POISONING, RULE_SIGNATURE_TAMPER")
    source_process_or_ip: str = Field(..., description="Attacker process or source IP")
    description: str = Field(..., description="Detailed description of tamper activity")
    severity: str = Field("CRITICAL", description="CRITICAL, HIGH, MEDIUM, LOW")


class EmergencyLockdownRequest(BaseModel):
    node_id: str = Field(..., description="Node ID to lock down (e.g. NODE-CORE-API)")
    reason: str = Field(..., description="Security justification for lockdown")


class VerifyAttestationRequest(BaseModel):
    ledger_type: str = Field(..., description="DATABASE_STATE_LEDGER, AGENT_BINARY_ATTESTATION, DETECTION_RULE_PACK, KAFKA_LOG_STREAM")
    test_payload: str = Field(..., description="Data payload to attest")


@router.get("/overview")
async def get_overview(db: AsyncSession = Depends(get_db)):
    """Retrieve platform self-protection posture score, tamper metrics, and defense mode"""
    try:
        return await PlatformProtectionService.get_overview(db)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/nodes")
async def get_integrity_nodes(
    subsystem: Optional[str] = Query(None, description="CONTROL_PLANE, AGENT_FLEET, DATA_PLANE, STORAGE_LAYER, DETECTION_ENGINE"),
    db: AsyncSession = Depends(get_db),
):
    """List attested platform components and integrity nodes"""
    nodes = await PlatformProtectionService.get_integrity_nodes(db, subsystem=subsystem)
    return [
        {
            "id": n.Id,
            "node_id": n.NodeId,
            "component_name": n.ComponentName,
            "subsystem": n.Subsystem,
            "status": n.Status,
            "integrity_score": n.IntegrityScore,
            "expected_hash": n.ExpectedHash,
            "current_hash": n.CurrentHash,
            "self_protection_level": n.SelfProtectionLevel,
            "last_attested_at": n.LastAttestedAt.isoformat() if n.LastAttestedAt else None,
        }
        for n in nodes
    ]


@router.get("/events")
async def get_tamper_events(
    component_type: Optional[str] = Query(None, description="AGENT, API_GATEWAY, DATABASE, KAFKA, REDIS, MINIO_STORAGE, QDRANT_VECTOR, SOAR_ENGINE"),
    severity: Optional[str] = Query(None, description="CRITICAL, HIGH, MEDIUM, LOW"),
    limit: int = Query(50, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
):
    """Retrieve historical and live tamper events"""
    events = await PlatformProtectionService.get_tamper_events(
        db, component_type=component_type, severity=severity, limit=limit
    )
    return [
        {
            "id": e.Id,
            "event_id": e.EventId,
            "component_type": e.ComponentType,
            "target_identifier": e.TargetIdentifier,
            "tamper_type": e.TamperType,
            "severity": e.Severity,
            "mitre_technique": e.MitreTechnique,
            "source_process_or_ip": e.SourceProcessOrIp,
            "description": e.Description,
            "action_taken": e.ActionTaken,
            "status": e.Status,
            "detected_at": e.DetectedAt.isoformat() if e.DetectedAt else None,
        }
        for e in events
    ]


@router.get("/policies")
async def get_tamper_policies(db: AsyncSession = Depends(get_db)):
    """List active anti-tamper enforcement policies"""
    policies = await PlatformProtectionService.get_tamper_policies(db)
    return [
        {
            "id": p.Id,
            "policy_id": p.PolicyId,
            "name": p.Name,
            "protection_scope": p.ProtectionScope,
            "enforcement_mode": p.EnforcementMode,
            "auto_lockdown_threshold": p.AutoLockdownThreshold,
            "is_enabled": p.IsEnabled,
            "created_at": p.CreatedAt.isoformat() if p.CreatedAt else None,
        }
        for p in policies
    ]


@router.get("/proofs")
async def get_cryptographic_proofs(db: AsyncSession = Depends(get_db)):
    """List Merkle root cryptographic hash-chain proofs"""
    proofs = await PlatformProtectionService.get_cryptographic_proofs(db)
    return [
        {
            "id": pr.Id,
            "proof_id": pr.ProofId,
            "ledger_type": pr.LedgerType,
            "merkle_root": pr.MerkleRoot,
            "previous_proof_hash": pr.PreviousProofHash,
            "verified_status": pr.VerifiedStatus,
            "timestamp": pr.Timestamp.isoformat() if pr.Timestamp else None,
        }
        for pr in proofs
    ]


@router.post("/report-tamper")
async def report_tamper_attempt(
    req: ReportTamperRequest,
    db: AsyncSession = Depends(get_db),
):
    """Report or simulate real-time tamper event and trigger active platform containment"""
    try:
        return await PlatformProtectionService.report_tamper_attempt(
            db,
            component_type=req.component_type,
            target_identifier=req.target_identifier,
            tamper_type=req.tamper_type,
            source_process_or_ip=req.source_process_or_ip,
            description=req.description,
            severity=req.severity,
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/emergency-lockdown")
async def emergency_lockdown(
    req: EmergencyLockdownRequest,
    db: AsyncSession = Depends(get_db),
):
    """Trigger emergency component lockdown, isolating memory and freezing keys"""
    try:
        return await PlatformProtectionService.trigger_emergency_lockdown(
            db,
            node_id=req.node_id,
            reason=req.reason,
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/verify-attestation")
async def verify_attestation(
    req: VerifyAttestationRequest,
    db: AsyncSession = Depends(get_db),
):
    """Compute and commit a cryptographic SHA-256 Merkle root attestation proof"""
    try:
        return await PlatformProtectionService.verify_cryptographic_attestation(
            db,
            ledger_type=req.ledger_type,
            test_payload=req.test_payload,
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
