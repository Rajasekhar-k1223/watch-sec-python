import os
import datetime
from datetime import timedelta
import uuid
import hashlib
from typing import Optional, List, Dict, Any

from fastapi import APIRouter, Depends, HTTPException, status, Query, Response
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy import and_, or_
from pydantic import BaseModel, Field

from app.db.session import get_db
from app.db.models import Agent, DeviceCertificate, User, Tenant, AuditLog, AgentEnrollmentToken
from app.api.deps import get_current_user
from app.services import ca_service
from app.services.local_entitlement_engine import local_entitlement_engine

router = APIRouter()

# ==============================================================================
# SCHEMAS
# ==============================================================================

class EnrollmentTokenRequest(BaseModel):
    agent_id: Optional[str] = None
    max_uses: int = Field(default=1, ge=1, le=10)
    ttl_minutes: int = Field(default=10, ge=1, le=10) # Strictly capped at 10 minutes

class EnrollmentTokenResponse(BaseModel):
    token: str
    tenant_id: int
    expires_at: str
    max_uses: int
    ttl_seconds: int

class EnrollRequest(BaseModel):
    agent_id: str
    tenant_id: int
    enrollment_token: str
    csr_pem: str
    tpm_quote: Optional[str] = None

class EnrollResponse(BaseModel):
    certificate_pem: str
    ca_chain_pem: str
    serial_number: str
    expires_at: str
    status: str = "ACTIVE"

class RenewRequest(BaseModel):
    agent_id: str
    csr_pem: str

class RevokeRequest(BaseModel):
    serial_number: Optional[str] = None
    agent_id: Optional[str] = None
    reason: str = Field(default="key_compromise")

class CertificateItem(BaseModel):
    id: int
    agent_id: str
    tenant_id: int
    serial_number: str
    public_key_hash: str
    issued_at: Optional[str]
    expires_at: str
    revoked_at: Optional[str]
    revocation_reason: Optional[str]
    status: str

# ==============================================================================
# 1. ENROLLMENT TOKEN ISSUANCE (ADMIN / RBAC)
# ==============================================================================

@router.post("/enrollment-token", response_model=EnrollmentTokenResponse)
async def create_agent_enrollment_token(
    payload: EnrollmentTokenRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    [SEC-08 / Phase 1C] Issues a single-use, cryptographically secure enrollment token.
    Enforces a strict 10-minute maximum expiration window.
    """
    tenant_id = current_user.TenantId if current_user.Role != "SuperAdmin" else (current_user.TenantId or 1)
    
    token_str = f"enr_{uuid.uuid4().hex}"
    ttl_mins = min(payload.ttl_minutes, 10)
    exp = datetime.datetime.utcnow() + timedelta(minutes=ttl_mins)

    token_record = AgentEnrollmentToken(
        Token=token_str,
        TenantId=tenant_id,
        DeploymentId=None,
        CreatedBy=current_user.Username,
        MaxUses=1, # Single-use enforced
        UsesCount=0,
        ExpiresAt=exp,
        IsRevoked=False,
        CreatedAt=datetime.datetime.utcnow()
    )
    db.add(token_record)

    db.add(AuditLog(
        TenantId=tenant_id,
        Actor=current_user.Username,
        Action="PKI_ENROLLMENT_TOKEN_ISSUED",
        Target=payload.agent_id or "fleet_agent",
        Details=f"Issued 10-min single-use mTLS enrollment token (Token: {token_str[:12]}...)",
        Timestamp=datetime.datetime.utcnow()
    ))
    await db.commit()

    return EnrollmentTokenResponse(
        token=token_str,
        tenant_id=tenant_id,
        expires_at=exp.isoformat(),
        max_uses=1,
        ttl_seconds=ttl_mins * 60
    )

# ==============================================================================
# 2. AGENT ENROLLMENT WITH CSR (AGENT ONBOARDING)
# ==============================================================================

@router.post("/enroll", response_model=EnrollResponse, status_code=status.HTTP_201_CREATED)
async def enroll_agent_certificate(
    request: EnrollRequest,
    db: AsyncSession = Depends(get_db)
):
    """
    [Phase 1C] Validates single-use 10-minute enrollment token, signs agent CSR via
    the Intermediate Ingestion CA, records certificate metadata, and enables mTLS.
    Private key NEVER leaves the endpoint agent.
    """
    now = datetime.datetime.utcnow()

    # 1. Validate Enrollment Token
    token_q = select(AgentEnrollmentToken).where(
        and_(
            AgentEnrollmentToken.Token == request.enrollment_token,
            AgentEnrollmentToken.TenantId == request.tenant_id
        )
    )
    token_res = await db.execute(token_q)
    token_record = token_res.scalars().first()

    if not token_record:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid enrollment token or tenant mismatch"
        )

    if token_record.IsRevoked:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Enrollment token is revoked: {token_record.RevokedReason or 'Manual revocation'}"
        )

    if token_record.ExpiresAt < now:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Enrollment token has expired (10-minute lifetime exceeded)"
        )

    if token_record.UsesCount >= token_record.MaxUses:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Enrollment token has already been consumed (single-use policy)"
        )

    # 2. Verify / Auto-Provision Agent in DB & Check Quota
    agent_res = await db.execute(select(Agent).where(Agent.AgentId == request.agent_id))
    agent = agent_res.scalars().first()

    if agent:
        if agent.TenantId != request.tenant_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Agent is registered under a different tenant"
            )
        if getattr(agent, "IsDecommissioned", False):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Decommissioned agent cannot enroll"
            )
    else:
        # Check quota for new agent enrollment
        quota_check = await local_entitlement_engine.check_agent_enrollment_quota(db, request.tenant_id)
        if not quota_check.get("allowed"):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Enrollment blocked by entitlement engine: {quota_check.get('reason')}"
            )

        agent = Agent(
            AgentId=request.agent_id,
            TenantId=request.tenant_id,
            Hostname=request.agent_id,
            Status="Enrolled (Pending mTLS)",
            RequireMtls=True,
            CreatedDate=now,
            LastSeen=now
        )
        db.add(agent)

    # 3. Sign CSR using Intermediate CA
    try:
        cert_pem, serial_number, pub_sha256 = ca_service.sign_agent_csr(
            csr_pem_str=request.csr_pem,
            tenant_id=request.tenant_id,
            agent_id=request.agent_id,
            days_valid=90
        )
        ca_chain_pem = ca_service.get_ca_cert_pem()
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to sign CSR: {str(e)}"
        )

    # 4. Invalidate prior active certificates for this agent
    prior_certs_res = await db.execute(
        select(DeviceCertificate).where(
            DeviceCertificate.AgentId == request.agent_id,
            DeviceCertificate.Status == "ACTIVE"
        )
    )
    for c in prior_certs_res.scalars().all():
        c.Status = "SUPERSEDED"

    # 5. Record New Active DeviceCertificate
    exp_at = now + timedelta(days=90)
    new_cert = DeviceCertificate(
        AgentId=request.agent_id,
        TenantId=request.tenant_id,
        SerialNumber=serial_number,
        PublicKeyHash=pub_sha256,
        TpmAttestationData=request.tpm_quote,
        IssuedAt=now,
        ExpiresAt=exp_at,
        Status="ACTIVE"
    )
    db.add(new_cert)

    # 6. Consume Single-Use Token & Enforce RequireMtls
    token_record.UsesCount += 1
    agent.RequireMtls = True
    if request.tpm_quote:
        agent.TpmHash = hashlib.sha256(request.tpm_quote.encode()).hexdigest()

    db.add(AuditLog(
        TenantId=request.tenant_id,
        Actor=f"agent:{request.agent_id}",
        Action="AGENT_CERTIFICATE_ENROLLED",
        Target=request.agent_id,
        Details=f"mTLS certificate issued (Serial: {serial_number}, Expires: {exp_at.isoformat()})",
        Timestamp=now
    ))

    await db.commit()

    return EnrollResponse(
        certificate_pem=cert_pem,
        ca_chain_pem=ca_chain_pem,
        serial_number=serial_number,
        expires_at=exp_at.isoformat(),
        status="ACTIVE"
    )

# ==============================================================================
# 3. CERTIFICATE RENEWAL (ATOMIC ROTATION)
# ==============================================================================

@router.post("/renew", response_model=EnrollResponse)
async def renew_agent_certificate(
    request: RenewRequest,
    db: AsyncSession = Depends(get_db)
):
    """
    [Phase 1C] Renews an agent certificate before expiration.
    Supersedes previous active certificate and signs new CSR.
    """
    now = datetime.datetime.utcnow()

    # Verify agent existence
    agent_res = await db.execute(select(Agent).where(Agent.AgentId == request.agent_id))
    agent = agent_res.scalars().first()
    if not agent or getattr(agent, "IsDecommissioned", False):
        raise HTTPException(status_code=404, detail="Agent not found or decommissioned")

    # Find active certificate to verify identity
    active_cert_res = await db.execute(
        select(DeviceCertificate).where(
            DeviceCertificate.AgentId == request.agent_id,
            DeviceCertificate.Status == "ACTIVE"
        ).order_by(DeviceCertificate.IssuedAt.desc())
    )
    active_cert = active_cert_res.scalars().first()
    if not active_cert:
        raise HTTPException(
            status_code=403,
            detail="No active certificate found for renewal. Initial enrollment required."
        )

    # Sign new CSR
    try:
        cert_pem, serial_number, pub_sha256 = ca_service.sign_agent_csr(
            csr_pem_str=request.csr_pem,
            tenant_id=agent.TenantId,
            agent_id=request.agent_id,
            days_valid=90
        )
        ca_chain_pem = ca_service.get_ca_cert_pem()
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to sign CSR: {str(e)}")

    # Atomic rotation: Retire old cert
    active_cert.Status = "SUPERSEDED"

    exp_at = now + timedelta(days=90)
    renewed_cert = DeviceCertificate(
        AgentId=agent.AgentId,
        TenantId=agent.TenantId,
        SerialNumber=serial_number,
        PublicKeyHash=pub_sha256,
        IssuedAt=now,
        ExpiresAt=exp_at,
        Status="ACTIVE"
    )
    db.add(renewed_cert)

    db.add(AuditLog(
        TenantId=agent.TenantId,
        Actor=f"agent:{request.agent_id}",
        Action="AGENT_CERTIFICATE_RENEWED",
        Target=request.agent_id,
        Details=f"Rotated cert (Old Serial: {active_cert.SerialNumber} -> New Serial: {serial_number})",
        Timestamp=now
    ))
    await db.commit()

    return EnrollResponse(
        certificate_pem=cert_pem,
        ca_chain_pem=ca_chain_pem,
        serial_number=serial_number,
        expires_at=exp_at.isoformat(),
        status="ACTIVE"
    )

# ==============================================================================
# 4. CERTIFICATE REVOCATION & CRL BROADCAST (ADMIN / RBAC)
# ==============================================================================

@router.post("/revoke")
async def revoke_certificate(
    request: RevokeRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    [Phase 1C] Instantly revokes a certificate, updates CRL, and logs an audit event.
    """
    now = datetime.datetime.utcnow()
    tenant_id = current_user.TenantId if current_user.Role != "SuperAdmin" else None

    # Query target certificates
    conditions = []
    if request.serial_number:
        conditions.append(DeviceCertificate.SerialNumber == request.serial_number)
    elif request.agent_id:
        conditions.append(DeviceCertificate.AgentId == request.agent_id)
        conditions.append(DeviceCertificate.Status == "ACTIVE")
    else:
        raise HTTPException(status_code=400, detail="Must supply serial_number or agent_id")

    if tenant_id is not None:
        conditions.append(DeviceCertificate.TenantId == tenant_id)

    q = select(DeviceCertificate).where(and_(*conditions))
    res = await db.execute(q)
    certs_to_revoke = res.scalars().all()

    if not certs_to_revoke:
        raise HTTPException(status_code=404, detail="No matching active certificate found to revoke")

    revoked_serials = []
    for c in certs_to_revoke:
        c.Status = "REVOKED"
        c.RevokedAt = now
        c.RevocationReason = request.reason
        revoked_serials.append(c.SerialNumber)

        db.add(AuditLog(
            TenantId=c.TenantId,
            Actor=current_user.Username,
            Action="CERTIFICATE_REVOKED",
            Target=c.AgentId,
            Details=f"Revoked certificate serial {c.SerialNumber}: {request.reason}",
            Timestamp=now
        ))

    await db.commit()

    # Re-generate CRL with all currently revoked certificates
    all_revoked_res = await db.execute(
        select(DeviceCertificate).where(DeviceCertificate.Status == "REVOKED")
    )
    revoked_list = [
        {
            "serial_number": r.SerialNumber,
            "revocation_date": r.RevokedAt or now,
            "reason": r.RevocationReason or "key_compromise"
        }
        for r in all_revoked_res.scalars().all()
    ]
    ca_service.generate_crl(revoked_list)

    return {
        "status": "success",
        "message": f"Successfully revoked {len(revoked_serials)} certificate(s)",
        "revoked_serials": revoked_serials
    }

# ==============================================================================
# 5. CERTIFICATE INVENTORY & STATUS (RBAC & AUDIT)
# ==============================================================================

@router.get("/certificates", response_model=List[CertificateItem])
async def list_certificates(
    status_filter: Optional[str] = Query(None, alias="status"),
    agent_id: Optional[str] = None,
    limit: int = 250,
    offset: int = 0,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Lists device certificates with strict tenant isolation."""
    conditions = []
    if current_user.Role != "SuperAdmin":
        conditions.append(DeviceCertificate.TenantId == current_user.TenantId)
    if status_filter:
        conditions.append(DeviceCertificate.Status == status_filter.upper())
    if agent_id:
        conditions.append(DeviceCertificate.AgentId == agent_id)

    q = select(DeviceCertificate)
    if conditions:
        q = q.where(and_(*conditions))
    q = q.order_by(DeviceCertificate.IssuedAt.desc()).offset(offset).limit(limit)

    res = await db.execute(q)
    items = []
    for c in res.scalars().all():
        items.append(CertificateItem(
            id=c.Id,
            agent_id=c.AgentId,
            tenant_id=c.TenantId,
            serial_number=c.SerialNumber,
            public_key_hash=c.PublicKeyHash,
            issued_at=c.IssuedAt.isoformat() if c.IssuedAt else None,
            expires_at=c.ExpiresAt.isoformat(),
            revoked_at=c.RevokedAt.isoformat() if c.RevokedAt else None,
            revocation_reason=c.RevocationReason,
            status=c.Status
        ))
    return items

@router.get("/status/{agent_id}")
async def get_agent_cert_status(
    agent_id: str,
    db: AsyncSession = Depends(get_db)
):
    """Public/Agent endpoint: Returns active certificate status and expiration countdown."""
    q = select(DeviceCertificate).where(
        DeviceCertificate.AgentId == agent_id,
        DeviceCertificate.Status == "ACTIVE"
    ).order_by(DeviceCertificate.IssuedAt.desc())
    res = await db.execute(q)
    cert = res.scalars().first()

    if not cert:
        return {"agent_id": agent_id, "has_active_cert": False, "status": "NOT_ENROLLED"}

    now = datetime.datetime.utcnow()
    days_left = max(0, (cert.ExpiresAt - now).days)
    is_expired = cert.ExpiresAt < now

    return {
        "agent_id": agent_id,
        "has_active_cert": not is_expired,
        "serial_number": cert.SerialNumber,
        "status": "EXPIRED" if is_expired else cert.Status,
        "expires_at": cert.ExpiresAt.isoformat(),
        "days_remaining": days_left,
        "renew_recommended": days_left <= 15
    }

# ==============================================================================
# 6. CRL & CA CHAIN DOWNLOADS (PUBLIC / AGENT ACCESSIBLE)
# ==============================================================================

@router.get("/ca-chain")
async def get_ca_chain():
    """Serves the trusted Intermediate + Root CA chain in PEM format."""
    chain_pem = ca_service.get_ca_cert_pem()
    return Response(content=chain_pem, media_type="application/x-pem-file")

@router.get("/crl")
async def get_certificate_revocation_list():
    """Serves the current X.509 Certificate Revocation List in PEM format."""
    crl_pem = ca_service.get_crl_pem()
    return Response(content=crl_pem, media_type="application/x-pem-file")

# ==============================================================================
# 7. AUTOMATED PKI LIFECYCLE AUDIT & EXPIRY WATCHDOG
# ==============================================================================

@router.post("/audit-lifecycle")
async def trigger_pki_lifecycle_audit(
    current_user: User = Depends(get_current_user)
):
    """
    [Phase 1D] Scans for certificates expiring <= 15 days, applies EXPIRED status,
    refreshes CRL, and records security audit alarms.
    """
    from app.tasks.pki_lifecycle_tasks import audit_and_maintain_pki_lifecycle
    return await audit_and_maintain_pki_lifecycle()

