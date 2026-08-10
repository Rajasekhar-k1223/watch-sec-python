from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from pydantic import BaseModel
from typing import Optional
from datetime import datetime, timedelta
import uuid

from app.db.session import get_db
from app.db.models import Agent, DeviceCertificate, User
from app.api.deps import get_current_user, verify_agent_signature
from app.services.ca_service import sign_agent_csr, get_ca_cert_pem

router = APIRouter()

class EnrollRequest(BaseModel):
    agent_id: str
    csr_pem: str
    tpm_quote: Optional[str] = None
    registration_token: str

class EnrollResponse(BaseModel):
    certificate_pem: str
    ca_chain_pem: str

class RenewRequest(BaseModel):
    agent_id: str
    csr_pem: str

class RevokeRequest(BaseModel):
    serial_number: str
    reason: str

@router.post("/enroll", response_model=EnrollResponse, status_code=status.HTTP_201_CREATED)
async def enroll_device(request: EnrollRequest, db: AsyncSession = Depends(get_db), agent_sig: str = Depends(verify_agent_signature)):
    agent = (await db.execute(select(Agent).where(Agent.AgentId == request.agent_id))).scalars().first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")

    try:
        certificate_pem, serial_number = sign_agent_csr(request.csr_pem)
        ca_chain_pem = get_ca_cert_pem()
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to sign CSR: {str(e)}")

    cert = DeviceCertificate(
        AgentId=agent.AgentId,
        TenantId=agent.TenantId,
        SerialNumber=serial_number,
        PublicKeyHash="dummy_hash",
        TpmAttestationData=request.tpm_quote,
        ExpiresAt=datetime.utcnow() + timedelta(days=90),
        Status="ACTIVE"
    )
    db.add(cert)

    agent.RequireMtls = True
    if request.tpm_quote:
        agent.TpmHash = "tpm_hash_placeholder"

    await db.commit()
    return EnrollResponse(certificate_pem=certificate_pem, ca_chain_pem=ca_chain_pem)

@router.post("/renew", response_model=EnrollResponse)
async def renew_certificate(request: RenewRequest, db: AsyncSession = Depends(get_db), agent_sig: str = Depends(verify_agent_signature)):
    agent = (await db.execute(select(Agent).where(Agent.AgentId == request.agent_id))).scalars().first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")

    old_certs = (await db.execute(
        select(DeviceCertificate).where(
            DeviceCertificate.AgentId == request.agent_id,
            DeviceCertificate.Status == "ACTIVE"
        )
    )).scalars().all()
    for c in old_certs:
        c.Status = "EXPIRED"

    try:
        certificate_pem, serial_number = sign_agent_csr(request.csr_pem)
        ca_chain_pem = get_ca_cert_pem()
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to sign CSR: {str(e)}")

    new_cert = DeviceCertificate(
        AgentId=agent.AgentId,
        TenantId=agent.TenantId,
        SerialNumber=serial_number,
        PublicKeyHash="dummy_hash_new",
        ExpiresAt=datetime.utcnow() + timedelta(days=90),
        Status="ACTIVE"
    )
    db.add(new_cert)
    await db.commit()

    return EnrollResponse(certificate_pem=certificate_pem, ca_chain_pem=ca_chain_pem)

@router.post("/revoke")
async def revoke_certificate(request: RevokeRequest, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    cert = (await db.execute(select(DeviceCertificate).where(DeviceCertificate.SerialNumber == request.serial_number))).scalars().first()
    if not cert:
        raise HTTPException(status_code=404, detail="Certificate not found")

    cert.Status = "REVOKED"
    cert.RevokedAt = datetime.utcnow()
    cert.RevocationReason = request.reason

    await db.commit()
    return {"status": "success", "message": f"Certificate {request.serial_number} revoked."}
