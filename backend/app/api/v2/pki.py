from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from typing import Optional
from datetime import datetime, timedelta
import uuid

from app.db.models import Agent, DeviceCertificate, User
from app.api.deps import get_current_user, verify_agent_signature

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
async def enroll_device(request: EnrollRequest, db=Depends(get_db), agent_sig: str = Depends(verify_agent_signature)):
    # 1. Validate Registration Token (Stubbed for now, normally queries AgentRegistrationToken)
    # 2. Validate TPM Quote (Stubbed)
    # 3. Look up Agent
    agent = db.query(Agent).filter(Agent.AgentId == request.agent_id).first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
        
    # 4. Process CSR and sign (Stubbed signature generation)
    # In a real PKI, we would use cryptography to sign the CSR here.
    serial_number = str(uuid.uuid4())
    dummy_cert = f"-----BEGIN CERTIFICATE-----\nMIID...{serial_number}...==\n-----END CERTIFICATE-----"
    dummy_ca = "-----BEGIN CERTIFICATE-----\nMIIE...CA...==\n-----END CERTIFICATE-----"
    
    # 5. Save Certificate to Database
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
    
    # Update Agent to require mTLS
    agent.RequireMtls = True
    if request.tpm_quote:
        agent.TpmHash = "tpm_hash_placeholder"
        
    db.commit()
    
    return EnrollResponse(certificate_pem=dummy_cert, ca_chain_pem=dummy_ca)

@router.post("/renew", response_model=EnrollResponse)
async def renew_certificate(request: RenewRequest, db=Depends(get_db), agent_sig: str = Depends(verify_agent_signature)):
    # In production, this endpoint requires mTLS.
    # The client certificate is validated at the edge (Nginx), and its serial is passed here.
    
    agent = db.query(Agent).filter(Agent.AgentId == request.agent_id).first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
        
    # Mark old certs as expired/rotated
    old_certs = db.query(DeviceCertificate).filter(
        DeviceCertificate.AgentId == request.agent_id, 
        DeviceCertificate.Status == "ACTIVE"
    ).all()
    for c in old_certs:
        c.Status = "EXPIRED"
        
    # Generate new certificate (Stubbed)
    serial_number = str(uuid.uuid4())
    dummy_cert = f"-----BEGIN CERTIFICATE-----\nMIID...{serial_number}...==\n-----END CERTIFICATE-----"
    dummy_ca = "-----BEGIN CERTIFICATE-----\nMIIE...CA...==\n-----END CERTIFICATE-----"
    
    new_cert = DeviceCertificate(
        AgentId=agent.AgentId,
        TenantId=agent.TenantId,
        SerialNumber=serial_number,
        PublicKeyHash="dummy_hash_new",
        ExpiresAt=datetime.utcnow() + timedelta(days=90),
        Status="ACTIVE"
    )
    
    db.add(new_cert)
    db.commit()
    
    return EnrollResponse(certificate_pem=dummy_cert, ca_chain_pem=dummy_ca)

@router.post("/revoke")
async def revoke_certificate(request: RevokeRequest, db=Depends(get_db), current_user: User = Depends(get_current_user)):
    # Requires Admin Role
    cert = db.query(DeviceCertificate).filter(DeviceCertificate.SerialNumber == request.serial_number).first()
    if not cert:
        raise HTTPException(status_code=404, detail="Certificate not found")
        
    cert.Status = "REVOKED"
    cert.RevokedAt = datetime.utcnow()
    cert.RevocationReason = request.reason
    
    # Option: update Agent.RequireMtls or quarantine the agent
    
    db.commit()
    
    return {"status": "success", "message": f"Certificate {request.serial_number} revoked."}
