from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import desc
from app.db.session import get_db
from app.db.models import ForensicEvidence, ChainOfCustodyLog, User
from app.services.forensic_vault import vault_engine
from app.api.deps import get_current_user, verify_agent_signature
from pydantic import BaseModel

router = APIRouter()

class UploadRequest(BaseModel):
    agent_id: str
    filename: str
    file_type: str # MemoryDump, Pcap
    size_in_bytes: int

class VerifyRequest(BaseModel):
    evidence_id: int
    sha256_hash: str

@router.post("/upload-request")
async def request_upload(payload: UploadRequest, db: Session = Depends(get_db), agent_sig: str = Depends(verify_agent_signature)):
    """Agent requests to upload a large artifact. Backend returns pre-signed S3 URL."""
    evidence_id, url = vault_engine.generate_upload_url(
        db, payload.agent_id, payload.filename, payload.file_type, payload.size_in_bytes
    )
    return {"status": "success", "evidence_id": evidence_id, "upload_url": url}

@router.post("/verify")
async def verify_upload(payload: VerifyRequest, db: Session = Depends(get_db), agent_sig: str = Depends(verify_agent_signature)):
    """Agent confirms upload completion and provides its local hash."""
    success, msg = vault_engine.verify_upload(db, payload.evidence_id, payload.sha256_hash)
    if not success:
        raise HTTPException(status_code=400, detail=msg)
    return {"status": "success", "message": msg}

@router.get("/evidence")
async def list_evidence(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    """List all stored forensic artifacts."""
    return db.query(ForensicEvidence).order_by(desc(ForensicEvidence.UploadedAt)).all()

@router.post("/{evidence_id}/legal-hold")
async def apply_legal_hold(evidence_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    """Toggle legal hold status."""
    admin_id = current_user.Username
    success = vault_engine.toggle_legal_hold(db, evidence_id, admin_id)
    if not success:
        raise HTTPException(status_code=404, detail="Evidence not found")
    return {"status": "success"}

@router.get("/{evidence_id}/chain-of-custody")
async def get_chain_of_custody(evidence_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    """Retrieve the immutable audit log for legal reporting."""
    logs = db.query(ChainOfCustodyLog).filter(ChainOfCustodyLog.EvidenceId == evidence_id)\
             .order_by(ChainOfCustodyLog.Timestamp).all()
    return logs
