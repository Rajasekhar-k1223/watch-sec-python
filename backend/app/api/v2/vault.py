from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
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
    file_type: str
    size_in_bytes: int

class VerifyRequest(BaseModel):
    evidence_id: int
    sha256_hash: str

@router.post("/upload-request")
async def request_upload(payload: UploadRequest, db: AsyncSession = Depends(get_db), agent_sig: str = Depends(verify_agent_signature)):
    evidence_id, url = await vault_engine.generate_upload_url(
        db, payload.agent_id, payload.filename, payload.file_type, payload.size_in_bytes
    )
    return {"status": "success", "evidence_id": evidence_id, "upload_url": url}

@router.post("/verify")
async def verify_upload(payload: VerifyRequest, db: AsyncSession = Depends(get_db), agent_sig: str = Depends(verify_agent_signature)):
    success, msg = await vault_engine.verify_upload(db, payload.evidence_id, payload.sha256_hash)
    if not success:
        raise HTTPException(status_code=400, detail=msg)
    return {"status": "success", "message": msg}

@router.get("/evidence")
async def list_evidence(db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    return (await db.execute(
        select(ForensicEvidence).order_by(desc(ForensicEvidence.UploadedAt))
    )).scalars().all()

@router.post("/{evidence_id}/legal-hold")
async def apply_legal_hold(evidence_id: int, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    success = await vault_engine.toggle_legal_hold(db, evidence_id, current_user.Username)
    if not success:
        raise HTTPException(status_code=404, detail="Evidence not found")
    return {"status": "success"}

@router.get("/{evidence_id}/chain-of-custody")
async def get_chain_of_custody(evidence_id: int, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    logs = (await db.execute(
        select(ChainOfCustodyLog)
        .where(ChainOfCustodyLog.EvidenceId == evidence_id)
        .order_by(ChainOfCustodyLog.Timestamp)
    )).scalars().all()
    return logs
