from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form, Header # type: ignore
from sqlalchemy.ext.asyncio import AsyncSession # type: ignore
from sqlalchemy.future import select # type: ignore
from typing import List, Optional # type: ignore
from sqlalchemy.future import select # type: ignore
from typing import List # type: ignore
from datetime import datetime # type: ignore
import shutil # type: ignore
import os # type: ignore
import json # type: ignore

from ..db.session import get_db # type: ignore
from ..db.models import SpeechLog, Tenant, Agent, User # type: ignore
from .deps import get_current_user # type: ignore
from .agents import verify_feature_access # type: ignore

router = APIRouter()

UPLOAD_DIR = "uploads/audio"
os.makedirs(UPLOAD_DIR, exist_ok=True)

@router.post("/upload/{agent_id}")
async def upload_speech_log(
    agent_id: str,
    file: UploadFile = File(...),
    duration: float = Form(0.0),
    db: AsyncSession = Depends(get_db),
    x_tenant_api_key: Optional[str] = Header(None, alias="X-Tenant-Api-Key")
):
    # 1. Validate Tenant via Header (matches Agent logic)
    if not x_tenant_api_key:
        raise HTTPException(status_code=401, detail="Authentication required")
        
    result_t = await db.execute(select(Tenant).where(Tenant.ApiKey == x_tenant_api_key))
    tenant = result_t.scalars().first()
    if not tenant:
        raise HTTPException(status_code=401, detail="Invalid API Key")

    # [SECURITY] Plan Check
    verify_feature_access(tenant.Plan, "SpeechMonitorEnabled")

    # 2. Save Audio File
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    filename = f"{agent_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{file.filename}"
    file_path = os.path.join(UPLOAD_DIR, filename)
    
    with open(file_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    # 3. Transcription (v2.6.0: Intelligent Keyword Mock)
    # In a full deployment, this would call OpenAI Whisper or Azure Speech
    # For now, we simulate detection based on filename or random triggers for the demo
    possible_transcripts = [
        "Discussion about internal project 'Phoenix' and the new encryption keys.",
        "User mentioned password reset for the main production database.",
        "Conversation regarding the upcoming legal contract and its restricted clauses.",
        "Routine check of the server room access logs.",
        "Meeting regarding the security override for the sovereign lockdown system."
    ]
    import random
    transcribed_text = random.choice(possible_transcripts)
    
    keywords_found = []
    # 4. Keyword Detection (Deeper Audit)
    risk_words = ["password", "encryption", "secret", "restricted", "override", "lockdown", "legal", "contract"] 
    for word in risk_words:
        if word in transcribed_text.lower():
            keywords_found.append(word)

    # 5. Save DB Record
    log = SpeechLog(
        AgentId=agent_id,
        AudioUrl=f"/api/speech/download/{filename}", # Fixed URL path
        TranscribedText=transcribed_text,
        Confidence=0.92, 
        DurationSeconds=duration,
        FlaggedKeywordsJson=json.dumps(keywords_found),
        Timestamp=datetime.utcnow()
    )
    
    db.add(log)
    
    # 6. [v2.6.0] Log Forensic Access in System Audit
    from .audit import log_system_event # type: ignore
    await log_system_event(db, "Agent", agent_id, "SPEECH_CAPTURE", f"Acoustic forensic data captured ({duration}s). Keywords: {', '.join(keywords_found) or 'None'}")
    
    await db.commit()
    return {"status": "Uploaded", "id": log.Id, "text": transcribed_text}

@router.get("/download/{filename}")
async def download_audio(
    filename: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Securely serves the captured audio files to authorized personnel."""
    path = os.path.join(UPLOAD_DIR, filename)
    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail="Audio file not found")
        
    # [SECURITY] Validate that this file belongs to the user's tenant
    # Filename format: {agent_id}_...
    agent_id = filename.split('_')[0]
    res_a = await db.execute(select(Agent).where(Agent.AgentId == agent_id))
    agent = res_a.scalars().first()
    
    if not agent or (current_user.Role != "SuperAdmin" and agent.TenantId != current_user.TenantId):
        raise HTTPException(status_code=403, detail="Access denied to forensic asset")
        
    from fastapi.responses import FileResponse
    return FileResponse(path, media_type="audio/wav")

@router.get("/list/{agent_id}")
async def get_speech_logs(
    agent_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    # [SECURITY] Ownership & Plan Check
    if agent_id != "ALL":
        res_a = await db.execute(select(Agent).where(Agent.AgentId == agent_id))
        agent = res_a.scalars().first()
        if not agent:
             raise HTTPException(status_code=404, detail="Agent not found")
             
        if current_user.Role != "SuperAdmin":
            if agent.TenantId != current_user.TenantId:
                raise HTTPException(status_code=403, detail="Access denied")
                
            res_t = await db.execute(select(Tenant).where(Tenant.Id == agent.TenantId))
            tenant = res_t.scalars().first()
            if tenant:
                 verify_feature_access(tenant.Plan, "SpeechMonitorEnabled")
        
        query = select(SpeechLog).where(SpeechLog.AgentId == agent_id)
    else:
        # Fetch ALL for current tenant (or all for SuperAdmin)
        query = select(SpeechLog)
        if current_user.Role != "SuperAdmin":
            # Link via Agent to filter by TenantId
            query = select(SpeechLog).join(Agent, SpeechLog.AgentId == Agent.AgentId).where(Agent.TenantId == current_user.TenantId)

    query = query.order_by(SpeechLog.Timestamp.desc()).limit(100)
    result = await db.execute(query)
    logs = result.scalars().all()
    return logs
