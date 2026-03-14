from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form # type: ignore
from sqlalchemy.ext.asyncio import AsyncSession # type: ignore
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
    tenant_api_key: str = Form(...),
    db: AsyncSession = Depends(get_db)
):
    # 1. Validate Tenant
    result_t = await db.execute(select(Tenant).where(Tenant.ApiKey == tenant_api_key))
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

    # 3. Transcription (Mock for now, or use Whisper if installed)
    transcribed_text = "Transcription Placeholder: [Audio Captured]"
    keywords_found = []
    
    # 4. Keyword Detection
    risk_words = ["attack", "password", "secret", "hack"] 
    for word in risk_words:
        if word in transcribed_text.lower():
            keywords_found.append(word)

    # 5. Save DB Record
    log = SpeechLog(
        AgentId=agent_id,
        AudioUrl=f"/static/audio/{filename}",
        TranscribedText=transcribed_text,
        Confidence=0.95, 
        DurationSeconds=duration,
        FlaggedKeywordsJson=json.dumps(keywords_found),
        Timestamp=datetime.utcnow()
    )
    
    db.add(log)
    await db.commit()
    
    return {"status": "Uploaded", "id": log.Id, "text": transcribed_text}

@router.get("/list/{agent_id}")
async def get_speech_logs(
    agent_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    # [SECURITY] Plan Check
    res_a = await db.execute(select(Agent).where(Agent.AgentId == agent_id))
    agent = res_a.scalars().first()
    if agent:
        res_t = await db.execute(select(Tenant).where(Tenant.Id == agent.TenantId))
        tenant = res_t.scalars().first()
        if tenant:
             verify_feature_access(tenant.Plan, "SpeechMonitorEnabled")

    query = select(SpeechLog).where(SpeechLog.AgentId == agent_id).order_by(SpeechLog.Timestamp.desc()).limit(100)
    result = await db.execute(query)
    logs = result.scalars().all()
    return logs
