from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from typing import List
from datetime import datetime
import shutil
import os
import json

from ..db.session import get_db
from ..db.models import SpeechLog, Tenant, Agent
from .deps import get_current_user
from ..db.models import User

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
    res = await db.execute(select(Tenant).where(Tenant.ApiKey == tenant_api_key))
    tenant = res.scalars().first()
    if not tenant:
        raise HTTPException(status_code=401, detail="Invalid Tenant Key")

    # 2. Save File
    timestamp = datetime.utcnow().strftime("%Y%m%d%H%M%S")
    filename = f"{agent_id}_{timestamp}_{file.filename}"
    file_path = os.path.join(UPLOAD_DIR, filename)
    
    with open(file_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)
        
    # 3. Transcribe (Mock for now, or use simple library if installed)
    # In a real scenario, we'd use 'speech_recognition' or OpenAI Whisper here.
    # For now, we will simulate transcription or look for a 'simulated_text' form field if provided for testing.
    # TODO: Integrate actual Speech-to-Text engine.
    transcribed_text = "(Audio Transcription Placeholder) - " + filename
    
    # Simple keyword detection
    keywords_found = []
    # Fetch flagged keywords from policy or settings (omitted for brevity, hardcoded for now)
    risk_words = ["attack", "password", "secret", "hack"] 
    for word in risk_words:
        if word in transcribed_text.lower():
            keywords_found.append(word)

    # 4. Save DB Record
    log = SpeechLog(
        AgentId=agent_id,
        AudioUrl=f"/static/audio/{filename}",
        TranscribedText=transcribed_text,
        Confidence=0.95, # Mock
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
    query = select(SpeechLog).where(SpeechLog.AgentId == agent_id).order_by(SpeechLog.Timestamp.desc()).limit(100)
    result = await db.execute(query)
    logs = result.scalars().all()
    return logs
