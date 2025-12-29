from fastapi import APIRouter, Depends, HTTPException, UploadFile, File
from typing import List
import os
from datetime import datetime
import shutil

from .deps import get_current_user
from .deps import get_current_user
from ..db.models import User, Agent
from ..db.session import get_db
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

router = APIRouter()

STORAGE_AUDIO = "storage/Audio"
STORAGE_SHADOWS = "storage/Shadows"

@router.post("/audio")
async def upload_audio(
    file: UploadFile = File(...),
    agent_id: str = "Unknown",
    db: AsyncSession = Depends(get_db)
    # current_user: User = Depends(get_current_user) # Agent might upload without user context if using API Key
):
    # Validate Agent if ID provided
    if agent_id and agent_id != "Unknown":
        result = await db.execute(select(Agent).where(Agent.AgentId == agent_id))
        agent = result.scalars().first()
        if not agent:
             raise HTTPException(status_code=404, detail="Agent not found")
    
    try:
        # Structure: storage/Audio/{agent_id}/{date_hour}/
        now = datetime.utcnow()
        date_folder = now.strftime("%Y%m%d_%H")
        
        target_dir = os.path.join(STORAGE_AUDIO, agent_id, date_folder)
        os.makedirs(target_dir, exist_ok=True)
        
        filename = f"{now.strftime('%M%S')}_{file.filename}"
        file_path = os.path.join(target_dir, filename)
        
        with open(file_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
            
        return {"status": "Uploaded", "path": file_path}
    except Exception as e:
        print(f"Error uploading audio: {e}")
        raise HTTPException(status_code=500, detail="Upload failed")

@router.post("/shadow")
@router.post("/shadow")
async def upload_shadow(
    file: UploadFile = File(...),
    agent_id: str = "Unknown",
    db: AsyncSession = Depends(get_db)
):
    # Validate
    if agent_id and agent_id != "Unknown":
         result = await db.execute(select(Agent).where(Agent.AgentId == agent_id))
         if not result.scalars().first():
             raise HTTPException(status_code=404, detail="Agent not found")
    try:
        # Structure: storage/Shadows/{agent_id}/{date}/
        now = datetime.utcnow()
        date_folder = now.strftime("%Y%m%d")
        
        target_dir = os.path.join(STORAGE_SHADOWS, agent_id, date_folder)
        os.makedirs(target_dir, exist_ok=True)
        
        filename = f"{now.strftime('%H%M%S')}_{file.filename}"
        file_path = os.path.join(target_dir, filename)
        
        with open(file_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
            
        return {"status": "Uploaded", "path": file_path}
    except Exception as e:
        print(f"Error uploading shadow file: {e}")
        raise HTTPException(status_code=500, detail="Upload failed")
