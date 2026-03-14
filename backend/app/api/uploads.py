from fastapi import APIRouter, Depends, HTTPException, UploadFile, File # type: ignore
from typing import List # type: ignore
import os # type: ignore
from datetime import datetime # type: ignore
import shutil # type: ignore

from .deps import get_current_user # type: ignore
from ..db.models import User, Agent, ShadowedFile # type: ignore
from ..db.session import get_db # type: ignore
from sqlalchemy.ext.asyncio import AsyncSession # type: ignore
from sqlalchemy.future import select # type: ignore

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
            
        # [NEW] Record in Database
        shadow_entry = ShadowedFile(
            AgentId=agent_id,
            OriginalPath=file.filename, # Agent should send original path as filename or header
            FileName=file.filename,
            StoragePath=file_path,
            FileSize=os.path.getsize(file_path),
            Timestamp=datetime.utcnow()
        )
        db.add(shadow_entry)
        await db.commit()
            
        return {"status": "Uploaded", "path": file_path, "id": shadow_entry.Id}
    except Exception as e:
        print(f"Error uploading shadow file: {e}")
        await db.rollback()
        raise HTTPException(status_code=500, detail="Upload failed")
