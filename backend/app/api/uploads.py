from fastapi import APIRouter, Depends, HTTPException, UploadFile, File
from typing import List
import os
from datetime import datetime
import shutil

from .deps import get_current_user
from ..db.models import User

router = APIRouter()

STORAGE_AUDIO = "storage/Audio"
STORAGE_SHADOWS = "storage/Shadows"

@router.post("/audio")
async def upload_audio(
    file: UploadFile = File(...),
    agent_id: str = "Unknown",
    # current_user: User = Depends(get_current_user) # Agent might upload without user context if using API Key
):
    # TODO: Validate Agent API Key if no user context
    
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
    agent_id: str = "Unknown"
):
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
