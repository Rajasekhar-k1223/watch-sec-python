from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form, Query
from fastapi.responses import FileResponse
from typing import List, Optional
from jose import JWTError, jwt
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from ..core.security import SECRET_KEY, ALGORITHM
from ..db.session import get_db
from fastapi.responses import FileResponse
from typing import List
from datetime import datetime
import os
import shutil

from ..db.session import get_db
from ..db.models import User, Agent
from .deps import get_current_user
from ..db.models import User

from pydantic import BaseModel

class ScreenshotDto(BaseModel):
    Filename: str
    Timestamp: datetime
    Size: int
    Url: str
    Date: str 
    IsAlert: bool = False

router = APIRouter()

STORAGE_BASE = "storage/Screenshots"

@router.get("/list/{agent_id}", response_model=List[ScreenshotDto])
async def list_screenshots(
    agent_id: str,
    current_user: User = Depends(get_current_user)
):
    # TODO: Tenant Check (Agent belongs to Tenant)
    
    agent_path = os.path.join(STORAGE_BASE, agent_id)
    if not os.path.exists(agent_path):
        return []

    result = []
    
    # Iterate Date Folders
    for date_dir_name in os.listdir(agent_path):
        date_dir_path = os.path.join(agent_path, date_dir_name)
        if not os.path.isdir(date_dir_path):
            continue
            
        for filename in os.listdir(date_dir_path):
            if not (filename.endswith(".webp") or filename.endswith(".png")):
                continue
                
            # Parse Filename: HHmmss_filename.webp
            try:
                time_part = filename.split('_')[0]
                date_time_str = f"{date_dir_name} {time_part}"
                timestamp = datetime.strptime(date_time_str, "%Y%m%d %H%M%S")
                
                # Get Size
                file_full_path = os.path.join(date_dir_path, filename)
                size = os.path.getsize(file_full_path)
            except:
                timestamp = datetime.utcnow()
                size = 0

            result.append(ScreenshotDto(
                Filename=filename,
                Date=date_dir_name,
                Timestamp=timestamp,
                Size=size,
                IsAlert="_ALERT" in filename,
                Url=f"/api/screenshots/view/{agent_id}/{date_dir_name}/{filename}"
            ))
            
    # Sort Descending
    result.sort(key=lambda x: x.Timestamp, reverse=True)
    return result


import base64
from ..socket_instance import sio

@router.post("/upload")
async def upload_screenshot(
    file: UploadFile = File(...),
    agent_id: str = Form(...),
    created_at: str = Form(...), # ISO Format
    db: AsyncSession = Depends(get_db)
):
    # 1. Validate Agent Exists
    result = await db.execute(select(Agent).where(Agent.AgentId == agent_id))
    agent = result.scalars().first()
    if not agent:
        # Fail silently or 404 to avoid leaking? Agent expects 200 usually or logs error.
        raise HTTPException(status_code=404, detail="Agent not registered")

    # Structure: storage/Screenshots/{agent_id}/{date_Ymd}/
    try:
        # Read file bytes first (we need them for both saving and emitting)
        file_bytes = await file.read()
        
        # Parse Date from CreatedAt or use Now
        try:
            dt = datetime.fromisoformat(created_at)
        except:
            dt = datetime.utcnow()
            
        date_folder = dt.strftime("%Y%m%d")
        
        target_dir = os.path.join(STORAGE_BASE, agent_id, date_folder)
        os.makedirs(target_dir, exist_ok=True)
        
        # Filename: HHmmss_uuid.webp
        time_part = dt.strftime("%H%M%S")
        filename = f"{time_part}_{file.filename}"
        file_path = os.path.join(target_dir, filename)
        
        # Save to Disk
        with open(file_path, "wb") as buffer:
            buffer.write(file_bytes)
            
        # Emit to Socket (Live View)
        # Frontend expects: connection.on("ReceiveScreen", (agentId, base64) => ...)
        # We need to send Data URI scheme
        b64_str = base64.b64encode(file_bytes).decode('utf-8')
        mime_type = "image/webp" if filename.endswith(".webp") else "image/png"
        data_uri = f"data:{mime_type};base64,{b64_str}"
        
        await sio.emit('ReceiveScreen', (agent_id, data_uri))
            
        return {"status": "Uploaded", "path": file_path}
    except Exception as e:
        print(f"Error uploading screenshot: {e}")
        raise HTTPException(status_code=500, detail=str(e))

from jose import JWTError, jwt
from ..core.security import SECRET_KEY, ALGORITHM

# Custom Dependency to allow Token in Query Params for Images (<img> tags can't set headers)
async def get_current_user_images(
    token: str = None, # Start with query param
    current_user: User = Depends(get_current_user) # Try standard header auth
):
    # This logic is tricky because Depends(get_current_user) will RAISE 401 if header missing.
    # We should make header auth optional, or implement manual logic.
    pass 

# Retrying implementing logic properly without double dependency conflict.
async def get_image_access_user(
    token: Optional[str] = None, # Query Param
    db: AsyncSession = Depends(get_db)
):
    if not token:
        # If no token param, this endpoint effectively acts publicly or we just fail.
        # But wait, frontend might use Header OR Param.
        # Since 'view_screenshot' is used by <img> tags, it almost exclusively relies on Query Param in this architecture.
        # So we enforce Query Param.
        raise HTTPException(status_code=401, detail="Not authenticated (Query token missing)")

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
             raise HTTPException(status_code=401, detail="Invalid token")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

    result = await db.execute(select(User).where(User.Username == username))
    user = result.scalars().first()
    if user is None:
        raise HTTPException(status_code=401, detail="User not found")
    return user

@router.get("/view/{agent_id}/{date}/{filename}")
async def view_screenshot(
    agent_id: str,
    date: str,
    filename: str,
    current_user: User = Depends(get_image_access_user) # Swapped dependency
):
    path = os.path.join(STORAGE_BASE, agent_id, date, filename)
    
    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail="Screenshot not found")
        
    media_type = "image/webp" if filename.endswith(".webp") else "image/png"
    return FileResponse(path, media_type=media_type)
