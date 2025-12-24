from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form
from fastapi.responses import FileResponse
from typing import List
from datetime import datetime
import os
import shutil

from ..schemas import ScreenshotDto
from .deps import get_current_user
from ..db.models import User

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
            if not filename.endswith(".webp"):
                continue
                
            # Parse Filename: HHmmss_filename.webp
            try:
                time_part = filename.split('_')[0]
                date_time_str = f"{date_dir_name} {time_part}"
                timestamp = datetime.strptime(date_time_str, "%Y%m%d %H%M%S")
            except:
                timestamp = datetime.utcnow()

            result.append(ScreenshotDto(
                Filename=filename,
                Date=date_dir_name,
                Timestamp=timestamp,
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
    created_at: str = Form(...) # ISO Format
):
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
        data_uri = f"data:image/png;base64,{b64_str}"
        
        await sio.emit('ReceiveScreen', (agent_id, data_uri))
            
        return {"status": "Uploaded", "path": file_path}
    except Exception as e:
        print(f"Error uploading screenshot: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/view/{agent_id}/{date}/{filename}")
async def view_screenshot(
    agent_id: str,
    date: str,
    filename: str,
    current_user: User = Depends(get_current_user)
):
    path = os.path.join(STORAGE_BASE, agent_id, date, filename)
    
    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail="Screenshot not found")
        
    return FileResponse(path, media_type="image/webp")
