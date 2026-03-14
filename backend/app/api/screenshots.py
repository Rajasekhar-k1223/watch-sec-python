from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form, Query
from fastapi.responses import FileResponse
from typing import List, Optional
from datetime import datetime
import os
import shutil
import base64
from io import BytesIO
from PIL import Image
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from jose import JWTError, jwt

from ..core.security import SECRET_KEY, ALGORITHM
from ..db.session import get_db
from ..db.models import User, Agent, Screenshot, Tenant
from .deps import get_current_user
from ..tasks.ocr_tasks import process_ocr_background
from ..core.constants import PLAN_LEVELS
from ..socket_instance import sio

class ScreenshotDto(BaseModel):
    Filename: str
    Date: str
    Timestamp: datetime
    Size: int
    IsAlert: bool = False
    Url: str
    ThumbnailUrl: Optional[str] = None

router = APIRouter()

STORAGE_BASE = "storage/Screenshots"
THUMBNAIL_BASE = "storage/Thumbnails" # [NEW]
os.makedirs(STORAGE_BASE, exist_ok=True)
os.makedirs(THUMBNAIL_BASE, exist_ok=True)

@router.get("/list/{agent_id}", response_model=List[ScreenshotDto])
async def list_screenshots(
    agent_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    limit: int = Query(50, ge=1, le=100), # [NEW] Pagination
    offset: int = Query(0, ge=0)
):
    # Tenant Check
    result = await db.execute(select(Agent).where(Agent.AgentId == agent_id))
    agent = result.scalars().first()
    
    if not agent:
        return []

    if current_user.Role != "SuperAdmin":
        if not current_user.TenantId or agent.TenantId != current_user.TenantId:
            raise HTTPException(status_code=403, detail="Access denied")

    # [OPTIMIZED] Query Database instead of scanning Disk
    query = (
        select(Screenshot)
        .where(Screenshot.AgentId == agent_id)
        .order_by(Screenshot.Timestamp.desc())
        .limit(limit)
        .offset(offset)
    )
    res = await db.execute(query)
    screenshots = res.scalars().all()
    
    return [
        ScreenshotDto(
            Filename=s.Filename,
            Date=s.DateFolder,
            Timestamp=s.Timestamp,
            Size=s.Size,
            IsAlert=s.IsAlert,
            Url=s.Url,
            ThumbnailUrl=s.ThumbnailUrl
        ) for s in screenshots
    ]


# --- Empty space to prevent conflict ---

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
            
        # [NEW] Generate and Save Thumbnail
        thumbnail_path = None
        try:
            thumb_dir = os.path.join(THUMBNAIL_BASE, agent_id, date_folder)
            os.makedirs(thumb_dir, exist_ok=True)
            thumbnail_path = os.path.join(thumb_dir, filename)
            
            with Image.open(BytesIO(file_bytes)) as img:
                img.thumbnail((200, 200)) # Standard 200px thumbnail
                img.save(thumbnail_path, format="WEBP", quality=80)
        except Exception as te:
            print(f"Thumbnail generation failed: {te}")

        # [NEW] Save to Database Index
        new_screenshot = Screenshot(
            AgentId=agent_id,
            TenantId=agent.TenantId,
            Filename=filename,
            DateFolder=date_folder,
            Timestamp=dt,
            Size=len(file_bytes),
            IsAlert="_ALERT" in filename,
            Url=f"/api/screenshots/view/{agent_id}/{date_folder}/{filename}",
            ThumbnailUrl=f"/api/screenshots/thumbnail/{agent_id}/{date_folder}/{filename}"
        )
        db.add(new_screenshot)
        await db.commit()

        # Emit to Socket (Live View)
        # Frontend expects: connection.on("ReceiveScreen", (agentId, base64) => ...)
        # We need to send Data URI scheme
        b64_str = base64.b64encode(file_bytes).decode('utf-8')
        mime_type = "image/webp" if filename.endswith(".webp") else "image/png"
        data_uri = f"data:{mime_type};base64,{b64_str}"
        
        await sio.emit('ReceiveScreen', (agent_id, data_uri), room=agent_id)
            
        # 5. Trigger OCR Background Task (Gated)
        # Only for Pro/Enterprise (Level >= 2)
        if agent.TenantId:
            t_res = await db.execute(select(Tenant).where(Tenant.Id == agent.TenantId))
            t_obj = t_res.scalars().first()
            if t_obj:
                 plan_level = PLAN_LEVELS.get(t_obj.Plan, 1)

        if plan_level >= 2: 
             process_ocr_background.delay(agent_id, filename, file_path)

        return {"status": "Uploaded", "path": file_path, "id": new_screenshot.Id}
    except Exception as e:
        print(f"Error uploading screenshot: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# --- Redundant imports removed ---

# Custom Dependency to allow Token in Query Params for Images (<img> tags can't set headers)
async def get_current_user_images(
    token: Optional[str] = None, # Start with query param
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
    current_user: User = Depends(get_image_access_user),
    db: AsyncSession = Depends(get_db)
):
    # [SECURITY] Validate Ownership
    result = await db.execute(select(Agent).where(Agent.AgentId == agent_id))
    agent = result.scalars().first()
    
    if not agent:
         raise HTTPException(status_code=404, detail="Agent not found")

    if current_user.Role != "SuperAdmin":
         if not current_user.TenantId or agent.TenantId != current_user.TenantId:
             raise HTTPException(status_code=403, detail="Access denied")

    path = os.path.join(STORAGE_BASE, agent_id, date, filename)
    
    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail="Screenshot not found")
        
    media_type = "image/webp" if filename.endswith(".webp") else "image/png"
    return FileResponse(path, media_type=media_type)

@router.get("/thumbnail/{agent_id}/{date}/{filename}")
async def view_thumbnail(
    agent_id: str,
    date: str,
    filename: str,
    current_user: User = Depends(get_image_access_user),
    db: AsyncSession = Depends(get_db)
):
    # [SECURITY] Same as view_screenshot
    result = await db.execute(select(Agent).where(Agent.AgentId == agent_id))
    agent = result.scalars().first()
    
    if not agent:
         raise HTTPException(status_code=404, detail="Agent not found")

    if current_user.Role != "SuperAdmin":
         if not current_user.TenantId or agent.TenantId != current_user.TenantId:
             raise HTTPException(status_code=403, detail="Access denied")

    path = os.path.join(THUMBNAIL_BASE, agent_id, date, filename)
    
    # Fallback if thumbnail fails but full image exists
    if not os.path.exists(path):
        path = os.path.join(STORAGE_BASE, agent_id, date, filename)
    
    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail="Not found")
        
    return FileResponse(path, media_type="image/webp")
