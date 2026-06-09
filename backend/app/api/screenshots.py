from fastapi import APIRouter, Depends, HTTPException, Request, Query, Header
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
from .deps import get_current_user, get_current_user_flexible
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
    offset: int = Query(0, ge=0),
    start_date: Optional[str] = None,
    end_date: Optional[str] = None
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
    query = select(Screenshot).where(Screenshot.AgentId == agent_id)
    
    if start_date:
        try:
            dt = datetime.fromisoformat(start_date)
            query = query.where(Screenshot.Timestamp >= dt)
        except ValueError:
            pass
            
    if end_date:
        try:
            dt = datetime.fromisoformat(end_date)
            query = query.where(Screenshot.Timestamp <= dt)
        except ValueError:
            pass
            
    query = query.order_by(Screenshot.Timestamp.desc()).limit(limit).offset(offset)
    
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


# --- Bulk Delete ---
class BulkDeleteRequest(BaseModel):
    AgentId: str
    Filenames: List[str]

@router.delete("/bulk")
async def bulk_delete_screenshots(
    request: BulkDeleteRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    result = await db.execute(select(Agent).where(Agent.AgentId == request.AgentId))
    agent = result.scalars().first()
    
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")

    if current_user.Role != "SuperAdmin":
        if not current_user.TenantId or agent.TenantId != current_user.TenantId:
            raise HTTPException(status_code=403, detail="Access denied")

    deleted_count = 0
    for filename in request.Filenames:
        res = await db.execute(select(Screenshot).where(
            Screenshot.AgentId == request.AgentId,
            Screenshot.Filename == filename
        ))
        s = res.scalars().first()
        if s:
            try:
                main_path = os.path.join(STORAGE_BASE, request.AgentId, s.DateFolder, filename)
                thumb_path = os.path.join(THUMBNAIL_BASE, request.AgentId, s.DateFolder, filename)
                if os.path.exists(main_path): os.remove(main_path)
                if os.path.exists(thumb_path): os.remove(thumb_path)
            except Exception as e:
                print(f"File delete error: {e}")
            
            await db.delete(s)
            deleted_count += 1
            
    await db.commit()
    return {"status": "Success", "deleted": deleted_count}
@router.post("/upload")
async def upload_screenshot(
    request: Request,
    db: AsyncSession = Depends(get_db),
    x_tenant_api_key: Optional[str] = Header(None, alias="X-Tenant-Api-Key"),
    x_signature: Optional[str] = Header(None, alias="X-Signature"),
    x_timestamp: Optional[str] = Header(None, alias="X-Timestamp")
):
    body_bytes = await request.body()
    
    # [SEC] Strict Zero-Trust Enforcement
    if not x_signature or not x_timestamp:
        raise HTTPException(status_code=401, detail="Missing cryptographic signature or timestamp")
        
    import json
    try:
        req_data = json.loads(body_bytes)
    except:
        raise HTTPException(status_code=400, detail="Invalid JSON body")
        
    agent_id = req_data.get("agent_id") or req_data.get("AgentId")
    if not agent_id:
        raise HTTPException(status_code=400, detail="agent_id missing")

    # 1. Validate Agent & Tenant Ownership
    result = await db.execute(select(Agent).where(Agent.AgentId == agent_id))
    agent = result.scalars().first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not registered")

    # Verify API Key matches Agent's Tenant
    t_res = await db.execute(select(Tenant).where(Tenant.Id == agent.TenantId))
    tenant_obj = t_res.scalars().first()
    if not tenant_obj:
        raise HTTPException(status_code=403, detail="Tenant not found")
        
    # 2. Cryptographic Validation
    import hmac, hashlib
    key_seed = agent.MachineId.encode() if agent.MachineId else tenant_obj.ApiKey.encode()
    signing_key = hashlib.sha256(key_seed).digest()
    
    msg = f"{body_bytes.decode('utf-8')}|{x_timestamp}".encode('utf-8')
    expected = hmac.new(signing_key, msg, hashlib.sha256).hexdigest()
    
    is_valid = hmac.compare_digest(expected, x_signature)
    if not is_valid and not agent.MachineId:
         fallback_key = tenant_obj.ApiKey.encode()
         expected_fallback = hmac.new(fallback_key, msg, hashlib.sha256).hexdigest()
         if hmac.compare_digest(expected_fallback, x_signature):
             is_valid = True
             
    if not is_valid:
        raise HTTPException(status_code=403, detail="Invalid signature")

    # 3. E2EE Decryption
    from ..core.security import decrypt_e2e_payload
    decrypted_bytes = decrypt_e2e_payload(body_bytes, agent.MachineSecret if agent.MachineSecret else key_seed.decode())
    if decrypted_bytes != body_bytes:
        req_data = json.loads(decrypted_bytes)

    # Structure: storage/Screenshots/{agent_id}/{date_Ymd}/
    try:
        file_b64 = req_data.get("file_b64")
        if not file_b64:
            raise HTTPException(status_code=400, detail="file_b64 missing")
        file_bytes = base64.b64decode(file_b64)
        
        created_at = req_data.get("created_at", datetime.utcnow().isoformat())
        # Parse Date from CreatedAt or use Now
        try:
            dt = datetime.fromisoformat(created_at)
        except:
            dt = datetime.utcnow()
            
        date_folder = dt.strftime("%Y%m%d")
        
        target_dir = os.path.join(STORAGE_BASE, agent_id, date_folder)
        os.makedirs(target_dir, exist_ok=True)
        
        # [SECURITY] Sanitize filename and validate extension to prevent Arbitrary File Write
        req_filename = req_data.get("filename", "screen.webp")
        safe_filename = os.path.basename(req_filename)
        if not safe_filename.lower().endswith(('.png', '.webp')):
             raise HTTPException(status_code=400, detail="Invalid file type. Only PNG and WEBP allowed.")
             
        # Filename: HHmmss_uuid.webp
        time_part = dt.strftime("%H%M%S")
        filename = f"{time_part}_{safe_filename}"
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

# Flexible dependency moved to deps.py for centralization.

@router.get("/view/{agent_id}/{date}/{filename}")
async def view_screenshot(
    agent_id: str,
    date: str,
    filename: str,
    current_user: User = Depends(get_current_user_flexible),
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
    current_user: User = Depends(get_current_user_flexible),
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
