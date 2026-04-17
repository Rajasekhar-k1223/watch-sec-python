from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Header # type: ignore
from typing import List, Optional # type: ignore
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
    db: AsyncSession = Depends(get_db),
    x_tenant_api_key: Optional[str] = Header(None, alias="X-Tenant-Api-Key")
):
    if not x_tenant_api_key:
        raise HTTPException(status_code=401, detail="Authentication required")

    if agent_id and agent_id != "Unknown":
        result = await db.execute(select(Agent).where(Agent.AgentId == agent_id))
        agent = result.scalars().first()
        if not agent:
             raise HTTPException(status_code=404, detail="Agent not found")
        
        from ..db.models import Tenant # type: ignore
        t_res = await db.execute(select(Tenant).where(Tenant.Id == agent.TenantId))
        tenant_obj = t_res.scalars().first()
        if not tenant_obj or tenant_obj.ApiKey != x_tenant_api_key:
            raise HTTPException(status_code=403, detail="Unauthorized")
    
    try:
        now = datetime.utcnow()
        date_folder = now.strftime("%Y%m%d_%H")
        target_dir = os.path.join(STORAGE_AUDIO, agent_id, date_folder)
        os.makedirs(target_dir, exist_ok=True)
        safe_filename = os.path.basename(file.filename)
        filename = f"{now.strftime('%M%S')}_{safe_filename}"
        file_path = os.path.join(target_dir, filename)
        with open(file_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
        return {"status": "Uploaded", "path": file_path}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/shadow")
async def upload_shadow(
    file: UploadFile = File(...),
    agent_id: str = "Unknown",
    db: AsyncSession = Depends(get_db),
    x_tenant_api_key: Optional[str] = Header(None, alias="X-Tenant-Api-Key"),
    x_content_sha256: Optional[str] = Header(None, alias="X-Content-Sha256")
):
    if not x_tenant_api_key:
        raise HTTPException(status_code=401, detail="Authentication required")

    if agent_id and agent_id != "Unknown":
         result = await db.execute(select(Agent).where(Agent.AgentId == agent_id))
         agent = result.scalars().first()
         if not agent:
             raise HTTPException(status_code=404, detail="Agent not found")
             
         from ..db.models import Tenant # type: ignore
         t_res = await db.execute(select(Tenant).where(Tenant.Id == agent.TenantId))
         tenant_obj = t_res.scalars().first()
         if not tenant_obj or tenant_obj.ApiKey != x_tenant_api_key:
             raise HTTPException(status_code=403, detail="Unauthorized")

    try:
        now = datetime.utcnow()
        date_folder = now.strftime("%Y%m%d")
        target_dir = os.path.join(STORAGE_SHADOWS, agent_id, date_folder)
        os.makedirs(target_dir, exist_ok=True)
        safe_filename = os.path.basename(file.filename)
        filename = f"{now.strftime('%H%M%S')}_{safe_filename}"
        file_path = os.path.join(target_dir, filename)
        
        with open(file_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
            
        # [v1.8.37] Forensic Integrity Verification
        if x_content_sha256:
             import hashlib # type: ignore
             sha256_hash = hashlib.sha256()
             with open(file_path, "rb") as f:
                 for byte_block in iter(lambda: f.read(4096), b""):
                     sha256_hash.update(byte_block)
             if sha256_hash.hexdigest().lower() != x_content_sha256.lower():
                  os.remove(file_path)
                  raise HTTPException(status_code=400, detail="Hash verification failed")

        shadow_entry = ShadowedFile(
            AgentId=agent_id, OriginalPath=file.filename, FileName=file.filename,
            StoragePath=file_path, FileSize=os.path.getsize(file_path), Timestamp=datetime.utcnow()
        )
        db.add(shadow_entry)
        await db.commit()
        return {"status": "Uploaded", "path": file_path, "id": shadow_entry.Id}
    except HTTPException: raise
    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=500, detail=str(e))
