from fastapi import APIRouter, Depends, HTTPException, Request, Header # type: ignore
from typing import List, Optional # type: ignore
import os # type: ignore
from datetime import datetime # type: ignore
import shutil # type: ignore
import base64 # type: ignore
import json # type: ignore

from .deps import get_current_user # type: ignore
from ..db.models import User, Agent, ShadowedFile, Tenant # type: ignore
from ..db.session import get_db # type: ignore
from sqlalchemy.ext.asyncio import AsyncSession # type: ignore
from sqlalchemy.future import select # type: ignore

router = APIRouter()

STORAGE_SHADOWS = "storage/Shadows"

@router.post("/shadow")
async def upload_shadow(
    request: Request,
    db: AsyncSession = Depends(get_db),
    x_tenant_api_key: Optional[str] = Header(None, alias="X-Tenant-Api-Key"),
    x_signature: Optional[str] = Header(None, alias="X-Signature"),
    x_timestamp: Optional[str] = Header(None, alias="X-Timestamp")
):
    body_bytes = await request.body()
    
    if not x_signature or not x_timestamp:
        raise HTTPException(status_code=401, detail="Missing signature")
        
    try:
        req_data = json.loads(body_bytes)
    except:
        raise HTTPException(status_code=400, detail="Invalid JSON")
        
    agent_id = req_data.get("agent_id") or req_data.get("AgentId")
    if not agent_id:
        raise HTTPException(status_code=400, detail="agent_id missing")

    result = await db.execute(select(Agent).where(Agent.AgentId == agent_id))
    agent = result.scalars().first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
        
    t_res = await db.execute(select(Tenant).where(Tenant.Id == agent.TenantId))
    tenant_obj = t_res.scalars().first()
    if not tenant_obj:
        raise HTTPException(status_code=403, detail="Tenant not found")

    # Cryptographic Validation
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

    # E2EE Decryption
    from ..core.security import decrypt_e2e_payload
    decrypted_bytes = decrypt_e2e_payload(body_bytes, agent.MachineSecret if agent.MachineSecret else key_seed.decode())
    if decrypted_bytes != body_bytes:
        req_data = json.loads(decrypted_bytes)

    try:
        file_b64 = req_data.get("file_b64")
        if not file_b64:
             raise HTTPException(status_code=400, detail="file_b64 missing")
        file_bytes = base64.b64decode(file_b64)
        
        req_filename = req_data.get("filename", "shadowed_file.dat")
        x_content_sha256 = req_data.get("content_sha256")
        
        now = datetime.utcnow()
        date_folder = now.strftime("%Y%m%d")
        target_dir = os.path.join(STORAGE_SHADOWS, agent_id, date_folder)
        os.makedirs(target_dir, exist_ok=True)
        safe_filename = os.path.basename(req_filename)
        filename = f"{now.strftime('%H%M%S')}_{safe_filename}"
        file_path = os.path.join(target_dir, filename)
        
        with open(file_path, "wb") as buffer:
            buffer.write(file_bytes)
            
        # Forensic Integrity Verification
        if x_content_sha256:
             sha256_hash = hashlib.sha256()
             with open(file_path, "rb") as f:
                 for byte_block in iter(lambda: f.read(4096), b""):
                     sha256_hash.update(byte_block)
             if sha256_hash.hexdigest().lower() != x_content_sha256.lower():
                  os.remove(file_path)
                  raise HTTPException(status_code=400, detail="Hash verification failed")

        shadow_entry = ShadowedFile(
            AgentId=agent_id, OriginalPath=req_filename, FileName=req_filename,
            StoragePath=file_path, FileSize=os.path.getsize(file_path), Timestamp=datetime.utcnow()
        )
        db.add(shadow_entry)
        await db.commit()
        return {"status": "Uploaded", "path": file_path, "id": shadow_entry.Id}
    except HTTPException: raise
    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=500, detail=str(e))
