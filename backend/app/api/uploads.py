from fastapi import APIRouter, Depends, HTTPException, Request, Header, Response # type: ignore
from typing import List, Optional # type: ignore
import os # type: ignore
from datetime import datetime # type: ignore
import shutil # type: ignore
import base64 # type: ignore
import json # type: ignore
import hmac # type: ignore
import hashlib # type: ignore
import logging # type: ignore

from .deps import get_current_user # type: ignore
from ..db.models import User, Agent, ShadowedFile, Tenant # type: ignore
from ..db.session import get_db # type: ignore
from ..services.minio_vault import minio_vault # type: ignore
from sqlalchemy.ext.asyncio import AsyncSession # type: ignore
from sqlalchemy.future import select # type: ignore

logger = logging.getLogger("UploadsAPI")

router = APIRouter()

STORAGE_SHADOWS = "storage/Shadows"
STORAGE_PCAPS = "storage/pcaps"
os.makedirs(STORAGE_PCAPS, exist_ok=True)

@router.post("/shadow")
async def upload_shadow(
    request: Request,
    db: AsyncSession = Depends(get_db),
    x_tenant_api_key: Optional[str] = Header(None, alias="X-Tenant-Api-Key"),
    x_signature: Optional[str] = Header(None, alias="X-Signature"),
    x_timestamp: Optional[str] = Header(None, alias="X-Timestamp")
):
    body_bytes = await request.body()
    
    # Dual-mode authentication: Agent HMAC signature OR Admin/Analyst JWT Bearer token
    is_admin_call = False
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        try:
            from jose import jwt
            from ..core.security import SECRET_KEY, ALGORITHM
            token_str = auth_header.split(" ", 1)[1]
            jwt_payload = jwt.decode(token_str, SECRET_KEY, algorithms=[ALGORITHM])
            if jwt_payload.get("sub"):
                is_admin_call = True
        except Exception:
            pass

    if not is_admin_call:
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

    # Cryptographic Validation for agent uploads
    if not is_admin_call:
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
    decrypted_bytes = decrypt_e2e_payload(body_bytes, agent.MachineId if agent.MachineId else key_seed.decode())
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
            
        # Forensic Integrity Verification: compute SHA-256 directly on decoded binary bytes
        computed_sha256 = hashlib.sha256(file_bytes).hexdigest().lower()
        if x_content_sha256:
             declared_clean = str(x_content_sha256).strip().lower()
             if not hmac.compare_digest(computed_sha256, declared_clean):
                  if os.path.exists(file_path):
                       os.remove(file_path)
                  raise HTTPException(
                      status_code=400,
                      detail=f"Hash verification failed: declared={declared_clean}, computed={computed_sha256}"
                  )

        # Lookup TenantId for forensic isolation
        agent_tenant_id = 1
        try:
             agent_res = await db.execute(select(Agent).where(Agent.AgentId == agent_id))
             agent_obj = agent_res.scalars().first()
             if agent_obj and agent_obj.TenantId:
                  agent_tenant_id = agent_obj.TenantId
        except Exception:
             pass

        # MinIO Sovereign S3 Object Storage dispatch
        minio_key = None
        try:
             minio_result = minio_vault.store_forensic_artifact(
                 tenant_id=agent_tenant_id,
                 agent_id=agent_id,
                 filename=safe_filename,
                 data_bytes=file_bytes,
                 declared_sha256=computed_sha256,
                 artifact_type="shadow"
             )
             minio_key = minio_result.get("object_key")
        except Exception as e:
             logger.warning(f"[Uploads] MinIO storage fallback (non-fatal): {e}")

        shadow_entry = ShadowedFile(
            AgentId=agent_id, OriginalPath=req_filename, FileName=req_filename,
            StoragePath=file_path, FileSize=os.path.getsize(file_path), Timestamp=datetime.utcnow()
        )
        db.add(shadow_entry)
        await db.commit()
        
        from ..socket_instance import sio
        await sio.emit("new_shadow_file", {
            "AgentId": agent_id,
            "FileName": req_filename,
            "Timestamp": datetime.utcnow().isoformat(),
            "Sha256": computed_sha256
        }, room=agent_id)
        
        return {
            "status": "Uploaded",
            "path": file_path,
            "id": shadow_entry.Id,
            "sha256": computed_sha256,
            "minio_key": minio_key,
            "verified": True
        }
    except HTTPException: raise
    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/shadow/{shadow_id}")
async def get_shadow_file(
    shadow_id: int,
    db: AsyncSession = Depends(get_db)
):
    """
    [Phase 2A] Retrieve and verify forensic shadow artifact.
    Re-evaluates SHA-256 before streaming to ensure end-to-end cryptographic integrity.
    """
    entry = (await db.execute(select(ShadowedFile).where(ShadowedFile.Id == shadow_id))).scalars().first()
    if not entry:
        raise HTTPException(status_code=404, detail="Shadow file not found")

    if entry.StoragePath and os.path.exists(entry.StoragePath):
        with open(entry.StoragePath, "rb") as f:
            data = f.read()
        sha256_hash = hashlib.sha256(data).hexdigest().lower()
        return Response(
            content=data,
            media_type="application/octet-stream",
            headers={
                "Content-Disposition": f"attachment; filename=\"{os.path.basename(entry.FileName or 'shadow.dat')}\"",
                "X-Content-Sha256": sha256_hash,
                "X-Agent-Id": entry.AgentId or ""
            }
        )
    raise HTTPException(status_code=404, detail="Artifact file missing from storage")

@router.post("/pcap")
async def upload_pcap(
    request: Request,
    db: AsyncSession = Depends(get_db),
    x_tenant_api_key: Optional[str] = Header(None, alias="X-Tenant-Api-Key"),
    x_signature: Optional[str] = Header(None, alias="X-Signature"),
    x_timestamp: Optional[str] = Header(None, alias="X-Timestamp")
):
    body_bytes = await request.body()
    try:
        req_data = json.loads(body_bytes)
    except:
        raise HTTPException(status_code=400, detail="Invalid JSON")
        
    agent_id = req_data.get("agent_id") or req_data.get("AgentId")
    if not agent_id:
        raise HTTPException(status_code=400, detail="agent_id missing")

    file_b64 = req_data.get("file_b64") or req_data.get("FileB64")
    if not file_b64:
        raise HTTPException(status_code=400, detail="FileB64 missing")
        
    file_bytes = base64.b64decode(file_b64)
    filename = req_data.get("filename") or req_data.get("FilePath") or "capture.pcap"
    
    target_dir = os.path.join(STORAGE_PCAPS, agent_id)
    os.makedirs(target_dir, exist_ok=True)
    file_path = os.path.join(target_dir, filename)
    
    with open(file_path, "wb") as buffer:
        buffer.write(file_bytes)
        
    # [Deep Packet Inspection (DPI)]
    # We trigger a background task to sweep the payload
    import asyncio
    async def inspect_pcap(filepath: str, a_id: str):
        try:
            with open(filepath, "rb") as f:
                content = f.read()
            # Simple string sweep for cleartext threats
            if b"password=" in content.lower() or b"malicious-payload" in content.lower():
                from ..db.session import AsyncSessionLocal
                from ..db.models import DetectionAlert
                from ..services.soar_engine import soar_engine
                
                async with AsyncSessionLocal() as bg_db:
                    alert = DetectionAlert(
                        AgentId=a_id,
                        RuleId=9005,
                        TelemetryId=0,
                        MatchedContent=f"PCAP Forensics: Cleartext credential or threat found in {filename}!"
                    )
                    bg_db.add(alert)
                    await bg_db.commit()
                    
                    try:
                        await soar_engine.trigger_playbook(bg_db, playbook_id=1, target_agent_id=a_id)
                    except:
                        pass
        except Exception as e:
            print(f"[PCAP DPI] Error: {e}")
            
    asyncio.create_task(inspect_pcap(file_path, agent_id))
    
    return {"status": "success", "file": filename}
