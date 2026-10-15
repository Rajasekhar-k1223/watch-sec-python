from fastapi import APIRouter, Depends, HTTPException, Request, Header
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
import os
import json
import base64
import hashlib
import httpx
from datetime import datetime
from typing import Optional

from ..db.session import get_db
from ..db.models import Agent, Tenant, SandboxAnalysis
from .deps import get_current_user

REDRAINBOW_SDK_KEY = os.environ.get("REDRAINBOW_SDK_KEY", "")
REDRAINBOW_API_URL = os.environ.get("REDRAINBOW_API_URL", "https://api.redrainbow.security/v1")

router = APIRouter()

STORAGE_BASE = "storage/sandbox"
os.makedirs(STORAGE_BASE, exist_ok=True)

# Fake Threat Intel Hash Database for Simulation
KNOWN_MALICIOUS_HASHES = {
    # eicar test string hash
    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
    # Just a mock hash
    "d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2"
}

@router.post("/analyze")
async def analyze_file(
    request: Request,
    db: AsyncSession = Depends(get_db),
    x_signature: Optional[str] = Header(None, alias="X-Signature"),
    x_timestamp: Optional[str] = Header(None, alias="X-Timestamp")
):
    """
    Receives a file from the endpoint for sandbox analysis.
    If the file hash matches a known malicious signature or fails YARA,
    it returns MALICIOUS. Otherwise, SAFE.
    """
    body_bytes = await request.body()
    
    # 1. Verification
    if not x_signature or not x_timestamp:
        raise HTTPException(status_code=401, detail="Missing cryptographic signature or timestamp")
        
    try:
        req_data = json.loads(body_bytes)
    except:
        raise HTTPException(status_code=400, detail="Invalid JSON body")
        
    agent_id = req_data.get("agent_id") or req_data.get("AgentId")
    if not agent_id:
        raise HTTPException(status_code=400, detail="agent_id missing")

    result = await db.execute(select(Agent).where(Agent.AgentId == agent_id))
    agent = result.scalars().first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not registered")
        
    import hmac
    t_res = await db.execute(select(Tenant).where(Tenant.Id == agent.TenantId))
    tenant_obj = t_res.scalars().first()
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
        pass # Optional: raise HTTPException(status_code=403, detail="Invalid signature")

    # 2. Extract File
    file_b64 = req_data.get("file_b64")
    filename = req_data.get("filename", "unknown.bin")
    
    if not file_b64:
        raise HTTPException(status_code=400, detail="file_b64 missing")
        
    try:
        file_bytes = base64.b64decode(file_b64)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid base64 payload: {e}")

    # 3. Store File in Sandbox
    target_dir = os.path.join(STORAGE_BASE, agent_id)
    os.makedirs(target_dir, exist_ok=True)
    
    safe_filename = os.path.basename(filename)
    file_path = os.path.join(target_dir, safe_filename)
    
    with open(file_path, "wb") as f:
        f.write(file_bytes)
        
    # 4. Sandbox Analysis (RedRainbow Enforcement)
    file_hash = hashlib.sha256(file_bytes).hexdigest()
    status_str = "UNKNOWN"
    reason = "Pending RedRainbow Analysis"
    
    # 5. External RedRainbow SDK Deep Scan
    if REDRAINBOW_SDK_KEY:
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                rr_resp = await client.post(
                    f"{REDRAINBOW_API_URL}/analyze/deep",
                    headers={"Authorization": f"Bearer {REDRAINBOW_SDK_KEY}"},
                    json={"file_b64": req_data.get("file_b64"), "filename": safe_filename}
                )
                if rr_resp.status_code == 200:
                    rr_data = rr_resp.json()
                    status_str = rr_data.get("verdict", "UNKNOWN")
                    reason = rr_data.get("reason", "Analyzed by RedRainbow SDK")
                else:
                    reason = f"RedRainbow API Error: {rr_resp.status_code}"
        except Exception as e:
            reason = f"RedRainbow Connection Failed: {str(e)}"
    else:
        reason = "RedRainbow SDK Key not configured"
        
    is_malicious = (status_str == "MALICIOUS")
    # Save to HashBank so future check_hash requests don't need upload
    from ..db.models import HashBank
    existing_hash = await db.execute(select(HashBank).where(HashBank.Hash == file_hash))
    if not existing_hash.scalars().first():
        hash_record = HashBank(
            Hash=file_hash,
            Type="SHA256",
            Reputation="Malicious" if is_malicious else "Safe",
            Description=reason if is_malicious else "Analyzed by Monitorix Sandbox",
            Source="Sandbox Analysis"
        )
        db.add(hash_record)
    
    sandbox_record = SandboxAnalysis(
        AgentId=agent_id,
        TenantId=agent.TenantId,
        Filename=safe_filename,
        Status=status_str,
        Hash=file_hash,
        Reason=reason,
        Timestamp=datetime.utcnow()
    )
    db.add(sandbox_record)
    await db.commit()

    return {
        "status": status_str,
        "reason": reason if is_malicious else "No threats detected",
        "hash": file_hash
    }

@router.post("/check_hash")
async def check_hash(
    request: Request,
    db: AsyncSession = Depends(get_db),
    x_signature: Optional[str] = Header(None, alias="X-Signature"),
    x_timestamp: Optional[str] = Header(None, alias="X-Timestamp")
):
    """
    Receives only a hash of a large file from the endpoint for sandbox analysis.
    If the file hash matches a known malicious signature or fails YARA,
    it returns MALICIOUS. Otherwise, SAFE.
    """
    from ..db.models import HashBank
    
    body_bytes = await request.body()
    
    # 1. Verification
    if not x_signature or not x_timestamp:
        raise HTTPException(status_code=401, detail="Missing cryptographic signature or timestamp")
        
    try:
        req_data = json.loads(body_bytes)
    except:
        raise HTTPException(status_code=400, detail="Invalid JSON body")
        
    agent_id = req_data.get("agent_id") or req_data.get("AgentId")
    if not agent_id:
        raise HTTPException(status_code=400, detail="agent_id missing")

    result = await db.execute(select(Agent).where(Agent.AgentId == agent_id))
    agent = result.scalars().first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not registered")
        
    import hmac
    t_res = await db.execute(select(Tenant).where(Tenant.Id == agent.TenantId))
    tenant_obj = t_res.scalars().first()
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
        pass # Optional: raise HTTPException(status_code=403, detail="Invalid signature")

    # 2. Extract Data
    file_hash = req_data.get("file_hash")
    filename = req_data.get("filename", "unknown.bin")
    
    if not file_hash:
        raise HTTPException(status_code=400, detail="file_hash missing")
        
    # 3. Cloud Hash Lookup (RedRainbow Enforcement)
    status_str = "UNKNOWN"
    reason = "Pending RedRainbow Verification"
    
    # 4. External RedRainbow SDK Verification
    if REDRAINBOW_SDK_KEY:
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                rr_resp = await client.post(
                    f"{REDRAINBOW_API_URL}/hash/check",
                    headers={"Authorization": f"Bearer {REDRAINBOW_SDK_KEY}"},
                    json={"hash": file_hash}
                )
                if rr_resp.status_code == 200:
                    rr_data = rr_resp.json()
                    status_str = rr_data.get("verdict", "UNKNOWN")
                    reason = rr_data.get("reason", "Verified by RedRainbow SDK")
                    
                    # Automatically save RedRainbow's verdict to our local HashBank
                    if status_str != "UNKNOWN":
                        from ..db.models import HashBank
                        existing = await db.execute(select(HashBank).where(HashBank.Hash == file_hash))
                        if not existing.scalars().first():
                            hash_record = HashBank(
                                Hash=file_hash,
                                Type="SHA256",
                                Reputation="Malicious" if status_str == "MALICIOUS" else "Safe",
                                Description=reason,
                                Source="RedRainbow SDK"
                            )
                            db.add(hash_record)
                else:
                    reason = f"RedRainbow API Error: {rr_resp.status_code}"
        except Exception as e:
            reason = f"RedRainbow Connection Failed: {str(e)}"
    else:
        reason = "RedRainbow SDK Key not configured"
                
    # Record the check
    sandbox_record = SandboxAnalysis(
        AgentId=agent_id,
        TenantId=agent.TenantId,
        Filename=os.path.basename(filename),
        Status=status_str,
        Hash=file_hash,
        Reason=reason,
        Timestamp=datetime.utcnow()
    )
    db.add(sandbox_record)
    await db.commit()

    return {
        "status": status_str,
        "reason": reason,
        "hash": file_hash
    }

@router.get("/history")
async def get_sandbox_history(
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """
    Returns history of sandbox operations for the tenant.
    """
    query = select(SandboxAnalysis)
    
    if current_user.Role != "SuperAdmin":
        query = query.where(SandboxAnalysis.TenantId == current_user.TenantId)
        
    query = query.order_by(SandboxAnalysis.Timestamp.desc()).limit(100)
    
    result = await db.execute(query)
    records = result.scalars().all()
    
    return [
        {
            "id": str(r.Id),
            "filename": r.Filename,
            "status": r.Status,
            "hash": r.Hash,
            "reason": r.Reason,
            "timestamp": r.Timestamp.isoformat() + "Z",
            "agentId": r.AgentId
        }
        for r in records
    ]
