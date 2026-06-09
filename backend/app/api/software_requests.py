from fastapi import APIRouter, Depends, HTTPException, Query, Request, Header
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime
import json
import hashlib
import hmac

from ..db.session import get_db
from ..db.models import SoftwareRequest, Agent, Tenant, User, EventLog
from .deps import get_current_user
from ..main_dashboard import sio_manager

router = APIRouter()

class CreateSoftwareRequest(BaseModel):
    AgentId: str
    SoftwareName: str
    Reason: Optional[str] = None
    TenantApiKey: Optional[str] = None

@router.post("")
async def create_software_request(
    payload: CreateSoftwareRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    x_tenant_api_key: Optional[str] = Header(None, alias="X-Tenant-Api-Key"),
    x_signature: Optional[str] = Header(None, alias="X-Signature"),
    x_timestamp: Optional[str] = Header(None, alias="X-Timestamp")
):
    """Agent calls this endpoint to request new software."""
    body_bytes = await request.body()
    if not x_signature or not x_timestamp:
        raise HTTPException(status_code=401, detail="Missing signature")

    agent_query = select(Agent).where(Agent.AgentId == payload.AgentId)
    agent_result = await db.execute(agent_query)
    agent = agent_result.scalars().first()
    
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
        
    tenant_query = select(Tenant).where(Tenant.Id == agent.TenantId)
    tenant_result = await db.execute(tenant_query)
    tenant = tenant_result.scalars().first()
    if not tenant:
        raise HTTPException(status_code=403, detail="Tenant not found")
        
    import hmac, hashlib
    key_seed = agent.MachineId.encode() if agent.MachineId else tenant.ApiKey.encode()
    signing_key = hashlib.sha256(key_seed).digest()
    msg = f"{body_bytes.decode('utf-8')}|{x_timestamp}".encode('utf-8')
    expected = hmac.new(signing_key, msg, hashlib.sha256).hexdigest()
    
    is_valid = hmac.compare_digest(expected, x_signature)
    if not is_valid and not agent.MachineId:
         fallback_key = tenant.ApiKey.encode()
         expected_fallback = hmac.new(fallback_key, msg, hashlib.sha256).hexdigest()
         if hmac.compare_digest(expected_fallback, x_signature): is_valid = True
             
    if not is_valid: raise HTTPException(status_code=403, detail="Invalid signature")
    
    # Create request
    new_request = SoftwareRequest(
        AgentId=agent.AgentId,
        TenantId=agent.TenantId,
        SoftwareName=payload.SoftwareName,
        Reason=payload.Reason,
        Status="PENDING",
        RequestedAt=datetime.utcnow()
    )
    db.add(new_request)
    await db.commit()
    
    return {"status": "success", "message": "Software request submitted"}

@router.get("")
async def get_software_requests(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Dashboard calls this to list requests."""
    query = select(SoftwareRequest, Agent.Hostname).join(Agent, Agent.AgentId == SoftwareRequest.AgentId)
    if current_user.Role != "SuperAdmin":
        query = query.where(SoftwareRequest.TenantId == current_user.TenantId)
        
    query = query.order_by(SoftwareRequest.RequestedAt.desc())
    result = await db.execute(query)
    
    response = []
    for req, hostname in result.all():
        response.append({
            "id": req.Id,
            "agentId": req.AgentId,
            "hostname": hostname,
            "softwareName": req.SoftwareName,
            "reason": req.Reason,
            "status": req.Status,
            "requestedAt": req.RequestedAt.isoformat() if req.RequestedAt else None
        })
    return response

@router.post("/{request_id}/approve")
async def approve_software_request(
    request_id: int,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Dashboard calls this to approve a request."""
    query = select(SoftwareRequest).where(SoftwareRequest.Id == request_id)
    if current_user.Role != "SuperAdmin":
        query = query.where(SoftwareRequest.TenantId == current_user.TenantId)
        
    result = await db.execute(query)
    req = result.scalars().first()
    
    if not req:
        raise HTTPException(status_code=404, detail="Request not found")
        
    if req.Status != "PENDING":
        raise HTTPException(status_code=400, detail="Request is not pending")
        
    # Get Tenant API Key for signing
    tenant_res = await db.execute(select(Tenant).where(Tenant.Id == req.TenantId))
    tenant = tenant_res.scalars().first()
    
    agent_res = await db.execute(select(Agent).where(Agent.AgentId == req.AgentId))
    agent = agent_res.scalars().first()
    
    if not tenant or not agent:
        raise HTTPException(status_code=500, detail="Tenant context or agent missing")
        
    req.Status = "APPROVED"
    req.UpdateDate = datetime.utcnow()
    
    # Trigger socket event to install software
    timestamp = datetime.utcnow().isoformat()
    action = "InstallSoftware"
    params = {"SoftwareName": req.SoftwareName, "RequestId": req.Id}
    
    msg_parts = [str(action), json.dumps(params, sort_keys=True), str(timestamp)]
    message = "|".join(msg_parts).encode('utf-8')
    machine_id = agent.MachineId or agent.AgentId
    key = hashlib.sha256(tenant.ApiKey.encode() + machine_id.encode()).digest()
    signature = hmac.new(key, message, hashlib.sha256).hexdigest()
    
    command_data = {
        "action": action,
        "params": params,
        "policy_name": "Approved Software Installation",
        "timestamp": timestamp,
        "signature": signature
    }
    
    # Push to Agent
    await sio_manager.emit('RemediationCommand', command_data, room=agent.AgentId)
    
    # Log Audit
    db.add(EventLog(
        AgentId=agent.AgentId,
        Type="SOFTWARE_APPROVAL",
        Details=f"Approved installation of {req.SoftwareName} by {current_user.Username}",
        Timestamp=datetime.utcnow(),
        Severity="Low"
    ))
    
    await db.commit()
    return {"status": "success", "message": "Installation command dispatched."}

@router.post("/{request_id}/deny")
async def deny_software_request(
    request_id: int,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Dashboard calls this to deny a request."""
    query = select(SoftwareRequest).where(SoftwareRequest.Id == request_id)
    if current_user.Role != "SuperAdmin":
        query = query.where(SoftwareRequest.TenantId == current_user.TenantId)
        
    result = await db.execute(query)
    req = result.scalars().first()
    
    if not req:
        raise HTTPException(status_code=404, detail="Request not found")
        
    req.Status = "DENIED"
    req.UpdateDate = datetime.utcnow()
    await db.commit()
    return {"status": "success", "message": "Request denied"}
