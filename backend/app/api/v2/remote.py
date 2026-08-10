"""
[v2.4.0] Remote Control API
Provides endpoints to trigger agent actions via Socket.IO.
"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from pydantic import BaseModel
from typing import Optional
from datetime import datetime

from ...db.session import get_db
from ...db.models import Agent, Tenant, User
from ...core.security import generate_agent_command_signature
from ...socket_instance import sio
from ..deps import get_current_user

router = APIRouter()

class ProcessKillRequest(BaseModel):
    pid: str

class ScriptRequest(BaseModel):
    language: str
    script_content: str

class ServiceRequest(BaseModel):
    service_name: str
    action: str

class FileUploadRequest(BaseModel):
    destination_path: str
    file_content_base64: str

class GenericActionRequest(BaseModel):
    action: str
    params: dict = {}

async def _emit_command(agent_id: str, action: str, params: dict, db: AsyncSession, current_user: User):
    """Helper to sign and emit a command to a specific agent."""
    if current_user.Role not in ("TenantAdmin", "SuperAdmin", "Analyst"):
        raise HTTPException(status_code=403, detail="Insufficient permissions for remote actions")

    res_a = await db.execute(select(Agent).where(Agent.AgentId == agent_id))
    agent = res_a.scalars().first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")

    res_t = await db.execute(select(Tenant).where(Tenant.Id == agent.TenantId))
    tenant = res_t.scalars().first()
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found for this agent")

    timestamp = datetime.utcnow().isoformat()
    full_params = {"Action": action}
    full_params.update(params)

    signature = generate_agent_command_signature(
        api_key=tenant.ApiKey, 
        machine_id=agent.MachineId or "",
        action="Remediation", 
        params=full_params, 
        timestamp=timestamp
    )

    payload = full_params.copy()
    payload["timestamp"] = timestamp
    payload["signature"] = signature

    await sio.emit('Remediation', payload, room=agent_id)
    return {"status": "success", "agent_id": agent_id, "action": action}


@router.post("/{agent_id}/kill-process")
async def kill_process(agent_id: str, req: ProcessKillRequest, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    return await _emit_command(agent_id, "KillProcess", {"TargetPID": req.pid}, db, current_user)

@router.post("/{agent_id}/execute-script")
async def execute_script(agent_id: str, req: ScriptRequest, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    return await _emit_command(agent_id, "ExecuteScript", {"Language": req.language, "ScriptContent": req.script_content}, db, current_user)

@router.post("/{agent_id}/manage-service")
async def manage_service(agent_id: str, req: ServiceRequest, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    return await _emit_command(agent_id, "ManageService", {"ServiceName": req.service_name, "ServiceAction": req.action}, db, current_user)

@router.post("/{agent_id}/upload-file")
async def upload_file(agent_id: str, req: FileUploadRequest, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    return await _emit_command(agent_id, "UploadFile", {"DestinationPath": req.destination_path, "FileContentBase64": req.file_content_base64}, db, current_user)

@router.post("/{agent_id}/action")
async def generic_action(agent_id: str, req: GenericActionRequest, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    """For other actions like LockSession, IsolateNetwork, TriggerIOCScan, TriggerMemoryDump, TriggerYaraScan, TriggerAgentUpdate, DownloadFile."""
    return await _emit_command(agent_id, req.action, req.params, db, current_user)
