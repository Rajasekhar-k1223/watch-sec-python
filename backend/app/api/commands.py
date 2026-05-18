from fastapi import APIRouter, Depends, HTTPException, status # type: ignore
from pydantic import BaseModel # type: ignore
from typing import Optional # type: ignore

from .deps import get_current_user, check_role # type: ignore
from ..db.models import User, Tenant # type: ignore
from ..core.security import generate_agent_command_signature # type: ignore
from ..socket_instance import sio # type: ignore

router = APIRouter()

class CommandRequest(BaseModel):
    Command: str # KillProcess, Isolate, Restart
    Target: Optional[str] = None # PID, ServiceName

@router.post("/execute/{agent_id}")
async def execute_command(
    agent_id: str,
    req: CommandRequest,
    current_user: User = Depends(check_role(["SuperAdmin", "TenantAdmin"]))
):
    # [SECURITY] Validate Agent Ownership
    from ..db.session import get_db # type: ignore
    from sqlalchemy.future import select # type: ignore
    async with AsyncSessionLocal() as db:
        from ..db.models import Agent # type: ignore
        res_a = await db.execute(select(Agent).where(Agent.AgentId == agent_id))
        agent = res_a.scalars().first()
        if not agent:
            raise HTTPException(status_code=404, detail="Agent not found")
        
        if current_user.Role != "SuperAdmin" and agent.TenantId != current_user.TenantId:
            raise HTTPException(status_code=403, detail="Access denied")
            
        # [v1.8.37] Fetch Tenant ApiKey for signing
        res_t = await db.execute(select(Tenant).where(Tenant.Id == agent.TenantId))
        tenant = res_t.scalars().first()
        if not tenant:
             raise HTTPException(status_code=404, detail="Tenant key not found")

    # 2. Audit Log
    from ..db.models import AuditLog # type: ignore
    from datetime import datetime # type: ignore
    audit = AuditLog(
        TenantId=current_user.TenantId or 0,
        Actor=current_user.Username,
        Action="Remote Remediation Action",
        Target=f"Agent: {agent_id}",
        Details=f"Command: {req.Command}, Target: {req.Target}",
        Timestamp=datetime.utcnow()
    )
    from ..db.session import AsyncSessionLocal # type: ignore
    async with AsyncSessionLocal() as db:
        db.add(audit)
        await db.commit()
    
    print(f"[Audit] User {current_user.Username} executing {req.Command} on {agent_id}")

    # 3. Emit via Socket.IO
    # [v1.8.37] Command Sovereignty: Generate HMAC Signature
    timestamp = datetime.utcnow().isoformat()
    # Payload matches Agent's RemediationHandler expects
    params = {"target": req.Target}
    signature = generate_agent_command_signature(
        api_key=tenant.ApiKey,
        machine_id=agent.MachineId or "",
        action=req.Command,
        params=params,
        timestamp=timestamp
    )

    # We should emit to the specific room ID of the agent.
    await sio.emit("ReceiveCommand", {
        "agent_id": agent_id,
        "action": req.Command,
        "params": params,
        "timestamp": timestamp,
        "signature": signature
    }, room=agent_id) 

    return {"Status": "Sent", "Message": f"Command '{req.Command}' sent to {agent_id}"}

@router.post("/screenshot/{agent_id}")
async def trigger_screenshot(
    agent_id: str,
    current_user: User = Depends(check_role(["SuperAdmin", "TenantAdmin", "Analyst"]))
):
    # [SECURITY] Validate Agent Ownership
    from ..db.session import AsyncSessionLocal # type: ignore
    from sqlalchemy.future import select # type: ignore
    from ..db.models import Agent # type: ignore
    async with AsyncSessionLocal() as db:
        res_a = await db.execute(select(Agent).where(Agent.AgentId == agent_id))
        agent = res_a.scalars().first()
        if not agent:
            raise HTTPException(status_code=404, detail="Agent not found")
            
        if current_user.Role != "SuperAdmin" and agent.TenantId != current_user.TenantId:
            raise HTTPException(status_code=403, detail="Access denied")
    # Audit Log
    from ..db.models import AuditLog # type: ignore
    from datetime import datetime # type: ignore
    audit = AuditLog(
        TenantId=current_user.TenantId or 0,
        Actor=current_user.Username,
        Action="Visual Activity Capture Request",
        Target=f"Agent: {agent_id}",
        Details="Requesting immediate visual activity capture (manual trigger)",
        Timestamp=datetime.utcnow()
    )
    from ..db.session import AsyncSessionLocal # type: ignore
    async with AsyncSessionLocal() as db:
        db.add(audit)
        await db.commit()

    # Emit TakeScreenshot event to the specific agent room
    print(f"[CMD] Requesting Screenshot from {agent_id}")
    await sio.emit("TakeScreenshot", {}, room=agent_id)
    return {"Status": "Sent", "Message": "Screenshot request sent"}
