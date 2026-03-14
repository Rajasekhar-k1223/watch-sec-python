from fastapi import APIRouter, Depends, HTTPException, status # type: ignore
from pydantic import BaseModel # type: ignore
from typing import Optional # type: ignore

from .deps import get_current_user # type: ignore
from ..db.models import User # type: ignore
from ..socket_instance import sio # type: ignore

router = APIRouter()

class CommandRequest(BaseModel):
    Command: str # KillProcess, Isolate, Restart
    Target: Optional[str] = None # PID, ServiceName

@router.post("/execute/{agent_id}")
async def execute_command(
    agent_id: str,
    req: CommandRequest,
    current_user: User = Depends(get_current_user)
):
    # 1. Security Check
    if current_user.Role not in ["SuperAdmin", "TenantAdmin"]:
        raise HTTPException(status_code=403, detail="Not authorized to execute commands")

    # 2. Audit Log
    from ..db.models import AuditLog # type: ignore
    from datetime import datetime # type: ignore
    audit = AuditLog(
        TenantId=current_user.TenantId or 0,
        Actor=current_user.Username,
        Action="Execute Remote Command",
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
    # We should emit to the specific room ID of the agent.
    # Assuming Agent joins room=agent_id on connect.
    await sio.emit("ReceiveCommand", {
        "agent_id": agent_id,
        "command": req.Command,
        "target": req.Target
    }) # Broadcast to all for now or use room=agent_id if implemented

    return {"Status": "Sent", "Message": f"Command '{req.Command}' sent to {agent_id}"}

@router.post("/screenshot/{agent_id}")
async def trigger_screenshot(
    agent_id: str,
    current_user: User = Depends(get_current_user)
):
    # Audit Log
    from ..db.models import AuditLog # type: ignore
    from datetime import datetime # type: ignore
    audit = AuditLog(
        TenantId=current_user.TenantId or 0,
        Actor=current_user.Username,
        Action="Trigger Manual Screenshot",
        Target=f"Agent: {agent_id}",
        Details="Requesting immediate screenshot capture",
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
