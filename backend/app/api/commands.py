from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from typing import Optional

from .deps import get_current_user
from ..db.models import User
from ..socket_instance import sio

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

    # 2. Audit Log (TODO: Implement AuditService and call here)
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
