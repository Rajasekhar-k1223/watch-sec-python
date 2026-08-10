from fastapi import APIRouter, Depends, HTTPException, Header
from pydantic import BaseModel
import json

from app.api.deps import get_current_user
from app.db.models import User

router = APIRouter()

class EventBusPayload(BaseModel):
    source_platform: str
    event_type: str
    data: dict

class SoarExecutePayload(BaseModel):
    agent_id: str
    playbook_id: int

def verify_federation_auth(current_user: User = Depends(get_current_user)):
    return current_user

@router.post("/event-bus")
async def ingest_federated_event(payload: EventBusPayload, user: User = Depends(verify_federation_auth)):
    print(f"[FEDERATION] Received {payload.event_type} from {payload.source_platform}")
    return {"status": "success", "message": "Event ingested"}

@router.get("/telemetry/stream")
async def stream_telemetry(user: User = Depends(verify_federation_auth)):
    mock_batch = [
        {"type": "ProcessCreate", "agent_id": "WIN-01", "cmd": "powershell.exe"},
        {"type": "NetworkConnect", "agent_id": "LNX-02", "ip": "1.1.1.1"}
    ]
    return {"status": "success", "batch": mock_batch}

@router.post("/soar/execute")
async def remote_soar_execute(payload: SoarExecutePayload, user: User = Depends(verify_federation_auth)):
    print(f"[FEDERATION] {user.Username} triggered Playbook {payload.playbook_id} on Agent {payload.agent_id}")
    return {"status": "success", "action": "Playbook triggered remotely"}
