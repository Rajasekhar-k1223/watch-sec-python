from fastapi import APIRouter, Depends, HTTPException, Header
from sqlalchemy.orm import Session
from app.db.session import get_db
from app.db.models import FederatedTrust
from pydantic import BaseModel
import json

router = APIRouter()

class EventBusPayload(BaseModel):
    source_platform: str
    event_type: str
    data: dict

class SoarExecutePayload(BaseModel):
    agent_id: str
    playbook_id: int

from app.api.deps import get_current_user
from app.db.models import User

def verify_federation_auth(current_user: User = Depends(get_current_user)):
    """
    [SECURITY] Federation API now requires a valid JWT Session Token (obtained via SDK Handshake).
    The JWT confirms the client has passed IP validation and key exchange.
    """
    # In a full RBAC model, check if current_user.Role allows Federation operations.
    return current_user

@router.post("/event-bus")
async def ingest_federated_event(payload: EventBusPayload, user: User = Depends(verify_federation_auth)):
    """
    Allows external platforms like RedRainbow (Offensive Security) or UniCloudOps (CSPM)
    to push intelligence INTO Monitorix. Requires SDK Session JWT.
    """
    print(f"[FEDERATION] Received {payload.event_type} from {payload.source_platform}")
    return {"status": "success", "message": "Event ingested"}

@router.get("/telemetry/stream")
async def stream_telemetry(user: User = Depends(verify_federation_auth)):
    """
    Simulates a streaming endpoint (or Kafka topic) where SentinelX or a central SIEM
    can pull the unified endpoint telemetry aggregated by Monitorix.
    """
    # Permission checks removed for prototype; relies on global JWT authentication
        
    # Mocking a batch of telemetry
    mock_batch = [
        {"type": "ProcessCreate", "agent_id": "WIN-01", "cmd": "powershell.exe"},
        {"type": "NetworkConnect", "agent_id": "LNX-02", "ip": "1.1.1.1"}
    ]
    return {"status": "success", "batch": mock_batch}

@router.post("/soar/execute")
async def remote_soar_execute(payload: SoarExecutePayload, user: User = Depends(verify_federation_auth)):
    """
    Allows an external XDR (SentinelX) or AI (MI-AI) to reach back down into Monitorix
    and trigger a SOAR playbook on a specific endpoint.
    """
    # Permission checks removed for prototype; relies on global JWT authentication
        
    # In a full implementation, this would call soar_engine.trigger_playbook()
    print(f"[FEDERATION] {user.Username} triggered Playbook {payload.playbook_id} on Agent {payload.agent_id}")
    
    return {"status": "success", "action": "Playbook triggered remotely"}
