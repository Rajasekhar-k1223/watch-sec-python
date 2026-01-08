from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form, WebSocket, WebSocketDisconnect
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from datetime import datetime
import os
import shutil
import uuid
import json
import base64
from typing import Dict

from ..db.session import get_db
from ..db.models import Agent, SessionRecording
from ..socket_instance import sio

router = APIRouter()

STORAGE_DIR = "storage/recordings"
os.makedirs(STORAGE_DIR, exist_ok=True)

# --- WebSocket Manager for Remote Control ---
class ConnectionManager:
    def __init__(self):
        self.active_connections: Dict[str, WebSocket] = {}

    async def connect(self, websocket: WebSocket, agent_id: str):
        await websocket.accept()
        self.active_connections[agent_id] = websocket
        print(f"[Remote] Agent {agent_id} Connected via WS")

    def disconnect(self, agent_id: str):
        if agent_id in self.active_connections:
            del self.active_connections[agent_id]
            print(f"[Remote] Agent {agent_id} Disconnected")

    async def send_command(self, agent_id: str, command: dict):
        if agent_id in self.active_connections:
            await self.active_connections[agent_id].send_text(json.dumps(command))
        else:
            print(f"[Remote] Agent {agent_id} not connected for command {command.get('type')}")

manager = ConnectionManager()

@router.websocket("/ws/agent/{agent_id}")
async def websocket_endpoint(websocket: WebSocket, agent_id: str):
    await manager.connect(websocket, agent_id)
    try:
        while True:
            # Receive Frame (Bytes)
            data = await websocket.receive_bytes()
            
            # Forward to Frontend via Socket.IO
            # Frontend expects base64 string "image"
            b64_img = base64.b64encode(data).decode('utf-8')
            
            # Broadcast to "agent_id" room (Frontend listens to this room)
            await sio.emit('stream_frame', {
                'agentId': agent_id,
                'image': b64_img
            }, room=agent_id)
            
    except WebSocketDisconnect:
        manager.disconnect(agent_id)
    except Exception as e:
        print(f"[Remote] WS Error: {e}")
        manager.disconnect(agent_id)

# --- Socket.IO Handlers for Input (Frontend -> Backend) ---

@sio.on('RemoteInput')
async def on_remote_input(sid, data):
    # data: { agentId, type: 'mousemove', x, y, ... }
    agent_id = data.get('agentId')
    if not agent_id: return

    # [SECURITY] Check User Authorization via Session
    # Since we implemented session saving in socket_events.py on connect/auth
    session = await sio.get_session(sid)
    user = session.get("user")
    
    if not user:
        # print("Unauthorized Remote Input") 
        return

    # Check Tenant Scope (if not SuperAdmin)
    # Ideally checking against Agent Table again, but simpler:
    # If the user successfully joined the 'agent_id' room, they passed the check in on_join.
    # However, 'RemoteInput' doesn't require being in the room logically, but we should enforce it 
    # OR re-verify. Re-verification is safer.
    # For speed (mouse moves), DB hit every packet is BAD.
    # Optim: Trust if they are in the Room? Or just trust session context if we cached Agent Ownership?
    # Let's do: If User is TenantAdmin, verify they joined the room "agent_id" ?
    # Sio rooms checking is async.
    # BETTER: We trust the Logic: "Users can only see the remote screen if they joined the room".
    # Sending input blindly without seeing screen is useless.
    # So if we enforce joined room == agent_id, we are good?
    
    # Since checking rooms list is internal to SIO, let's assume if they have a valid Session User 
    # AND the Agent belongs to their Tenant (which we can cache or just rely on the fact they accessed the UI).
    # Real-time compromised check: Explicit DB or Cache.
    # Compromise: Check if user['tenantId'] matches what we know about the agent.
    # But we don't know Agent's tenant here without DB.
    # Valid approach: The `manager` only holds active WS connections.
    # The Frontend sends input.
    # Let's rely on the fact that `on_join` was strict. 
    # If strict security demanded:
    # 1. User connects -> Auth & Cache TenantID
    # 2. User joins 'agent_id' -> We verified Agent.TenantID == User.TenantID
    # 3. RemoteInput -> We verify User is in room 'agent_id'
    
    rooms = sio.rooms(sid)
    if agent_id in rooms or user['role'] == "SuperAdmin":
        await manager.send_command(agent_id, data)

@sio.on('start_stream')
async def on_start_stream(sid, data):
    agent_id = data.get('agentId')
    if agent_id:
        print(f"[Remote] Start Stream requested for {agent_id}")
        await manager.send_command(agent_id, {"type": "start_stream"})

@sio.on('stop_stream')
async def on_stop_stream(sid, data):
    agent_id = data.get('agentId')
    if agent_id:
        print(f"[Remote] Stop Stream requested for {agent_id}")
        await manager.send_command(agent_id, {"type": "stop_stream"})

# --- Session Recording Upload ---

@router.post("/upload-session")
async def upload_session_recording(
    agent_id: str = Form(...),
    duration: int = Form(...),
    start_time: str = Form(...), # ISO Format
    file: UploadFile = File(...),
    db: AsyncSession = Depends(get_db)
):
    # Validate Agent
    result = await db.execute(select(Agent).where(Agent.AgentId == agent_id))
    agent = result.scalars().first()
    
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")

    # Save File
    filename = f"{agent_id}_{datetime.now().strftime('%Y%m%d%H%M%S')}_{uuid.uuid4().hex[:6]}.mp4"
    file_path = os.path.join(STORAGE_DIR, filename)
    
    try:
        with open(file_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to save file: {e}")
        
    try:
        start_dt = datetime.fromisoformat(start_time)
    except:
        start_dt = datetime.utcnow()

    # Create DB Record
    recording = SessionRecording(
        AgentId=agent_id,
        Type="RemoteDesktop",
        StartTime=start_dt,
        EndTime=datetime.utcnow(),
        DurationSeconds=duration,
        VideoFilePath=file_path,
        FileSize=os.path.getsize(file_path)
    )
    
    db.add(recording)
    await db.commit()
    
    return {"status": "success", "file_path": file_path, "id": recording.Id}
