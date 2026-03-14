from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form, WebSocket, WebSocketDisconnect # type: ignore
from sqlalchemy.ext.asyncio import AsyncSession # type: ignore
from sqlalchemy.future import select # type: ignore
from datetime import datetime # type: ignore
import os # type: ignore
import shutil # type: ignore
import uuid # type: ignore
import json # type: ignore
import base64 # type: ignore
from typing import Dict # type: ignore

from ..db.session import get_db, AsyncSessionLocal # type: ignore
from ..db.models import Agent, SessionRecording, Tenant # type: ignore
from ..socket_instance import sio # type: ignore
from .agents import verify_feature_access # type: ignore

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
async def websocket_endpoint(websocket: WebSocket, agent_id: str, api_key: str = None):
    # [SECURITY] Validate API Key
    if not api_key:
        # Check query params if not passed as arg
        api_key = websocket.query_params.get("api_key")
        
    if not api_key:
        await websocket.close(code=4003) # Unauthorized
        return

    async with AsyncSessionLocal() as db:
        res = await db.execute(select(Tenant).where(Tenant.ApiKey == api_key))
        tenant = res.scalars().first()
        if not tenant:
            await websocket.close(code=4003)
            return
            
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
        # [SECURITY] Plan Check
        session = await sio.get_session(sid)
        user = session.get("user")
        if user and user.get("tenantId"):
            async with AsyncSessionLocal() as db:
                res = await db.execute(select(Tenant).where(Tenant.Id == user["tenantId"]))
                tenant = res.scalars().first()
                if tenant:
                    verify_feature_access(tenant.Plan, "LiveStreamEnabled")

        # Try WS first
        await manager.send_command(agent_id, {"type": "start_stream"})
        # FAILSAFE: Send via Socket.IO to wake up the agent if not connected
        await sio.emit('ControlRemote', {'Action': 'Start'}, room=agent_id)

@sio.on('stop_stream')
async def on_stop_stream(sid, data):
    agent_id = data.get('agentId')
    if agent_id:
        print(f"[Remote] Stop Stream requested for {agent_id}")
        await manager.send_command(agent_id, {"type": "stop_stream"})
        # FAILSAFE: Send via Socket.IO
        await sio.emit('ControlRemote', {'Action': 'Stop'}, room=agent_id)

# --- Remote Shell Handlers ---

@sio.on('ShellInput')
async def on_shell_input(sid, data):
    """
    Frontend sends input -> Backend forwards to Agent
    """
    agent_id = data.get('agentId')
    if agent_id:
        # Security: Plan Check
        session = await sio.get_session(sid)
        user = session.get("user")
        if user and user.get("tenantId"):
            async with AsyncSessionLocal() as db:
                res = await db.execute(select(Tenant).where(Tenant.Id == user["tenantId"]))
                tenant = res.scalars().first()
                if tenant:
                    verify_feature_access(tenant.Plan, "RemoteShellEnabled")

        await sio.emit('ShellInput', data, room=agent_id)

@sio.on('ShellResize')
async def on_shell_resize(sid, data):
    """
    Frontend terminal resized -> Backend forwards to Agent PTY
    """
    agent_id = data.get('agentId')
    if agent_id:
        await sio.emit('ShellResize', data, room=agent_id)

@sio.on('ShellOutput')
async def on_shell_output(sid, data):
    """
    Agent sends output -> Backend forwards to Frontend
    """
    agent_id = data.get('AgentId')
    output = data.get('Output')
    
    # We might need to verify the sender is indeed the agent (via session/token)
    # But for now, we forward to the room.
    if agent_id:
        await sio.emit('ShellOutput', data, room=agent_id)

@sio.on('ListFiles')
async def on_list_files(sid, data):
    agent_id = data.get('agentId')
    path = data.get('path', '.')
    if agent_id:
        print(f"[FileManager] ListFiles for {agent_id}: {path}")
        await sio.emit('ListFiles', {'path': path}, room=agent_id)

@sio.on('FileList')
async def on_file_list(sid, data):
    agent_id = data.get('AgentId')
    if agent_id:
        await sio.emit('FileList', data, room=agent_id)

@sio.on('DownloadFile')
async def on_download_file(sid, data):
    agent_id = data.get('agentId')
    path = data.get('path')
    if agent_id and path:
        await sio.emit('DownloadFile', {'path': path}, room=agent_id)

@sio.on('FileContent')
async def on_file_content(sid, data):
    agent_id = data.get('AgentId')
    if agent_id:
        await sio.emit('FileContent', data, room=agent_id)

@sio.on('DeleteFile')
async def on_delete_file(sid, data):
    agent_id = data.get('agentId')
    path = data.get('path')
    if agent_id and path:
        await sio.emit('DeleteFile', {'path': path}, room=agent_id)

# --- WebRTC Signaling Handlers ---

@sio.on('webrtc_offer')
async def on_webrtc_offer(sid, data):
    """Agent -> Backend -> Frontend"""
    agent_id = data.get('target')
    if agent_id:
        # Broadcast to everyone in the room (frontends)
        await sio.emit('webrtc_offer', data, room=agent_id, skip_sid=sid)

@sio.on('webrtc_answer')
async def on_webrtc_answer(sid, data):
    """Frontend -> Backend -> Agent"""
    agent_id = data.get('target')
    if agent_id:
        # Send strictly to the agent (or everyone in room if agent is listening)
        await sio.emit('webrtc_answer', data, room=agent_id, skip_sid=sid)

@sio.on('webrtc_ice_candidate')
async def on_webrtc_ice_candidate(sid, data):
    """Bi-directional ICE exchange"""
    agent_id = data.get('target')
    if agent_id:
        await sio.emit('webrtc_ice_candidate', data, room=agent_id, skip_sid=sid)

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

    # [SECURITY] Plan Check
    res_t = await db.execute(select(Tenant).where(Tenant.Id == agent.TenantId))
    tenant = res_t.scalars().first()
    if tenant:
        verify_feature_access(tenant.Plan, "LiveStreamEnabled")

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
