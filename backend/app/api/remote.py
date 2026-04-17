from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form, WebSocket, WebSocketDisconnect, Header # type: ignore
from sqlalchemy.ext.asyncio import AsyncSession # type: ignore
from sqlalchemy.future import select # type: ignore
from datetime import datetime # type: ignore
import os # type: ignore
import shutil # type: ignore
import uuid # type: ignore
import json # type: ignore
import base64 # type: ignore
from typing import Dict, Optional, List # type: ignore

from ..db.session import get_db, AsyncSessionLocal # type: ignore
from ..db.models import Agent, SessionRecording, Tenant # type: ignore
from ..core.security import generate_agent_command_signature # type: ignore
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
async def websocket_endpoint(websocket: WebSocket, agent_id: str, api_key: Optional[str] = None):
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

        # [SECURITY FIX] v1.8.42 - Enforce Agent-Tenant Ownership
        # Prevents an attacker with Key A from hijacking a websocket for Agent B
        agent_res = await db.execute(select(Agent).where(Agent.AgentId == agent_id, Agent.TenantId == tenant.Id))
        if not agent_res.scalars().first():
            print(f"[SECURITY ALERT] WebSocket Hijack Attempt blocked! Tenant {tenant.Id} tried to connect for Agent {agent_id}")
            await websocket.close(code=4003)
            return
            
    await manager.connect(websocket, agent_id)
    # Join a relay room for this agent so this process can receive forwarded inputs
    await sio.enter_room(None, f"relay_{agent_id}", sid=None) # Cannot use sid=None easily in some sio versions, use a fake SID or just rely on global join
    # Actually, we can just have the process listen to the room.
    # Sio.enter_room(sid, room) requires a SID.
    # BUT we want THE PROCESS to be in the room? 
    # Sio doesn't have "process in room". It has "SIDs in room".
    # Since agent_api doesn't have the User's SID, we can't join the user to the relay room.
    # INSTEAD: Just broadcast 'ForwardInput' globally or to a room, and every process checks manager.active_connections.
    
    # Let's just broadcast 'ForwardInput' globally (no room) or to the room 'relay_agents'.
    # For now, broadcasting to all processes is fine for few agents.
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
        # [v1.8.37] Remote Input Sovereignty: Sign Input Relay
        async with AsyncSessionLocal() as db:
            res_a = await db.execute(select(Agent).where(Agent.AgentId == agent_id))
            agent = res_a.scalars().first()
            if not agent: return
            
            res_t = await db.execute(select(Tenant).where(Tenant.Id == agent.TenantId))
            tenant = res_t.scalars().first()
            if not tenant: return
            
        timestamp = datetime.utcnow().isoformat()
        # Sign payload (including type, x, y, key, etc)
        signature = generate_agent_command_signature(
            api_key=tenant.ApiKey,
            machine_id=agent.MachineId or "",
            action="RemoteInput",
            params=data, # Sign entire input data
            timestamp=timestamp
        )
        data['timestamp'] = timestamp
        data['signature'] = signature

        print(f"[DEBUG] Relaying Signed RemoteInput to room {agent_id}: {data.get('type')}")
        # 1. Primary: Broadcast via Socket.IO (Works across processes via Redis)
        await sio.emit('RemoteInput', data, room=agent_id, skip_sid=sid)

        # 2. Optimization: Local WebSocket Bypass
        if agent_id in manager.active_connections:
            await manager.send_command(agent_id, data)

@sio.on('start_stream')
@sio.on('StartStream')
async def on_start_stream(sid, data):
    agent_id = data.get('agentId') or data.get('AgentId')
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
                    # from .agents import verify_feature_access # Already imported
                    try:
                        verify_feature_access(tenant.Plan, "LiveStreamEnabled")
                    except Exception as e:
                        print(f"Feature Access Denied: {e}")
                        return

        # [v1.8.37] Stream Sovereignty: Signed Control Commands
        async with AsyncSessionLocal() as db:
            res_a = await db.execute(select(Agent).where(Agent.AgentId == agent_id))
            agent = res_a.scalars().first()
            if not agent: return
            res_t = await db.execute(select(Tenant).where(Tenant.Id == agent.TenantId))
            tenant = res_t.scalars().first()
            if not tenant: return

        timestamp = datetime.utcnow().isoformat()
        signature = generate_agent_command_signature(
            api_key=tenant.ApiKey, machine_id=agent.MachineId or "",
            action="StartStream", params={"Action": "Start"}, timestamp=timestamp
        )
        payload = {"Action": "Start", "timestamp": timestamp, "signature": signature}

        print(f"[DEBUG] Emitting Signed StartStream to room {agent_id}")
        # 1. Primary: Socket.IO Broadcast
        await sio.emit('StartStream', payload, room=agent_id)

        # 2. Optimization: WebSocket Bypass
        if agent_id in manager.active_connections:
            await manager.send_command(agent_id, payload)

@sio.on('stop_stream')
@sio.on('StopStream')
async def on_stop_stream(sid, data):
    agent_id = data.get('agentId') or data.get('AgentId')
    if agent_id:
        # [v1.8.37] Stream Sovereignty: Signed Control Commands
        async with AsyncSessionLocal() as db:
            res_a = await db.execute(select(Agent).where(Agent.AgentId == agent_id))
            agent = res_a.scalars().first()
            if not agent: return
            res_t = await db.execute(select(Tenant).where(Tenant.Id == agent.TenantId))
            tenant = res_t.scalars().first()
            if not tenant: return

        timestamp = datetime.utcnow().isoformat()
        signature = generate_agent_command_signature(
            api_key=tenant.ApiKey, machine_id=agent.MachineId or "",
            action="StopStream", params={"Action": "Stop"}, timestamp=timestamp
        )
        payload = {"Action": "Stop", "timestamp": timestamp, "signature": signature}

        # 1. Primary: Socket.IO Broadcast
        await sio.emit('StopStream', payload, room=agent_id)

        # 2. Optimization: WebSocket Bypass
        if agent_id in manager.active_connections:
            await manager.send_command(agent_id, payload)

@sio.on('stream_frame')
async def on_stream_frame(sid, data):
    """Relay JPEG frame from Agent to Frontend Room"""
    agent_id = data.get('agentId')
    if agent_id:
        # print(f"[DEBUG] Relay Frame from {agent_id}")
        # Broadcast to anyone in the agent's room (Frontends)
        await sio.emit('stream_frame', data, room=agent_id, skip_sid=sid)

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

        # [SECURITY] Verify user is in the Agent Room or is SuperAdmin
        rooms = sio.rooms(sid)
        if agent_id in rooms or user['role'] == "SuperAdmin":
            # [v1.8.37] Shell Sovereignty: Sign Input
            async with AsyncSessionLocal() as db:
                res_a = await db.execute(select(Agent).where(Agent.AgentId == agent_id))
                agent = res_a.scalars().first()
                if not agent: return
                
                res_t = await db.execute(select(Tenant).where(Tenant.Id == agent.TenantId))
                tenant = res_t.scalars().first()
                if not tenant: return
            
            timestamp = datetime.utcnow().isoformat()
            input_text = data.get('input', '')
            signature = generate_agent_command_signature(
                api_key=tenant.ApiKey,
                machine_id=agent.MachineId or "",
                action="ShellInput",
                params={"input": input_text},
                timestamp=timestamp
            )
            
            data['timestamp'] = timestamp
            data['signature'] = signature
            
            await sio.emit('ShellInput', data, room=agent_id)
        else:
            print(f"[SECURITY] Unauthorized ShellInput attempt for {agent_id} by {user.get('username')}")

@sio.on('ShellResize')
async def on_shell_resize(sid, data):
    """
    Frontend terminal resized -> Backend forwards to Agent PTY
    """
    agent_id = data.get('agentId')
    if agent_id:
        session = await sio.get_session(sid)
        user = session.get("user")
        if not user: return

        rooms = sio.rooms(sid)
        if agent_id in rooms or user['role'] == "SuperAdmin":
            await sio.emit('ShellResize', data, room=agent_id)

@sio.on('ShellOutput')
async def on_shell_output(sid, data):
    """
    Agent sends output -> Backend forwards to Frontend
    """
    session = await sio.get_session(sid)
    if not session or not session.get('is_agent'):
        return

    agent_id = session.get('agent_id')
    if agent_id:
        # Use verified agent_id from session for room routing
        data['AgentId'] = agent_id
        await sio.emit('ShellOutput', data, room=agent_id, skip_sid=sid)

async def _sign_and_emit_file_command(sid, agent_id, action, path, data_key):
    """[v1.8.37] Centralized File Command Signing Utility."""
    async with AsyncSessionLocal() as db:
        res_a = await db.execute(select(Agent).where(Agent.AgentId == agent_id))
        agent = res_a.scalars().first()
        if not agent: return
        
        res_t = await db.execute(select(Tenant).where(Tenant.Id == agent.TenantId))
        tenant = res_t.scalars().first()
        if not tenant: return

    timestamp = datetime.utcnow().isoformat()
    # Params must match agent-side reconstruction exactly
    params = {"path": path}
    signature = generate_agent_command_signature(
        api_key=tenant.ApiKey,
        machine_id=agent.MachineId or "",
        action=action,
        params=params,
        timestamp=timestamp
    )
    
    payload = {
        'path': path,
        'timestamp': timestamp,
        'signature': signature
    }
    await sio.emit(action, payload, room=agent_id)

@sio.on('ListFiles')
async def on_list_files(sid, data):
    agent_id = data.get('agentId')
    path = data.get('path', '.')
    if agent_id:
        session = await sio.get_session(sid)
        user = session.get("user")
        if not user: return

        rooms = sio.rooms(sid)
        if agent_id in rooms or user['role'] == "SuperAdmin":
            print(f"[FileManager] ListFiles for {agent_id}: {path}")
            await _sign_and_emit_file_command(sid, agent_id, "ListFiles", path, "path")

@sio.on('FileList')
async def on_file_list(sid, data):
    session = await sio.get_session(sid)
    if not session or not session.get('is_agent'): return
    
    agent_id = session.get('agent_id')
    if agent_id:
        data['AgentId'] = agent_id
        await sio.emit('FileList', data, room=agent_id, skip_sid=sid)

@sio.on('DownloadFile')
async def on_download_file(sid, data):
    agent_id = data.get('agentId')
    path = data.get('path')
    if not agent_id or not path: return
    
    # Verify User Ownership
    session = await sio.get_session(sid)
    user = session.get("user")
    if not user: return
    
    # Re-verify room membership (set by on_join)
    rooms = sio.rooms(sid)
    if agent_id in rooms or user['role'] == "SuperAdmin":
        await _sign_and_emit_file_command(sid, agent_id, "DownloadFile", path, "path")

@sio.on('FileContent')
async def on_file_content(sid, data):
    session = await sio.get_session(sid)
    if not session or not session.get('is_agent'): return
    
    agent_id = session.get('agent_id')
    if agent_id:
        data['AgentId'] = agent_id
        await sio.emit('FileContent', data, room=agent_id, skip_sid=sid)

@sio.on('DeleteFile')
async def on_delete_file(sid, data):
    agent_id = data.get('agentId')
    path = data.get('path')
    if not agent_id or not path: return
    
    session = await sio.get_session(sid)
    user = session.get("user")
    if not user: return
    
    rooms = sio.rooms(sid)
    if agent_id in rooms or user['role'] == "SuperAdmin":
        await _sign_and_emit_file_command(sid, agent_id, "DeleteFile", path, "path")

# --- WebRTC Signaling Handlers ---

@sio.on('webrtc_offer')
async def on_webrtc_offer(sid, data):
    """Agent -> Backend -> Frontend"""
    session = await sio.get_session(sid)
    if not session or not session.get('is_agent'): return
    
    agent_id = session.get('agent_id')
    if agent_id:
        # Enforce verified agent identity
        data['target'] = agent_id # Fix if agent tried to spoof target
        await sio.emit('webrtc_offer', data, room=agent_id, skip_sid=sid)

@sio.on('webrtc_answer')
async def on_webrtc_answer(sid, data):
    """Frontend -> Backend -> Agent"""
    agent_id = data.get('target')
    if not agent_id: return
    
    session = await sio.get_session(sid)
    user = session.get("user")
    if not user: return

    rooms = sio.rooms(sid)
    if agent_id in rooms or user['role'] == "SuperAdmin":
        await sio.emit('webrtc_answer', data, room=agent_id, skip_sid=sid)

@sio.on('webrtc_ice_candidate')
@sio.on('ice_candidate')
async def on_webrtc_ice_candidate(sid, data):
    """Bi-directional ICE exchange"""
    # This is tricky as both Agent and User send it.
    # We'll check the session role.
    session = await sio.get_session(sid)
    if not session: return
    
    if session.get('is_agent'):
        agent_id = session.get('agent_id')
        if agent_id:
            data['target'] = agent_id
            await sio.emit('ice_candidate', data, room=agent_id, skip_sid=sid)
    else:
        # Frontend/User
        agent_id = data.get('target') or data.get('agentId')
        if agent_id:
             rooms = sio.rooms(sid)
             if agent_id in rooms or (session.get('user') and session['user']['role'] == "SuperAdmin"):
                 await sio.emit('ice_candidate', data, room=agent_id, skip_sid=sid)

# --- Session Recording Upload ---

@router.post("/upload-session")
async def upload_session_recording(
    agent_id: str = Form(...),
    duration: int = Form(...),
    start_time: str = Form(...), # ISO Format
    file: UploadFile = File(...),
    db: AsyncSession = Depends(get_db),
    x_tenant_api_key: Optional[str] = Header(None, alias="X-Tenant-Api-Key")
):
    # [v1.8.37] SECURITY: Authenticate Agent Identity
    if not x_tenant_api_key:
        raise HTTPException(status_code=401, detail="Authentication required")
        
    # Validate Agent & Tenant Ownership
    result = await db.execute(select(Agent).where(Agent.AgentId == agent_id))
    agent = result.scalars().first()
    
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")

    res_t = await db.execute(select(Tenant).where(Tenant.Id == agent.TenantId))
    tenant = res_t.scalars().first()
    if not tenant or tenant.ApiKey != x_tenant_api_key:
        print(f"[SECURITY ALERT] Remote Session upload spoofing attempt for Agent {agent_id}")
        raise HTTPException(status_code=403, detail="Unauthorized session upload")

    # [SECURITY] Plan Check
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
