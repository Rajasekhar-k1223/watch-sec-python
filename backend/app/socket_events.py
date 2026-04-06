from .socket_instance import sio # type: ignore
from jose import JWTError, jwt # type: ignore
from sqlalchemy.future import select # type: ignore
from .core.security import SECRET_KEY, ALGORITHM # type: ignore
from .db.session import AsyncSessionLocal # type: ignore
from .db.models import Agent, Tenant # type: ignore
from typing import Any, Dict, Optional, List # type: ignore

@sio.event
async def connect(sid: str, environ: Dict[str, Any], auth: Optional[Dict[str, Any]] = None):
    print(f"[DEBUG] Socket Connect: SID={sid} Auth={auth}")
    # [SECURITY] Strict Auth
    token = None
    if auth:
        token = auth.get('token')
    
    # Fallback to query string
    if not token:
        from urllib.parse import parse_qs # type: ignore
        query_string = environ.get('QUERY_STRING', '')
        params = parse_qs(query_string)
        token_list = params.get('token')
        if token_list:
            token = token_list[0]
            if token:
                print(f"[DEBUG] Found Token in Query String: {token[:10]}...")
    
    # Fallback to query param if logic changes, but auth dict is standard
    # Fallback to query param if logic changes, but auth dict is standard
    # [AGENT AUTH] Check for API Key if no User Token
    api_key = None
    if auth:
        api_key = auth.get('apiKey')

    if not token and not api_key:
        print(f"[Socket.IO] Connection Rejected: No Token or API Key ({sid})")
        return False # Reject

    # A. User Auth (JWT)
    if token:
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            role = payload.get("role")
            tenant_id = payload.get("tenantId")
            username = payload.get("sub")
            
            # Save Session
            await sio.save_session(sid, {
                'username': username,
                'role': role,
                'tenantId': tenant_id, # Normalize key to tenantId (camelCase-ish match)
                'user': { 'id': 0, 'username': username, 'role': role, 'tenantId': tenant_id } # Compat
            })
            print(f"[Socket.IO] User Connected: {username} ({role})")
            return True
        except Exception as e:
            print(f"[Socket.IO] User Auth Failed: {e}")
            return False

    # B. Agent Auth (API Key)
    if api_key:
        try:
             async with AsyncSessionLocal() as db:
                result = await db.execute(select(Tenant).where(Tenant.ApiKey == api_key))
                tenant = result.scalars().first()
                
                if tenant and auth:
                    agent_id = auth.get('room', f"Agent-{sid}")
                    
                    await sio.save_session(sid, {
                        'role': 'Agent',
                        'tenantId': tenant.Id,
                        'username': agent_id,
                        'is_agent': True,
                        'agent_id': agent_id 
                    })
                    print(f"[Socket.IO] Agent Connected: {agent_id} (Tenant: {tenant.Id})")
                    
                    # [FIX] Always join own agent room to ensure receipt of control commands
                    await sio.enter_room(sid, agent_id)
                    print(f"[Socket.IO] Agent strictly joined room: {agent_id}")
                    
                    return True
                else:
                    print(f"[Socket.IO] Agent Auth Failed: Invalid API Key {api_key}")
                    return False
        except Exception as e:
            print(f"[Socket.IO] DB Error during Agent Auth: {e}")
            return False

    if auth and 'room' in auth:
        # Validate Initial Room Join?
        # Usually frontend connects then emits 'join', but if they send room in handshake:
        pass 

@sio.event
async def disconnect(sid: str):
    print(f"[Socket.IO] Client Disconnected: {sid}")

@sio.on('update_progress')
async def on_update_progress(sid: str, data: Dict[str, Any]):
    """
    Relay update progress from Agent to Frontend.
    Data: {'agentId': '...', 'progress': 50}
    """
    # 1. Validate Session (Is this an Agent?)
    session = await sio.get_session(sid)
    if not session or not session.get('is_agent'):
        return # Ignore unauthorized
        
    agent_id = data.get('agentId')
    progress = data.get('progress')
    
    if agent_id and progress is not None:
        # Broadcast to Tenant Room so Frontend sees it
        tenant_id = session.get('tenantId')
        if tenant_id:
            room = f"tenant_{tenant_id}"
            await sio.emit('update_progress', data, room=room)

@sio.on('*')
async def catch_all(sid: str, event: str, data: Any):
    # print(f"[Socket.IO] Event DEBUG: SID={sid} Event={event} Data={data}")
    pass

@sio.on('join')
@sio.on('join_room')
async def on_join(sid: str, data: Dict[str, Any]):
    room = data.get('room')
    if not room:
        return
    await sio.enter_room(sid, room)
    print(f"[DEBUG] Client {sid} joined room: {room}")

    session = await sio.get_session(sid)
    user = session.get("user")
    
    print(f"[Socket.IO] Join Request from {sid}: Room={room} User={user.get('username') if user else 'None'}")

    # 1. If User is Authenticated
    if user:
        # A. Tenant Room Join (e.g. "tenant_123")
        if room.startswith("tenant_"):
            try:
                target_tid = int(room.split("_")[1])
                if user['role'] == "SuperAdmin" or user['tenantId'] == target_tid:
                    await sio.enter_room(sid, room)
                    print(f"[Socket.IO] {user['username']} successfully joined {room}")
                else:
                    print(f"[Socket.IO] Access Denied: {user['username']} (Tenant {user['tenantId']}) tried to join {room}")
            except Exception as e:
                print(f"[Socket.IO] Error parsing tenant room {room}: {e}")
                
        # B. Agent Room Join (e.g. "DEVICE-UUID")
        else:
             # Assume it's an Agent ID. Verify ownership.
             if user['role'] == "SuperAdmin":
                 await sio.enter_room(sid, room)
                 print(f"[Socket.IO] SuperAdmin joined Agent Room {room}")
             else:
                 async with AsyncSessionLocal() as db:
                     res = await db.execute(select(Agent).where(Agent.AgentId == room))
                     agent = res.scalars().first()
                     if agent and agent.TenantId == user['tenantId']:
                         await sio.enter_room(sid, room)
                         print(f"[Socket.IO] {user['username']} joined Agent Room {room}")
                     else:
                         print(f"[Socket.IO] Access Denied or Agent Not Found: {room} for user {user['username']}")

    # 2. If Not User (e.g. Agent connecting/joining its own room?)
    # Agents usually don't "join" explicitly via this event, they separate namespaces or just listen/emit.
    # If Agents DO use this 'join' event, we need a way to auth them (e.g. API Key).
    # For now, we assume this 'join' event is primarily for Frontend Clients watching streams.
    else:
        print(f"[Socket.IO] Unauthenticated join attempt for {room}")

@sio.on('bandwidth_stats')
async def handle_bandwidth_stats(sid: str, data: Any):
    """Handle real-time bandwidth stats from agent"""
    try:
        # We need to find which tenant this agent belongs to.
        # Ideally we have this in session, but for now we trust the room structure or look it up.
        # Assuming the agent is already in 'tenant_X' room is risky for broadcast, 
        # we want to broadcast TO the tenant admin, not FROM the tenant admin.
        # Actually, we just want to send this to the "tenant_dashboard" or similar.
        # For simplicity, let's assume admins join 'tenant_{id}' and agents join 'tenant_{id}_agents' or similar?
        # Existing logic: Agents join 'tenant_{id}'. Admins join 'tenant_{id}'?
        # If so, broadcasting to 'tenant_{id}' sends it to everyone including other agents.
        # Let's verify room logic.
        # For now, let's just emit to the room.
        
        # We need the Agent ID and Tenant ID.
        # In 'connect', we store this in sio.get_session(sid).
        session = await sio.get_session(sid)
        if not session: return

        agent_id = session.get('agent_id')
        tenant_id = session.get('tenantId') # Note: camelCase in save_session
            
        if agent_id and tenant_id:
             await sio.emit('agent_bandwidth_update', {
                'agent_id': agent_id,
                'stats': data
            }, room=f"tenant_{tenant_id}")
             
    except Exception as e:
        print(f"Error handling bandwidth stats: {e}")

@sio.on('agent_event')
async def on_agent_event(sid: str, data: Dict[str, Any]):
    """
    Receive generic events from agents (USB, Network, Security)
    and broadcast them to the dashboard.
    """
    session = await sio.get_session(sid)
    if not session:
        return

    # [SECURITY] Use tenantId from session, NOT from client payload
    tenant_id = session.get('tenantId')
    
    if tenant_id:
        room = f"tenant_{tenant_id}"
        # Ensure the data contains the correct tenantId for the frontend
        data['tenantId'] = tenant_id
        await sio.emit('new_alert', data, room=room)
    else:
        print(f"[Socket.IO] [WARNING] Agent event from {sid} ignored: No TenantId in session.")


# ======================================================
# LIVE STREAM & WEBRTC RELAY
# ======================================================

import httpx # type: ignore

@sio.on('start_stream')
async def on_start_stream(sid: str, data: Dict[str, Any]):
    """Relay user request to agent"""
    agent_id = data.get('agentId')
    if agent_id:
        print(f"[DEBUG] Signaling start_stream to room: {agent_id} | Data: {data}")
        
        # 1. Standard Redis Broadcast (High Availability)
        await sio.emit('StartStream', data, room=agent_id)
        
        # 2. [NEW] Internal Bridge Relay (Guaranteed Delivery)
        # This bypasses Redis signaling issues by calling the Gateway directly
        try:
            async with httpx.AsyncClient() as client:
                # Use internal Docker service name
                gateway_url = f"http://watch-sec-agent-gateway:8005/api/agent/internal/relay-stream/{agent_id}"
                print(f"[RELAY] Sending bridge signal to {gateway_url}")
                
                # Payload matches RelayStreamRequest schema
                relay_data = {
                    "width": data.get("width", 1280),
                    "quality": data.get("quality", 80),
                    "agentId": agent_id
                }
                
                response = await client.post(gateway_url, json=relay_data, timeout=2.0)
                print(f"[RELAY_STATUS] Gateway responded: {response.status_code}")
        except Exception as e:
            print(f"[RELAY_FAILED] Internal bridge unreachable: {e}")

@sio.on('stop_stream')
async def on_stop_stream(sid: str, data: Dict[str, Any]):
    """Relay 'stop_stream' from Frontend to Agent as 'StopStream'"""
    agent_id = data.get('agentId')
    if agent_id:
        print(f"[Socket.IO] Signaling: stop_stream -> Agent {agent_id}")
        await sio.emit('StopStream', data, room=agent_id)

@sio.on('ice_candidate')
async def on_ice_candidate(sid: str, data: Dict[str, Any]):
    """Relay ICE Candidate from Frontend to Agent as 'webrtc_ice_candidate'"""
    agent_id = data.get('target')
    if agent_id:
        await sio.emit('webrtc_ice_candidate', data, room=agent_id)

@sio.on('webrtc_answer')
async def on_webrtc_answer(sid: str, data: Dict[str, Any]):
    """Relay WebRTC Answer from Frontend to Agent"""
    agent_id = data.get('target')
    if agent_id:
        await sio.emit('webrtc_answer', data, room=agent_id)

@sio.on('RemoteInput')
async def on_remote_input(sid: str, data: Dict[str, Any]):
    """Relay Remote Input (Keyboard/Mouse) from Frontend to Agent"""
    agent_id = data.get('agentId')
    if agent_id:
        await sio.emit('RemoteInput', data, room=agent_id)

# --- Agent to Frontend Relays ---

@sio.on('stream_frame')
async def on_stream_frame(sid: str, data: Dict[str, Any]):
    """Relay JPEG frame from Agent to Frontend (as ReceiveScreen and stream_frame)"""
    session = await sio.get_session(sid)
    if not session or not session.get('is_agent'): return
    
    agent_id = session.get('agent_id')
    tenant_id = session.get('tenantId')
    
    if tenant_id:
        image_data = data.get('image')
        if not image_data: return
        
        # print(f"[DEBUG] Relaying frame from agent: {agent_id} (Tenant: {tenant_id})")
        # Agents.tsx expects 'ReceiveScreen' with (agentId, base64) as separate arguments
        # python-socketio: pass a tuple to have them delivered as separate args in JS
        await sio.emit('ReceiveScreen', (agent_id, image_data), room=f"tenant_{tenant_id}")
        await sio.emit('ReceiveScreen', (agent_id, image_data), room=agent_id) # Direct to agent room for focused listeners
        
        # RemoteDesktop.tsx expects 'stream_frame' with a single dict object
        await sio.emit('stream_frame', data, room=f"tenant_{tenant_id}")
        await sio.emit('stream_frame', data, room=agent_id) # Direct to agent room for focused listeners

@sio.on('webrtc_offer')
async def on_webrtc_offer(sid: str, data: Dict[str, Any]):
    """Relay WebRTC Offer from Agent to Frontend"""
    session = await sio.get_session(sid)
    if not session or not session.get('is_agent'): return
    
    tenant_id = session.get('tenantId')
    if tenant_id:
        await sio.emit('webrtc_offer', data, room=f"tenant_{tenant_id}")

@sio.on('webrtc_ice_candidate')
async def on_agent_ice_candidate(sid: str, data: Dict[str, Any]):
    """Relay ICE Candidate from Agent to Frontend as 'ice_candidate'"""
    session = await sio.get_session(sid)
    if not session or not session.get('is_agent'): return
    
    tenant_id = session.get('tenantId')
    if tenant_id:
        await sio.emit('ice_candidate', data, room=f"tenant_{tenant_id}")

