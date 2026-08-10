from .socket_instance import sio # type: ignore
from jose import JWTError, jwt # type: ignore
from sqlalchemy.future import select # type: ignore
from .core.security import SECRET_KEY, ALGORITHM # type: ignore
from .db.session import AsyncSessionLocal # type: ignore
from .db.models import Agent, Tenant # type: ignore
from typing import Any, Dict, Optional, List # type: ignore
import httpx # type: ignore
import secrets 
import hmac 
import hashlib

# [NEW] Persistent client for high-performance bridge relaying
_bridge_client = httpx.AsyncClient(timeout=2.0)


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
    # [AGENT AUTH] Check for API Key or Machine Secret if no User Token
    api_key = None
    machine_secret = None
    if auth:
        api_key = auth.get('apiKey')
        machine_secret = auth.get('machineSecret')

    if not token and not api_key and not machine_secret:
        print(f"[Socket.IO] Connection Rejected: No Token, API Key, or Machine Secret ({sid})")
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
            await sio.enter_room(sid, f"tenant_{tenant_id}")
            print(f"[Socket.IO] User Connected: {username} ({role}) - Room: tenant_{tenant_id}")
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
                    agent_id = auth.get('room')
                    if not agent_id: return False
                    
                    # [v1.8.37] Identity Pinning: Verify Agent-Tenant Ownership
                    res = await db.execute(select(Agent).where(Agent.AgentId == agent_id))
                    existing_agent = res.scalars().first()
                    
                    if existing_agent and existing_agent.TenantId != tenant.Id:
                         print(f"[SECURITY ALERT] SID {sid} tried to spoof Agent {agent_id}!")
                         return False

                    challenge = secrets.token_hex(16)
                    await sio.save_session(sid, {
                        'role': 'Agent',
                        'is_agent': True, # [NEW] v1.8.37
                        'tenantId': tenant.Id,
                        'agent_id': agent_id,
                        'challenge': challenge,
                        'is_verified': False
                    })
                    
                    await sio.emit('identity_challenge', {'challenge': challenge}, to=sid)
                    return True
                return False
        except Exception as e:
            print(f"[Socket.IO] Agent Auth Error: {e}")
            return False

    # C. Agent Auth (Machine Secret / Zero Trust)
    if machine_secret:
        try:
            async with AsyncSessionLocal() as db:
                agent_id = auth.get('room') if auth else None
                if not agent_id: return False
                
                res = await db.execute(select(Agent).where(Agent.AgentId == agent_id))
                agent = res.scalars().first()
                
                if agent and agent.MachineId:
                    # Validate the provided machine secret directly
                    # In this setup, MachineId IS the MachineSecret (or derived from it).
                    # Actually, the agent has the MachineSecret. We need to verify it.
                    # For a websocket, we can just issue a challenge as well.
                    challenge = secrets.token_hex(16)
                    await sio.save_session(sid, {
                        'role': 'Agent',
                        'is_agent': True,
                        'tenantId': agent.TenantId,
                        'agent_id': agent_id,
                        'challenge': challenge,
                        'is_verified': False
                    })
                    await sio.emit('identity_challenge', {'challenge': challenge}, to=sid)
                    return True
                return False
        except Exception as e:
            print(f"[Socket.IO] Agent Machine Secret Auth Error: {e}")
            return False

    return False

@sio.event
async def disconnect(sid: str):
    print(f"[Socket.IO] Client Disconnected: {sid}")

@sio.on('update_progress')
async def on_update_progress(sid: str, data: Dict[str, Any]):
    """
    Relay update progress from Agent to Frontend.
    Data: {'agentId': '...', 'progress': 50}
    """
    # 1. Validate Session (Is this a Verified Agent?)
    session = await sio.get_session(sid)
    if not session or not session.get('is_agent') or not session.get('is_verified'):
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

@sio.on('verify_identity')
async def on_verify_identity(sid: str, data: Dict[str, Any]):
    """
    Complete the Challenge-Response handshake.
    Agent sends HMACSig(challenge, machine_secret).
    """
    session = await sio.get_session(sid)
    if not session or not session.get('agent_id'): return
    
    challenge = session.get('challenge')
    signature = data.get('signature')
    agent_id = session.get('agent_id')
    tenant_id = session.get('tenantId')

    # [v1.8.37] Proof of Hardware logic
    # We re-derive the expected signature using the tenant secret + agent identity info
    # In a real PROD system, we'd look up the agent's unique pubkey or registered secret.
    # For this hardened demo, we use the Ghost Identity pattern (Key salt).
    async with AsyncSessionLocal() as db:
        res = await db.execute(select(Tenant).where(Tenant.Id == tenant_id))
        tenant = res.scalars().first()
        if not tenant: return
        
        # [v1.8.37] Cryptographic Verification Gate
        # Upgrade: Use the actual MachineId from the database record
        res_a = await db.execute(select(Agent).where(Agent.AgentId == agent_id))
        agent = res_a.scalars().first()
        if not agent or not agent.MachineId:
             # Fallback to derivation for un-migrated agents
             secret = f"HW_PROOF_{tenant.ApiKey}_{agent_id}".encode()
        else:
             # Use authoritative Hardware ID as the HMAC Key
             secret = hashlib.sha256(tenant.ApiKey.encode() + agent.MachineId.encode()).digest()
             
        expected = hmac.new(secret, challenge.encode(), hashlib.sha256).hexdigest()
        
        if hmac.compare_digest(signature, expected):
            print(f"[Socket.IO] Handshake SUCCESS for Agent {agent_id}. Access Granted.")
            session['is_verified'] = True
            await sio.save_session(sid, session)
            # ONLY NOW join the command room
            await sio.enter_room(sid, agent_id)
            await sio.emit('identity_verified', {'status': 'OK'}, to=sid)
        else:
            print(f"[SECURITY ALERT] Handshake FAILED for Agent {agent_id}. Disconnecting.")
            await sio.disconnect(sid)

@sio.on('join')
@sio.on('join_room')
async def on_join(sid: str, data: Dict[str, Any]):
    room = data.get('room')
    if not room:
        return
    
    session = await sio.get_session(sid)
    if not session:
        print(f"[Socket.IO] Join Rejection: No Session for {sid}")
        return
        
    user = session.get("user")
    # [v1.2.5] Fallback for legacy session structure
    if not user and session.get('username'):
        user = session
    
    print(f"[Socket.IO] Join Request from {sid}: Room={room} User={user.get('username') if user else 'None'}")

    # 1. If User is Authenticated
    if user:
        # A. Tenant Room Join (e.g. "tenant_123")
        if str(room).startswith("tenant_"):
            try:
                target_tid = int(str(room).split("_")[1])
                if user.get('role') == "SuperAdmin" or int(user.get('tenantId', -1)) == target_tid:
                    await sio.enter_room(sid, room)
                    print(f"[Socket.IO] {user.get('username')} successfully joined {room}")
                else:
                    print(f"[Socket.IO] Access Denied: {user.get('username')} (Tenant {user.get('tenantId')}) tried to join {room}")
            except Exception as e:
                print(f"[Socket.IO] Error parsing tenant room {room}: {e}")
                
        # B. Agent Room Join (e.g. "DEVICE-UUID")
        else:
             # Assume it's an Agent ID. [SECURITY] Verify ownership to prevent cross-agent snooping.
             target_agent_id = str(room)
             if user.get('role') == "SuperAdmin":
                 await sio.enter_room(sid, target_agent_id)
                 print(f"[Socket.IO] SuperAdmin joined Agent Room {target_agent_id}")
             else:
                 async with AsyncSessionLocal() as db:
                     res = await db.execute(select(Agent).where(Agent.AgentId == target_agent_id))
                     agent = res.scalars().first()
                     if agent and agent.TenantId == user.get('tenantId'):
                         await sio.enter_room(sid, target_agent_id)
                         print(f"[Socket.IO] {user.get('username')} joined Agent Room {target_agent_id}")
                     else:
                         print(f"[Socket.IO] Access Denied or Agent Not Found: {target_agent_id} for user {user.get('username')}")

    # 2. If Not User (e.g. Agent connecting/joining its own room?)
    elif session.get('is_agent'):
         # Agents are allowed to join their own rooms (already handled in connect, but just in case)
         if session.get('agent_id') == room:
             await sio.enter_room(sid, room)
    else:
        print(f"[Socket.IO] Unauthenticated join attempt for {room} from {sid}")

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
        if not session or not session.get('is_verified'): return

        agent_id = session.get('agent_id')
            
        if agent_id:
             # [v1.8.37] Signal Isolation: Emit only to the private agent room
             await sio.emit('agent_bandwidth_update', {
                'agent_id': agent_id,
                'stats': data
            }, room=agent_id)
             
    except Exception as e:
        print(f"Error handling bandwidth stats: {e}")

@sio.on('agent_event')
async def on_agent_event(sid: str, data: Dict[str, Any]):
    """
    Receive generic events from agents (USB, Network, Security)
    and broadcast them to the dashboard.
    """
    session = await sio.get_session(sid)
    if not session or not session.get('is_verified'):
        return

    # [SECURITY] Use tenantId and agent_id from session, NOT from client payload
    tenant_id = session.get('tenantId')
    agent_id = session.get('agent_id')
    
    if tenant_id and agent_id:
        # [v1.8.37] Signal Isolation: Emit strictly to the private agent room
        # Ensure the data contains the correct tenantId for the frontend
        data['tenantId'] = tenant_id
        await sio.emit('new_alert', data, room=agent_id)
    else:
        print(f"[Socket.IO] [WARNING] Agent event from {sid} ignored: Missing context.")


# ======================================================
# LIVE STREAM & WEBRTC RELAY
# ======================================================

import httpx # type: ignore

async def _validate_agent_access(session: Dict, agent_id: str) -> bool:
    """Helper to verify if a socket session has access to a specific agent"""
    if not session: return False
    if session.get('role') == "SuperAdmin": return True
    
    tenant_id = session.get('tenantId')
    if not tenant_id: return False
    
    async with AsyncSessionLocal() as db:
        res = await db.execute(select(Agent.TenantId).where(Agent.AgentId == agent_id))
        owner_id = res.scalar()
        return owner_id == tenant_id

@sio.on('start_stream')
async def on_start_stream(sid: str, data: Dict[str, Any]):
    """Relay user request to agent"""
    session = await sio.get_session(sid)
    agent_id = data.get('agentId')
    if agent_id:
        if not await _validate_agent_access(session, agent_id):
            print(f"[SECURITY ALERT] Unauthorized start_stream attempt by {sid} for Agent {agent_id}")
            return

        print(f"[DEBUG] Signaling start_stream to room: {agent_id} | Data: {data}")
        
        # 1. Standard Redis Broadcast (High Availability)
        await sio.emit('StartStream', data, room=agent_id)
        
        # 2. [OPTIMIZED] Internal Bridge Relay (Shared Client)
        try:
            # Use internal Docker service name
            gateway_url = f"http://watch-sec-agent-gateway:8005/api/agent/internal/relay-stream/{agent_id}"
            
            # Payload matches RelayStreamRequest schema
            relay_data = {
                "width": data.get("width", 1280),
                "quality": data.get("quality", 80),
                "agentId": agent_id
            }
            
            response = await _bridge_client.post(gateway_url, json=relay_data)
            # print(f"[RELAY_STATUS] Gateway responded: {response.status_code}")
        except Exception as e:
            print(f"[RELAY_FAILED] Internal bridge unreachable: {e}")

@sio.on('stop_stream')
async def on_stop_stream(sid: str, data: Dict[str, Any]):
    """Relay 'stop_stream' from Frontend to Agent as 'StopStream'"""
    session = await sio.get_session(sid)
    agent_id = data.get('agentId')
    if agent_id:
        if not await _validate_agent_access(session, agent_id):
            return

        print(f"[Socket.IO] Signaling: stop_stream -> Agent {agent_id}")
        await sio.emit('StopStream', data, room=agent_id)

@sio.on('ice_candidate')
async def on_ice_candidate(sid: str, data: Dict[str, Any]):
    """Relay ICE Candidate from Frontend to Agent as 'webrtc_ice_candidate'"""
    session = await sio.get_session(sid)
    agent_id = data.get('target')
    if agent_id:
        if not await _validate_agent_access(session, agent_id):
            return
        await sio.emit('webrtc_ice_candidate', data, room=agent_id)

@sio.on('webrtc_answer')
async def on_webrtc_answer(sid: str, data: Dict[str, Any]):
    """Relay WebRTC Answer from Frontend to Agent"""
    session = await sio.get_session(sid)
    agent_id = data.get('target')
    if agent_id:
        if not await _validate_agent_access(session, agent_id):
            return
        await sio.emit('webrtc_answer', data, room=agent_id)

@sio.on('RemoteInput')
async def on_remote_input(sid: str, data: Dict[str, Any]):
    """Relay Remote Input (Keyboard/Mouse) from Frontend to Agent"""
    session = await sio.get_session(sid)
    agent_id = data.get('agentId')
    if agent_id:
        if not await _validate_agent_access(session, agent_id):
            return
        await sio.emit('RemoteInput', data, room=agent_id)

# --- Agent to Frontend Relays ---

@sio.on('stream_frame')
async def on_stream_frame(sid: str, data: Dict[str, Any]):
    """
    Relay JPEG frame from Agent to Frontend.
    [SECURITY] BROADCAST ISOLATION: We now emit to the private agent room ONLY.
    """
    session = await sio.get_session(sid)
    if not session or not session.get('is_agent') or not session.get('is_verified'): return
    
    agent_id = session.get('agent_id')
    
    if agent_id:
        image_data = data.get('image')
        if not image_data: return
        
        # [v1.8.34] Isolated Relay: Only users authorized for THIS agent see the frame
        await sio.emit('ReceiveScreen', (agent_id, image_data), room=agent_id)
        await sio.emit('stream_frame', data, room=agent_id)

@sio.on('webrtc_offer')
async def on_webrtc_offer(sid: str, data: Dict[str, Any]):
    """Relay WebRTC Offer from Agent to private agent room"""
    session = await sio.get_session(sid)
    if not session or not session.get('is_agent') or not session.get('is_verified'): return
    
    agent_id = session.get('agent_id')
    if agent_id:
        await sio.emit('webrtc_offer', data, room=agent_id)

@sio.on('webrtc_ice_candidate')
async def on_agent_ice_candidate(sid: str, data: Dict[str, Any]):
    """Relay ICE Candidate from Agent to private agent room"""
    session = await sio.get_session(sid)
    if not session or not session.get('is_agent'): return
    
    agent_id = session.get('agent_id')
    if agent_id:
        await sio.emit('ice_candidate', data, room=agent_id)

# ======================================================
# AGENTLESS TERMINAL (SSH)
# ======================================================

import asyncssh # type: ignore
import asyncio # type: ignore

# Dictionary to hold active SSH processes mapped by Socket ID and Endpoint IP
# active_terminals[sid][endpoint_ip] = process
active_terminals = {}

@sio.on('start_agentless_terminal')
async def on_start_agentless_terminal(sid: str, data: Dict[str, Any]):
    session = await sio.get_session(sid)
    if not session or session.get('role') not in ['SuperAdmin', 'TenantAdmin']:
        await sio.emit('agentless_terminal_output', {'output': '\r\nAccess Denied\r\n'}, to=sid)
        return
        
    endpoint_ip = data.get('ip')
    terminal_id = data.get('terminal_id')
    if not endpoint_ip or not terminal_id: return
    
    # Spawn background task so we don't block the socket thread
    asyncio.create_task(_run_agentless_ssh(sid, endpoint_ip, terminal_id))

async def _run_agentless_ssh(sid: str, endpoint_ip: str, terminal_id: str):
    from .services.agentless_engine import agentless_engine # type: ignore
    from .db.session import AsyncSessionLocal # type: ignore
    from .db.models import AgentlessEndpoint # type: ignore
    try:
        async with AsyncSessionLocal() as db:
            # 1. Tenant Isolation Check
            res = await db.execute(select(AgentlessEndpoint).where(AgentlessEndpoint.IpAddress == endpoint_ip))
            endpoint = res.scalars().first()
            
            if not endpoint:
                await sio.emit('agentless_terminal_output', {'terminal_id': terminal_id, 'ip': endpoint_ip, 'output': '\r\nError: Endpoint not found in database.\r\n'}, to=sid)
                return
                
            session = await sio.get_session(sid)
            user_tenant_id = int(session.get('tenantId', -1))
            if session.get('role') != 'SuperAdmin' and endpoint.TenantId != user_tenant_id:
                await sio.emit('agentless_terminal_output', {'terminal_id': terminal_id, 'ip': endpoint_ip, 'output': '\r\n[SECURITY ALERT] Access Denied: Tenant Isolation Enforcement blocked cross-tenant connection.\r\n'}, to=sid)
                return
                
            await sio.emit('agentless_terminal_output', {'terminal_id': terminal_id, 'ip': endpoint_ip, 'output': f'\r\n[Monitorix] Initializing secure connection to {endpoint_ip}...\r\n'}, to=sid)
            
            creds = await agentless_engine.get_vault_credentials_for_terminal(endpoint_ip, db)
            
        if creds['type'] != 'ssh_key' and creds['type'] != 'password':
            await sio.emit('agentless_terminal_output', {'terminal_id': terminal_id, 'ip': endpoint_ip, 'output': '\r\nError: Unsupported credential type.\r\n'}, to=sid)
            return
            
        # Construct kwargs based on credential type
        connect_kwargs = {
            'host': endpoint_ip,
            'username': creds['username'],
        }
        
        # 2. Trust On First Use (TOFU)
        if endpoint.SshHostKeyFingerprint:
            connect_kwargs['known_hosts'] = asyncssh.import_known_hosts(f"{endpoint_ip} {endpoint.SshHostKeyFingerprint}")
        else:
            connect_kwargs['known_hosts'] = None # Accept any on first use
        
        if creds['type'] == 'ssh_key':
            connect_kwargs['client_keys'] = [asyncssh.import_private_key(creds['secret'])]
        elif creds['type'] == 'password':
            connect_kwargs['password'] = creds['secret']
            
        async with asyncssh.connect(**connect_kwargs) as conn:
            # Handle TOFU save
            if not endpoint.SshHostKeyFingerprint:
                new_fingerprint = conn.get_server_host_key().export_public_key('openssh').decode('utf-8').strip()
                async with AsyncSessionLocal() as db_update:
                    res_up = await db_update.execute(select(AgentlessEndpoint).where(AgentlessEndpoint.IpAddress == endpoint_ip))
                    ep_up = res_up.scalars().first()
                    ep_up.SshHostKeyFingerprint = new_fingerprint
                    await db_update.commit()
                await sio.emit('agentless_terminal_output', {'terminal_id': terminal_id, 'ip': endpoint_ip, 'output': '\r\n[Security] First time connecting. Host Key Fingerprint saved (TOFU).\r\n'}, to=sid)
            
            # Request a pseudo-terminal (PTY)
            async with conn.create_process(term_type='xterm-256color', term_size=(80, 24)) as process:
                if sid not in active_terminals:
                    active_terminals[sid] = {}
                active_terminals[sid][terminal_id] = process
                
                await sio.emit('agentless_terminal_output', {'terminal_id': terminal_id, 'ip': endpoint_ip, 'output': '\r\n--- SECURE SHELL ESTABLISHED ---\r\n'}, to=sid)
                
                # Continuously read from stdout/stderr and pipe to websocket
                while True:
                    out = await process.stdout.read(4096)
                    if not out:
                        break
                    # If bytes, decode, else string
                    if isinstance(out, bytes):
                        out = out.decode('utf-8', errors='replace')
                    await sio.emit('agentless_terminal_output', {'terminal_id': terminal_id, 'ip': endpoint_ip, 'output': out}, to=sid)
                    
    except asyncssh.PermissionDenied:
        await sio.emit('agentless_terminal_output', {'terminal_id': terminal_id, 'ip': endpoint_ip, 'output': '\r\n[Terminal Error] Permission Denied: Invalid credentials in vault.\r\n'}, to=sid)
    except asyncssh.KeyExchangeFailed as e:
        await sio.emit('agentless_terminal_output', {'terminal_id': terminal_id, 'ip': endpoint_ip, 'output': f'\r\n[CRITICAL SECURITY ALERT] Host Key Mismatch! Possible Man-In-The-Middle Attack.\r\nConnection Aborted.\r\nDetails: {str(e)}\r\n'}, to=sid)
    except Exception as e:
        await sio.emit('agentless_terminal_output', {'terminal_id': terminal_id, 'ip': endpoint_ip, 'output': f'\r\n[Terminal Error] {str(e)}\r\n'}, to=sid)
    finally:
        if sid in active_terminals and terminal_id in active_terminals[sid]:
            del active_terminals[sid][terminal_id]
        await sio.emit('agentless_terminal_output', {'terminal_id': terminal_id, 'ip': endpoint_ip, 'output': '\r\n--- CONNECTION CLOSED ---\r\n'}, to=sid)

@sio.on('agentless_terminal_input')
async def on_agentless_terminal_input(sid: str, data: Dict[str, Any]):
    char = data.get('input')
    terminal_id = data.get('terminal_id')
    
    if sid in active_terminals and terminal_id in active_terminals[sid] and char:
        process = active_terminals[sid][terminal_id]
        # Write to process stdin
        if isinstance(char, str):
            process.stdin.write(char)
        else:
            process.stdin.write(char.decode('utf-8'))

