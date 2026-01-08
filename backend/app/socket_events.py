from .socket_instance import sio
from jose import JWTError, jwt
from sqlalchemy.future import select
from .core.security import SECRET_KEY, ALGORITHM
from .db.session import AsyncSessionLocal
from .db.models import Agent

@sio.event
async def connect(sid, environ, auth=None):
    # [SECURITY] Strict Auth
    token = None
    if auth:
        token = auth.get('token')
    
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
        from .db.models import Tenant
        try:
             async with AsyncSessionLocal() as db:
                result = await db.execute(select(Tenant).where(Tenant.ApiKey == api_key))
                tenant = result.scalars().first()
                
                if tenant:
                    await sio.save_session(sid, {
                        'role': 'Agent',
                        'tenantId': tenant.Id,
                        'username': f"Agent-{sid}",
                        'is_agent': True
                    })
                    print(f"[Socket.IO] Agent Connected for Tenant: {tenant.Name} (ID: {tenant.Id})")
                    
                    # Agent-Specific Room Join Logic
                    # If Agent sends room in auth, we honor it (usually AgentId)
                    if auth and 'room' in auth:
                        room = auth['room']
                        await sio.enter_room(sid, room)
                        print(f"[Socket.IO] Agent joined own room: {room}")
                    
                    return True
                else:
                    print(f"[Socket.IO] Agent Auth Failed: Invalid Key")
                    return False
        except Exception as e:
            print(f"[Socket.IO] DB Error during Agent Auth: {e}")
            return False

    if auth and 'room' in auth:
        # Validate Initial Room Join?
        # Usually frontend connects then emits 'join', but if they send room in handshake:
        pass 

@sio.event
async def disconnect(sid):
    print(f"[Socket.IO] Client Disconnected: {sid}")

@sio.on('join')
async def on_join(sid, data):
    session = await sio.get_session(sid)
    role = session.get('role')
    user_tenant_id = session.get('tenant_id')
    
    room = data.get('room')
    if not room:
        return

    # 1. Tenant Room Check
    if room.startswith('tenant_'):
        try:
            target_id = int(room.split('_')[1])
            if role != 'SuperAdmin' and user_tenant_id != target_id:
                print(f"[Socket.IO] blocked join tenant_{target_id} for user {session.get('username')}")
                return 
        except:
    session = await sio.get_session(sid)
    user = session.get("user")
    
    # 1. If User is Authenticated
    if user:
        # A. Tenant Room Join (e.g. "tenant_123")
        if room.startswith("tenant_"):
            try:
                target_tid = int(room.split("_")[1])
                if user['role'] == "SuperAdmin" or user['tenantId'] == target_tid:
                    await sio.enter_room(sid, room)
                    print(f"[Socket.IO] {user['username']} joined {room}")
                else:
                    print(f"[Socket.IO] Access Denied: {user['username']} tried to join {room}")
            except:
                pass
                
        # B. Agent Room Join (e.g. "DEVICE-UUID")
        else:
             # Assume it's an Agent ID. Verify ownership.
             if user['role'] == "SuperAdmin":
                 await sio.enter_room(sid, room)
             else:
                 async with AsyncSessionLocal() as db:
                     res = await db.execute(select(Agent).where(Agent.AgentId == room))
                     agent = res.scalars().first()
                     if agent and agent.TenantId == user['tenantId']:
                         await sio.enter_room(sid, room)
                         print(f"[Socket.IO] {user['username']} joined Agent Room {room}")
                     else:
                         print(f"[Socket.IO] Access Denied or Agent Not Found: {room}")

    # 2. If Not User (e.g. Agent connecting/joining its own room?)
    # Agents usually don't "join" explicitly via this event, they separate namespaces or just listen/emit.
    # If Agents DO use this 'join' event, we need a way to auth them (e.g. API Key).
    # For now, we assume this 'join' event is primarily for Frontend Clients watching streams.
    else:
        print(f"[Socket.IO] Unauthenticated join attempt for {room}")

@sio.on('agent_event')
async def on_agent_event(sid, data):
    """
    Receive generic events from agents (USB, Network, Security)
    and broadcast them to the dashboard.
    """
    # print(f"[Event] {data.get('type')} from {data.get('agent_id')}: {data.get('details')}")
    # Broadcast to specific tenant room if provided in data
    # The agent should send TenantId or we lookup. Assuming Agent sends for now or we just use global if missing (backward compat)
    # BUT we want to fix leaks. So if no TenantId, we might log it but not broadcast to all.
    # Ideally Agent sends "TenantId" in the event payload.
    
    tenant_id = data.get('tenantId') or data.get('TenantId')
    if tenant_id:
        room = f"tenant_{tenant_id}"
        await sio.emit('new_alert', data, room=room)
    else:
        # Fallback only for SuperAdmins listening on 'admin_global' if we implemented it, 
        # or just drop to prevent leak.
        pass
        # await sio.emit('new_alert', data, room='dashboard') # DISABLED LEAK
