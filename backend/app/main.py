from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import socketio
from .socket_instance import sio
from .api import reports, auth, dashboard, ai, tenants, users, agents, install, downloads, commands, events, mail, audit, screenshots, policies, productivity, billing, uploads

# Initialize App
app = FastAPI(title="WatchSec Backend", version="2.0.0")

# CORS
# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_origin_regex=r"https://.*\.ngrok-free\.app|https://.*\.trycloudflare\.com|http://localhost:\d+|http://127\.0\.0\.1:\d+",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount Socket.IO
app.mount("/socket.io", socketio.ASGIApp(sio))

@sio.event
async def connect(sid, environ, auth=None):
    print(f"Socket Connected: {sid}. Auth: {auth}")
    if auth and 'room' in auth:
        room = auth['room']
        await sio.enter_room(sid, room)
        print(f"[STREAM_DEBUG] Socket {sid} Auto-JOINED room {room} via Auth")

@sio.on('join_room')
async def join_room(sid, data):
    room = data.get('room')
    if room:
        await sio.enter_room(sid, room)
        print(f"[STREAM_DEBUG] Socket {sid} JOINED room {room}")
        # Verify
        # participants = sio.manager.rooms.get('/', {}).get(room, "Unknown")
        # print(f"  -> Room Members: {participants}")
    else:
        print(f"[STREAM_DEBUG] Socket {sid} tried to join None room")

@sio.event
async def disconnect(sid):
    print(f"Socket Disconnected: {sid}")

# --- Live Streaming Events ---
# --- Live Streaming Events ---
@sio.on('*')
async def catch_all(event, sid, data):
    print(f"[STREAM_DEBUG] Catch-All: Unhandled Event '{event}' from {sid}")

@sio.on('start_stream')
async def StartStream(sid, data):
    # Frontend -> Backend -> Agent
    target_agent_id = data.get('agentId')
    print(f"[STREAM_DEBUG] Backend received start_stream for: {target_agent_id}")   
    print(f"[STREAM_DEBUG] Backend received start_stream for: {data}")  
    print(f"[STREAM_DEBUG] Backend received start_stream for: {sid}")  
    # DEBUG: Inspect Room
    # Note: access depends on Manager type, assuming Defaults (MemoryManager)
    try:
        # Dictionary of rooms: sio.manager.rooms[namespace][room_name] -> set(sids)
        namespace_rooms = sio.manager.rooms.get('/', {})
        participants = namespace_rooms.get(target_agent_id, "ROOM_NOT_FOUND")
        
        # Print ALL rooms to see what's available
        print(f"[STREAM_DEBUG] Available Rooms: {list(namespace_rooms.keys())}")
        print(f"[STREAM_DEBUG] StartStream for {target_agent_id}. Room Participants: {participants}")
    except Exception as e:
        print(f"[STREAM_DEBUG] Could not inspect room: {e}")

    print(f"[STREAM_DEBUG] Backend received start_stream. Relaying...")
    await sio.emit('start_stream', data, room=target_agent_id)

@sio.on('stop_stream')
async def StopStream(sid, data):
    # Frontend -> Backend -> Agent
    target_agent_id = data.get('agentId')
    print(f"[STREAM_DEBUG] Backend received stop_stream for: {target_agent_id}. Relaying to room.")
    await sio.emit('stop_stream', data, room=target_agent_id)

@sio.on('stream_frame')
async def StreamFrame(sid, data):
    # Agent -> Backend -> Frontend
    # data: { agentId, image (base64) }
    agent_id = data.get('agentId')
    
    # Debug Frame Receipt
    img_len = len(data.get('image', ''))
    # Throttle logs slightly or just print short info
    print(f"[STREAM_DEBUG] Frame received from {agent_id}, Size: {img_len}")

    # Check Room (Diagnosis)
    # participants = sio.manager.rooms.get('/', {}).get(agent_id, set())
    # if not participants:
    #     print(f"[STREAM_DEBUG] WARNING: No listeners in room {agent_id}! Frame dropped.")

    # Broadcast to room so frontend receives it
    await sio.emit('receive_stream_frame', data, room=agent_id)

# Include Routers
app.include_router(auth.router, prefix="/api/auth", tags=["Auth"])
app.include_router(tenants.router, prefix="/api/tenants", tags=["Tenants"])
app.include_router(users.router, prefix="/api/users", tags=["Users"])
app.include_router(agents.router, prefix="/api/agents", tags=["Agents"])
app.include_router(install.router, prefix="/api/install", tags=["Install"])
app.include_router(downloads.router, prefix="/api/downloads", tags=["Downloads"])
app.include_router(commands.router, prefix="/api/commands", tags=["Commands"])
app.include_router(events.router, prefix="/api/events", tags=["Events"])
app.include_router(mail.router, prefix="/api/mail", tags=["Mail"])
app.include_router(audit.router, prefix="/api/audit", tags=["Audit"])
app.include_router(screenshots.router, prefix="/api/screenshots", tags=["Screenshots"])
app.include_router(policies.router, prefix="/api/policies", tags=["Policies"])
app.include_router(productivity.router, prefix="/api/productivity", tags=["Productivity"])
app.include_router(billing.router, prefix="/api/billing", tags=["Billing"])
app.include_router(uploads.router, prefix="/api/uploads", tags=["Uploads"])
app.include_router(reports.router, prefix="/api", tags=["Reports"])
app.include_router(dashboard.router, prefix="/api", tags=["Dashboard"])
app.include_router(ai.router, prefix="/api/ai", tags=["Artificial Intelligence"])

@app.get("/")
async def root():
    return {"message": "WatchSec Backend (Python Edition) is Running", "status": "Online"}

@app.get("/api/health")
async def health_check():
    return {"status": "healthy", "version": "python-2.0.0"}

# Main Entry Point for Debugging
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)
