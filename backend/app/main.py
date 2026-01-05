from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import socketio

from .db.session import settings
from .socket_instance import sio

from .api import (
    reports, auth, dashboard, ai, tenants, users, agents, install,
    downloads, commands, events, mail, audit, screenshots, policies,
    productivity, billing, uploads, system, ocr, thesaurus, speech,
    hashbank, fingerprints, searches, remote
)

# ======================================================
# Load Settings (Lazy + Cached – Railway Safe)
# ======================================================
# settings = settings()

# ======================================================
# FastAPI App
# ======================================================
app = FastAPI(
    title="WatchSec Backend",
    version="2.0.0",
)


# ======================================================
# CORS Middleware (MUST be before Socket.IO)
# ======================================================
# Combine settings and local definitions
# Combine settings and local definitions
# Combine settings and local definitions
# DEBUG: Allowing ALL origins temporarily to resolve persistent CORS error.
allow_origins = ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allow_origins,
    allow_origin_regex=None,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ======================================================
# Socket.IO Mount
# ======================================================
app.mount("/socket.io", socketio.ASGIApp(sio))


# ======================================================
# Socket.IO Events
# ======================================================
@sio.event
async def connect(sid, environ, auth=None):
    print(f"[SOCKET] Connected: {sid}, Auth: {auth}")
    if auth and "room" in auth:
        await sio.enter_room(sid, auth["room"])
        print(f"[SOCKET] {sid} joined room {auth['room']}")

@sio.event
async def disconnect(sid):
    print(f"[SOCKET] Disconnected: {sid}")

@sio.on("*")
async def catch_all(event, sid, data):
    print(f"[SOCKET] Unhandled Event '{event}' from {sid}")

# ======================================================
# Streaming Events
# ======================================================
@sio.on("start_stream")
async def start_stream(sid, data):
    agent_id = data.get("agentId")
    print(f"[STREAM] start_stream -> {agent_id}")
    await sio.emit("start_stream", data, room=agent_id)

@sio.on("stop_stream")
async def stop_stream(sid, data):
    agent_id = data.get("agentId")
    print(f"[STREAM] stop_stream -> {agent_id}")
    await sio.emit("stop_stream", data, room=agent_id)

@sio.on("stream_frame")
async def stream_frame(sid, data):
    agent_id = data.get("agentId")
    img_len = len(data.get("image", ""))
    print(f"[STREAM] frame from {agent_id} ({img_len} bytes)")
    await sio.emit("receive_stream_frame", data, room=agent_id)

# ======================================================
# WebRTC Signaling
# ======================================================
@sio.on("webrtc_offer")
async def webrtc_offer(sid, data):
    await sio.emit("webrtc_offer", data, room=data.get("target"), skip_sid=sid)

@sio.on("webrtc_answer")
async def webrtc_answer(sid, data):
    await sio.emit("webrtc_answer", data, room=data.get("target"), skip_sid=sid)

@sio.on("ice_candidate")
async def ice_candidate(sid, data):
    await sio.emit("ice_candidate", data, room=data.get("target"), skip_sid=sid)

# ======================================================
# API Routers
# ======================================================
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
app.include_router(ai.router, prefix="/api/ai", tags=["AI"])
app.include_router(system.router, prefix="/api", tags=["System"])
app.include_router(ocr.router, prefix="/api", tags=["OCR"])
app.include_router(thesaurus.router, prefix="/api", tags=["Thesaurus"])
app.include_router(speech.router, prefix="/api", tags=["Speech"])
app.include_router(hashbank.router, prefix="/api", tags=["HashBanks"])
app.include_router(fingerprints.router, prefix="/api", tags=["Fingerprints"])
app.include_router(searches.router, prefix="/api", tags=["Searches"])
app.include_router(remote.router, prefix="/api", tags=["Remote Control"])

# ======================================================
# Health Endpoints
# ======================================================
@app.get("/")
async def root():
    return {
        "service": "WatchSec Backend",
        "status": "online",
    }

@app.get("/api/health")
async def health():
    return {
        "status": "healthy",
        "version": "2.0.0",
    }

# Main Entry Point for Debugging
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)

# Force Reload Trigger 3
