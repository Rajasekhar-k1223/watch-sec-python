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
    allow_origin_regex=r"https://.*\.ngrok-free\.app|https://.*\.trycloudflare\.com|http://localhost:\d+|http://127\.0\.0\.1:\d+",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount Socket.IO
app.mount("/socket.io", socketio.ASGIApp(sio))

@sio.event
async def connect(sid, environ):
    print(f"Socket Connected: {sid}")

@sio.event
async def join_room(sid, data):
    room = data.get('room')
    if room:
        sio.enter_room(sid, room)
        print(f"Socket {sid} joined room {room}")

@sio.event
async def disconnect(sid):
    print(f"Socket Disconnected: {sid}")

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
