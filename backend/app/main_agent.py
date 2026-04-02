from contextlib import asynccontextmanager # type: ignore
import fastapi # type: ignore # pyre-ignore
from fastapi import FastAPI, Response, Request # type: ignore # pyre-ignore
from fastapi.exceptions import RequestValidationError # type: ignore
from fastapi.middleware.cors import CORSMiddleware # type: ignore
import socketio # type: ignore
from sqlalchemy import text # type: ignore
from .socket_instance import sio # type: ignore
from .db.session import settings, engine # type: ignore

from .api import ( # type: ignore
    auth, tenants, users, agents, install, # type: ignore
    downloads, commands, events, mail, audit, # type: ignore
    screenshots, policies, productivity, billing, # type: ignore
    uploads, reports, dashboard, ai, system, # type: ignore
    ocr, thesaurus, speech, hashbank, fingerprints, # type: ignore
    searches, remote, vulnerabilities, trials, agents, bandwidth, # type: ignore
    notifications, report_downloads # type: ignore
) # type: ignore
import asyncio # type: ignore

@asynccontextmanager
async def lifespan(app: FastAPI):
    # --- STARTUP: Database Check ---
    print("--- STARTUP: API Server Ready ---")

    async def cleanup_update_status():
        while True:
            await asyncio.sleep(600) # Every 10 mins
            try:
                from .db.session import AsyncSessionLocal # type: ignore
                from .db.models import Agent # type: ignore
                from datetime import datetime, timedelta # type: ignore
                from sqlalchemy import update # type: ignore
                
                async with AsyncSessionLocal() as db:
                    ten_mins_ago = datetime.utcnow() - timedelta(minutes=10)
                    q = update(Agent).where(
                        Agent.UpdateStatus == "pending",
                        Agent.LastUpdateAttempt < ten_mins_ago
                    ).values(
                        UpdateStatus="failed",
                        UpdateFailureReason="Update Timeout: Agent did not report back within 10 minutes."
                    )
                    await db.execute(q)
                    await db.commit()
                    print("[Cleanup] Stale update statuses timed out.")
            except Exception as e:
                print(f"[Cleanup Error] {e}")

    asyncio.create_task(cleanup_update_status())
    
    # [NEW] Trial Expiration Background Task
    async def expire_trials_task():
        while True:
            await asyncio.sleep(60)  # Check every minute
            try:
                from .db.session import AsyncSessionLocal # type: ignore
                from .core import trial_manager # type: ignore
                
                async with AsyncSessionLocal() as db:
                    expired_trials = await trial_manager.find_expired_trials(db)
                    
                    for trial in expired_trials:
                        # Mark trial as inactive
                        await trial_manager.expire_trial(db, trial)
                        
                        # Emit Socket.IO event to disable feature on all tenant agents
                        await sio.emit(
                            'UpdateConfig',
                            {trial.FeatureName: False},
                            room=f"tenant_{trial.TenantId}"
                        )
                        
                        print(f"[Trial] Expired {trial.FeatureName} for Tenant {trial.TenantId}")
            except Exception as e:
                print(f"[Trial Expiration Error] {e}")
    
    asyncio.create_task(expire_trials_task())
    yield
    # --- SHUTDOWN ---
    print("--- SHUTDOWN ---")


# ======================================================
# FastAPI App
# ======================================================
app = FastAPI(
    title="Monitorix Agent Gateway",
    version="1.2.2",
    lifespan=lifespan,
)

# ======================================================
# CORS — SINGLE SOURCE OF TRUTH
# ======================================================
ALLOWED_ORIGINS = settings.BACKEND_CORS_ORIGINS


# Trust X-Forwarded-Proto from Nginx to generate HTTPS links/redirects
from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware # type: ignore
app.add_middleware(ProxyHeadersMiddleware, trusted_hosts="*")

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ======================================================
# API ROUTERS (Minimal Ingestion Set)
# ======================================================
app.include_router(auth.router, prefix="/api/auth", tags=["Auth"])
app.include_router(agents.router, prefix="/api/agents", tags=["Agents"])
app.include_router(agents.agent_router, prefix="/api/agent", tags=["Agent Communication"])
app.include_router(downloads.router, prefix="/api/downloads", tags=["Downloads"])
app.include_router(events.router, prefix="/api/events", tags=["Events"])
app.include_router(mail.router, prefix="/api/mail", tags=["Mail"])
app.include_router(screenshots.router, prefix="/api/screenshots", tags=["Screenshots"])
app.include_router(remote.router, prefix="/api", tags=["Remote Control"])
app.include_router(system.router, prefix="/api", tags=["System"])

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    import traceback # type: ignore
    print(f"[ERROR] Global Exception Handler caught: {exc}")
    traceback.print_exc()
    return Response(content="Internal Server Error", status_code=500)

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    print(f"[DEBUG] Validation Error: {exc.errors()}")
    print(f"[DEBUG] Body: {await request.body()}")
    return Response(content=str(exc.errors()), status_code=422)

# ======================================================
# Socket.IO (MOUNT LAST)
# ======================================================
from . import socket_events # Register Event Handlers # type: ignore
# app.mount("/socket.io", socketio.ASGIApp(sio)) # Redundant - Wrapped at bottom

# ======================================================
# Health
# ======================================================
@app.get("/")
async def root():
    return {
        "status": "online",
        "service": "AGENT-GATEWAY-ISOLATED",
        "version": "1.2.2-GATEWAY", 
        "timestamp": "2026-03-31T22:30:00",
        "message": "Welcome to the Dedicated Agent Ingestion Point.",
        "docs": "/docs"
    }

@app.get("/api/health")
async def health():
    return {"status": "healthy"}

# ======================================================
# MOUNT SOCKET.IO APP
# ======================================================
app = socketio.ASGIApp(sio, app)
