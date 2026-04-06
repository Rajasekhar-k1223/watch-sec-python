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

    # [NEW] Ensure MongoDB Indexes for Performance
    async def ensure_mongo_indexes():
        try:
            from .db.session import mongo_client # type: ignore
            db = mongo_client["watchsec"]

            print("[MongoDB] Ensuring performance indexes...")
            # Activity: hot-path for per-agent log queries
            activity = db["activity"]
            await activity.create_index([("AgentId", 1), ("Timestamp", -1)])
            await activity.create_index([("TenantId", 1), ("Timestamp", -1)])
            await activity.create_index([("Timestamp", -1)])

            # Security events: used by /events/report and dashboard
            sec_events = db["security_events"]
            await sec_events.create_index([("AgentId", 1), ("Timestamp", -1)])
            await sec_events.create_index([("TenantId", 1), ("Timestamp", -1)])

            print("[MongoDB] Indexes ensured.")
        except Exception as e:
            print(f"[MongoDB Index Error] {e}")

    await ensure_mongo_indexes()

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
    title="Monitorix Backend",
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
# API ROUTERS (MUST be before Socket.IO)
# ======================================================
app.include_router(auth.router, prefix="/api/auth", tags=["Auth"])
app.include_router(tenants.router, prefix="/api/tenants", tags=["Tenants"])
app.include_router(users.router, prefix="/api/users", tags=["Users"])
app.include_router(agents.router, prefix="/api/agents", tags=["Agents"])
app.include_router(agents.agent_router, prefix="/api/agent", tags=["Agent Communication"])
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
app.include_router(speech.router, prefix="/api/speech", tags=["Speech"])
app.include_router(hashbank.router, prefix="/api", tags=["HashBanks"])
app.include_router(fingerprints.router, prefix="/api", tags=["Fingerprints"])
app.include_router(searches.router, prefix="/api", tags=["Searches"])
app.include_router(remote.router, prefix="/api", tags=["Remote Control"])
app.include_router(vulnerabilities.router, prefix="/api/vulnerabilities", tags=["Vulnerabilities"])
app.include_router(trials.router, prefix="/api/trials", tags=["Trials"])
app.include_router(bandwidth.router, prefix="/api", tags=["Bandwidth"])
app.include_router(notifications.router, prefix="/api", tags=["Notifications"])
app.include_router(report_downloads.router, prefix="/api", tags=["Report Downloads"])

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
        "version": "2.1.0-FIXED", 
        "timestamp": "2026-01-06T07:30:00",
        "docs": "/docs"
    }

@app.get("/api/health")
async def health():
    return {"status": "healthy"}

# ======================================================
# MOUNT SOCKET.IO APP
# ======================================================
app = socketio.ASGIApp(sio, app)
