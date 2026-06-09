from contextlib import asynccontextmanager # type: ignore
import fastapi # type: ignore # pyre-ignore
import httpx # type: ignore
import os # type: ignore
from fastapi import FastAPI, Response, Request # type: ignore # pyre-ignore
from fastapi.exceptions import RequestValidationError # type: ignore
from fastapi.middleware.cors import CORSMiddleware # type: ignore
import socketio # type: ignore
from sqlalchemy import text # type: ignore
from .socket_instance import sio # type: ignore
from .db.session import settings, engine # type: ignore

from .core.plugins import plugin_manager # type: ignore
from prometheus_fastapi_instrumentator import Instrumentator # type: ignore
import asyncio # type: ignore
import re
import sys
from io import StringIO

# ======================================================
# GLOBAL LOG REDACTOR (PII Scrubbing for stdout/stderr)
# ======================================================
class PIILogRedactor:
    PII_PATTERNS = {
        "Email": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
        "CreditCard": r"\b(?:\d{4}[- ]?){3}\d{4}\b",
        "SSN": r"\b\d{3}-\d{2}-\d{4}\b",
        "Phone": r"\b\+?[1-9]\d{7,14}\b",
        "TenantKey": r"ENC:[a-zA-Z0-9+/=]+",
        "AgentIdentity": r"[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}"
    }

    @classmethod
    def redact(cls, text):
        if not isinstance(text, str): return text
        redacted = text
        for label, pattern in cls.PII_PATTERNS.items():
            redacted = re.sub(pattern, f"[REDACTED_{label.upper()}]", redacted)
        return redacted

class RedactedStream:
    def __init__(self, original_stream):
        self.original_stream = original_stream

    def write(self, data):
        self.original_stream.write(PIILogRedactor.redact(data))

    def flush(self):
        self.original_stream.flush()

# Hook into standard output to prevent information leakage
sys.stdout = RedactedStream(sys.stdout) # type: ignore
sys.stderr = RedactedStream(sys.stderr) # type: ignore

@asynccontextmanager
async def lifespan(app: FastAPI):
    # --- STARTUP ---
    app.state.httpx_client = httpx.AsyncClient(timeout=2.0)
    print("--- STARTUP: API Server Ready (Shared Client Init) ---")

    async def ensure_sql_columns():
        try:
            from .db.session import engine # type: ignore
            from sqlalchemy import text # type: ignore
            async with engine.connect() as conn:
                # Check Policies table
                try:
                    res = await conn.execute(text("PRAGMA table_info(Policies)"))
                    cols = [row[1] for row in res.fetchall()]
                except:
                    res = await conn.execute(text("DESCRIBE Policies"))
                    cols = [row[0] for row in res.fetchall()]
                
                if "GeolocationEnabled" not in cols:
                    print("[SQL] Adding GeolocationEnabled to Policies...")
                    await conn.execute(text("ALTER TABLE Policies ADD COLUMN GeolocationEnabled BOOLEAN DEFAULT TRUE"))
                    await conn.commit()

                # Check Agents table
                try:
                    res = await conn.execute(text("PRAGMA table_info(Agents)"))
                    cols = [row[1] for row in res.fetchall()]
                except:
                    res = await conn.execute(text("DESCRIBE Agents"))
                    cols = [row[0] for row in res.fetchall()]
                
                if "GeolocationEnabled" not in cols:
                    print("[SQL] Adding GeolocationEnabled to Agents...")
                    await conn.execute(text("ALTER TABLE Agents ADD COLUMN GeolocationEnabled BOOLEAN DEFAULT TRUE"))
                
                if "ThreatScore" not in cols:
                    print("[SQL] Adding ThreatScore to Agents...")
                    await conn.execute(text("ALTER TABLE Agents ADD COLUMN ThreatScore INTEGER DEFAULT 0"))

                if "RiskLevel" not in cols:
                    print("[SQL] Adding RiskLevel to Agents...")
                    await conn.execute(text("ALTER TABLE Agents ADD COLUMN RiskLevel VARCHAR(50) DEFAULT 'Normal'"))

                await conn.commit()
            print("[SQL] Columns verified.")
        except Exception as e:
            print(f"[SQL Migration Error] {e}")

    await ensure_sql_columns()

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
    await app.state.httpx_client.aclose()
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
# RATE LIMITING MIDDLEWARE (Anti-Flooding)
# ======================================================
from datetime import datetime, timedelta # type: ignore
_request_counts = {} # {(id, path): [timestamps]}

@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    # [v1.8.37] Resilience: Prevent agent flooding
    path = request.url.path
    
    # [SEC v2.1.0] Identity Extraction (mTLS & Trust Tokens)
    client_cert_subject = request.headers.get("X-Client-Cert-Subject") # Injected by Nginx mTLS
    trust_token = request.headers.get("X-Monitorix-Trust-Token")
    agent_id = request.headers.get("X-Agent-Id")
    
    # Enforce Hardware/Transport Identity for high-risk endpoints in Strict Mode
    if os.getenv("MONITORIX_STRICT_AGENT_AUTH") == "1":
        if path.startswith("/api/agent/") and not trust_token and not client_cert_subject:
             return Response(content="Identity Verification Required (mTLS or Trust Token missing)", status_code=403)

    if not path.startswith("/api/events/report") and not path.startswith("/api/agent/"):
        return await call_next(request)
    
    # Identify by Agent-Id header or IP
    ident = agent_id or request.client.host # type: ignore
    now = datetime.utcnow()
    key = (ident, path)
    
    if key not in _request_counts:
        _request_counts[key] = []
    
    # Keep only last minute
    minute_ago = now - timedelta(minutes=1)
    _request_counts[key] = [t for t in _request_counts[key] if t > minute_ago]
    
    # Limit: 100 requests per minute per agent/path
    if len(_request_counts[key]) > 100:
        return Response(content="Rate limit exceeded. Check agent logs.", status_code=429)
    
    _request_counts[key].append(now)
    
    # [v1.8.37] Strict Transport Security (HSTS)
    response = await call_next(request)
    
    # --- [FORTRESS SECURITY HEADERS] ---
    # 1. Force HTTPS
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"
    
    # 2. Prevent Clickjacking
    response.headers["X-Frame-Options"] = "DENY"
    
    # 3. Prevent MIME-Sniffing
    response.headers["X-Content-Type-Options"] = "nosniff"
    
    # 4. Enable Browser XSS Filters
    response.headers["X-XSS-Protection"] = "1; mode=block"
    
    # 5. Referrer Policy
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    
    # 6. Content Security Policy (Strict)
    # Allows self, plus standard Google Fonts and Socket.IO requirements
    csp = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; " # Removed unsafe-eval for security
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data: blob:; "
        "connect-src 'self' ws: wss:; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "form-action 'self';"
    )
    response.headers["Content-Security-Policy"] = csp
    
    return response

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

# [v2.4.0] Real-time Observability: Prometheus Metrics
Instrumentator().instrument(app).expose(app)

# ======================================================
# API ROUTERS (MUST be before Socket.IO)
# ======================================================
# [v2.1.0] Modular Plugin Architecture: Dynamic Route Discovery
plugin_manager.app = app
plugin_manager.load_api_plugins("app.api")
plugin_manager.load_api_plugins("app.api.v2")

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
