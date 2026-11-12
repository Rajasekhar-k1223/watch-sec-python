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
    
    # [NEW] Agentless Background Telemetry Task
    async def agentless_background_telemetry():
        from .services.agentless_engine import AgentlessEngine
        from .db.session import AsyncSessionLocal
        from .db.models import AgentlessCredential
        from sqlalchemy.future import select

        engine = AgentlessEngine()
        
        # Initial wait before starting loop
        await asyncio.sleep(5)
        
        while True:
            try:
                from .db.models import AgentlessEndpoint
                async with AsyncSessionLocal() as db:
                    result = await db.execute(
                        select(AgentlessCredential, AgentlessEndpoint)
                        .join(AgentlessEndpoint, AgentlessCredential.EndpointId == AgentlessEndpoint.Id)
                    )
                    creds_endpoints = result.all()
                    
                for c, ep in creds_endpoints:
                    try:
                        ip = ep.IpAddress
                        os_type = ep.OsType
                        if not ip: continue
                        
                        # Poll
                        if os_type.lower() == 'windows':
                            data = await engine.poll_windows_wmi(ip, c.Id)
                        else:
                            data = await engine.poll_linux_ssh(ip, c.Id)
                        data['ip'] = ip
                        data['os'] = os_type
                        
                        # Broadcast to UI
                        print(f"[Agentless] Emitting telemetry for {ip}", flush=True)
                        await sio.emit('AgentlessTelemetry', data)
                    except Exception as poll_err:
                        print(f"[Agentless Telemetry Error] {c.Id}: {poll_err}", flush=True)
                        
            except Exception as e:
                print(f"[Agentless Telemetry Task Error] {e}", flush=True)

            await asyncio.sleep(30) # Poll every 30 seconds

    asyncio.create_task(agentless_background_telemetry())

    # [PG-OPT] Materialized View Refresh Task
    # Keeps mv_tenant_dashboard_stats, mv_agent_risk_summary, etc. fresh.
    # Runs every 5 minutes on PostgreSQL only (skipped on SQLite local dev).
    async def refresh_materialized_views_task():
        from .db.session import AsyncSessionLocal  # type: ignore
        from .db.pg_helpers import refresh_all_materialized_views  # type: ignore
        import asyncio as _asyncio

        # Initial wait — let the DB settle after startup
        await _asyncio.sleep(30)

        while True:
            try:
                async with AsyncSessionLocal() as db:
                    await refresh_all_materialized_views(db)
            except Exception as mv_err:
                print(f"[MV Refresh Error] {mv_err}", flush=True)
            await _asyncio.sleep(300)  # Every 5 minutes

    # [PG-OPT] GDPR Retention Purge Task (nightly at startup + every 24h)
    async def gdpr_retention_task():
        from .db.session import AsyncSessionLocal  # type: ignore
        from .db.pg_helpers import purge_tenant_data  # type: ignore
        from .db.models import Tenant  # type: ignore
        from sqlalchemy.future import select as _select  # type: ignore
        import asyncio as _asyncio

        # Run once at startup, then every 24 hours
        await _asyncio.sleep(60)

        while True:
            try:
                async with AsyncSessionLocal() as db:
                    result = await db.execute(_select(Tenant.Id))
                    tenant_ids = result.scalars().all()
                    for tid in tenant_ids:
                        try:
                            await purge_tenant_data(db, tid)
                        except Exception as t_err:
                            print(f"[GDPR Purge] Tenant {tid} error: {t_err}", flush=True)
                print("[GDPR Purge] Completed for all tenants.", flush=True)
            except Exception as gdpr_err:
                print(f"[GDPR Retention Task Error] {gdpr_err}", flush=True)
            await _asyncio.sleep(86400)  # Every 24 hours

    asyncio.create_task(refresh_materialized_views_task())
    asyncio.create_task(gdpr_retention_task())

    # [THREAT INTEL] Auto-seed well-known public feeds on first boot + schedule 6-hour sync
    async def threat_intel_bootstrap_task():
        from .db.session import AsyncSessionLocal  # type: ignore
        from .db.models import ThreatFeed  # type: ignore
        from sqlalchemy.future import select as _select  # type: ignore
        from .services.threat_intel_pipeline import ti_pipeline  # type: ignore
        import asyncio as _asyncio

        # Wait for DB to fully settle
        await _asyncio.sleep(20)

        # Well-known free public threat intel feeds (HTTPS only)
        DEFAULT_FEEDS = [
            {
                "Name": "Feodo Tracker (abuse.ch) — C2 IPv4",
                "SourceUrl": "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
                "FeedType": "plain",
            },
            {
                "Name": "URLhaus (abuse.ch) — Malware URLs",
                "SourceUrl": "https://urlhaus.abuse.ch/downloads/text/",
                "FeedType": "plain",
            },
            {
                "Name": "SSLBL (abuse.ch) — Botnet C2 IPs",
                "SourceUrl": "https://sslbl.abuse.ch/blacklist/sslipblacklist.txt",
                "FeedType": "plain",
            },
            {
                "Name": "Emerging Threats — Compromised IPs",
                "SourceUrl": "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
                "FeedType": "plain",
            },
        ]

        while True:
            try:
                async with AsyncSessionLocal() as db:
                    result = await db.execute(_select(ThreatFeed))
                    existing = result.scalars().all()
                    existing_urls = {getattr(f, "SourceUrl", "") for f in existing}

                    # Seed missing default feeds
                    seeded = 0
                    for feed_def in DEFAULT_FEEDS:
                        if feed_def["SourceUrl"] not in existing_urls:
                            feed = ThreatFeed(
                                Name=feed_def["Name"],
                                SourceUrl=feed_def["SourceUrl"],
                                FeedType=feed_def["FeedType"],
                                IsEnabled=True,
                            )
                            db.add(feed)
                            seeded += 1
                    if seeded:
                        await db.commit()
                        print(f"[ThreatIntel] Seeded {seeded} default threat feeds.", flush=True)

                    # Sync all enabled feeds
                    print("[ThreatIntel] Starting scheduled feed sync...", flush=True)
                    await ti_pipeline.sync_all_active_feeds(db)
                    print("[ThreatIntel] Feed sync complete. IOC cache primed.", flush=True)

            except Exception as ti_err:
                print(f"[ThreatIntel Bootstrap Error] {ti_err}", flush=True)

            # Resync every 6 hours
            await _asyncio.sleep(6 * 3600)

    asyncio.create_task(threat_intel_bootstrap_task())

    # [NEW] v3.0 Streaming Architecture Setup
    from .core.kafka_producer import kafka_client
    from .db.clickhouse import clickhouse_db
    
    await kafka_client.connect()
    clickhouse_db.connect()

    yield

    # --- SHUTDOWN ---
    await kafka_client.disconnect()
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

# [FIX] Manually mount the secondary agent_router since PluginManager only mounts the first router per file
from .api import agents, sandbox
from .api.v2 import soc_ops, saas_global, marketplace, commercial, commercial_lifecycle, compliance, global_platform, autonomous_security, security_intelligence, security_research, global_mdr_mssp, continuous_evolution, itdr, cnapp, easm, waap, dspm, secrets_security, database_security, k8s_security, supply_chain, ndr, platform_protection, malware_analysis, attack_validation, ai_agent_security
app.include_router(agents.agent_router, prefix="/api/agent", tags=["Agent Communication"])
app.include_router(sandbox.router, prefix="/api/sandbox", tags=["Sandbox"])
app.include_router(soc_ops.router, prefix="/api/v2/soc", tags=["Enterprise SOC & MDR Operations"])
app.include_router(saas_global.router, prefix="/api/v2/saas", tags=["SaaS & Global Enterprise"])
app.include_router(saas_global.billing_router, prefix="/api/v2/billing", tags=["Billing & Usage Metering"])
app.include_router(marketplace.router, prefix="/api/v2/marketplace", tags=["Ecosystem & Marketplace"])
app.include_router(commercial.router, prefix="/api/v2/commercial", tags=["Commercialization & Managed Security"])
app.include_router(commercial_lifecycle.router)
app.include_router(compliance.router, prefix="/api/v2/compliance", tags=["Compliance"])
app.include_router(compliance.router, prefix="/api/compliance", tags=["Compliance Legacy"])
app.include_router(global_platform.router, prefix="/api/v2/global-platform", tags=["Global Security Platform"])

app.include_router(autonomous_security.router, prefix="/api/v2/autonomous", tags=["Autonomous Security & Defense"])
app.include_router(security_intelligence.router, prefix="/api/v2/intelligence", tags=["Security Intelligence Network"])
app.include_router(security_research.router, prefix="/api/v2/research", tags=["Security Research & Innovation Lab"])
app.include_router(global_mdr_mssp.router, prefix="/api/v2/mssp", tags=["Global MDR & MSSP"])
app.include_router(continuous_evolution.router, prefix="/api/v2/evolution", tags=["Continuous Evolution & Release Governance"])
app.include_router(itdr.router, prefix="/api/v2/itdr", tags=["Identity Threat Detection & Response"])
app.include_router(cnapp.router, prefix="/api/v2/cnapp", tags=["Cloud Security, CNAPP & CSPM"])
app.include_router(easm.router, prefix="/api/v2/easm", tags=["External Attack Surface Management"])
app.include_router(waap.router, prefix="/api/v2/waap", tags=["Web Application & API Security (WAAP / WAF)"])
app.include_router(dspm.router, prefix="/api/v2/dspm", tags=["Data Security Posture Management (DSPM)"])
app.include_router(secrets_security.router, prefix="/api/v2/secrets", tags=["Secrets Security & Vault Governance"])
app.include_router(database_security.router, prefix="/api/v2/database-security", tags=["Database Security & Activity Monitoring (DAM)"])
app.include_router(k8s_security.router, prefix="/api/v2/k8s-security", tags=["Kubernetes & Container Workload Security (KSPM / CWPP)"])
app.include_router(supply_chain.router, prefix="/api/v2/supply-chain", tags=["Software Supply-Chain Security & SBOM Governance"])
app.include_router(ndr.router, prefix="/api/v2/ndr", tags=["Advanced Network Detection & Response (NDR)"])
app.include_router(platform_protection.router, prefix="/api/v2/platform-protection", tags=["Platform Self-Protection & Tamper Defense"])
app.include_router(malware_analysis.router, prefix="/api/v2/malware-analysis", tags=["Advanced Malware Analysis & Detonation Sandbox"])
app.include_router(attack_validation.router, prefix="/api/v2/attack-validation", tags=["Attack-Path Validation & Automated Breach Emulation"])
app.include_router(ai_agent_security.router, prefix="/api/v2/ai", tags=["Sovereign AI Agent Security & MCP Governance"])


from .core.sanitizer import sanitize_raw_body # type: ignore

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    import traceback # type: ignore
    print(f"[ERROR] Global Exception Handler caught: {type(exc).__name__}: {str(exc)}")
    traceback.print_exc(limit=5)
    return Response(content="Internal Server Error", status_code=500)

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    raw_body = await request.body()
    sanitized_body = sanitize_raw_body(raw_body)
    print(f"[DEBUG] Validation Error: {exc.errors()}")
    print(f"[DEBUG] Sanitized Body: {sanitized_body}")
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
