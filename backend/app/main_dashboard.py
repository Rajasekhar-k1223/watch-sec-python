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
    downloads, commands, events, mail, audit, audit_export, # type: ignore
    screenshots, policies, productivity, billing, # type: ignore
    uploads, reports, dashboard, ai, system, # type: ignore
    ocr, thesaurus, speech, hashbank, fingerprints, # type: ignore
    searches, remote, vulnerabilities, trials, agents, bandwidth, # type: ignore
    notifications, report_downloads, incidents, network, apikeys, # type: ignore
    yara, software_requests, remediation, sso, support, clusters # type: ignore
) # type: ignore
from .api.v2 import ( # type: ignore
    agentless, agentless_receiver, cloud_visibility, compliance, threat_intel, # type: ignore
    hunting, ransomware, risk, lineage, copilot, detection, dlp, # type: ignore
    ueba, deception, vault, soar, pki, federation, remote as remote_v2 # type: ignore
) # type: ignore
import asyncio # type: ignore

@asynccontextmanager
async def lifespan(app: FastAPI):
    # --- STARTUP: Database Check ---
    print("--- STARTUP: API Server Ready ---")

    # [PERF] Ensure MongoDB Indexes for Dashboard Performance
    async def ensure_mongo_indexes():
        try:
            from .db.session import mongo_client # type: ignore
            db = mongo_client["watchsec"]
            collection = db["activity"]
            print("[MongoDB] Ensuring performance indexes...")
            # Compound index for Agent-specific history (fast 24h lookups per agent)
            await collection.create_index([("AgentId", 1), ("Timestamp", -1)])
            # Single index for global dashboard filters
            await collection.create_index([("Timestamp", -1)])
            print("[MongoDB] Indexes ensured successfully.")
        except Exception as e:
            print(f"[MongoDB Index Error] {e}")

    await ensure_mongo_indexes()

    # [SOAR] Ensure default playbooks exist
    async def ensure_default_playbooks():
        try:
            from .db.session import AsyncSessionLocal # type: ignore
            from .db.models import SoarPlaybook # type: ignore
            from sqlalchemy.future import select # type: ignore
            import json
            
            async with AsyncSessionLocal() as db:
                playbook_id_1 = (await db.execute(select(SoarPlaybook).where(SoarPlaybook.Id == 1))).scalars().first()
                if not playbook_id_1:
                    print("[SOAR] Seeding Default Playbook 1 (Critical Mitigation)...")
                    # Force ID 1 if possible, but sqlalchemy will auto-increment. We'll search by name if ID varies, but let's just insert it and hope it's ID 1.
                    # Or we can just insert with Id=1 explicitly since it's Postgres.
                    playbook = SoarPlaybook(
                        Id=1,
                        Name="Critical Threat Mitigation",
                        TriggerCondition="Ransomware/Sigma",
                        ActionsJson=json.dumps([{"action": "KillProcess"}, {"action": "IsolateNetwork"}]),
                        RequiresApproval=False
                    )
                    db.add(playbook)
                    await db.commit()
                    print("[SOAR] Default Playbook 1 seeded.")
        except Exception as e:
            print(f"[SOAR Seeding Error] {e}")

    await ensure_default_playbooks()

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
                            data = await engine.poll_windows_wmi(ip, str(c.Id))
                        else:
                            data = await engine.poll_linux_ssh(ip, str(c.Id))
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
    
    # [CSPM] Background Telemetry Task
    async def cspm_background_telemetry():
        from .services.cspm_engine import cspm_engine
        from .db.session import AsyncSessionLocal
        
        # Initial wait before starting loop
        await asyncio.sleep(10)
        
        while True:
            try:
                async with AsyncSessionLocal() as db:
                    await cspm_engine.poll_cloud_telemetry(db)
            except Exception as e:
                print(f"[CSPM Telemetry Task Error] {e}", flush=True)

            await asyncio.sleep(60) # Poll every 60 seconds

    asyncio.create_task(cspm_background_telemetry())
    
    yield
    # --- SHUTDOWN ---
    print("--- SHUTDOWN ---")


# ======================================================
# FastAPI App
# ======================================================
app = FastAPI(
    title="Monitorix Dashboard & Admin API",
    version="2.2.0-STABLE",
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
app.include_router(incidents.router, prefix="/api/incidents", tags=["Incidents"])
app.include_router(network.router, prefix="/api/network", tags=["Network"])
app.include_router(apikeys.router, prefix="/api/apikeys", tags=["API Keys"])
app.include_router(agentless.router, prefix="/api/v2/agentless", tags=["Agentless"])
app.include_router(yara.router, prefix="/api/yara", tags=["YARA"])
app.include_router(software_requests.router, prefix="/api/software_requests", tags=["Software Requests"])
app.include_router(remediation.router, prefix="/api/remediation", tags=["Remediation"])
app.include_router(sso.router, prefix="/api/sso", tags=["SSO"])
app.include_router(support.router, prefix="/api/support", tags=["Support"])
app.include_router(clusters.router, prefix="/api/clusters", tags=["Clusters"])
app.include_router(audit_export.router, prefix="/api/audit", tags=["Audit Export"])
app.include_router(agentless_receiver.router, prefix="/api/v2/agentless", tags=["Agentless Receiver"])
app.include_router(cloud_visibility.router, prefix="/api/v2/cloud", tags=["Cloud Visibility"])
app.include_router(compliance.router, prefix="/api/v2/compliance", tags=["Compliance"])
app.include_router(threat_intel.router, prefix="/api/v2/threat-intel", tags=["Threat Intel"])
app.include_router(hunting.router, prefix="/api/v2/hunting", tags=["Hunting"])
app.include_router(ransomware.router, prefix="/api/v2/ransomware", tags=["Ransomware"])
app.include_router(risk.router, prefix="/api/v2/risk", tags=["Risk Engine"])
app.include_router(lineage.router, prefix="/api/v2/lineage", tags=["Process Lineage"])
app.include_router(copilot.router, prefix="/api/v2/copilot", tags=["AI Copilot"])
app.include_router(detection.router, prefix="/api/v2/detection", tags=["Detection"])
app.include_router(dlp.router, prefix="/api/v2/dlp", tags=["DLP"])
app.include_router(ueba.router, prefix="/api/v2/ueba", tags=["UEBA"])
app.include_router(deception.router, prefix="/api/v2/deception", tags=["Deception"])
app.include_router(vault.router, prefix="/api/v2/vault", tags=["Forensic Vault"])
app.include_router(soar.router, prefix="/api/v2/soar", tags=["SOAR"])
app.include_router(pki.router, prefix="/api/v2/pki", tags=["PKI"])
app.include_router(federation.router, prefix="/api/v2/federation", tags=["Federation"])
app.include_router(remote_v2.router, prefix="/api/v2/remote", tags=["Remote Control V2"])

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
