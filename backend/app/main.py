from contextlib import asynccontextmanager
from fastapi import FastAPI, Response
from fastapi.middleware.cors import CORSMiddleware
import socketio
from sqlalchemy import text
from .socket_instance import sio
from .db.session import settings, engine

from .api import (
    auth, tenants, users, agents, install,
    downloads, commands, events, mail, audit,
    screenshots, policies, productivity, billing,
    uploads, reports, dashboard, ai, system,
    ocr, thesaurus, speech, hashbank, fingerprints,
    searches, remote
)

@asynccontextmanager
async def lifespan(app: FastAPI):
    # --- STARTUP: Check & Fix Database Schema ---
    print("--- STARTUP: Checking Database Schema ---")
    try:
        async with engine.begin() as conn:
            # List of columns to check/add in 'Agents' table
            # Format: (ColumnName, ColumnType)
            new_columns = [
                ("LocationTrackingEnabled", "TINYINT(1) DEFAULT 0"),
                ("UsbBlockingEnabled", "TINYINT(1) DEFAULT 0"),
                ("NetworkMonitoringEnabled", "TINYINT(1) DEFAULT 0"),
                ("FileDlpEnabled", "TINYINT(1) DEFAULT 0"),
            ]
            
            for col_name, col_type in new_columns:
                try:
                    # Attempt to add the column. 
                    # If it exists, this might fail depending on DB version/strictness, 
                    # or we can check information_schema first. 
                    # But 'try-except' is robust for "Duplicate column name" error (1060).
                    print(f"Checking/Adding column '{col_name}' to Agents...")
                    await conn.execute(text(f"ALTER TABLE Agents ADD COLUMN {col_name} {col_type}"))
                    print(f" -> Added '{col_name}' successfully.")
                except Exception as e:
                    # Ignore if "Duplicate column name" (Error 1060)
                    if "1060" in str(e) or "Duplicate column" in str(e):
                        print(f" -> Column '{col_name}' already exists. Skipping.")
                    else:
                        print(f" -> Error adding '{col_name}': {e}")
            
    except Exception as e:
        print(f"--- STARTUP ERROR: Database Migration Failed: {e} ---")

    yield
    # --- SHUTDOWN ---
    print("--- SHUTDOWN ---")


# ======================================================
# FastAPI App
# ======================================================
app = FastAPI(
    title="WatchSec Backend",
    version="2.1.0-FIXED",
    lifespan=lifespan,
)

# ======================================================
# CORS — SINGLE SOURCE OF TRUTH
# ======================================================
ALLOWED_ORIGINS = settings.BACKEND_CORS_ORIGINS

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
# Socket.IO (MOUNT LAST)
# ======================================================
from . import socket_events # Register Event Handlers
app.mount("/socket.io", socketio.ASGIApp(sio))

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
