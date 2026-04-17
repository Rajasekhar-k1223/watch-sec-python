import fastapi # type: ignore # pyre-ignore
from fastapi import APIRouter, Depends, HTTPException, status, Query, Header, Request # type: ignore # pyre-ignore
import re
from ..tasks.general import analyze_risk_background # type: ignore
from ..services.ai_service import ai_service # type: ignore
from ..core.remediation import evaluate_remediation # type: ignore
import json
from typing import List, Optional, Any, Dict, cast # type: ignore
from datetime import datetime, timedelta # type: ignore
from sqlalchemy.ext.asyncio import AsyncSession # type: ignore
from sqlalchemy.future import select # type: ignore

from ..db.session import get_db, get_mongo_db # type: ignore
from ..db.models import Tenant, EventLog, ActivityLog as ActivityLogModel # type: ignore
from ..schemas import SecurityEventLog, ActivityLog, ActivityLogDto, ActivityStats, SecurityEventDto # type: ignore
from .deps import get_current_user # type: ignore
from ..db.models import User # type: ignore
from motor.motor_asyncio import AsyncIOMotorClient # type: ignore
from pydantic import BaseModel # type: ignore
from ..core.constants import FEATURE_TIERS # type: ignore

router = APIRouter()

from ..socket_instance import sio # type: ignore

# --- Security Events ---

@router.get("/activity")
async def log_activity_get():
    return {"status": "ignored", "message": "Received GET. Please update agent to use HTTPS."}

@router.get("/{agent_id}", response_model=List[SecurityEventLog])
async def get_security_events(
    agent_id: str,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    date_range: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0)
):
    # [SECURITY] Tenant Ownership Check
    from ..db.models import Agent # type: ignore
    agent_res = await db.execute(select(Agent).where(Agent.AgentId == agent_id))
    agent = agent_res.scalars().first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
        
    if current_user.Role != "SuperAdmin" and agent.TenantId != current_user.TenantId:
        raise HTTPException(status_code=403, detail="Access denied")

    query = select(EventLog).where(EventLog.AgentId == agent_id)
    
    if date_range:
        now = datetime.utcnow()
        if date_range == "24h":
            start_date = (now - timedelta(hours=24)).isoformat()
        elif date_range == "7d":
            start_date = (now - timedelta(days=7)).isoformat()
        elif date_range == "30d":
            start_date = (now - timedelta(days=30)).isoformat()
    
    if start_date or end_date:
        if start_date:
            try:
                dt_start = datetime.fromisoformat(start_date.replace('Z', '+00:00'))
            except ValueError:
                dt_start = start_date
            query = query.where(EventLog.Timestamp >= dt_start)
        if end_date:
            try:
                dt_end = datetime.fromisoformat(end_date.replace('Z', '+00:00'))
            except ValueError:
                dt_end = end_date
            query = query.where(EventLog.Timestamp <= dt_end)
            
    query = query.order_by(EventLog.Timestamp.desc())
    query = query.limit(limit).offset(offset)
        
    result = await db.execute(query)
    events = result.scalars().all()
    
    return [
        {
            "AgentId": e.AgentId,
            "Type": e.Type,
            "Details": e.Details,
            "Timestamp": e.Timestamp
        }
        for e in events
    ]

@router.post("/report")
async def report_event(
    request: Request,
    dto: SecurityEventDto,
    db: AsyncSession = Depends(get_db),
    x_tenant_api_key: Optional[str] = Header(None, alias="X-Tenant-Api-Key"),
    x_signature: Optional[str] = Header(None, alias="X-Signature"),
    x_timestamp: Optional[str] = Header(None, alias="X-Timestamp")
):
    # [v1.8.38] Telemetry Stealth: KEY SUPPRESSION ENFORCED
    # We NO LONGER accept the API key in the DTO or headers.
    # We find it using the authoritative mapping of AgentId -> Tenant.
    if dto.TenantApiKey or x_tenant_api_key:
        # [SECURITY] Forbid cleartext key transmission
        raise HTTPException(
            status_code=403, 
            detail="SECURITY VIOLATION: Cleartext API Key suppressed in Stealth Mode. Update Agent."
        )

    from ..db.models import Agent # type: ignore
    res_a = await db.execute(select(Agent).where(Agent.AgentId == dto.AgentId))
    agent = res_a.scalars().first()
    if not agent or not agent.TenantId:
        raise HTTPException(status_code=404, detail="Agent identity unmapped")

    # Authoritative Retrieval: Use the DB to find the ONLY valid key for this agent
    res_t = await db.execute(select(Tenant).where(Tenant.Id == agent.TenantId))
    tenant = res_t.scalars().first()
    if not tenant:
        raise HTTPException(status_code=403, detail="Tenant identity unknown")
        
    # auth_api_key for signature verification
    auth_api_key = tenant.ApiKey
        
    # [v1.8.37] Sovereignty Verified
    if not x_signature or not x_timestamp:
        raise HTTPException(status_code=401, detail="Signature missing")
        
    import hmac, hashlib # type: ignore
    key_seed = auth_api_key.encode()
    if agent.MachineId: key_seed += agent.MachineId.encode()
    signing_key = hashlib.sha256(key_seed).digest()
    
    body_bytes = await request.body()
    msg = f"{body_bytes.decode('utf-8')}|{x_timestamp}".encode('utf-8')
    expected = hmac.new(signing_key, msg, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, x_signature):
        print(f"[AUTH ERROR] /report - Signature mismatch!")
        print(f"  AgentId: {dto.AgentId}")
        print(f"  MachineId in DB: '{agent.MachineId}'")
        print(f"  ApiKey in DB: '{auth_api_key[:8]}...'")
        print(f"  Timestamp: {x_timestamp}")
        print(f"  Raw Msg: {msg}")
        print(f"  Expected: {expected}")
        print(f"  Got: {x_signature}")
        raise HTTPException(status_code=403, detail="Invalid signature")

    ts_naive = dto.Timestamp.replace(tzinfo=None) if dto.Timestamp.tzinfo else dto.Timestamp
    
    event = EventLog(AgentId=dto.AgentId, Type=dto.Type, Details=dto.Details, Timestamp=ts_naive)
    db.add(event)
    await db.commit()

    # AI Analysis flow ...
    try:
        if dto.Type == "USB_INSERTION":
            details_data = json.loads(dto.Details)
            inventory = details_data.get("inventory", [])
            if inventory:
                ai_result = ai_service.analyze_usb_risk(inventory)
                ai_event = EventLog(AgentId=dto.AgentId, Type="AI_ANALYSIS", Details=str(ai_result), Timestamp=datetime.utcnow())
                db.add(ai_event)
                await db.commit()
    except: pass

    # Broadcast
    target_room = str(dto.AgentId)
    await sio.emit('ReceiveEvent', {'agentId': dto.AgentId, 'type': dto.Type, 'details': dto.Details, 'timestamp': dto.Timestamp.isoformat()}, room=target_room)
    
    return {"status": "Logged"}

@router.post("/activity")
async def log_activity(
    request: Request,
    dto: ActivityLogDto,
    db: AsyncSession = Depends(get_db),
    x_tenant_api_key: Optional[str] = Header(None, alias="X-Tenant-Api-Key"),
    x_signature: Optional[str] = Header(None, alias="X-Signature"),
    x_timestamp: Optional[str] = Header(None, alias="X-Timestamp"),
    mongo: AsyncIOMotorClient = Depends(get_mongo_db)
):
    # [v1.8.38] Telemetry Stealth: KEY SUPPRESSION ENFORCED
    if dto.TenantApiKey or x_tenant_api_key:
         raise HTTPException(status_code=403, detail="Stealth Breach: Plaintext Key Disallowed")

    from ..db.models import Agent # type: ignore
    res_a = await db.execute(select(Agent).where(Agent.AgentId == dto.AgentId))
    agent_obj = res_a.scalars().first()
    if not agent_obj or not agent_obj.TenantId:
        raise HTTPException(status_code=404)

    # Resolve Authoritative Tenant Key
    res_t = await db.execute(select(Tenant).where(Tenant.Id == agent_obj.TenantId))
    tenant = res_t.scalars().first()
    
    if not tenant:
        raise HTTPException(status_code=403)

    auth_api_key = tenant.ApiKey

    # Verify Signature
    if not x_signature or not x_timestamp: raise HTTPException(status_code=401)
    import hmac, hashlib # type: ignore
    key_seed = auth_api_key.encode()
    if agent_obj.MachineId: key_seed += agent_obj.MachineId.encode()
    signing_key = hashlib.sha256(key_seed).digest()

    body_bytes = await request.body()
    msg = f"{body_bytes.decode('utf-8')}|{x_timestamp}".encode('utf-8')
    expected = hmac.new(signing_key, msg, hashlib.sha256).hexdigest()

    if not hmac.compare_digest(expected, x_signature):
        raise HTTPException(status_code=403, detail="Invalid signature")

    risk_score, risk_level = analyze_risk(dto.WindowTitle, dto.ProcessName, dto.Url or "")
    ts_naive = dto.Timestamp.replace(tzinfo=None) if dto.Timestamp.tzinfo else dto.Timestamp

    sql_activity = ActivityLogModel(
        AgentId=dto.AgentId, TenantId=tenant.Id, ActivityType=dto.ActivityType,
        ProcessName=dto.ProcessName, WindowTitle=dto.WindowTitle, Url=dto.Url,
        DurationSeconds=dto.DurationSeconds, IdleSeconds=dto.IdleSeconds,
        Category=dto.Category, ProductivityScore=dto.ProductivityScore,
        RiskScore=risk_score, RiskLevel=risk_level, Timestamp=ts_naive
    )
    db.add(sql_activity)
    await db.commit()
    
    room_name = str(dto.AgentId)
    await sio.emit('new_client_activity', {
        'AgentId': dto.AgentId, 'ActivityType': dto.ActivityType, 'ProcessName': dto.ProcessName,
        'WindowTitle': dto.WindowTitle, 'Url': dto.Url, 'DurationSeconds': dto.DurationSeconds,
        'IdleSeconds': dto.IdleSeconds, 'Category': dto.Category, 'ProductivityScore': dto.ProductivityScore,
        'RiskLevel': risk_level, 'Timestamp': dto.Timestamp.isoformat()
    }, room=room_name)

    return {"status": "Logged"}

# --- Activity Analytics (mongo) ---
@router.get("/activity/{agent_id}", response_model=List[ActivityLog])
async def get_activity_logs(
    agent_id: str,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    date_range: Optional[str] = None,
    current_user: User = Depends(get_current_user),
    db_sql: AsyncSession = Depends(get_db),
    mongo: AsyncIOMotorClient = Depends(get_mongo_db),
    limit: int = Query(100, ge=1, le=2000),
    offset: int = Query(0, ge=0)
):
    from ..db.models import Agent # type: ignore
    agent_res = await db_sql.execute(select(Agent).where(Agent.AgentId == agent_id))
    agent_obj = agent_res.scalars().first()
    if not agent_obj or (current_user.Role != "SuperAdmin" and agent_obj.TenantId != current_user.TenantId):
        raise HTTPException(status_code=403)

    try:
        db = mongo["watchsec"]
        collection = db["activity"]
        query: Dict[str, Any] = {"AgentId": agent_id}
        cursor = collection.find(query).sort("Timestamp", -1).skip(offset).limit(limit) 
        results = await cursor.to_list(length=limit)
        return results
    except: return []

def analyze_risk(title: str, process: str, url: str):
    score = 0; level = "Normal"
    text = (f"{title} {process} {url}").lower()
    if any(k in text for k in ["terminal", "powershell", "nmap"]): score = 80; level = "High"
    return score, level

