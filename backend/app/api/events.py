import fastapi # type: ignore # pyre-ignore
from fastapi import APIRouter, Depends, HTTPException, status, Query, Header # type: ignore # pyre-ignore
import re
from ..tasks.general import analyze_risk_background # type: ignore
from typing import List, Optional, Any, Dict, cast # type: ignore
from datetime import datetime, timedelta # type: ignore
from sqlalchemy.ext.asyncio import AsyncSession # type: ignore
from sqlalchemy.future import select # type: ignore

from ..db.session import get_db, get_mongo_db # type: ignore
from ..db.models import Tenant, EventLog, ActivityLog as ActivityLogModel # type: ignore
from ..schemas import SecurityEventLog, ActivityLog, ActivityLogDto, ActivityStats # type: ignore
from .deps import get_current_user # type: ignore
from ..db.models import User # type: ignore
from motor.motor_asyncio import AsyncIOMotorClient # type: ignore
from pydantic import BaseModel # type: ignore
from ..core.constants import FEATURE_TIERS # type: ignore
# Check circular import risk: agents imports events? Unlikely.
# We can import verify_feature_access inside the function to be safe if needed, 
# but let's try top level if possible, or keep local. 
# actually local import was in my patch. 
# But just in case, let's add constants here.

router = APIRouter()

from ..socket_instance import sio # type: ignore

# --- Security Events ---

# [LEGACY/FIX] Handle GET /activity (Result of 301 Redirect POST->GET) to silence 401s
# MUST BE DEFINED BEFORE /{agent_id}
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
    query = select(EventLog).where(EventLog.AgentId == agent_id)
    
    # [NEW] Handle Date Range
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
    
    # Map to schema
    return [
        {
            "AgentId": e.AgentId,
            "Type": e.Type,
            "Details": e.Details,
            "Timestamp": e.Timestamp        }
        for e in events
    ]

@router.post("/simulate/{agent_id}")
async def simulate_event(
    agent_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    if current_user.Role not in ["SuperAdmin", "TenantAdmin"]:
        raise HTTPException(status_code=403, detail="Not authorized")

    event = EventLog(
        AgentId=agent_id,
        Type="Simulated Threat",
        Details="This is a test event triggered from the Python Backend.",
        Timestamp=datetime.utcnow()
    )
    
    db.add(event)
    await db.commit()
    
    # [NEW] Also Simulate Activity Log (Mongo) for UI Testing
    try:
        from ..db.session import mongo_client # type: ignore
        db_mongo = mongo_client["watchsec"]
        collection = db_mongo["activity"]
        
        # We need TenantId from SQL
        # current_user.TenantId is reliable
        
        sim_activity = {
            "AgentId": agent_id,
            "TenantId": current_user.TenantId,
            "ActivityType": "Simulated",
            "ProcessName": "Simulation.exe",
            "WindowTitle": "Simulated Activity Event for Testing",
            "Url": "http://localhost/test",
            "DurationSeconds": 60,
            "IdleSeconds": 0,
            "Category": "Productive",
            "ProductivityScore": 100,
            "RiskScore": 0,
            "RiskLevel": "Normal",
            "Timestamp": datetime.utcnow()
        }
        await collection.insert_one(sim_activity)
    except Exception as e:
        print(f"Error simulating mongo activity: {e}")
        
    return {"message": "Event Simulated (SQL + Mongo)"}

# --- Generic Event Reporting (USB, Network, Etc) ---
class SecurityEventDto(BaseModel):
    AgentId: str
    TenantApiKey: Optional[str] = None
    Type: str
    Details: str
    Timestamp: datetime

@router.post("/report")
async def report_event(
    dto: SecurityEventDto,
    db: AsyncSession = Depends(get_db),
    x_tenant_api_key: Optional[str] = Header(None, alias="X-Tenant-Api-Key")
):
    # 1. Resolve API Key (Header > Body)
    api_key = x_tenant_api_key or dto.TenantApiKey
    if not api_key:
        raise HTTPException(status_code=401, detail="X-Tenant-Api-Key header or TenantApiKey in body required")

    # 2. Validate Tenant
    result = await db.execute(select(Tenant).where(Tenant.ApiKey == api_key))
    tenant = result.scalars().first()
    
    if not tenant:
        raise HTTPException(status_code=401, detail="Invalid API Key")
    
    print(f"[DEBUG /api/events/report] Tenant lookup result: {tenant}")

    # [RECOVERY] Revival logic for Started event
    if "Started" in dto.Details:
        from ..db.models import Agent # type: ignore
        res_a = await db.execute(select(Agent).where(Agent.AgentId == dto.AgentId))
        agent_a = res_a.scalars().first()
        if agent_a and agent_a.IsPendingUninstall:
            print(f"[RECOVERY] Agent {dto.AgentId} reported Started via generic events - Clearing IsPendingUninstall.")
            agent_a.IsPendingUninstall = False
            await db.commit()

    # [SECURITY] Plan Check
    # Map Event Type to Feature Key
    from ..core.constants import FEATURE_TIERS # type: ignore
    
    # Heuristic Mapping
    type_map = {
        "Keylog": "KeyloggerEnabled",
        "Clipboard": "ClipboardMonitorEnabled", 
        "Usb": "UsbBlockingEnabled",
        "AppBlock": "AppBlockerEnabled",
        "Printer": "PrinterMonitorEnabled",
        "Location": "LocationTrackingEnabled",
        "Shadow": "ShadowMonitorEnabled",
        "Net": "NetworkMonitoringEnabled"
    }

    req_feat = None
    for k, feat in type_map.items():
        if k.lower() in dto.Type.lower():
            req_feat = feat
            break
            
    if req_feat:
        # We need verify_feature_access but we haven't imported it in this scope typically
        # Let's import or check manually
        from .agents import verify_feature_access # type: ignore
        verify_feature_access(tenant.Plan, req_feat)

    # Ensure Timestamp is naive UTC
    ts_naive = dto.Timestamp
    if ts_naive.tzinfo is not None:
        ts_naive = ts_naive.astimezone(None).replace(tzinfo=None)

    # 2. [SECURITY] Verify Agent Ownership
    from ..db.models import Agent # type: ignore
    res_a = await db.execute(select(Agent).where(Agent.AgentId == dto.AgentId))
    agent = res_a.scalars().first()
    
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
        
    if agent.TenantId != tenant.Id:
        print(f"[SECURITY] Conflict: Agent {dto.AgentId} reported under Tenant {tenant.Id} but belongs to {agent.TenantId}")
        raise HTTPException(status_code=403, detail="Agent does not belong to this tenant")

    # 3. Log to SQL
    event = EventLog(
        AgentId=dto.AgentId,
        Type=dto.Type,
        Details=dto.Details,
        Timestamp=ts_naive
    )
    db.add(event)
    await db.commit()

    # [NEW] Log to MongoDB (All Logs Requirement)
    try:
        from ..db.session import mongo_client # type: ignore
        db_mongo = mongo_client["watchsec"]
        collection = db_mongo["security_events"]
        
        event_doc = dto.model_dump()
        event_doc["TenantId"] = tenant.Id # Use DB TenantId
        event_doc["Timestamp"] = ts_naive # Motor handles datetime
        
        await collection.insert_one(event_doc)
    except Exception as e:
        print(f"Error logging security event to Mongo: {e}")
    
    # 4. Realtime Alert via Socket
    # Broadcast to specific Tenant Room
    # [SECURITY] Isolate sensitive event types (like Clipboard) to the specific agent room
    # instead of broadcasting to the entire tenant feed.
    target_room = f"tenant_{tenant.Id}"
    if dto.Type.lower() == "clipboard":
        target_room = str(dto.AgentId)
        
    await sio.emit('ReceiveEvent', {
        'agentId': dto.AgentId,
        'type': dto.Type, 
        'details': dto.Details,
        'timestamp': dto.Timestamp.isoformat()
    }, room=target_room)
    
    return {"status": "Logged"}

# --- Activity Logs ---

@router.get("/activity/{agent_id}", response_model=List[ActivityLog])
async def get_activity_logs(
    agent_id: str,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    date_range: Optional[str] = None,
    mongo: AsyncIOMotorClient = Depends(get_mongo_db),
    limit: int = Query(100, ge=1, le=2000),
    offset: int = Query(0, ge=0)
):
    try:
        db = mongo["watchsec"]
        collection = db["activity"]
        
        # Use exact match (index-friendly) instead of $regex
        query: Dict[str, Any] = {"AgentId": agent_id}
        
        print(f"[ActivityLogs-Mongo] Querying Agent: {agent_id}")
        
        # Date Range
        if date_range and date_range != "all":
            now = datetime.utcnow()
            if date_range == "24h":
                start_date = (now - timedelta(hours=24)).isoformat()
            elif date_range == "7d":
                start_date = (now - timedelta(days=7)).isoformat()
            elif date_range == "30d":
                start_date = (now - timedelta(days=30)).isoformat()
        
        if start_date or end_date:
            query["Timestamp"] = {}
            if start_date:
                try:
                    query["Timestamp"]["$gte"] = datetime.fromisoformat(start_date)
                except ValueError:
                    query["Timestamp"]["$gte"] = start_date
            if end_date:
                try:
                    query["Timestamp"]["$lte"] = datetime.fromisoformat(end_date)
                except ValueError:
                    query["Timestamp"]["$lte"] = end_date
        
        # Use MongoDB aggregation to group contiguous sessions server-side
        # This replaces the 5000-record Python fetch + in-memory grouping
        pipeline = [
            {"$match": query},
            {"$sort": {"Timestamp": -1}},
            {"$skip": offset},
            {"$limit": limit * 20},  # Fetch enough raw records to produce 'limit' sessions
            {"$group": {
                "_id": {
                    "agentId": "$AgentId",
                    "process": "$ProcessName",
                    "title": "$WindowTitle",
                    "type": "$ActivityType"
                },
                "DurationSeconds": {"$sum": "$DurationSeconds"},
                "IdleSeconds": {"$sum": "$IdleSeconds"},
                "EndTime": {"$max": "$Timestamp"},
                "StartTime": {"$min": "$Timestamp"},
                "Category": {"$last": "$Category"},
                "ProductivityScore": {"$avg": "$ProductivityScore"},
                "RiskScore": {"$last": "$RiskScore"},
                "RiskLevel": {"$last": "$RiskLevel"},
                "Url": {"$last": "$Url"},
                "AgentId": {"$last": "$AgentId"}
            }},
            {"$sort": {"EndTime": -1}},
            {"$limit": limit}
        ]
        
        cursor = collection.aggregate(pipeline)
        results = await cursor.to_list(length=limit)
        print(f"[ActivityLogs-Mongo] Returned {len(results)} grouped sessions (aggregation)")

        return [
            {
                "AgentId": r["AgentId"],
                "ActivityType": r["_id"]["type"],
                "ProcessName": r["_id"]["process"],
                "WindowTitle": r["_id"]["title"],
                "Url": r.get("Url"),
                "DurationSeconds": r["DurationSeconds"],
                "IdleSeconds": r["IdleSeconds"],
                "Category": r["Category"],
                "ProductivityScore": r["ProductivityScore"],
                "RiskScore": r.get("RiskScore", 0.0),
                "RiskLevel": r.get("RiskLevel", "Normal"),
                "Timestamp": r["EndTime"],
                "startTime": r["StartTime"].isoformat() if isinstance(r["StartTime"], datetime) else r["StartTime"],
                "endTime": r["EndTime"].isoformat() if isinstance(r["EndTime"], datetime) else r["EndTime"]
            }
            for r in results
        ]
    except Exception as e:
        print(f"Error fetching logs from Mongo: {e}")
        # Return empty list on failure to avoid 500 which triggers CORS error
        return []

@router.get("/activity/{agent_id}/stats", response_model=ActivityStats)
async def get_activity_stats(
    agent_id: str,
    date_range: Optional[str] = Query("24h"),
    mongo: AsyncIOMotorClient = Depends(get_mongo_db),
    current_user: User = Depends(get_current_user)
):
    try:
        db = mongo["watchsec"]
        collection = db["activity"]
        
        match_filter: Dict[str, Any] = {"AgentId": {"$regex": f"^{re.escape(agent_id)}$", "$options": "i"}}
        
        if date_range and date_range != "all":
            now = datetime.utcnow()
            start_date = now - timedelta(hours=24)
            if date_range == "7d":
                start_date = now - timedelta(days=7)
            elif date_range == "30d":
                start_date = now - timedelta(days=30)
            match_filter["Timestamp"] = {"$gte": start_date}
            
        pipeline = [
            {"$match": match_filter},
            {"$group": {
                "_id": "$AgentId",
                "total_duration": {"$sum": "$DurationSeconds"},
                "total_idle": {"$sum": "$IdleSeconds"},
                "avg_productivity": {"$avg": "$ProductivityScore"},
                "count": {"$sum": 1}
            }}
        ]
        
        cursor = collection.aggregate(pipeline)
        results = await cursor.to_list(length=1)
        
        if not results:
            return {
                "total_duration": 0,
                "total_idle": 0,
                "active_work": 0,
                "avg_productivity": 0,
                "count": 0
            }
            
        res = results[0]
        total = float(res.get("total_duration", 0))
        idle = float(res.get("total_idle", 0))
        
        return {
            "total_duration": total,
            "total_idle": idle,
            "active_work": max(0.0, total - idle),
            "avg_productivity": float(res.get("avg_productivity", 0)),
            "count": int(res.get("count", 0))
        }
    except Exception as e:
        print(f"Error calculating stats: {e}")
        # fallback
        return {
            "total_duration": 0,
            "total_idle": 0,
            "active_work": 0,
            "avg_productivity": 0,
            "count": 0
        }

def analyze_risk(title: str, process: str, url: str):
    score = 0
    level = "Normal"
    
    text = (f"{title} {process} {url}").lower()
    
    high_risk = ["terminal", "powershell", "cmd", "nmap", "wireshark", "tor browser", "metasploit"]
    if any(k in text for k in high_risk):
        score = 80
        level = "High"
    
    unproductive = ["youtube", "facebook", "netflix", "instagram", "tiktok", "steam"]
    if any(k in text for k in unproductive):
        score = 10
        level = "Unproductive"
        
    return score, level

# MOVED TO TOP

@router.post("/activity")
async def log_activity(
    dto: ActivityLogDto,
    db: AsyncSession = Depends(get_db),
    x_tenant_api_key: Optional[str] = Header(None, alias="X-Tenant-Api-Key"),
    x_agent_id: Optional[str] = Header(None, alias="X-Agent-Id"),
    mongo: AsyncIOMotorClient = Depends(get_mongo_db)
):
    # 1. Resolve API Key (Header > Body)
    api_key = x_tenant_api_key or dto.TenantApiKey
    if not api_key:
        raise HTTPException(status_code=401, detail="X-Tenant-Api-Key header or TenantApiKey in body required")

    # 2. [SECURITY] Strict Agent Validation
    # If X-Agent-Id header is provided (pushed by Gateway), verify it matches the body payload.
    # This prevents Agent A from spoofing logs for Agent B within the same tenant.
    if x_agent_id and x_agent_id != dto.AgentId:
        print(f"[SECURITY ALERT] Spoofing Attempt! Agent {x_agent_id} tried to report as {dto.AgentId}")
        raise HTTPException(status_code=403, detail="Agent ID Spoofing Detected")

    # 2. Validate Tenant
    result = await db.execute(select(Tenant).where(Tenant.ApiKey == api_key))
    tenant = result.scalars().first()
    
    if not tenant:
        raise HTTPException(status_code=401, detail="Unauthorized Tenant")

    # [SECURITY] Resolve Agent and Verify Ownership
    from ..db.models import Agent # type: ignore
    result_agent = await db.execute(select(Agent).where(Agent.AgentId == dto.AgentId))
    agent_obj = result_agent.scalars().first()
    
    if not agent_obj:
        raise HTTPException(status_code=404, detail="Agent not found")
        
    if agent_obj.TenantId != tenant.Id:
        print(f"[SECURITY] Activity Conflict: Agent {dto.AgentId} (Tenant {agent_obj.TenantId}) reported as Tenant {tenant.Id}")
        raise HTTPException(status_code=403, detail="Agent does not belong to this tenant")

    # Perform Analysis
    risk_score, risk_level = analyze_risk(dto.WindowTitle, dto.ProcessName, dto.Url or "")
    
    # Ensure Timestamp is naive UTC for SQL consistency
    ts_naive = dto.Timestamp
    if ts_naive.tzinfo is not None:
        ts_naive = ts_naive.astimezone(None).replace(tzinfo=None)
    
    # Insert Record (SQL)
    sql_activity = ActivityLogModel(
        AgentId=dto.AgentId,
        TenantId=tenant.Id, # Use DB/Verified TenantId
        ActivityType=dto.ActivityType,
        ProcessName=dto.ProcessName,
        WindowTitle=dto.WindowTitle,
        Url=dto.Url,
        DurationSeconds=dto.DurationSeconds,
        IdleSeconds=dto.IdleSeconds,
        Category=dto.Category,
        ProductivityScore=dto.ProductivityScore,
        RiskScore=risk_score,
        RiskLevel=risk_level,
        Timestamp=ts_naive
    )
    db.add(sql_activity)
    # We will commit at the end

    # Insert Record (MongoDB)
    try:
        from ..db.session import mongo_client # type: ignore
        db_mongo = mongo_client["watchsec"]
        collection = db_mongo["activity"]
        
        log_entry = dto.model_dump()
        log_entry["TenantId"] = tenant.Id # Use DB Verified TenantId
        log_entry["RiskScore"] = risk_score
        log_entry["RiskLevel"] = risk_level
        log_entry["Timestamp"] = ts_naive 
        
        await collection.insert_one(log_entry)
        
    except Exception as e:
        print(f"Error logging activity to Mongo: {e}")
    
    try:
        await db.commit()
    except Exception as e:
        print(f"Error logging activity to SQL: {e}")
        raise HTTPException(status_code=500, detail="SQL Log Error")

    # Broadcast via Socket.IO -> TENANT ROOM
    if tenant:
        # [SECURITY] Isolate sensitive activity types (Clipboard) to prevent cross-agent leakage
        room_name = f"tenant_{tenant.Id}"
        if dto.ActivityType.lower() == "clipboard":
            room_name = str(dto.AgentId)
            
        await sio.emit('ReceiveEvent', {
            'agentId': dto.AgentId,
            'title': dto.ActivityType,
            'details': f"{dto.ProcessName or ''} {dto.WindowTitle or dto.Url or ''}".strip(),
            'timestamp': dto.Timestamp.isoformat(),
            'DurationSeconds': dto.DurationSeconds, # Send duration for client-side accum
            'IdleSeconds': dto.IdleSeconds
        }, room=room_name)
        
        # Broadcast Detailed Activity for Realtime Logs -> Correct Room
        # Use isolated room_name derived above
        print(f"[Socket.IO] Emitting new_client_activity to {room_name} for Agent {dto.AgentId}")
        await sio.emit('new_client_activity', {
            'AgentId': dto.AgentId,
            'ActivityType': dto.ActivityType,
            'ProcessName': dto.ProcessName,
            'WindowTitle': dto.WindowTitle,
            'Url': dto.Url,
            'DurationSeconds': dto.DurationSeconds,
            'IdleSeconds': dto.IdleSeconds,
            'Category': dto.Category,
            'ProductivityScore': dto.ProductivityScore,
            'RiskLevel': risk_level,
            'Timestamp': dto.Timestamp.isoformat()
        }, room=room_name)

    return {"status": "Logged UNBUFFERED"}
