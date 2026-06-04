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
from ..services.dispatcher_service import dispatcher # [v2.6.0]

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
    api_key_sent = dto.TenantApiKey or x_tenant_api_key

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
        
    auth_api_key = tenant.ApiKey

    # Check for legacy (unsigned) handshake from older agents
    is_legacy = False
    if not x_signature or not x_timestamp:
        if api_key_sent and api_key_sent == auth_api_key:
            is_legacy = True
            print(f"[AUTH] [LEGACY] Graceful fallback allowed for legacy agent {dto.AgentId} (/report)")
        else:
            raise HTTPException(status_code=401, detail="Signature missing and legacy key mismatch")
        
    if not is_legacy:
        # Enforce Stealth key suppression for modern signed requests
        if api_key_sent:
            raise HTTPException(
                status_code=403, 
                detail="SECURITY VIOLATION: Cleartext API Key suppressed in Stealth Mode. Update Agent."
            )
            
        import hmac, hashlib # type: ignore
        if agent.MachineId:
            key_seed = agent.MachineId.encode()
        else:
            key_seed = auth_api_key.encode()
        signing_key = hashlib.sha256(key_seed).digest()
        
        body_bytes = await request.body()
        msg = f"{body_bytes.decode('utf-8')}|{x_timestamp}".encode('utf-8')
        expected = hmac.new(signing_key, msg, hashlib.sha256).hexdigest()
        is_valid = hmac.compare_digest(expected, x_signature)
        
        # [DEBUG] Log ApiKey-only signature for comparison
        fallback_key = auth_api_key.encode()
        expected_fallback = hmac.new(fallback_key, msg, hashlib.sha256).hexdigest()
        
        # [SECURITY] Removed hardcoded agent ID bypass. All agents must pass HMAC validation.
     
        if not is_valid and not agent.MachineId:
            # Fallback: Try ApiKey only (Initial registration handshake)
            if hmac.compare_digest(expected_fallback, x_signature):
                is_valid = True
                print(f"[AUTH] Initial handshake successful for {dto.AgentId}. Awaiting MachineId sync via Heartbeat.")
     
        if not is_valid:
            raise HTTPException(status_code=403, detail="Invalid signature")

        # [SEC] E2EE Payload Decryption
        from ..core.security import decrypt_e2e_payload
        decrypted_bytes = decrypt_e2e_payload(body_bytes, agent.MachineSecret if (agent and agent.MachineSecret) else key_seed.decode())
        if decrypted_bytes != body_bytes:
            import json
            decrypted_dict = json.loads(decrypted_bytes)
            dto = SecurityEventDto(**decrypted_dict)

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
                from ..services.ai_service import ai_service # type: ignore
                ai_result = ai_service.analyze_usb_risk(inventory)
                ai_event = EventLog(AgentId=dto.AgentId, Type="AI_ANALYSIS", Details=str(ai_result), Timestamp=datetime.utcnow())
                db.add(ai_event)
                await db.commit()
    except: pass

    # [v2.6.0] External Dispatch for Critical Events
    if dto.Type in ["THREAT_DETECTED", "MALWARE_ACTIVITY", "SERVICE_DOWN", "UNAUTHORIZED_ACCESS"]:
        import asyncio
        asyncio.create_task(dispatcher.dispatch_critical_alert(
            title=f"Critical Security Event: {dto.Type}",
            message=dto.Details,
            severity="Critical",
            agent_id=dto.AgentId,
            cluster_name=agent.ClusterName,
            webhook_url=tenant.WebhookUrl
        ))

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
    x_timestamp: Optional[str] = Header(None, alias="X-Timestamp")
):
    api_key_sent = dto.TenantApiKey or x_tenant_api_key

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

    # Check for legacy (unsigned) handshake from older agents
    is_legacy = False
    if not x_signature or not x_timestamp:
        if api_key_sent and api_key_sent == auth_api_key:
            is_legacy = True
            print(f"[AUTH] [LEGACY] Graceful fallback allowed for legacy agent {dto.AgentId} (/activity)")
        else:
            raise HTTPException(status_code=401, detail="Signature missing and legacy key mismatch")

    if not is_legacy:
        # Enforce Stealth key suppression for modern signed requests
        if api_key_sent:
             raise HTTPException(status_code=403, detail="Stealth Breach: Plaintext Key Disallowed")
             
        import hmac, hashlib # type: ignore
        if agent_obj.MachineId:
            key_seed = agent_obj.MachineId.encode()
        else:
            key_seed = auth_api_key.encode()
        signing_key = hashlib.sha256(key_seed).digest()
    
        body_bytes = await request.body()
        msg = f"{body_bytes.decode('utf-8')}|{x_timestamp}".encode('utf-8')
        expected = hmac.new(signing_key, msg, hashlib.sha256).hexdigest()
    
        # [v1.8.61] Cryptographic Handshake Fallback
        is_valid = hmac.compare_digest(expected, x_signature)
        
        if not is_valid and not agent_obj.MachineId:
            fallback_key = auth_api_key.encode()
            expected_fallback = hmac.new(fallback_key, msg, hashlib.sha256).hexdigest()
            if hmac.compare_digest(expected_fallback, x_signature):
                is_valid = True
    
        if not is_valid:
            raise HTTPException(status_code=403, detail="Invalid signature")

        # [SEC] E2EE Payload Decryption
        from ..core.security import decrypt_e2e_payload
        decrypted_bytes = decrypt_e2e_payload(body_bytes, agent_obj.MachineSecret if (agent_obj and agent_obj.MachineSecret) else key_seed.decode())
        if decrypted_bytes != body_bytes:
            import json
            decrypted_dict = json.loads(decrypted_bytes)
            dto = ActivityLogDto(**decrypted_dict)

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
    limit: int = Query(100, ge=1, le=2000),
    offset: int = Query(0, ge=0)
):
    from ..db.models import Agent # type: ignore
    agent_res = await db_sql.execute(select(Agent).where(Agent.AgentId == agent_id))
    agent_obj = agent_res.scalars().first()
    if not agent_obj or (current_user.Role != "SuperAdmin" and agent_obj.TenantId != current_user.TenantId):
        raise HTTPException(status_code=403)

    query = select(ActivityLogModel).where(ActivityLogModel.AgentId == agent_id)
    
    if start_date:
        dt_start = datetime.fromisoformat(start_date.replace('Z', '+00:00'))
        query = query.where(ActivityLogModel.Timestamp >= dt_start)
    if end_date:
        dt_end = datetime.fromisoformat(end_date.replace('Z', '+00:00'))
        query = query.where(ActivityLogModel.Timestamp <= dt_end)
        
    if date_range and not start_date and not end_date:
        now = datetime.utcnow()
        if date_range == "24h":
            delta = timedelta(hours=24)
        elif date_range == "7d":
            delta = timedelta(days=7)
        else:
            delta = timedelta(days=30)

        # Get latest log timestamp in database
        from sqlalchemy import func
        ts_res = await db_sql.execute(select(func.max(ActivityLogModel.Timestamp)).where(ActivityLogModel.AgentId == agent_id))
        latest_ts = ts_res.scalar()

        if not latest_ts:
            query = query.where(ActivityLogModel.Timestamp >= now - delta)
        elif latest_ts < now - delta:
            # Pivot window to the last active range ending at latest_ts
            query = query.where(ActivityLogModel.Timestamp >= latest_ts - delta).where(ActivityLogModel.Timestamp <= latest_ts)
        else:
            # We have recent activity in the window, query normally
            query = query.where(ActivityLogModel.Timestamp >= now - delta)

    query = query.order_by(ActivityLogModel.Timestamp.desc())
    query = query.limit(limit).offset(offset)
    
    result = await db_sql.execute(query)
    logs = result.scalars().all()
    
    # Map to schema if needed, but returning models usually works if JSON encodable
    return [
        {
            "AgentId": l.AgentId,
            "ActivityType": l.ActivityType,
            "WindowTitle": l.WindowTitle,
            "ProcessName": l.ProcessName,
            "Url": l.Url,
            "DurationSeconds": l.DurationSeconds,
            "IdleSeconds": l.IdleSeconds,
            "Category": l.Category,
            "ProductivityScore": l.ProductivityScore,
            "RiskLevel": l.RiskLevel,
            "Timestamp": l.Timestamp
        }
        for l in logs
    ]

@router.get("/activity/{agent_id}/stats")
async def get_activity_stats(
    agent_id: str,
    date_range: Optional[str] = Query("24h"),
    current_user: User = Depends(get_current_user),
    db_sql: AsyncSession = Depends(get_db)
):
    from ..db.models import Agent # type: ignore
    agent_res = await db_sql.execute(select(Agent).where(Agent.AgentId == agent_id))
    agent_obj = agent_res.scalars().first()
    if not agent_obj or (current_user.Role != "SuperAdmin" and agent_obj.TenantId != current_user.TenantId):
        raise HTTPException(status_code=403, detail="Access denied")

    from sqlalchemy import func
    stats_query = select(
        func.sum(ActivityLogModel.DurationSeconds).label("total_duration"),
        func.sum(ActivityLogModel.IdleSeconds).label("total_idle")
    ).where(ActivityLogModel.AgentId == agent_id)

    if date_range:
        now = datetime.utcnow()
        if date_range == "24h":
            delta = timedelta(hours=24)
        elif date_range == "7d":
            delta = timedelta(days=7)
        else:
            delta = timedelta(days=30)

        # Get latest log timestamp in database
        ts_res = await db_sql.execute(select(func.max(ActivityLogModel.Timestamp)).where(ActivityLogModel.AgentId == agent_id))
        latest_ts = ts_res.scalar()

        if not latest_ts:
            stats_query = stats_query.where(ActivityLogModel.Timestamp >= now - delta)
        elif latest_ts < now - delta:
            # Pivot window to the last active range ending at latest_ts
            stats_query = stats_query.where(ActivityLogModel.Timestamp >= latest_ts - delta).where(ActivityLogModel.Timestamp <= latest_ts)
        else:
            # We have recent activity in the window, query normally
            stats_query = stats_query.where(ActivityLogModel.Timestamp >= now - delta)

    stats_res = await db_sql.execute(stats_query)
    stats_row = stats_res.first()

    total_duration = float(stats_row.total_duration or 0.0) if stats_row else 0.0
    total_idle = float(stats_row.total_idle or 0.0) if stats_row else 0.0
    active_work = max(0.0, total_duration - total_idle)

    return {
        "total_duration": total_duration,
        "total_idle": total_idle,
        "active_work": active_work
    }

@router.post("/simulate/{agent_id}")
async def simulate_agent_event(
    agent_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    from ..db.models import Agent # type: ignore
    agent_res = await db.execute(select(Agent).where(Agent.AgentId == agent_id))
    agent = agent_res.scalars().first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
        
    if current_user.Role != "SuperAdmin" and agent.TenantId != current_user.TenantId:
        raise HTTPException(status_code=403, detail="Access denied")

    # Generate a random simulated security threat event
    import random
    threats = [
        ("Vulnerability Alert", "Found 3 vulnerable packages: CVE-2023-4863 (Critical), CVE-2023-2033 (High), CVE-2023-3079 (High)"),
        ("Process Started", "Suspicious Process execution: nmap -sS -O 192.168.1.1. PID: 8871"),
        ("USB insertion", "Blocked unauthorized USB Mass Storage Device (Vendor ID: 0930, Product ID: 6545)"),
        ("Policy Violation", "Unauthorized terminal access attempted by user 'developer'."),
        ("Data Loss Prevention", "Blocked exfiltration of credit card numbers in chrome.exe upload payload.")
    ]
    t_type, t_details = random.choice(threats)
    now = datetime.utcnow()

    event = EventLog(
        AgentId=agent_id,
        Type=t_type,
        Details=t_details,
        Timestamp=now,
        Severity="High",
        Status="Open"
    )
    db.add(event)

    # Generate simulated client activity logs as well so the user can verify activity storage instantly
    activities = [
        ("AppFocus", "VSCode.exe", "index.tsx - monitorix-frontend - Visual Studio Code", None, 300.0, 10.0, "Productive", 90.0, 0.0, "Normal"),
        ("UrlVisit", "chrome.exe", "https://github.com/google/deepmind - GitHub", "https://github.com/google/deepmind", 450.0, 30.0, "Productive", 85.0, 0.0, "Normal"),
        ("AppFocus", "slack.exe", "Slack - Deepmind Collaboration Workspace", None, 180.0, 15.0, "Neutral", 50.0, 0.0, "Normal"),
        ("AppFocus", "cmd.exe", "Command Prompt - npm run build", None, 120.0, 5.0, "Productive", 80.0, 20.0, "Normal"),
        ("AppFocus", "zoom.exe", "Zoom Meeting - Daily Standup", None, 900.0, 45.0, "Neutral", 60.0, 0.0, "Normal")
    ]

    for act_type, proc, title, url, dur, idle, cat, prod, r_score, r_level in random.sample(activities, 3):
        # Pick a random timestamp within the last 2 hours
        offset_mins = random.randint(0, 120)
        act_time = now - timedelta(minutes=offset_mins)
        
        act_log = ActivityLogModel(
            AgentId=agent_id,
            TenantId=agent.TenantId,
            ActivityType=act_type,
            ProcessName=proc,
            WindowTitle=title,
            Url=url,
            DurationSeconds=dur,
            IdleSeconds=idle,
            Category=cat,
            ProductivityScore=prod,
            RiskScore=r_score,
            RiskLevel=r_level,
            Timestamp=act_time
        )
        db.add(act_log)
        
        # Broadcast simulated activity log via socket so they stream instantly onto the dashboard
        await sio.emit('new_client_activity', {
            'AgentId': agent_id,
            'ActivityType': act_type,
            'ProcessName': proc,
            'WindowTitle': title,
            'Url': url,
            'DurationSeconds': dur,
            'IdleSeconds': idle,
            'Category': cat,
            'ProductivityScore': prod,
            'RiskLevel': r_level,
            'Timestamp': act_time.isoformat()
        }, room=agent_id)

    await db.commit()

    # Prepare broadcast payloads
    # Send both uppercase and lowercase keys to ensure 100% frontend compatibility with all components
    broadcast_data = {
        "agentId": agent_id,
        "AgentId": agent_id,
        "type": t_type,
        "Type": t_type,
        "details": t_details,
        "Details": t_details,
        "timestamp": now.isoformat(),
        "Timestamp": now.isoformat(),
        "severity": "high",
        "Severity": "High",
        "status": "Open",
        "Status": "Open",
        "tenantId": agent.TenantId
    }

    # Emit to all potential dashboard / live monitor listeners
    await sio.emit('new_event', broadcast_data, room=agent_id)
    await sio.emit('new_alert', broadcast_data, room=agent_id)
    await sio.emit('ReceiveEvent', broadcast_data, room=agent_id)
    await sio.emit('agent_list_update', {"agentId": agent_id}, room=f"tenant_{agent.TenantId}")

    return {"status": "success", "message": "Event simulated successfully"}

def analyze_risk(title: str, process: str, url: str):
    score = 0; level = "Normal"
    text = (f"{title} {process} {url}").lower()
    if any(k in text for k in ["terminal", "powershell", "nmap"]): score = 80; level = "High"
    return score, level

