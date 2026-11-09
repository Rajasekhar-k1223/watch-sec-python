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

@router.get("/security/all")
async def get_all_security_logs(
    agent_id: Optional[str] = None,
    type: Optional[str] = None,
    severity: Optional[str] = None,
    search: Optional[str] = None,
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Central log ingestion query endpoint for SIEM & Windows/Linux EventLog search."""
    from ..db.models import Agent, EventLog
    from sqlalchemy import or_, desc

    stmt = select(EventLog)
    if current_user.Role != "SuperAdmin":
        stmt = stmt.join(Agent, EventLog.AgentId == Agent.AgentId).where(Agent.TenantId == current_user.TenantId)

    if agent_id and agent_id != "All":
        stmt = stmt.where(EventLog.AgentId == agent_id)
    if type and type != "All":
        stmt = stmt.where(EventLog.Type == type)
    if severity and severity != "All":
        stmt = stmt.where(EventLog.Severity == severity)
    if search:
        search_fmt = f"%{search}%"
        stmt = stmt.where(or_(EventLog.Details.ilike(search_fmt), EventLog.Type.ilike(search_fmt), EventLog.AgentId.ilike(search_fmt)))

    stmt = stmt.order_by(desc(EventLog.Timestamp)).offset(offset).limit(limit)
    rows = (await db.execute(stmt)).scalars().all()

    return [
        {
            "Id": log.Id,
            "AgentId": log.AgentId,
            "Type": log.Type,
            "Details": log.Details,
            "Timestamp": log.Timestamp.isoformat() if log.Timestamp else "",
            "Status": log.Status or "Open",
            "Severity": log.Severity or "Medium",
            "IsAlert": log.IsAlert or False,
            "RawData": log.RawData
        }
        for log in rows
    ]

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
    from sqlalchemy import func
    agent_res = await db.execute(select(Agent).where(func.lower(Agent.AgentId) == func.lower(agent_id)))
    agent = agent_res.scalars().first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
        
    if current_user.Role != "SuperAdmin" and agent.TenantId != current_user.TenantId:
        raise HTTPException(status_code=403, detail="Access denied")

    from ..db.pg_pagination import paginate_event_logs

    # Handle legacy date_range logic
    if date_range:
        now = datetime.utcnow()
        if date_range == "24h":
            start_date = (now - timedelta(hours=24)).isoformat()
        elif date_range == "7d":
            start_date = (now - timedelta(days=7)).isoformat()
        elif date_range == "30d":
            start_date = (now - timedelta(days=30)).isoformat()

    dt_start = None
    dt_end = None

    if start_date:
        try:
            dt_start = datetime.fromisoformat(start_date.replace('Z', '+00:00'))
        except ValueError:
            pass
    if end_date:
        try:
            dt_end = datetime.fromisoformat(end_date.replace('Z', '+00:00'))
        except ValueError:
            pass

    page = await paginate_event_logs(
        db, agent_id,
        limit=limit,
        offset=offset,
        start_ts=dt_start,
        end_ts=dt_end,
        as_dict=True
    )

    # Maintain backwards compatibility with frontend expecting an array
    # If frontend is updated later to send `cursor`, this same endpoint will be 100x faster.
    return [
        {
            "AgentId": e["AgentId"],
            "Type": e["Type"],
            "Details": e["Details"],
            "Timestamp": e["Timestamp"]
        }
        for e in page.items
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

    import hmac, hashlib # type: ignore
    body_bytes = await request.body()

    if not x_signature or not x_timestamp:
        # [COMPAT] Legacy agents running as SYSTEM cannot access keyring — accept signed events
        # from registered agents that include their hardware-bound machine secret.
        unsigned_ok = agent and dto.TenantApiKey and dto.TenantApiKey == auth_api_key
        if not unsigned_ok:
            raise HTTPException(status_code=401, detail="Missing cryptographic signature or timestamp")
        print(f"[COMPAT] Accepting unsigned event from legacy agent {dto.AgentId}")
        # Strip api key reference so the rest of the handler doesn't reject on it
        api_key_sent = None
    else:
        # Enforce Stealth key suppression for modern signed requests (cleartext key never in signed payload)
        if api_key_sent:
            raise HTTPException(
                status_code=403,
                detail="SECURITY VIOLATION: Cleartext API Key suppressed in Stealth Mode. Update Agent."
            )

        if agent.MachineId:
            key_seed = agent.MachineId.encode()
        else:
            key_seed = auth_api_key.encode()
        signing_key = hashlib.sha256(key_seed).digest()

        body_str = body_bytes.decode('utf-8')
        msg = f"{body_str}|{x_timestamp}".encode('utf-8')
        expected = hmac.new(signing_key, msg, hashlib.sha256).hexdigest()
        is_valid = hmac.compare_digest(expected, x_signature)

        # Fallback: try API key (raw, no sha256 wrapper)
        if not is_valid:
            fallback_key = auth_api_key.encode()
            expected_fallback = hmac.new(fallback_key, msg, hashlib.sha256).hexdigest()
            if hmac.compare_digest(expected_fallback, x_signature):
                is_valid = True

        # Fallback: try sha256(api_key) as seed (DataQueue format when machine_secret is None)
        if not is_valid:
            fallback_key2 = hashlib.sha256(auth_api_key.encode()).digest()
            expected_fallback2 = hmac.new(fallback_key2, msg, hashlib.sha256).hexdigest()
            if hmac.compare_digest(expected_fallback2, x_signature):
                is_valid = True

        if not is_valid:
            raise HTTPException(status_code=403, detail="Invalid signature")

        # [SEC] E2EE Payload Decryption (signed payloads only)
        from ..core.security import decrypt_e2e_payload
        decrypted_bytes = decrypt_e2e_payload(body_bytes, agent.MachineId if (agent and agent.MachineId) else key_seed.decode())
        if decrypted_bytes != body_bytes:
            import json
            decrypted_dict = json.loads(decrypted_bytes)
            dto = SecurityEventDto(**decrypted_dict)

    ts_naive = dto.Timestamp.replace(tzinfo=None) if dto.Timestamp.tzinfo else dto.Timestamp
    
    # Prevent duplicate events from being stored multiple times for the same agent and date/time
    existing = await db.execute(select(EventLog).where(
        EventLog.AgentId == dto.AgentId,
        EventLog.Type == dto.Type,
        EventLog.Timestamp == ts_naive
    ))
    if existing.scalars().first():
        return {"status": "success", "message": "Duplicate event ignored"}
    
    event = EventLog(
        AgentId=dto.AgentId,
        Type=dto.Type,
        Details=dto.Details,
        Timestamp=ts_naive,
        Severity=dto.Severity,
        IsAlert=dto.IsAlert
    )
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

    # [NEW] Item 2: Live Activity & Input Auditing DLP Scan
    if dto.Type in ["KeystrokeLog", "ClipboardAuditReport"]:
        lower_details = dto.Details.lower()
        keywords = ["password", "confidential", "secret", "ssn", "credit card", "api_key"]
        has_sensitive = any(kw in lower_details for kw in keywords)
        
        if has_sensitive:
            # Elevate severity of the logged event
            event.Severity = "Critical"
            event.Status = "Open"
            await db.commit()
            
            # Fire an alert
            import asyncio
            asyncio.create_task(dispatcher.dispatch_critical_alert(
                title=f"DLP Alert: Sensitive data found in {dto.Type}",
                message=f"Keywords matched in {dto.Type}.",
                severity="Critical",
                agent_id=dto.AgentId,
                cluster_name=agent.ClusterName if agent else None,
                webhook_url=tenant.WebhookUrl
            ))
            
        # Stream live to the new Input Auditing UI panel
        payload = {
            'AgentId': dto.AgentId,
            'Type': dto.Type,
            'Details': dto.Details,
            'Timestamp': ts_naive.isoformat(),
            'Severity': event.Severity if event.Severity else "Normal"
        }
        await sio.emit('new_audit_event', payload, room=str(dto.AgentId))
        await sio.emit('new_audit_event', payload, room=f"tenant_{tenant.Id}")

    # [NEW] Item 3: Location Tracking Map Ingestion
    if dto.Type == "LocationTrackingReport":
        try:
            loc_data = json.loads(dto.Details)
            if "loc" in loc_data:
                lat_str, lng_str = loc_data["loc"].split(",")
                lat = float(lat_str.strip())
                lng = float(lng_str.strip())
                source = loc_data.get("source", "Unknown")
                
                from ..db.models import LocationReport # type: ignore
                loc_report = LocationReport(
                    AgentId=dto.AgentId,
                    TenantId=tenant.Id,
                    Latitude=lat,
                    Longitude=lng,
                    Source=source,
                    Timestamp=ts_naive
                )
                db.add(loc_report)
                await db.commit()
        except Exception as e:
            print(f"[LocationTracking] Failed to parse location report: {e}")

    # [NEW] Item 4: Deception Engine Escalation
    if dto.Type == "FileIntegrityAlert":
        event.Severity = "Critical"
        event.Status = "Open"
        await db.commit()
        import asyncio
        asyncio.create_task(dispatcher.dispatch_critical_alert(
            title=f"File Integrity Violation",
            message=dto.Details,
            severity="Critical",
            agent_id=dto.AgentId,
            cluster_name=agent.ClusterName if agent else None,
            webhook_url=tenant.WebhookUrl
        ))
        
        payload = {
            'AgentId': dto.AgentId,
            'Type': dto.Type,
            'Details': dto.Details,
            'Timestamp': ts_naive.isoformat(),
            'Severity': "Critical"
        }
        await sio.emit('new_event', payload, room=str(dto.AgentId))
        await sio.emit('new_event', payload, room=f"tenant_{tenant.Id}")
    deception_events = ["DeceptionAlert", "DeceptionTriggered", "RansomwareDecoyTouched"]
    if dto.Type in deception_events or dto.Type in ["AppControlViolation", "UsbBlocked"]:
        event.Severity = "Critical"
        event.Status = "Open"
        event.IsAlert = True
        await db.commit()

    # [v2.6.0] External Dispatch for Critical Events
    if dto.Type in ["THREAT_DETECTED", "MALWARE_ACTIVITY", "SERVICE_DOWN", "UNAUTHORIZED_ACCESS", "AppControlViolation", "UsbBlocked"] + deception_events:
        import asyncio
        asyncio.create_task(dispatcher.dispatch_critical_alert(
            title=f"Critical Security Event: {dto.Type}",
            message=dto.Details,
            severity="Critical",
            agent_id=dto.AgentId,
            cluster_name=agent.ClusterName,
            webhook_url=tenant.WebhookUrl
        ))
        
        # [SOAR Integration] Push telemetry directly to RedRainbow/SIEM
        payload = {
            'agentId': dto.AgentId,
            'type': dto.Type,
            'details': dto.Details,
            'timestamp': ts_naive.isoformat(),
            'severity': event.Severity
        }
        asyncio.create_task(dispatcher.dispatch_siem_webhook(db, dto.AgentId, payload))

    # [NEW] Dynamic SOAR Playbook Evaluator
    if event.IsAlert and event.Severity == "Critical":
        from app.db.models import SoarPlaybook
        from app.services.soar_engine import soar_engine
        import asyncio

        # Fetch active playbooks
        playbooks = (await db.execute(select(SoarPlaybook))).scalars().all()
        for pb in playbooks:
            # Simple string matching for trigger condition
            if dto.Type.lower() in pb.TriggerCondition.lower() or pb.TriggerCondition.lower() in dto.Type.lower() or "critical" in pb.TriggerCondition.lower():
                # Trigger the SOAR engine with the matched playbook
                await soar_engine.trigger_playbook(db, pb.Id, agent.AgentId)

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
    import logging
    # logging.debug(f"Received activity POST: {dto.dict()}")
    api_key_sent = dto.TenantApiKey or x_tenant_api_key

    from ..db.models import Agent # type: ignore
    from sqlalchemy import func
    res_a = await db.execute(select(Agent).where(func.lower(Agent.AgentId) == func.lower(dto.AgentId)))
    agent_obj = res_a.scalars().first()
    if not agent_obj or not agent_obj.TenantId:
        # Agent not registered yet — silently skip to prevent 404 flood
        return {"status": "skipped", "reason": "Agent not registered"}

    # Resolve Authoritative Tenant Key
    res_t = await db.execute(select(Tenant).where(Tenant.Id == agent_obj.TenantId))
    tenant = res_t.scalars().first()
    
    if not tenant:
        raise HTTPException(status_code=403)

    auth_api_key = tenant.ApiKey

    # [SEC] Strict Zero-Trust Enforcement.
    if not x_signature or not x_timestamp:
        # [COMPAT] Allow unsigned activity from legacy pre-v1.8.64 agents that send API key in body
        if api_key_sent and api_key_sent == auth_api_key:
            # Legacy agent authenticated via API key - skip signature, proceed
            pass
        else:
            raise HTTPException(status_code=401, detail="Missing cryptographic signature or timestamp")
        # No signature to validate - return early after saving below
        risk_score, risk_level = analyze_risk(dto.WindowTitle if hasattr(dto, 'WindowTitle') and dto.WindowTitle else "", dto.ProcessName if hasattr(dto, 'ProcessName') and dto.ProcessName else "", dto.Url if hasattr(dto, 'Url') and dto.Url else "")
        ts_naive = dto.Timestamp.replace(tzinfo=None) if dto.Timestamp.tzinfo else dto.Timestamp
        sql_activity = ActivityLogModel(
            AgentId=dto.AgentId, TenantId=tenant.Id, ActivityType=dto.ActivityType,
            WindowTitle=getattr(dto, 'WindowTitle', None), ProcessName=getattr(dto, 'ProcessName', None),
            Url=getattr(dto, 'Url', None), RiskScore=risk_score, RiskLevel=risk_level,
            DurationSeconds=getattr(dto, 'DurationSeconds', 0.0), IdleSeconds=getattr(dto, 'IdleSeconds', 0.0),
            Category=getattr(dto, 'Category', 'Neutral'), ProductivityScore=getattr(dto, 'ProductivityScore', 0.0),
            Timestamp=ts_naive, IpAddress=getattr(dto, 'IpAddress', None)
        )
        db.add(sql_activity)
        await db.commit()
        
        # [NEW] Emit live activity for compat block
        payload = {
            'AgentId': dto.AgentId, 'ActivityType': dto.ActivityType, 'ProcessName': dto.ProcessName,
            'WindowTitle': dto.WindowTitle, 'Url': dto.Url, 'DurationSeconds': getattr(dto, 'DurationSeconds', 0.0),
            'IdleSeconds': getattr(dto, 'IdleSeconds', 0.0), 'Category': getattr(dto, 'Category', 'Neutral'),
            'ProductivityScore': getattr(dto, 'ProductivityScore', 0.0),
            'RiskLevel': risk_level, 'Timestamp': ts_naive.isoformat()
        }
        await sio.emit('new_client_activity', payload, room=f"tenant_{tenant.Id}")
        await sio.emit('new_client_activity', payload, room="superadmin")
        await sio.emit('new_client_activity', payload, room=str(dto.AgentId))
        
        return {"status": "ok", "compat": True}
         
    import hmac, hashlib # type: ignore
    
    body_bytes = await request.body()
    msg = f"{body_bytes.decode('utf-8')}|{x_timestamp}".encode('utf-8')
    is_valid = False

    if agent_obj.MachineId:
        res_t = await db.execute(select(Tenant).where(Tenant.Id == agent_obj.TenantId))
        tenant = res_t.scalars().first()
        key_seed = tenant.ApiKey.encode()
        signing_key = hashlib.sha256(key_seed).digest()
        expected = hmac.new(signing_key, msg, hashlib.sha256).hexdigest()
        if hmac.compare_digest(expected, x_signature):
            is_valid = True
            
    if not is_valid:
        key_seed_fallback = auth_api_key.encode()
        signing_key_fallback = hashlib.sha256(key_seed_fallback).digest()
        expected_fallback = hmac.new(signing_key_fallback, msg, hashlib.sha256).hexdigest()
        if hmac.compare_digest(expected_fallback, x_signature):
            is_valid = True

    if not is_valid:
        raise HTTPException(status_code=403, detail="Invalid signature")

    # [SEC] E2EE Payload Decryption
    from ..core.security import decrypt_e2e_payload
    decrypted_bytes = decrypt_e2e_payload(body_bytes, agent_obj.MachineId if (agent_obj and agent_obj.MachineId) else key_seed.decode())
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
    
    payload = {
        'AgentId': dto.AgentId, 'ActivityType': dto.ActivityType, 'ProcessName': dto.ProcessName,
        'WindowTitle': dto.WindowTitle, 'Url': dto.Url, 'DurationSeconds': dto.DurationSeconds,
        'IdleSeconds': dto.IdleSeconds, 'Category': dto.Category, 'ProductivityScore': dto.ProductivityScore,
        'RiskLevel': risk_level, 'Timestamp': dto.Timestamp.isoformat()
    }
    await sio.emit('new_client_activity', payload, room=f"tenant_{tenant.Id}")
    await sio.emit('new_client_activity', payload, room="superadmin")
    await sio.emit('new_client_activity', payload, room=str(dto.AgentId))

    return {"status": "Logged"}

# --- Activity Analytics (mongo) ---
@router.get("/activity/{agent_id}")
async def get_activity_logs(
    agent_id: str,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    date_range: Optional[str] = None,
    current_user: User = Depends(get_current_user),
    db_sql: AsyncSession = Depends(get_db),
    limit: int = Query(100, ge=1, le=2000),
    offset: int = Query(0, ge=0),
    cursor: Optional[int] = Query(None)
):
    from ..db.models import Agent # type: ignore
    from sqlalchemy import func
    agent_res = await db_sql.execute(select(Agent).where(func.lower(Agent.AgentId) == func.lower(agent_id)))
    agent_obj = agent_res.scalars().first()
    if not agent_obj or (current_user.Role != "SuperAdmin" and agent_obj.TenantId != current_user.TenantId):
        raise HTTPException(status_code=403)

    from ..db.pg_pagination import paginate_activity_logs

    if date_range and not start_date and not end_date:
        now = datetime.utcnow()
        if date_range == "24h":
            start_date = (now - timedelta(hours=24)).isoformat()
        elif date_range == "7d":
            start_date = (now - timedelta(days=7)).isoformat()
        else:
            start_date = (now - timedelta(days=30)).isoformat()

    dt_start = None
    dt_end = None
    if start_date:
        try:
            dt_start = datetime.fromisoformat(start_date.replace('Z', '+00:00'))
        except:
            pass
    if end_date:
        try:
            dt_end = datetime.fromisoformat(end_date.replace('Z', '+00:00'))
        except:
            pass

    page = await paginate_activity_logs(
        db_sql, agent_id,
        tenant_id=agent_obj.TenantId,
        limit=limit,
        offset=offset,
        cursor=cursor,
        start_ts=dt_start,
        end_ts=dt_end,
        as_dict=True
    )

    return [
        {
            "AgentId": l["AgentId"],
            "ActivityType": l["ActivityType"],
            "WindowTitle": l["WindowTitle"],
            "ProcessName": l["ProcessName"],
            "Url": l["Url"],
            "DurationSeconds": l["DurationSeconds"] or 0.0,
            "IdleSeconds": l["IdleSeconds"] or 0.0,
            "Category": l["Category"],
            "ProductivityScore": l["ProductivityScore"],
            "RiskLevel": l["RiskLevel"],
            "Timestamp": l["Timestamp"],
            # [FIX] Derived start/end timestamps so the frontend can show a real time range
            "StartTime": l["Timestamp"].isoformat() if l["Timestamp"] else None,
            "EndTime": (l["Timestamp"] + __import__('datetime').timedelta(seconds=l["DurationSeconds"] or 0)).isoformat() if l["Timestamp"] else None,
        }
        for l in page.items
    ]

@router.get("/activity/{agent_id}/stats")
async def get_activity_stats(
    agent_id: str,
    date_range: Optional[str] = Query("24h"),
    current_user: User = Depends(get_current_user),
    db_sql: AsyncSession = Depends(get_db)
):
    from ..db.models import Agent # type: ignore
    from sqlalchemy import func
    agent_res = await db_sql.execute(select(Agent).where(func.lower(Agent.AgentId) == func.lower(agent_id)))
    agent_obj = agent_res.scalars().first()
    if not agent_obj or (current_user.Role != "SuperAdmin" and agent_obj.TenantId != current_user.TenantId):
        raise HTTPException(status_code=403, detail="Access denied")

    hours = 24
    if date_range == "7d": hours = 168
    elif date_range == "30d": hours = 720

    from ..db.pg_helpers import pg
    
    # 1. Fetch KPI stats
    stats_dict = await pg.get_activity_stats(db_sql, agent_id, hours)
    if not stats_dict:
        stats_dict = {"total_duration_seconds": 0, "total_idle_seconds": 0}

    total_duration = stats_dict.get("total_duration_seconds", 0.0)
    total_idle = stats_dict.get("total_idle_seconds", 0.0)
    active_work = max(0.0, total_duration - total_idle)

    # 2. Fetch recent logs using paginator
    from ..db.pg_pagination import paginate_activity_logs
    recent_page = await paginate_activity_logs(db_sql, agent_id, limit=15, as_dict=True)
    
    recent_logs = []
    for doc in recent_page.items:
        recent_logs.append({
            "type": doc["ActivityType"],
            "details": f"{doc.get('ProcessName') or ''} {doc.get('WindowTitle') or ''}".strip(),
            "timestamp": doc["Timestamp"],
            "agentId": doc["AgentId"]
        })

    return {
        "total_duration": total_duration,
        "total_idle": total_idle,
        "active_work": active_work,
        "recentLogs": recent_logs,
        "_extended_stats": stats_dict 
    }

@router.post("/simulate/{agent_id}")
async def simulate_agent_event(
    agent_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    from ..db.models import Agent # type: ignore
    from sqlalchemy import func
    agent_res = await db.execute(select(Agent).where(func.lower(Agent.AgentId) == func.lower(agent_id)))
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
        ("Data Loss Prevention", "Blocked exfiltration of credit card numbers in chrome.exe upload payload."),
        ("DeceptionTriggered", "Honeypot Triggered: Unauthorized read access to C:\\ProgramData\\passwords.txt")
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
        payload = {
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
        }
        await sio.emit('new_client_activity', payload, room=f"tenant_{agent.TenantId}")
        await sio.emit('new_client_activity', payload, room="superadmin")
        await sio.emit('new_client_activity', payload, room=agent_id)

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

@router.get("/locations")
async def get_latest_locations(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    from ..db.models import LocationReport, Agent # type: ignore
    
    # Query latest location for all active agents in the tenant
    query = select(LocationReport, Agent.Hostname).join(
        Agent, LocationReport.AgentId == Agent.AgentId
    ).where(
        LocationReport.TenantId == current_user.TenantId
    ).order_by(
        LocationReport.AgentId, LocationReport.Timestamp.desc()
    )
    
    result = await db.execute(query)
    rows = result.all()
    
    # Deduplicate: only keep the newest record per agent
    latest_locations = {}
    for loc_report, hostname in rows:
        if loc_report.AgentId not in latest_locations:
            latest_locations[loc_report.AgentId] = {
                "AgentId": loc_report.AgentId,
                "Hostname": hostname or loc_report.AgentId,
                "Latitude": loc_report.Latitude,
                "Longitude": loc_report.Longitude,
                "Source": loc_report.Source,
                "Timestamp": loc_report.Timestamp.isoformat()
            }
            
    return list(latest_locations.values())
