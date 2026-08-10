from app.core.celery_app import celery_app # type: ignore
from sqlalchemy import create_engine, select, update # type: ignore
from sqlalchemy.orm import sessionmaker # type: ignore
from app.db.models import Agent, Vulnerability, AgentSoftware, EventLog, Tenant # type: ignore
from datetime import datetime, timedelta # type: ignore
from app.db.session import settings # type: ignore
import json # type: ignore
import logging # type: ignore
from packaging import version # type: ignore

# Setup Sync DB Connection for Celery
sync_url = settings.DATABASE_URL.replace("sqlite+aiosqlite", "sqlite") \
                                .replace("postgresql+asyncpg", "postgresql") \
                                .replace("mysql+aiomysql", "mysql+pymysql")
engine = create_engine(sync_url)
Session = sessionmaker(bind=engine)

logger = logging.getLogger("Celery-Security")

@celery_app.task
def scan_vulnerabilities_background(agent_id: str, software_json: str):
    """
    Scans an agent's software inventory against known Vulnerabilities.
    Updates the Agent's vulnerability count/status and synchronizes the SBOM.
    """
    print(f"DEBUG: scan_vulnerabilities_background started for {agent_id}", flush=True)
    session = Session()
    try:
        # [NEW] If software is not provided in call, fetch from DB history
        if not software_json:
            print(f"DEBUG: No software_json provided, fetching from DB for {agent_id}", flush=True)
            result = session.execute(select(Agent).where(Agent.AgentId == agent_id))
            agent_record = result.scalars().first()
            if agent_record and agent_record.InstalledSoftwareJson:
                software_json = agent_record.InstalledSoftwareJson
                print(f"DEBUG: Loaded software for Agent {agent_id} from DB: {len(software_json)} chars", flush=True)
            else:
                print(f"DEBUG: No software inventory found for Agent {agent_id}. Skipping scan.", flush=True)
                return

        try:
            software_list = json.loads(software_json)
            print(f"DEBUG: Scanning {len(software_list)} items for Agent {agent_id}", flush=True)
        except Exception as pe:
            print(f"DEBUG: Failed to parse software JSON for Agent {agent_id}: {pe}", flush=True)
            return

        # Fetch all vulnerabilities (Caching recommended in prod)
        vulnerabilities = session.query(Vulnerability).all()
        logger.info(f"Matched against {len(vulnerabilities)} known vulnerabilities")
        
        vuln_count = 0
        found_cves = []

        # --- [v2.6.0] Relational SBOM Synchronization ---
        # 1. Clear old inventory for this agent
        session.query(AgentSoftware).filter(AgentSoftware.AgentId == agent_id).delete()
        
        new_sw_items = []
        for sw in software_list:
            name = sw.get("Name", "Unknown")
            version_str = sw.get("Version", "Unknown")
            sw_type = sw.get("Type", "OS")
            
            # Calculate vulnerability count for this specific package
            sw_vuln_count = 0
            highest_severity = "None"
            has_patch = False
            latest_version = None

            for v in vulnerabilities:
                # Basic Match: Name contains Product
                if v.AffectedProduct.lower() in name.lower():
                    is_vulnerable = False
                    logger.debug(f"Possible match: {name} v{version_str} vs {v.CVE} ({v.AffectedProduct})")
                    
                    try:
                        sv = version.parse(version_str) if version_str and version_str != "Unknown" else None
                        v_min = version.parse(v.MinVersion) if v.MinVersion else None
                        v_max = version.parse(v.MaxVersion) if v.MaxVersion else None
                        
                        if sv:
                            if v_min and v_max:
                                if v_min <= sv <= v_max:
                                    is_vulnerable = True
                            elif v_min:
                                if sv >= v_min:
                                    is_vulnerable = True
                            elif v_max:
                                if sv <= v_max:
                                    is_vulnerable = True
                            else:
                                is_vulnerable = True
                        else:
                            is_vulnerable = True
                    except Exception as ve:
                        logger.warning(f"Version parse error for {name} ({version_str}): {ve}")
                        is_vulnerable = True

                    if is_vulnerable:
                        sw_vuln_count += 1
                        vuln_count += 1
                        found_cves.append(f"{v.CVE} ({v.Severity})")
                        logger.info(f"[!] VULNERABILITY FOUND on {agent_id}: {v.CVE} in {name}")
                        
                        # [NEW] Calculate Severity and Patch status
                        severity_map = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "None": 0}
                        curr_sev = severity_map.get(highest_severity, 0)
                        new_sev = severity_map.get(v.Severity, 0)
                        if new_sev > curr_sev:
                            highest_severity = v.Severity
                            
                        # Use MaxVersion + 1 as the patch target simplified logic
                        if v.MaxVersion:
                            has_patch = True
                            if not latest_version:
                                latest_version = v.MaxVersion
                            else:
                                try:
                                    if version.parse(v.MaxVersion) > version.parse(latest_version):
                                        latest_version = v.MaxVersion
                                except: pass
            
            # Save SBOM detail
            new_sw_items.append(AgentSoftware(
                AgentId=agent_id,
                Name=name,
                Version=version_str,
                Type=sw_type,
                VulnerabilityCount=sw_vuln_count,
                Severity=highest_severity,
                HasPatchAvailable=has_patch,
                LatestVersion=latest_version,
                LastSeen=datetime.utcnow()
            ))
            
        session.add_all(new_sw_items)
        session.commit()
        print(f"DEBUG: Successfully synced {len(new_sw_items)} AgentSoftware records for {agent_id}", flush=True)

        if vuln_count > 0:
            logger.warning(f"Agent {agent_id} has {vuln_count} vulnerabilities: {found_cves}")
            import hmac
            import hashlib
            from app.socket_instance import sio_sync
            
            alert = EventLog(
                AgentId=agent_id,
                Type="Vulnerability Alert",
                Details=f"Found {vuln_count} vulnerable packages: {', '.join(set(found_cves))}",
                Timestamp=datetime.utcnow()
            )
            session.add(alert)
            session.commit()
            logger.info(f"Alert recorded for Agent {agent_id}")

            # [AUTO-PATCH] If enabled, dispatch background update command
            agent_record = session.query(Agent).filter(Agent.AgentId == agent_id).first()
            if agent_record and agent_record.AutoPatchEnabled:
                logger.info(f"Auto-Patch ENABLED for Agent {agent_id}. Dispatching update...")
                
                tenant = session.query(Tenant).filter(Tenant.Id == agent_record.TenantId).first()
                if tenant:
                    # Construct Command
                    command = ""
                    if "win" in (agent_record.Hostname or "").lower() or "windows" in (agent_record.Version or "").lower():
                        command = "winget upgrade --all --silent --accept-package-agreements --accept-source-agreements --include-unknown"
                    else:
                        command = "export DEBIAN_FRONTEND=noninteractive; apt-get update && apt-get upgrade -y"

                    # Sign Command
                    timestamp = datetime.utcnow().isoformat()
                    action = "ExecuteCommand"
                    params = {"command": command}
                    msg_parts = [str(action), json.dumps(params, sort_keys=True), str(timestamp)]
                    message = "|".join(msg_parts).encode('utf-8')
                    machine_id = agent_record.MachineId or agent_record.AgentId
                    key = hashlib.sha256(tenant.ApiKey.encode() + machine_id.encode()).digest()
                    signature = hmac.new(key, message, hashlib.sha256).hexdigest()

                    # Dispatch via Sync Manager
                    payload = {
                        "action": action,
                        "params": params,
                        "timestamp": timestamp,
                        "signature": signature,
                        "policy_name": "Automatic Vulnerability Remediation"
                    }
                    sio_sync.emit('Remediation', payload, room=agent_id)
                    logger.info(f"Auto-Patch Command Dispatched to Agent {agent_id}")
        else:
            logger.info(f"No vulnerabilities found for Agent {agent_id}")
            
        # [v2.6.0] Emit Real-Time UI Refresh Event
        try:
            from app.socket_instance import sio_sync
            sio_sync.emit('agent_software_update', {'agentId': agent_id}, room=agent_id)
            sio_sync.emit('agent_software_update', {'agentId': agent_id})  # broadcast to all for safety
            logger.info(f"Emitted agent_software_update for {agent_id}")
        except Exception as socket_err:
            logger.error(f"Failed to emit software update socket event: {socket_err}")
            
    except Exception as e:
        logger.error(f"Scan failed for Agent {agent_id}: {e}")
        import traceback # type: ignore
        logger.error(traceback.format_exc())
    finally:
        session.close()

@celery_app.task
def cleanup_agents():
    """[v2.6.0] Auto-Decommission Zombies & Generate Offline Alerts."""
    from app.db.models import ActivityLog, DetectionAlert
    from app.services.alert_service import alert_service
    import asyncio
    
    session = Session()
    try:
        decommission_threshold = datetime.utcnow() - timedelta(hours=24)
        offline_threshold = datetime.utcnow() - timedelta(minutes=2)
        
        # 1. Fetch agents transitioning to Offline
        going_offline = session.execute(
            select(Agent).where(Agent.LastSeen < offline_threshold, Agent.Status == "Online")
        ).scalars().all()
        
        if going_offline:
            # Prefetch tenants to avoid N+1 queries
            tenant_ids = {a.TenantId for a in going_offline if a.TenantId}
            tenants = session.execute(
                select(Tenant).where(Tenant.Id.in_(tenant_ids))
            ).scalars().all()
            tenant_map = {t.Id: t for t in tenants}
            
            async def dispatch_alerts():
                for agent in going_offline:
                    details = f"Agent {agent.Hostname or agent.AgentId} heartbeat lost (Last Seen: {agent.LastSeen})"
                    
                    # Create ActivityLog
                    log = ActivityLog(
                        AgentId=agent.AgentId,
                        TenantId=agent.TenantId,
                        Type="AgentOffline",
                        Details=details,
                        IsAlert=True,
                        Timestamp=datetime.utcnow()
                    )
                    session.add(log)
                    
                    # Create DetectionAlert for Dashboard
                    alert = DetectionAlert(
                        AgentId=agent.AgentId,
                        MatchedContent=details,
                        Status="New",
                        Severity="High",
                        RuleContent="Agent Offline",
                        Timestamp=datetime.utcnow()
                    )
                    session.add(alert)
                    session.flush() # To get alert.Id
                    
                    # Dispatch to external integrations (Slack/Teams)
                    tenant = tenant_map.get(agent.TenantId)
                    if tenant and tenant.IntegrationConfigJson:
                        try:
                            config = json.loads(tenant.IntegrationConfigJson)
                            if config:
                                alert_data = {
                                    "Id": alert.Id,
                                    "AgentId": agent.AgentId,
                                    "Type": "AgentOffline",
                                    "Severity": "High",
                                    "Details": details,
                                    "Timestamp": alert.Timestamp.isoformat()
                                }
                                await alert_service.dispatch_alert(config, alert_data)
                        except Exception as e:
                            logger.error(f"Failed to dispatch offline alert: {e}")
            
            # Run the async dispatch block
            try:
                loop = asyncio.get_event_loop()
                if loop.is_running():
                    asyncio.ensure_future(dispatch_alerts())
                else:
                    loop.run_until_complete(dispatch_alerts())
            except RuntimeError:
                asyncio.run(dispatch_alerts())
                
            # Update status to Offline
            session.execute(
                update(Agent)
                .where(Agent.LastSeen < offline_threshold, Agent.Status == "Online")
                .values(Status="Offline")
            )
        
        # 2. Decommission Zombies (Hidden from main list)
        session.execute(
            update(Agent)
            .where(Agent.LastSeen < decommission_threshold, Agent.Status == "Offline")
            .values(Status="Decommissioned")
        )
        
        session.commit()
        if going_offline:
            logger.info(f"Agent status cleanup: Marked {len(going_offline)} agents offline.")
    except Exception as e:
        logger.error(f"Cleanup task failed: {e}")
        session.rollback()
    finally:
        session.close()
