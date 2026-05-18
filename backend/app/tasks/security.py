from app.core.celery_app import celery_app # type: ignore
from sqlalchemy import create_engine, select, update # type: ignore
from sqlalchemy.orm import sessionmaker # type: ignore
from app.db.models import Agent, Vulnerability # type: ignore
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
    Updates the Agent's vulnerability count/status.
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

        for sw in software_list:
            name = sw.get("Name", "Unknown").lower()
            sw_version = sw.get("Version", "Unknown")
            
            for v in vulnerabilities:
                # Basic Match: Name contains Product
                if v.AffectedProduct.lower() in name:
                    is_vulnerable = False
                    logger.debug(f"Possible match: {name} v{sw_version} vs {v.CVE} ({v.AffectedProduct})")
                    
                    try:
                        sv = version.parse(sw_version) if sw_version and sw_version != "Unknown" else None
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
                        logger.warning(f"Version parse error for {name} ({sw_version}): {ve}")
                        is_vulnerable = True

                    if is_vulnerable:
                        vuln_count += 1
                        found_cves.append(f"{v.CVE} ({v.Severity})")
                        logger.info(f"[!] VULNERABILITY FOUND on {agent_id}: {v.CVE} in {name}")
        
        if vuln_count > 0:
            logger.warning(f"Agent {agent_id} has {vuln_count} vulnerabilities: {found_cves}")
            
            from app.db.models import EventLog, Agent, Tenant # type: ignore
            from datetime import datetime # type: ignore
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
            
    except Exception as e:
        logger.error(f"Scan failed for Agent {agent_id}: {e}")
        import traceback # type: ignore
        logger.error(traceback.format_exc())
    finally:
        session.close()

@celery_app.task
def cleanup_agents():
    """[v2.6.0] Auto-Decommission Zombies (Short-lived Replicas)."""
    from datetime import datetime, timedelta # type: ignore
    session = Session()
    try:
        # If an agent is offline for > 24h, mark as 'Decommissioned'
        decommission_threshold = datetime.utcnow() - timedelta(hours=24)
        
        # Mark as Offline if no heartbeat for 2 mins
        offline_threshold = datetime.utcnow() - timedelta(minutes=2)
        
        # 1. Update status to Offline
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
        logger.info("Agent status cleanup & decommissioning task completed.")
    except Exception as e:
        logger.error(f"Cleanup task failed: {e}")
    finally:
        session.close()
