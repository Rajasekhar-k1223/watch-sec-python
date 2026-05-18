from app.core.celery_app import celery_app # type: ignore
from sqlalchemy import create_engine, select # type: ignore
from sqlalchemy.orm import sessionmaker # type: ignore
from app.db.models import Agent, EventLog, Notification, Policy # type: ignore
from app.db.session import settings # type: ignore
from app.services.ai_service import ai_service # type: ignore
from datetime import datetime, timedelta
import logging
import json

# Setup Sync DB Connection for Celery
sync_url = settings.DATABASE_URL.replace("sqlite+aiosqlite", "sqlite") \
                                .replace("postgresql+asyncpg", "postgresql") \
                                .replace("mysql+aiomysql", "mysql+pymysql")
engine = create_engine(sync_url)
Session = sessionmaker(bind=engine)

logger = logging.getLogger("Celery-AI")

@celery_app.task
def analyze_fleet_security_posture():
    """
    [v2.1.0] Background Task: Periodic Fleet-wide AI Security Assessment.
    Correlates events and updates Threat Scores for all active agents.
    """
    session = Session()
    try:
        # 1. Fetch Active Agents
        one_hour_ago = datetime.utcnow() - timedelta(hours=1)
        agents = session.query(Agent).filter(Agent.LastHeartbeat > one_hour_ago).all()
        
        for agent in agents:
            # 2. Fetch Recent Events for Correlation
            # We look at the last 2 hours of events
            window_start = datetime.utcnow() - timedelta(hours=2)
            # Since EventLog is in MongoDB usually, we might need a different fetch strategy
            # BUT in this codebase, some EventLogs might be in SQL for high-priority alerts
            # Let's assume we have a way to get recent events (mocking for now or using SQL if available)
            
            # For the sake of the task, we fetch from SQL EventLog (AuditLog/EventLog)
            recent_events_res = session.execute(
                select(EventLog).where(EventLog.AgentId == agent.AgentId, EventLog.Timestamp > window_start)
            )
            events = []
            for row in recent_events_res.scalars().all():
                events.append({
                    "Type": row.Type,
                    "Details": row.Details,
                    "Timestamp": row.Timestamp.isoformat()
                })
            
            if not events: continue

            # [v2.6.9] AI Whitelisting Filter
            filtered_events = events
            if agent.PolicyId:
                policy = session.query(Policy).filter(Policy.Id == agent.PolicyId).first()
                if policy and policy.ExclusionsJson:
                    try:
                        exclusions = json.loads(policy.ExclusionsJson)
                        if exclusions:
                            filtered_events = []
                            for ev in events:
                                is_excluded = False
                                details = str(ev.get("Details", "")).lower()
                                for ex in exclusions:
                                    ex_val = str(ex.get("value", "")).lower()
                                    if not ex_val: continue
                                    
                                    if ex.get("type") == "path" and ex_val in details:
                                        is_excluded = True; break
                                    if ex.get("type") == "hash" and ex_val in details:
                                        is_excluded = True; break
                                    if ex.get("type") == "ip" and ex_val in details:
                                        is_excluded = True; break
                                
                                if not is_excluded:
                                    filtered_events.append(ev)
                    except Exception as e:
                        logger.error(f"Failed to process exclusions for agent {agent.AgentId}: {e}")
            
            if not filtered_events: 
                # Reset threat score if all events were filtered out
                agent.ThreatScore = 0
                agent.RiskLevel = "Low"
                continue
            
            # 3. AI Threat Scoring
            analysis = ai_service.calculate_threat_score(agent.AgentId, filtered_events)
            
            # 4. Update Agent Metadata
            # We store the latest threat score in the Agent record (metadata/column)
            agent.ThreatScore = analysis["Score"]
            agent.RiskLevel = analysis["Level"]
            
            # 5. [ALERTS] If Risk Level escalated to High/Critical, trigger notification
            if analysis["Level"] in ["High", "Critical"]:
                notif = Notification(
                    TenantId=agent.TenantId,
                    AgentId=agent.AgentId,
                    Title=f"AI Alert: {analysis['Level']} Threat Score Detected",
                    Message=f"Agent {agent.Hostname} scored {analysis['Score']}/100. Identified Risks: {', '.join(analysis['TopRisks'])}.",
                    Type=analysis["Level"],
                    CreatedAt=datetime.utcnow()
                )
                session.add(notif)
                
                # [v2.6.8] AUTONOMOUS REMEDIATION
                # Fetch agent's policy to check if autonomous defense is enabled
                try:
                    import hashlib, hmac, uuid, json
                    from app.db.models import Tenant, EventLog, Policy
                    
                    # Get assigned policy
                    policy = None
                    if agent.PolicyId:
                        policy = session.query(Policy).filter(Policy.Id == agent.PolicyId).first()
                    
                    # If enabled and score exceeds threshold
                    if policy and policy.AutonomousRemediationEnabled and analysis["Score"] >= policy.ThreatScoreThreshold:
                        tenant = session.query(Tenant).filter(Tenant.Id == agent.TenantId).first()
                        if tenant:
                            # Generate a System Recovery Key (AI-Initiated)
                            ai_key = f"AI-AUTO-{str(uuid.uuid4())[:8].upper()}"
                            unlock_hash = hashlib.sha256(ai_key.encode()).hexdigest()
                            
                            # Sign the command
                            action = "SOVEREIGN_LOCKDOWN"
                            params = {"unlock_hash": unlock_hash}
                            ts = datetime.utcnow().isoformat()
                            
                            machine_id = agent.MachineId or agent.AgentId
                            hmac_key = hashlib.sha256(tenant.ApiKey.encode() + machine_id.encode()).digest()
                            msg_parts = [action, json.dumps(params, sort_keys=True), ts]
                            signature = hmac.new(hmac_key, "|".join(msg_parts).encode(), hashlib.sha256).hexdigest()
                            
                            payload = {
                                "action": action,
                                "params": params,
                                "timestamp": ts,
                                "signature": signature,
                                "policy_name": f"Autonomous AI Defense ({policy.Name})"
                            }
                            
                            # Emit via Sync Socket
                            from app.socket_instance import sio_sync
                            sio_sync.emit('Remediation', payload, room=f"agent_{agent.AgentId}")
                            
                            # Log the Autonomous Governance Event
                            audit = EventLog(
                                AgentId=agent.AgentId,
                                TenantId=agent.TenantId,
                                EventType="SOVEREIGN_GOVERNANCE",
                                Severity="CRITICAL",
                                Description=f"AUTONOMOUS NEUTRALIZATION: AI triggered lockdown for {agent.Hostname} based on policy '{policy.Name}' (Score: {analysis['Score']} >= Threshold: {policy.ThreatScoreThreshold}). Recovery Key: {ai_key}",
                                Timestamp=datetime.utcnow()
                            )
                            session.add(audit)
                            
                            # Update Agent State
                            agent.LastRemediation = f"AI Lockdown ({policy.Name}): {datetime.utcnow().isoformat()}"
                            
                except Exception as ex:
                    logger.error(f"Autonomous remediation failed for {agent.AgentId}: {ex}")

                # Emit to Dashboard
                try:
                    from app.socket_instance import sio_sync
                    sio_sync.emit('ThreatEscalation', {
                        "agentId": agent.AgentId,
                        "score": analysis["Score"],
                        "level": analysis["Level"],
                        "risks": analysis["TopRisks"]
                    }, room=f"tenant_{agent.TenantId}")
                except: pass
        
        session.commit()
        logger.info(f"Fleet security posture analysis complete. Scanned {len(agents)} agents.")
        
    except Exception as e:
        logger.error(f"Fleet analysis failed: {e}")
        session.rollback()
    finally:
        session.close()

@celery_app.task
def generate_ai_remediation_suggestions(agent_id: str, incident_id: int):
    """
    [v2.1.0] Background Task: Generate context-aware remediation steps for a specific incident.
    """
    session = Session()
    try:
        # 1. Fetch Incident/Alert Details
        # ... logic to fetch relevant context ...
        
        # 2. LLM-Based Generation (Stub)
        # suggestions = ai_service.get_remediation_suggestions(context)
        pass
    finally:
        session.close()
