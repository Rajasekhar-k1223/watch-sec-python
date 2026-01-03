from app.core.celery_app import celery_app
from sqlalchemy import create_engine, select, update
from sqlalchemy.orm import sessionmaker
from app.db.models import Agent, Vulnerability
from app.db.session import settings
import json
import logging

# Setup Sync DB Connection for Celery
sync_url = settings.DATABASE_URL.replace("sqlite+aiosqlite", "sqlite").replace("postgresql+asyncpg", "postgresql")
engine = create_engine(sync_url)
Session = sessionmaker(bind=engine)

logger = logging.getLogger("Celery-Security")

@celery_app.task
def scan_vulnerabilities_background(agent_id: str, software_json: str):
    """
    Scans an agent's software inventory against known Vulnerabilities.
    Updates the Agent's vulnerability count/status.
    """
    if not software_json:
        return

    try:
        software_list = json.loads(software_json)
    except:
        return

    session = Session()
    try:
        # Fetch all vulnerabilities (Caching recommended in prod)
        vulnerabilities = session.query(Vulnerability).all()
        
        vuln_count = 0
        found_cves = []

        for sw in software_list:
            name = sw.get("Name", "").lower()
            version = sw.get("Version", "")
            
            for v in vulnerabilities:
                # Basic Match: Name contains Product
                if v.AffectedProduct.lower() in name:
                    # Version Check (Simplified)
                    # TODO: Implement full SemVer parsing
                    # Here we just flag if product matches for MVP
                    vuln_count += 1
                    found_cves.append(v.CVE)
        
        if vuln_count > 0:
            logger.warning(f"Agent {agent_id} has {vuln_count} vulnerabilities: {found_cves}")
            
            # Update Agent Record (Assuming we add a VulnerabilityCount column later, 
            # or just log it for now as per plan to 'Flag' it)
            # For MVP, let's just log a Security Event if critical
            
            from app.db.models import EventLog
            from datetime import datetime
            
            # Deduplicate alerts? 
            # For now, insert an alert event
            alert = EventLog(
                AgentId=agent_id,
                Type="Vulnerability Alert",
                Details=f"Found {vuln_count} vulnerable packages: {', '.join(set(found_cves))}",
                Timestamp=datetime.utcnow()
            )
            session.add(alert)
            session.commit()
            
    except Exception as e:
        logger.error(f"Scan failed: {e}")
    finally:
        session.close()
