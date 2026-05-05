from app.core.celery_app import celery_app # type: ignore
from pymongo import MongoClient # type: ignore
from sqlalchemy import create_engine # type: ignore
from sqlalchemy.orm import sessionmaker # type: ignore
import os # type: ignore
import json # type: ignore
from bson.objectid import ObjectId # type: ignore
from datetime import datetime # type: ignore

# DB Config (Sync for Celery Worker)
# Standardized to use .env passwords
MONGO_URL = os.getenv("MONGO_URL", "mongodb://admin:monitorix2025@watch-sec-mongo:27017/appdb?authSource=admin")
MYSQL_URL = os.getenv("DATABASE_URL", "").replace("aiomysql", "pymysql")

def get_sync_mongo():
    client = MongoClient(MONGO_URL)
    return client["watchsec"]

# Sync Engine for SQL
engine = None
if MYSQL_URL:
    try:
        engine = create_engine(MYSQL_URL, pool_pre_ping=True)
    except: engine = None
SessionLocal = sessionmaker(bind=engine) if engine else None

@celery_app.task
def analyze_risk_background(log_id_str: str, title: str, process: str, url: str):
    """
    Intelligent Background Task to analyze risk and update both SQL and MongoDB records.
    """
    print(f"[Celery] Intelligent Risk Analysis for Log: {log_id_str}")
    
    score = 0
    level = "Normal"
    category = "Neutral"
    prod_score = 50.0  # Base neutral score
    
    # Text to scan
    content = (f"{title} {process} {url}").lower()
    
    # 1. Fetch Thesaurus Rules from MySQL
    thesaurus_rules = []
    if SessionLocal:
        try:
            from app.db.models import ThesaurusEntry # type: ignore
            with SessionLocal() as session:
                entries = session.query(ThesaurusEntry).all()
                for e in entries:
                    keywords = [e.Keyword.lower()]
                    try:
                        syns = json.loads(e.Synonyms or "[]")
                        keywords.extend([s.lower() for s in syns])
                    except: pass
                    thesaurus_rules.append({
                        "keywords": keywords,
                        "category": e.Category
                    })
        except Exception as e:
            print(f"[Celery] Error fetching Thesaurus: {e}")

    # 2. Match Keywords
    for rule in thesaurus_rules:
        if any(k in content for k in rule["keywords"]):
            category = rule["category"]
            # Assign Scoring based on Category
            cat_lower = category.lower()
            if any(x in cat_lower for x in ["security", "hacking", "malware", "risk", "illegal"]):
                score = 85
                level = "High"
                prod_score = 0
            elif any(x in cat_lower for x in ["social", "entertainment", "gaming", "unproductive"]):
                score = 20
                level = "Unproductive"
                prod_score = 10
            elif any(x in cat_lower for x in ["work", "productivity", "office", "code", "dev"]):
                score = 0
                level = "Normal"
                prod_score = 100
                category = "Productive"
            break  # Stop at first match for simplicity

    # 3. Fallback (Legacy check for critical strings if Thesaurus is empty)
    if not thesaurus_rules or category == "Neutral":
        high_risk = ["terminal", "powershell", "cmd", "nmap", "wireshark", "tor browser", "metasploit"]
        if any(k in content for k in high_risk):
            score = 80
            level = "High"
            category = "Security"
            prod_score = 0
        
        unproductive = ["youtube", "facebook", "netflix", "instagram", "tiktok", "steam"]
        if any(k in content for k in unproductive):
            score = 10
            level = "Unproductive"
            category = "Entertainment"
            prod_score = 20

    # 4. Update SQL Database
    if SessionLocal:
        try:
            from app.db.models import ActivityLog # type: ignore
            with SessionLocal() as session:
                # Try to pars ID as int
                try:
                    sql_id = int(log_id_str)
                    log_obj = session.query(ActivityLog).filter(ActivityLog.Id == sql_id).first()
                    if log_obj:
                        log_obj.RiskScore = float(score)
                        log_obj.RiskLevel = level
                        log_obj.Category = category
                        log_obj.ProductivityScore = float(prod_score)
                        session.commit()
                        print(f"[Celery] Updated SQL Log {sql_id}")
                except ValueError:
                    pass # Not an integer ID
        except Exception as e:
            print(f"[Celery] Error updating SQL: {e}")

    # 5. Update MongoDB
    try:
        # Try to parse as ObjectId
        if len(log_id_str) == 24:
            db = get_sync_mongo()
            collection = db["activity"]
            result = collection.update_one(
                {"_id": ObjectId(log_id_str)},
                {"$set": {
                    "RiskScore": float(score), 
                    "RiskLevel": level,
                    "Category": category,
                    "ProductivityScore": float(prod_score)
                }}
            )
            print(f"[Celery] Updated Mongo Log {log_id_str}")
    except Exception as e:
        print(f"[Celery] Error updating Mongo: {e}")
    
    return {"id": log_id_str, "score": score, "level": level, "category": category}

@celery_app.task
def staggered_bulk_patch(agent_ids: list, batch_size=10, delay=60):
    """
    Rolling Update: Sets agents to 'pending_manual_push' in batches to avoid server spikes.
    This prevents the "Thundering Herd" problem when updating hundreds of agents.
    """
    from app.db.models import Agent, AuditLog # type: ignore
    from app.core.constants import LATEST_AGENT_VERSION # type: ignore
    from time import sleep
    from datetime import datetime

    total = len(agent_ids)
    print(f"[Celery] Starting Staggered Bulk Patch for {total} agents (Batch: {batch_size}, Delay: {delay}s)")

    if not SessionLocal:
        print("[Celery] Error: SessionLocal not initialized for staggered_bulk_patch.")
        return

    for i in range(0, total, batch_size):
        batch = agent_ids[i:i + batch_size]
        print(f"[Celery] Processing Update Batch {i//batch_size + 1} ({len(batch)} agents)...")
        
        try:
            with SessionLocal() as session:
                # Update specific agents
                agents_to_update = session.query(Agent).filter(Agent.AgentId.in_(batch)).all()
                for agent in agents_to_update:
                    agent.UpdateStatus = "pending_manual_push"
                    agent.TargetVersion = LATEST_AGENT_VERSION
                    
                    # Log audit entry for tracking
                    audit = AuditLog(
                        TenantId=agent.TenantId,
                        Actor="SYSTEM_BATCH",
                        Action="Push Manual Patch",
                        Target=f"{agent.Hostname} ({agent.AgentId})",
                        Details=f"Rolling staggered update triggered by admin (Batch {i//batch_size + 1})",
                        Timestamp=datetime.utcnow()
                    )
                    session.add(audit)
                
                session.commit()
                print(f"[Celery] Batch {i//batch_size + 1} committed successfully.")
        except Exception as e:
            print(f"[Celery] Batch Error at {i}: {e}")

        # Sleep only if there are more batches to process
        if i + batch_size < total:
            print(f"[Celery] Throttling: Waiting {delay}s before next batch to protect server bandwidth...")
            sleep(delay)

    print(f"[Celery] SUCCESS: Staggered rollout for {total} agents complete.")
    return {"status": "completed", "total_agents": total}
