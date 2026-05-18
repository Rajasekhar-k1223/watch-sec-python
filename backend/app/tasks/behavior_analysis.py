from app.core.celery_app import celery_app # type: ignore
from sqlalchemy import create_engine, select # type: ignore
from sqlalchemy.orm import sessionmaker # type: ignore
from app.db.models import Agent, EventLog, Policy # type: ignore
from app.db.session import settings # type: ignore
from datetime import datetime, timedelta
import logging
import json

# Setup Sync DB Connection for Celery
sync_url = settings.DATABASE_URL.replace("sqlite+aiosqlite", "sqlite") \
                                .replace("postgresql+asyncpg", "postgresql") \
                                .replace("mysql+aiomysql", "mysql+pymysql")
engine = create_engine(sync_url)
Session = sessionmaker(bind=engine)

logger = logging.getLogger("Celery-Behavior")

@celery_app.task
def analyze_workforce_productivity():
    """
    [v2.7.5] Background Task: Periodic Workforce Productivity & Behavioral Analysis.
    Calculates Focus Scores, identifies Burnout risk, and detects Behavioral Drift.
    """
    session = Session()
    try:
        # 1. Fetch Active Agents (last 24 hours for daily summary)
        day_ago = datetime.utcnow() - timedelta(hours=24)
        agents = session.query(Agent).filter(Agent.LastHeartbeat > day_ago).all()
        
        for agent in agents:
            # 2. Get Policy Mapping
            policy = None
            if agent.PolicyId:
                policy = session.query(Policy).filter(Policy.Id == agent.PolicyId).first()
            
            prod_map = {}
            if policy and policy.ProductivityJson:
                try: prod_map = json.loads(policy.ProductivityJson)
                except: pass
            
            # 3. Fetch Activity Events
            recent_events = session.query(EventLog).filter(
                EventLog.AgentId == agent.AgentId,
                EventLog.Timestamp > day_ago,
                EventLog.Type == "ActivityMonitor"
            ).all()
            
            if not recent_events: continue
            
            # 4. Calculate Focus Score
            total_time = 0
            focus_time = 0
            distraction_time = 0
            late_hours = 0
            
            # Categorization Logic
            for i in range(len(recent_events)):
                ev = recent_events[i]
                details = ev.Details.lower()
                
                is_productive = False
                is_distraction = False
                
                for key, val in prod_map.items():
                    if key.lower() in details:
                        if val == "Productive": is_productive = True
                        elif val == "Distraction": is_distraction = True
                        break
                
                total_time += 1
                if is_productive: focus_time += 1
                elif is_distraction: distraction_time += 1
                
                # Check for "After-Hours" (Burnout Indicator)
                if ev.Timestamp.hour >= 20 or ev.Timestamp.hour <= 6:
                    late_hours += 1
            
            focus_score = (focus_time / total_time * 100) if total_time > 0 else 0
            
            # 5. Burnout Detection
            burnout_risk = "Low"
            if late_hours > 120: # 2 hours of work in late hours
                burnout_risk = "High"
            elif late_hours > 30:
                burnout_risk = "Medium"
            
            # 6. Behavioral Drift (Mock logic: compare to a baseline)
            # In production, we'd compare this week's FocusScore vs Last week's
            drift = "Stable"
            if focus_score < 40: drift = "Declining Engagement"
            
            # 7. Update Agent Behavioral Metadata
            hi_data = {
                "FocusScore": round(focus_score, 1),
                "DistractionRatio": round((distraction_time / total_time * 100), 1) if total_time > 0 else 0,
                "BurnoutRisk": burnout_risk,
                "BehavioralDrift": drift,
                "TotalActiveMinutes": total_time,
                "LateHoursMinutes": late_hours,
                "LastAnalyzed": datetime.utcnow().isoformat()
            }
            
            agent.BehavioralMetadataJson = json.dumps(hi_data)
            
        session.commit()
        logger.info(f"Workforce analysis complete for {len(agents)} agents.")
        
    except Exception as e:
        logger.error(f"Behavioral analysis failed: {e}")
        session.rollback()
    finally:
        session.close()
