import datetime
from sqlalchemy.orm import Session
from app.db.models import DeviceRiskProfile, Agent

def map_score_to_level(score: float) -> str:
    if score <= 25:
        return "Low"
    elif score <= 60:
        return "Medium"
    elif score <= 85:
        return "High"
    return "Critical"

def calculate_risk_score(db: Session, agent_id: str):
    # Retrieve the profile or create one
    profile = db.query(DeviceRiskProfile).filter(DeviceRiskProfile.AgentId == agent_id).first()
    agent = db.query(Agent).filter(Agent.AgentId == agent_id).first()
    
    if not profile:
        if not agent:
            return None # Agent does not exist
        profile = DeviceRiskProfile(AgentId=agent_id, TenantId=agent.TenantId)
        db.add(profile)
    
    # In a real implementation, we would query MongoDB telemetry to calculate these vectors.
    # For now, we simulate the logic or pull from basic agent stats if available.
    
    # Simple stubs for the vectors based on agent stats
    # 1. Device Risk: if AutoPatchEnabled is false, higher risk
    if agent and not agent.AutoPatchEnabled:
        profile.DeviceRiskScore = min(profile.DeviceRiskScore + 10.0, 100.0)
        
    # Example decay logic: if last calculated > 24 hours, reduce score
    now = datetime.datetime.utcnow()
    hours_since = (now - profile.LastCalculatedAt).total_seconds() / 3600.0
    if hours_since > 24:
        decay_factor = 0.9 # 10% decay per 24 hours
        profile.UserRiskScore *= decay_factor
        profile.ProcessRiskScore *= decay_factor
        profile.NetworkRiskScore *= decay_factor
        profile.BehavioralRiskScore *= decay_factor
        profile.ThreatIntelRiskScore *= decay_factor
    
    # Weighted Average Calculation
    total_score = (
        (profile.ThreatIntelRiskScore * 0.30) +
        (profile.BehavioralRiskScore * 0.25) +
        (profile.ProcessRiskScore * 0.20) +
        (profile.NetworkRiskScore * 0.15) +
        (profile.UserRiskScore * 0.05) +
        (profile.DeviceRiskScore * 0.05)
    )
    
    profile.TotalRiskScore = round(total_score, 2)
    profile.RiskLevel = map_score_to_level(profile.TotalRiskScore)
    profile.LastCalculatedAt = now
    
    if agent:
        agent.ThreatScore = int(profile.TotalRiskScore)
        agent.RiskLevel = profile.RiskLevel
        
    db.commit()
    return profile
