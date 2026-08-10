import datetime
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from app.db.models import DeviceRiskProfile, Agent

def map_score_to_level(score: float) -> str:
    if score <= 25:
        return "Low"
    elif score <= 60:
        return "Medium"
    elif score <= 85:
        return "High"
    return "Critical"

async def calculate_risk_score(db: AsyncSession, agent_id: str):
    profile = (await db.execute(select(DeviceRiskProfile).where(DeviceRiskProfile.AgentId == agent_id))).scalars().first()
    agent = (await db.execute(select(Agent).where(Agent.AgentId == agent_id))).scalars().first()

    if not profile:
        if not agent:
            return None
        profile = DeviceRiskProfile(AgentId=agent_id, TenantId=agent.TenantId)
        db.add(profile)

    if agent and not agent.AutoPatchEnabled:
        profile.DeviceRiskScore = min(profile.DeviceRiskScore + 10.0, 100.0)

    # Wire in UEBA Evaluation
    try:
        from app.services.ueba_engine import ueba_engine
        # Evaluate recent mock event for the agent to simulate real-time ingestion
        # In a real system, this happens continually on the data stream
        mock_event = {
            "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
            "process_name": "unknown_binary.exe"
        }
        eval_result = await ueba_engine.evaluate_event(db, agent_id, mock_event)
        
        if eval_result["score"] > 0:
            profile.BehavioralRiskScore = min(profile.BehavioralRiskScore + eval_result["score"], 100.0)
            
            # If there are user-level anomalies (like impossible travel), spike UserRisk
            for anomaly in eval_result["anomalies"]:
                if "travel" in anomaly.lower() or "hours" in anomaly.lower():
                    profile.UserRiskScore = min(profile.UserRiskScore + 50.0, 100.0)
    except Exception as e:
        print(f"[RiskEngine] Failed to evaluate UEBA: {e}")

    now = datetime.datetime.utcnow()
    hours_since = (now - profile.LastCalculatedAt).total_seconds() / 3600.0
    if hours_since > 24:
        decay = 0.9
        profile.UserRiskScore *= decay
        profile.ProcessRiskScore *= decay
        profile.NetworkRiskScore *= decay
        profile.BehavioralRiskScore *= decay
        profile.ThreatIntelRiskScore *= decay

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

    await db.commit()
    return profile
