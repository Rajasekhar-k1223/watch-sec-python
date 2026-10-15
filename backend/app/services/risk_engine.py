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

    now = datetime.datetime.utcnow()
    if not profile:
        if not agent:
            return None
        profile = DeviceRiskProfile(
            AgentId=agent_id, 
            TenantId=agent.TenantId,
            DeviceRiskScore=15.0,
            UserRiskScore=10.0,
            ProcessRiskScore=10.0,
            NetworkRiskScore=15.0,
            BehavioralRiskScore=10.0,
            ThreatIntelRiskScore=10.0,
            TotalRiskScore=12.5,
            RiskLevel="Low",
            LastCalculatedAt=now
        )
        db.add(profile)

    # Initialize any None attributes
    profile.DeviceRiskScore = profile.DeviceRiskScore if profile.DeviceRiskScore is not None else 15.0
    profile.UserRiskScore = profile.UserRiskScore if profile.UserRiskScore is not None else 10.0
    profile.ProcessRiskScore = profile.ProcessRiskScore if profile.ProcessRiskScore is not None else 10.0
    profile.NetworkRiskScore = profile.NetworkRiskScore if profile.NetworkRiskScore is not None else 15.0
    profile.BehavioralRiskScore = profile.BehavioralRiskScore if profile.BehavioralRiskScore is not None else 10.0
    profile.ThreatIntelRiskScore = profile.ThreatIntelRiskScore if profile.ThreatIntelRiskScore is not None else 10.0
    profile.LastCalculatedAt = profile.LastCalculatedAt or now

    if agent and not getattr(agent, "AutoPatchEnabled", False):
        profile.DeviceRiskScore = min(profile.DeviceRiskScore + 10.0, 100.0)

    # Wire in UEBA Evaluation
    try:
        from app.services.ueba_engine import ueba_engine
        mock_event = {
            "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
            "process_name": "unknown_binary.exe"
        }
        eval_result = await ueba_engine.evaluate_event(db, agent_id, mock_event)
        
        if eval_result.get("score", 0) > 0:
            profile.BehavioralRiskScore = min(profile.BehavioralRiskScore + eval_result["score"], 100.0)
            
            for anomaly in eval_result.get("anomalies", []):
                if "travel" in anomaly.lower() or "hours" in anomaly.lower():
                    profile.UserRiskScore = min(profile.UserRiskScore + 50.0, 100.0)
    except Exception as e:
        print(f"[RiskEngine] Failed to evaluate UEBA: {e}")

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
