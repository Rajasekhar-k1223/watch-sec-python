import asyncio
import os
import sys

sys.path.append("/opt/apps/monitorix/watch-sec-python/backend")

from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker
from sqlalchemy.future import select
from app.db.models import EventLog, AgentReport
from app.services.ai_service import ai_service

async def test_summary():
    database_url = os.getenv("DATABASE_URL", "postgresql+asyncpg://monitorix:monitorix_secure_pass@localhost:5432/monitorix")
    print(f"[Test] Connecting to: {database_url}")
    engine = create_async_engine(database_url, echo=True)
    async_session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    async with async_session() as db:
        # 1. Fetch first agent
        res = await db.execute(select(AgentReport))
        agents = res.scalars().all()
        print(f"[Test] Found {len(agents)} agents in database.")
        
        target_agent_id = "vmi3011362"
        if agents:
            target_agent_id = agents[0].AgentId
            print(f"[Test] Using agent: {target_agent_id}")
        else:
            print(f"[Test] No agents found. Using default agent ID: {target_agent_id}")

        # 2. Query EventLogs for this agent
        res_events = await db.execute(select(EventLog).where(EventLog.AgentId == target_agent_id))
        events = res_events.scalars().all()
        print(f"[Test] Found {len(events)} EventLogs for agent: {target_agent_id}")

        # 3. Simulate summarize_incident backend route logic
        mapped_events = []
        for e in events:
            mapped_events.append({
                "Type": e.Type or "Unknown",
                "Details": e.Details or "",
                "Timestamp": e.Timestamp.isoformat() if e.Timestamp else "",
                "Severity": e.Severity or "Medium"
            })

        print(f"[Test] Mapped events structure: {mapped_events}")
        
        summary = ai_service.generate_incident_summary(mapped_events)
        threat_assessment = ai_service.calculate_threat_score(target_agent_id, mapped_events)

        print("\n=== AI INCIDENT FORENSIC SUMMARY ===")
        print(summary)
        print("\n=== THREAT SCORE ASSESSMENT ===")
        print(threat_assessment)
        print("===============================\n")

    await engine.dispose()

if __name__ == "__main__":
    asyncio.run(test_summary())
