import asyncio
import os
import sys
import random
import uuid
from datetime import datetime, timedelta

# Add parent dir to path to allow imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession # type: ignore
from sqlalchemy.orm import sessionmaker # type: ignore
from sqlalchemy.future import select # type: ignore
from app.db.models import Agent, AgentReportEntity, Tenant, AuditLog # type: ignore
from dotenv import load_dotenv # type: ignore

load_dotenv()
DATABASE_URL = os.getenv("DATABASE_URL")

async def seed_data():
    print("[Seed] Starting dummy data generation...")
    
    engine = create_async_engine(DATABASE_URL, echo=False)
    async_session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    async with async_session() as db:
        # Get Tenant
        result = await db.execute(select(Tenant).where(Tenant.Name == "Default Tenant"))
        tenant = result.scalars().first()
        
        if not tenant:
            print("[Seed] No Default Tenant found! Run seed.py first.")
            return

        print(f"[Seed] Found tenant: {tenant.Id}")

        now = datetime.utcnow()

        # Seed 9 Agents
        agents = []
        for i in range(9):
            agent_id = str(uuid.uuid4())
            agent = Agent(
                AgentId=agent_id,
                TenantId=tenant.Id,
                Hostname=f"WIN-CLIENT-{1000+i}",
                Status="Online" if i < 7 else "Offline",
                LastSeen=now - timedelta(minutes=random.randint(0, 5) if i < 7 else random.randint(30, 300)),
                NetworkInMbps=random.uniform(0.1, 5.0) if i < 7 else 0.0,
                NetworkOutMbps=random.uniform(0.1, 2.0) if i < 7 else 0.0,
                ThreatScore=random.randint(0, 100),
                RiskLevel="High" if i == 0 else ("Medium" if i < 3 else "Normal")
            )
            db.add(agent)
            agents.append(agent)
        
        await db.commit()
        print(f"[Seed] Created {len(agents)} dummy agents.")

        # Seed Agent Reports (Telemetry for the last 24 hours)
        reports = []
        for agent in agents:
            for hours_ago in range(24):
                ts = now - timedelta(hours=hours_ago, minutes=random.randint(0, 59))
                report = AgentReportEntity(
                    AgentId=agent.AgentId,
                    TenantId=tenant.Id,
                    Status="Online",
                    CpuUsage=random.uniform(5.0, 85.0),
                    MemoryUsage=random.uniform(10.0, 95.0),
                    DiskUsage=random.uniform(20.0, 80.0),
                    NetworkInMbps=random.uniform(0.1, 5.0),
                    NetworkOutMbps=random.uniform(0.1, 2.0),
                    Timestamp=ts
                )
                db.add(report)
                reports.append(report)
        
        await db.commit()
        print(f"[Seed] Created {len(reports)} dummy agent reports.")

        # Seed Audit Logs (Recent Alerts)
        logs = []
        log_types = ["SystemIdle", "System System Idle", "ThreatDetected", "AppFocus", "FileAccess"]
        for i in range(20):
            ts = now - timedelta(minutes=random.randint(1, 1440))
            ltype = random.choice(log_types)
            log = AuditLog(
                TenantId=tenant.Id,
                Action=ltype,
                UserId=1,
                TargetResource="System",
                IpAddress="127.0.0.1",
                UserAgent="Monitorix Agent",
                Status="Success",
                Details=f"Event triggered by {agents[random.randint(0,8)].Hostname}",
                Timestamp=ts
            )
            db.add(log)
            logs.append(log)
        
        await db.commit()
        print(f"[Seed] Created {len(logs)} dummy audit logs.")

    print("[Seed] Seeding Complete.")
    await engine.dispose()

if __name__ == "__main__":
    asyncio.run(seed_data())
