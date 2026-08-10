import asyncio
from sqlalchemy.future import select
from app.db.session import async_session
from app.db.models import Agent, Tenant

async def main():
    async with async_session() as db:
        res_a = await db.execute(select(Agent).where(Agent.AgentId == "EC2AMAZ-MLAM305"))
        agent = res_a.scalars().first()
        res_t = await db.execute(select(Tenant).where(Tenant.Id == agent.TenantId))
        tenant = res_t.scalars().first()
        print(f"Agent MachineId: {agent.MachineId}")
        print(f"Tenant ApiKey: {tenant.ApiKey}")

asyncio.run(main())
