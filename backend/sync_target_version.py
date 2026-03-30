import asyncio
from sqlalchemy import update
from app.db.session import AsyncSessionLocal
from app.db.models import Agent
from app.core.constants import LATEST_AGENT_VERSION

async def sync_version():
    async with AsyncSessionLocal() as db:
        print(f"Syncing all agents to TargetVersion: {LATEST_AGENT_VERSION}")
        await db.execute(
            update(Agent)
            .values(TargetVersion=LATEST_AGENT_VERSION)
        )
        await db.commit()
        print("Done.")

if __name__ == "__main__":
    asyncio.run(sync_version())
