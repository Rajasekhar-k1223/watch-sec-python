import asyncio
import sys
import os
from sqlalchemy.future import select

# Add parent dir to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.db.session import AsyncSessionLocal
from app.db.models import Tenant

async def seed_tenant():
    async with AsyncSessionLocal() as db:
        # Check if exists
        key = "e7cdae55-2e7e-467a-bdc5-3cbf5d321368"
        result = await db.execute(select(Tenant).where(Tenant.ApiKey == key))
        existing = result.scalars().first()
        
        if existing:
            print(f"Tenant with key {key} already exists.")
        else:
            print(f"Seeding missing tenant: {key}")
            new_tenant = Tenant(
                Name="Restored Access Tenant",
                ApiKey=key,
                Plan="Enterprise",
                AgentLimit=100
            )
            db.add(new_tenant)
            await db.commit()
            print("Tenant seeded successfully.")

if __name__ == "__main__":
    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    asyncio.run(seed_tenant())
