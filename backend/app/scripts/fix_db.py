import asyncio
import os
import sys
import random
from datetime import datetime, timedelta

# Add parent dir to path to allow imports
sys.path.append('/opt/projects/monitorix/watch-sec-python/backend')

from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession # type: ignore
from sqlalchemy.orm import sessionmaker # type: ignore
from sqlalchemy.future import select # type: ignore
from sqlalchemy import update
from app.db.models import Agent, Tenant # type: ignore
from dotenv import load_dotenv # type: ignore

load_dotenv('/opt/projects/monitorix/watch-sec-python/backend/.env')
DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    DATABASE_URL = "postgresql+asyncpg://monitorix:monitorix_secure_pwd@localhost:5432/monitorix"

print(f"Connecting to: {DATABASE_URL}")

async def fix_data():
    engine = create_async_engine(DATABASE_URL, echo=False)
    async_session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    async with async_session() as db:
        result = await db.execute(select(Agent))
        agents = result.scalars().all()
        
        now = datetime.utcnow()
        count = 0
        
        users = ["administrator", "root", "sysadmin", "john.doe"]
        countries = ["United States", "France", "Germany", "United Kingdom", "Japan"]
        
        for i, a in enumerate(agents):
            a.Version = "v4.2.5"
            a.TargetVersion = "v4.2.5"
            a.ActiveUser = random.choice(users)
            a.Country = random.choice(countries)
            a.PublicIp = f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
            a.LocalIp = f"172.31.{random.randint(1,255)}.{random.randint(1,255)}"
            a.Latitude = random.uniform(20.0, 50.0)
            a.Longitude = random.uniform(-100.0, 10.0)
            a.PowerStatusJson = '{"level": 100, "isPlugged": true}'
            
            # Make half of them offline
            if i % 2 != 0:
                a.LastSeen = now - timedelta(hours=random.randint(1, 48))
            else:
                a.LastSeen = now
                
            db.add(a)
            count += 1
            
        await db.commit()
        print(f"Updated {count} agents with rich data.")

    await engine.dispose()

if __name__ == "__main__":
    asyncio.run(fix_data())
