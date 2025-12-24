import asyncio
import os
import sys

# Add parent dir to path to allow imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker
from sqlalchemy.future import select
from app.db.models import Base, Tenant, User, Policy
from app.core.security import get_password_hash
from dotenv import load_dotenv

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")

async def seed():
    print("[Seed] Starting Database Seeding...")
    
    engine = create_async_engine(DATABASE_URL, echo=True)
    async_session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    async with async_session() as db:
        async with engine.begin() as conn:
            # Create Tables if not exist (Simulate Migrations)
            await conn.run_sync(Base.metadata.create_all)

        # 1. Check Tenant
        result = await db.execute(select(Tenant).where(Tenant.Name == "Default Tenant"))
        tenant = result.scalars().first()
        
        if not tenant:
            print("[Seed] Creating Default Tenant...")
            tenant = Tenant(
                Name="Default Tenant",
                ApiKey="def-tenant-key-123",
                Plan="Enterprise",
                TrustedDomainsJson='["localhost", "127.0.0.1"]',
                TrustedIPsJson='["127.0.0.1"]'
            )
            db.add(tenant)
            await db.commit()
            await db.refresh(tenant)
        else:
            print("[Seed] Default Tenant exists.")

        # 2. Check Admin User
        result = await db.execute(select(User).where(User.Username == "admin"))
        user = result.scalars().first()
        
        if not user:
            print("[Seed] Creating Admin User...")
            user = User(
                Username="admin",
                # Use simple hash or plain for demo. Using hash to prove Auth works.
                # Password = "admin"
                PasswordHash=get_password_hash("admin"), 
                Role="SuperAdmin",
                TenantId=tenant.Id
            )
            db.add(user)
            await db.commit()
        else:
             print("[Seed] Admin User exists.")
             
        # 3. Check Default Policy
        result = await db.execute(select(Policy).where(Policy.Name == "Default Policy"))
        policy = result.scalars().first()
        
        if not policy:
            print("[Seed] Creating Default Policy...")
            policy = Policy(
                TenantId=tenant.Id,
                Name="Default Policy",
                Actions="Log",
                IsActive=True
            )
            db.add(policy)
            await db.commit()

    print("[Seed] Seeding Complete.")
    await engine.dispose()

if __name__ == "__main__":
    asyncio.run(seed())
