import asyncio
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker
from sqlalchemy import text

DATABASE_URL = "postgresql+asyncpg://sentinel_user:rVcDsUVYia5tsHefxFKTbPOl@db.monitorix.co.in:41892/monitorix"

async def main():
    engine = create_async_engine(DATABASE_URL)
    async_session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    
    async with async_session() as session:
        await session.execute(text('UPDATE "Agents" SET "Version" = \'v2.1.7\', "TargetVersion" = \'v2.1.8\', "UpdateStatus" = \'pending_manual_push\' WHERE "AgentId" = \'EC2AMAZ-MLAM305\';'))
        await session.commit()
        print("Agent DB record updated to force manual push on next heartbeat.")

if __name__ == "__main__":
    asyncio.run(main())
