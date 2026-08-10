import asyncio
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker
from sqlalchemy import text

DATABASE_URL = "postgresql+asyncpg://sentinel_user:rVcDsUVYia5tsHefxFKTbPOl@db.monitorix.co.in:41892/monitorix"

async def main():
    engine = create_async_engine(DATABASE_URL)
    async_session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    
    async with async_session() as session:
        result = await session.execute(text('SELECT COUNT(*) FROM "ActivityLogs" WHERE "AgentId" = \'EC2AMAZ-MLAM305\';'))
        row = result.fetchone()
        print(f"Total Activity Logs for agent: {row[0]}")
        
        result2 = await session.execute(text('SELECT "Timestamp", "WindowTitle", "ProcessName" FROM "ActivityLogs" WHERE "AgentId" = \'EC2AMAZ-MLAM305\' ORDER BY "Timestamp" DESC LIMIT 5;'))
        rows = result2.fetchall()
        print(f"Latest 5 logs: {rows}")

if __name__ == "__main__":
    asyncio.run(main())
