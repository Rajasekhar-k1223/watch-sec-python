import asyncio
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy import text

DATABASE_URL = "postgresql+asyncpg://sentinel_user:rVcDsUVYia5tsHefxFKTbPOl@db.monitorix.co.in:41892/monitorix"
engine = create_async_engine(DATABASE_URL)

async def migrate():
    async with engine.begin() as conn:
        try:
            await conn.execute(text('ALTER TABLE "Agents" ADD COLUMN "ActiveUser" VARCHAR(255) DEFAULT \'Unknown\';'))
            print("Added ActiveUser column")
        except Exception as e:
            print(f"Error: {e}")
            
        try:
            await conn.execute(text('ALTER TABLE "Agents" ADD COLUMN "UserLoginTime" VARCHAR(255) DEFAULT \'Unknown\';'))
            print("Added UserLoginTime column")
        except Exception as e:
            print(f"Error: {e}")

asyncio.run(migrate())
