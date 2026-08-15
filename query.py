import asyncio
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy import text
async def run():
    engine = create_async_engine("postgresql+asyncpg://sentinel_user:rVcDsUVYia5tsHefxFKTbPOl@db.monitorix.co.in:41892/monitorix")
    async with engine.connect() as conn:
        res = await conn.execute(text("SELECT \"Id\", \"Username\", \"Role\", \"TenantId\" FROM \"Users\""))
        for row in res: print(row)
asyncio.run(run())
