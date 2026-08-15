import asyncio
from backend.app.db.session import SessionLocal
from sqlalchemy import text

async def main():
    async with SessionLocal() as db:
        res = await db.execute(text("SELECT Timestamp, CpuUsage, MemoryUsage FROM SystemStatus WHERE Timestamp > datetime('now', '-24 hours') ORDER BY Timestamp DESC"))
        rows = res.fetchall()
        print(f"Total rows: {len(rows)}")
        for r in rows:
            print(r)

asyncio.run(main())
