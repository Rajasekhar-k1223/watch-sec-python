import asyncio
from backend.app.db.session import SessionLocal
from sqlalchemy import text

async def main():
    async with SessionLocal() as db:
        res = await db.execute(text("SELECT strftime('%Y-%m-%d %H:00', 'now') as bucket"))
        print(list(res))

asyncio.run(main())
