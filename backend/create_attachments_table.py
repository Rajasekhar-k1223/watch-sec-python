
import asyncio
from app.db.session import engine, Base
from app.db.models import MailAttachment

async def init_models():
    async with engine.begin() as conn:
        print("Creating new tables...")
        await conn.run_sync(Base.metadata.create_all)
        print("Done.")

if __name__ == "__main__":
    asyncio.run(init_models())
