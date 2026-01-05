import asyncio
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy import text
from app.db.session import settings
from app.db.models import Base

async def reset_database():
    print("!!! WARNING: RESETTING DATABASE (Fixing Ghost Migrations) !!!")
    
    # Ensure we use pymysql for sync operations if needed, or just standard async
    # Settings already has the correct URL (mysql+aiomysql)
    engine = create_async_engine(settings.DATABASE_URL, echo=True)
    
    async with engine.begin() as conn:
        # Disable foreign key checks to allow dropping tables freely
        await conn.execute(text("SET FOREIGN_KEY_CHECKS = 0"))
        
        # Drop alembic table manually to ensure history is gone
        await conn.execute(text("DROP TABLE IF EXISTS alembic_version"))
        
        # Reflect and Drop All Tables
        # Since we might have legacy tables not in our metadata, strictly speaking
        # drop_all only drops what it knows. 
        # But for the alembic_version issue, dropping that table is usually enough 
        # to allow 'alembic upgrade head' to think it's a new DB.
        # BUT, if tables exist, 'upgrade head' will fail creating them.
        # So we MUST drop all known tables.
        
        print("Dropping all tables defined in code...")
        await conn.run_sync(Base.metadata.drop_all)
        
        await conn.execute(text("SET FOREIGN_KEY_CHECKS = 1"))
        
    print("Database Reset Complete.")
    await engine.dispose()

if __name__ == "__main__":
    asyncio.run(reset_database())
