import asyncio
import os
import sys

# Add parent dir
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy import text
from app.db.session import settings

async def migrate():
    print("[Migration] Adding TrustedDomainsJson/TrustedIPsJson to Tenants table...")
    engine = create_async_engine(settings.DATABASE_URL, echo=True)
    
    async with engine.begin() as conn:
        try:
            # Check if column exists, or just try to add it. 
            # MySQL 'ADD COLUMN IF NOT EXISTS' syntax is version dependent (MariaDB supports it, MySQL 8.0 does not directly in ALTER TABLE).
            # We'll use a try/except block for simplicity or raw SQL.
            
            # Add TrustedDomainsJson
            try:
                await conn.execute(text("ALTER TABLE Tenants ADD COLUMN TrustedDomainsJson TEXT;"))
                print(" -> Added TrustedDomainsJson")
            except Exception as e:
                print(f" -> TrustedDomainsJson might already exist: {e}")

            # Add TrustedIPsJson
            try:
                await conn.execute(text("ALTER TABLE Tenants ADD COLUMN TrustedIPsJson TEXT;"))
                print(" -> Added TrustedIPsJson")
            except Exception as e:
                print(f" -> TrustedIPsJson might already exist: {e}")
                
        except Exception as e:
            print(f"[Error] Migration failed: {e}")

    await engine.dispose()
    print("[Migration] Complete.")

if __name__ == "__main__":
    asyncio.run(migrate())
