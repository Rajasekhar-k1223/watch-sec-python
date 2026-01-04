import sys
import os
import asyncio
from sqlalchemy import text
from app.db.session import engine, settings

# Add app path
sys.path.append(os.getcwd())

async def check_connection():
    print(f"Checking connection for: {settings.DATABASE_URL}")
    
    try:
        async with engine.connect() as conn:
            # Check DB Type
            print(f"Connected! DB Driver: {engine.driver}")
            
            # Check for Users table
            # SQLite query to list tables
            # List ALL tables
            if "sqlite" in settings.DATABASE_URL:
                result = await conn.execute(text("SELECT name FROM sqlite_master WHERE type='table';"))
            else:
                result = await conn.execute(text("SHOW TABLES;"))
                
            tables = result.scalars().all()
            print(f"Tables found: {tables}")
            
            if "Users" in tables or "users" in tables:
                print(f"SUCCESS: 'Users' table found.")
            else:
                print(f"FAILURE: 'Users' table NOT found.")
                
    except Exception as e:
        print(f"FAILURE: Connection error: {e}")

if __name__ == "__main__":
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    asyncio.run(check_connection())
