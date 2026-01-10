import asyncio
from sqlalchemy import text
from app.db.session import engine

async def fix_schema():
    print("--- Manual DB Migration: Adding PowerStatusJson ---")
    async with engine.begin() as conn:
        try:
            print("Attempting to add 'PowerStatusJson' column to Agents table...")
            await conn.execute(text("ALTER TABLE Agents ADD COLUMN PowerStatusJson TEXT"))
            print("SUCCESS: Column 'PowerStatusJson' added.")
        except Exception as e:
            if "1060" in str(e) or "Duplicate column" in str(e):
                print("INFO: Column 'PowerStatusJson' already exists.")
            else:
                print(f"ERROR: Failed to add column: {e}")

if __name__ == "__main__":
    asyncio.run(fix_schema())
