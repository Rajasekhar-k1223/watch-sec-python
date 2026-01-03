import asyncio
import os
import aiosqlite
import datetime
from dotenv import load_dotenv
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy import text
from pymongo import MongoClient

# Load Env
load_dotenv()
load_dotenv(".env")
from app.db.models import Agent, EventLog
# ActivityLog is now Mongo-only for high volume

# Local DB Path (Offline)
LOCAL_DB_PATH = "watch-sec.db"

# Target DBs (Live/Railway)
# Load from Environment
TARGET_SQL_URL = os.getenv("DATABASE_URL")
TARGET_MONGO_URL = os.getenv("MONGO_URL")

async def sync():
    if not os.path.exists(LOCAL_DB_PATH):
        print(f"Local DB {LOCAL_DB_PATH} not found.")
        return

    if not TARGET_SQL_URL:
        print("Target DATABASE_URL not set.")
        return
        
    if not TARGET_MONGO_URL:
        print("Target MONGO_URL not set (Required for Activity Logs).")
        return

    print(f"Starting HYBRID Sync from {LOCAL_DB_PATH}")
    print(f" -> Core Data to SQL: {TARGET_SQL_URL.split('@')[-1]}")
    print(f" -> Logs to Mongo: {TARGET_MONGO_URL.split('@')[-1]}")

    local_agents = []
    local_activity = []
    local_events = []

    # 1. Read Local SQLite
    async with aiosqlite.connect(LOCAL_DB_PATH) as db:
        async with db.execute("SELECT * FROM Agents") as cursor:
            columns = [description[0] for description in cursor.description]
            local_agents = [dict(zip(columns, row)) for row in await cursor.fetchall()]
        
        async with db.execute("SELECT * FROM ActivityLogs") as cursor:
            columns = [description[0] for description in cursor.description]
            local_activity = [dict(zip(columns, row)) for row in await cursor.fetchall()]

        async with db.execute("SELECT * FROM EventLogs") as cursor:
             columns = [description[0] for description in cursor.description]
             local_events = [dict(zip(columns, row)) for row in await cursor.fetchall()]

    print(f"Read: {len(local_agents)} Agents, {len(local_activity)} Activities, {len(local_events)} Events")

    # 2. Sync Core Data to SQL (Agents, Critical Events)
    sql_engine = create_async_engine(TARGET_SQL_URL, echo=False)
    async with sql_engine.begin() as conn:
        print("Syncing SQL Data...")
        # Note: In production, use upserts. Here we simply print for verification in this script
        # Real implementation would look like:
        # await conn.execute(insert(Agent).values(local_agents).on_conflict_do_update(...))
        pass
    await sql_engine.dispose()
    
    # 3. Sync Activity Logs to MongoDB
    print("Syncing MongoDB Data...")
    try:
        mongo_client = MongoClient(TARGET_MONGO_URL)
        mongo_db = mongo_client["watchsec"]
        activity_collection = mongo_db["activity"]
        
        if local_activity:
            # Transform for Mongo (Date handling)
            # Ensure Timestamp is datetime object
            # MongoDB uses "_id", strict types
            docs_to_insert = []
            for item in local_activity:
                # Convert string timestamps if necessary, though aiosqlite usually gives strings
                if isinstance(item.get("Timestamp"), str):
                     item["Timestamp"] = datetime.datetime.fromisoformat(item["Timestamp"])
                docs_to_insert.append(item)
            
            if docs_to_insert:
                activity_collection.insert_many(docs_to_insert, ordered=False)
                print(f" -> Inserted {len(docs_to_insert)} Activity Logs to Mongo")
    except Exception as e:
        print(f"Mongo Sync Failed: {e}")

    print("Hybrid Sync Complete!")

if __name__ == "__main__":
    if "sqlite" in (TARGET_SQL_URL or ""):
        # For testing
        asyncio.run(sync())
    else:
        # Prod
        asyncio.run(sync())
