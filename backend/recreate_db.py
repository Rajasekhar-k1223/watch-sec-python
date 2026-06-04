"""
recreate_db.py — Recreate all MySQL tables in monitorix_db from SQLAlchemy models
Run inside the backend container:
    python recreate_db.py
"""
import asyncio
import os
import sys

# ── 1. Load env so DATABASE_URL / MONGO_URL are set ────────────────────────
from dotenv import load_dotenv
load_dotenv(override=True)

DATABASE_URL = os.getenv("DATABASE_URL", "")
MONGO_URL    = os.getenv("MONGO_URL", "")

print(f"[DB]    MySQL  → {DATABASE_URL}")
print(f"[DB]    Mongo  → {MONGO_URL}")

if not DATABASE_URL or "monitorix_db" not in DATABASE_URL:
    print("[ERROR] DATABASE_URL must point to monitorix_db. Aborting.")
    sys.exit(1)

# ── 2. Import models so SQLAlchemy registers them on Base.metadata ──────────
from app.db.session import engine, Base, mongo_client

# Import every model module so the mappers are registered
import app.db.models  # noqa: F401 — registers all ORM classes

# ── 3. Drop & recreate all tables (MySQL) ──────────────────────────────────
async def recreate_mysql():
    print("\n[MySQL] Dropping all existing tables in monitorix_db …")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    print("[MySQL] All tables dropped.")

    print("[MySQL] Creating all tables …")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    # List created tables
    from sqlalchemy import text
    async with engine.begin() as conn:
        result = await conn.execute(text("SHOW TABLES"))
        tables = [row[0] for row in result.fetchall()]
    print(f"[MySQL] ✅ {len(tables)} tables created:")
    for t in sorted(tables):
        print(f"         • {t}")

# ── 4. Create MongoDB collections & indexes ────────────────────────────────
async def recreate_mongo():
    print("\n[Mongo] Setting up collections and indexes in monitorix_db …")
    db = mongo_client["monitorix_db"]

    indexes = {
        "activity": [
            ("AgentId", 1),
            ("Timestamp", -1),
        ],
        "keystrokes": [
            ("AgentId", 1),
            ("Timestamp", -1),
        ],
        "clipboard": [
            ("AgentId", 1),
            ("Timestamp", -1),
        ],
        "network_events": [
            ("AgentId", 1),
            ("Timestamp", -1),
        ],
        "browser_history": [
            ("AgentId", 1),
            ("Timestamp", -1),
        ],
        "print_jobs": [
            ("AgentId", 1),
            ("Timestamp", -1),
        ],
        "usb_events": [
            ("AgentId", 1),
            ("Timestamp", -1),
        ],
        "file_events": [
            ("AgentId", 1),
            ("Timestamp", -1),
        ],
        "location_events": [
            ("AgentId", 1),
            ("Timestamp", -1),
        ],
        "heartbeats": [
            ("AgentId", 1),
            ("Timestamp", -1),
        ],
        "agent_commands": [
            ("AgentId", 1),
            ("Status", 1),
        ],
        "remote_shell_sessions": [
            ("AgentId", 1),
        ],
    }

    from pymongo import ASCENDING, DESCENDING
    direction_map = {1: ASCENDING, -1: DESCENDING}

    for collection_name, fields in indexes.items():
        col = db[collection_name]
        for field, direction in fields:
            await col.create_index(
                [(field, direction_map[direction])],
                background=True
            )
        print(f"         • {collection_name} — indexes created")

    # Verify existing collections
    col_names = await db.list_collection_names()
    print(f"[Mongo] ✅ {len(col_names)} collections found: {sorted(col_names)}")

# ── 5. Main ────────────────────────────────────────────────────────────────
async def main():
    await recreate_mysql()
    await recreate_mongo()
    print("\n✅ monitorix_db fully recreated. All tables and indexes are ready.")

if __name__ == "__main__":
    asyncio.run(main())
