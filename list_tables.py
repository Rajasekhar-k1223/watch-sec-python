import asyncio
from sqlalchemy import inspect
from app.db.session import engine

async def print_tables():
    def get_tables(conn):
        inspector = inspect(conn)
        return inspector.get_table_names()
    
    async with engine.connect() as conn:
        tables = await conn.run_sync(get_tables)
        for t in sorted(tables):
            print(t)

if __name__ == "__main__":
    asyncio.run(print_tables())
