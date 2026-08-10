import asyncio
import os
from app.db.session import engine, AsyncSessionLocal
from app.db.models import User
from app.core.security import get_password_hash
from datetime import datetime

async def insert_superadmin():
    async with AsyncSessionLocal() as db:
        # Check if exists
        from sqlalchemy.future import select
        result = await db.execute(select(User).where(User.Username == "superadmin"))
        existing = result.scalars().first()
        
        if existing:
            print("SuperAdmin already exists.")
            return

        superadmin = User(
            Username="superadmin",
            Email="superadmin@monitorix.com",
            PasswordHash=get_password_hash(os.getenv("INITIAL_ADMIN_PASSWORD", "changeme!")),
            Role="SuperAdmin",
            ActiveStatus=True,
            CreatedDate=datetime.utcnow(),
            UpdateDate=datetime.utcnow()
        )
        
        db.add(superadmin)
        await db.commit()
        print("SuperAdmin successfully inserted.")

if __name__ == "__main__":
    asyncio.run(insert_superadmin())
