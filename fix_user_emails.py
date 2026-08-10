import asyncio
import os
from sqlalchemy.future import select
from app.db.session import engine, AsyncSessionLocal
from app.db.models import User, Tenant

async def fix_emails():
    async with AsyncSessionLocal() as db:
        result = await db.execute(select(User).where(User.Email.is_(None) | (User.Email == "")))
        users = result.scalars().all()
        for u in users:
            if u.TenantId:
                t_result = await db.execute(select(Tenant).where(Tenant.Id == u.TenantId))
                t = t_result.scalars().first()
                if t and t.AdminEmail:
                    u.Email = t.AdminEmail
                    print(f"Updated user {u.Username} with email {t.AdminEmail}")
        await db.commit()
        print("Done fixing emails.")

if __name__ == "__main__":
    asyncio.run(fix_emails())
