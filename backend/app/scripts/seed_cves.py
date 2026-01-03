import asyncio
import os
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy import select
from app.db.models import Vulnerability, Base
from dotenv import load_dotenv

load_dotenv()
load_dotenv(".env")

DATABASE_URL = os.getenv("DATABASE_URL")

async def seed_vulnerabilities():
    if not DATABASE_URL:
        print("DATABASE_URL not set.")
        return

    print("Seeding Vulnerabilities...")
    engine = create_async_engine(DATABASE_URL, echo=False)
    
    # Ensure tables exist (optional, usually Alembic does this)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    
    
    # New Async Session logic requires async sessionmaker or manual context
    # Fixed for modern SQLAlchemy Async
    from sqlalchemy.ext.asyncio import AsyncSession
    async_session_maker = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    async with async_session_maker() as db:
        # Check if already seeded
        result = await db.execute(select(Vulnerability).limit(1))
        if result.scalars().first():
            print("Vulnerabilities already seeded.")
            return

        cves = [
            Vulnerability(
                CVE="CVE-2023-2033",
                AffectedProduct="Chrome",
                MinVersion="0.0.0",
                MaxVersion="112.0.5615.121",
                Severity="High",
                Description="Type confusion in V8 in Google Chrome prior to 112.0.5615.121 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page."
            ),
            Vulnerability(
                CVE="CVE-2023-4863",
                AffectedProduct="Chrome",
                MinVersion="0.0.0",
                MaxVersion="116.0.5845.188",
                Severity="Critical",
                Description="Heap buffer overflow in WebP in Google Chrome prior to 116.0.5845.188 allowed a remote attacker to perform an out of bounds memory write via a crafted HTML page."
            ),
             Vulnerability(
                CVE="CVE-2023-3079",
                AffectedProduct="Chrome",
                MinVersion="0.0.0",
                MaxVersion="114.0.5735.110",
                Severity="High",
                Description="Type confusion in V8."
            ),
            Vulnerability(
                CVE="CVE-2023-21716",
                AffectedProduct="Word",
                MinVersion="0.0.0",
                MaxVersion="16.0.10000.0", # Simplified
                Severity="Critical",
                Description="Microsoft Word Remote Code Execution Vulnerability."
            ),
             Vulnerability(
                CVE="CVE-2024-3400",
                AffectedProduct="GlobalProtect",
                MinVersion="0.0.0",
                MaxVersion="6.1.0", 
                Severity="Critical",
                Description="Palo Alto Networks GlobalProtect Gateway Command Injection."
            )
        ]
        
        db.add_all(cves)
        await db.commit()
        print(f"Seeded {len(cves)} Vulnerabilities.")

    await engine.dispose()

if __name__ == "__main__":
    asyncio.run(seed_vulnerabilities())
