import asyncio
from app.db.session import async_session
from app.db.models import Agent
from sqlalchemy import update

async def reset():
    async with async_session() as session:
        await session.execute(update(Agent).where(Agent.AgentId == "EC2AMAZ-MLAM305").values(Version="v2.1.7", UpdateStatus="idle"))
        await session.commit()
        print("Reset agent version to v2.1.7!")

if __name__ == "__main__":
    asyncio.run(reset())
