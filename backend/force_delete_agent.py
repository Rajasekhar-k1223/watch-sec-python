import asyncio
from app.db.session import AsyncSessionLocal
from app.db.models import Agent, Base

async def force_delete():
    agent_ids = [
        "50a7b52a-dd0d-4434-94f3-85bf593d2f96",
        "47736cd1-3318-44ff-857a-274e3383b2be",
        "01918c87-61b6-4b62-98e7-6e4214faeb72"
    ]
    async with AsyncSessionLocal() as session:
        for agent_id in agent_ids:
            # Dynamically delete from all child tables referencing Agents.AgentId
            for table in reversed(Base.metadata.sorted_tables):
                for fk in table.foreign_keys:
                    if fk.target_fullname in ["Agents.AgentId", "Agents.Id"]:
                        col_name = fk.parent.name
                        try:
                            await session.execute(table.delete().where(getattr(table.c, col_name) == agent_id))
                        except Exception as e:
                            pass
            
            # Finally delete the agent
            from sqlalchemy import delete
            await session.execute(delete(Agent).where(Agent.AgentId == agent_id))
            print(f"Successfully force-deleted agent {agent_id} and all its dependencies!")
            
        await session.commit()

if __name__ == "__main__":
    asyncio.run(force_delete())
