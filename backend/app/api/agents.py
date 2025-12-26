from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from pydantic import BaseModel
from typing import Optional, List

from ..db.session import get_db
from ..db.models import Agent, User
from .deps import get_current_user
from ..socket_instance import sio

router = APIRouter()

@router.get("/")
async def get_agents(
    current_user: User = Depends(get_current_user), 
    db: AsyncSession = Depends(get_db)
):
    query = select(Agent)
    
    # Filter by Tenant for non-SuperAdmin
    if current_user.Role != "SuperAdmin":
        if not current_user.TenantId:
            return []
        query = query.where(Agent.TenantId == current_user.TenantId)
        
    result = await db.execute(query)
    agents = result.scalars().all()
    return agents

@router.delete("/{agent_id}")
async def delete_agent(
    agent_id: int, # Database ID
    current_user: User = Depends(get_current_user), 
    db: AsyncSession = Depends(get_db)
):
    if current_user.Role != "SuperAdmin" and current_user.Role != "TenantAdmin":
         raise HTTPException(status_code=403, detail="Not authorized")

    # Find Agent
    result = await db.execute(select(Agent).where(Agent.Id == agent_id))
    agent = result.scalars().first()
    
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
        
    # Check Tenant Scoping
    if current_user.Role == "TenantAdmin" and agent.TenantId != current_user.TenantId:
        raise HTTPException(status_code=404, detail="Agent not found") # Hide cross-tenant data

    await db.delete(agent)
    await db.commit()
    
    return status.HTTP_204_NO_CONTENT

@router.post("/{agent_string_id}/toggle-screenshots")
async def toggle_screenshots(
    agent_string_id: str, # String ID (e.g. "DEVICE-123")
    enabled: bool,
    current_user: User = Depends(get_current_user), 
    db: AsyncSession = Depends(get_db)
):
    # Find Agent
    result = await db.execute(select(Agent).where(Agent.AgentId == agent_string_id))
    agent = result.scalars().first()
    
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    
    # Check Tenant Scoping
    if current_user.Role != "SuperAdmin":
        if not current_user.TenantId or agent.TenantId != current_user.TenantId:
             raise HTTPException(status_code=403, detail="Not authorized")

    agent.ScreenshotsEnabled = enabled
    await db.commit()
    
    return {"AgentId": agent.AgentId, "ScreenshotsEnabled": agent.ScreenshotsEnabled}

@router.post("/{agent_string_id}/take-screenshot")
async def take_screenshot(
    agent_string_id: str,
    current_user: User = Depends(get_current_user), 
    db: AsyncSession = Depends(get_db)
):
    try:
        # Local import to avoid circular dependencies
        # from ..socket_instance import sio

        # Find Agent
        result = await db.execute(select(Agent).where(Agent.AgentId == agent_string_id))
        agent = result.scalars().first()
        
        if not agent:
            raise HTTPException(status_code=404, detail="Agent not found")
        
        # Check Tenant Scoping
        if current_user.Role != "SuperAdmin":
            if not current_user.TenantId or agent.TenantId != current_user.TenantId:
                 raise HTTPException(status_code=403, detail="Not authorized")

        # Emit Command to Agent Room
        print(f"[API] Triggering Manual Screenshot for {agent.AgentId}")
        await sio.emit('TakeScreenshot', {'AgentId': agent.AgentId}, room=agent.AgentId)

        return {"status": "triggered", "agentId": agent.AgentId}
    except Exception as e:
        import traceback
        traceback.print_exc()
        # Return 500 but try to ensure CORS doesn't block reading it in dev
        raise HTTPException(status_code=500, detail=f"Internal Error: {str(e)}")

from ..schemas import AgentSettingsUpdate

@router.post("/{agent_string_id}/settings")
async def update_settings(
    agent_string_id: str,
    settings: AgentSettingsUpdate,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    result = await db.execute(select(Agent).where(Agent.AgentId == agent_string_id))
    agent = result.scalars().first()
    
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
        
    if current_user.Role != "SuperAdmin":
        if not current_user.TenantId or agent.TenantId != current_user.TenantId:
             raise HTTPException(status_code=403, detail="Not authorized")

    agent.ScreenshotQuality = settings.ScreenshotQuality
    agent.ScreenshotResolution = settings.ScreenshotResolution
    agent.MaxScreenshotSize = settings.MaxScreenshotSize
    
    await db.commit()
    
    return {"status": "Updated", "settings": settings}
