from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import FileResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
import shutil
import os
import json
import uuid
from typing import Optional

from ..db.session import get_db
from ..db.models import Tenant
from .deps import get_current_user
from ..db.models import User

router = APIRouter()

@router.get("/agent")
async def download_agent(
    os_type: str = "windows", # renamed from 'os' to avoid conflict with module
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    # 1. Identify Tenant
    if not current_user.TenantId:
        raise HTTPException(status_code=400, detail="User has no TenantId")
        
    tenant_result = await db.execute(select(Tenant).where(Tenant.Id == current_user.TenantId))
    tenant = tenant_result.scalars().first()
    
    if not tenant:
        raise HTTPException(status_code=401, detail="Tenant not found")

    # 2. Locate Template
    template_folder_map = {
        "linux": "linux-x64",
        "mac": "osx-x64",
        "windows": "win-x64"
    }
    folder_name = template_folder_map.get(os_type.lower(), "win-x64")
    
    base_path = "storage" # Relative to cwd
    template_path = os.path.join(base_path, "AgentTemplate", folder_name)
    
    if not os.path.exists(template_path):
        raise HTTPException(status_code=404, detail=f"Agent Template for {os_type} not found on server.")

    # 3. Prepare Temp Directory
    temp_id = str(uuid.uuid4())
    temp_path = os.path.join(base_path, "temp", temp_id)
    agent_folder = os.path.join(temp_path, "watch-sec-agent")
    
    try:
        # Create Temp Dir Parent
        os.makedirs(temp_path, exist_ok=True)

        # Copy Template
        shutil.copytree(template_path, agent_folder)
        
        # 4. Inject Configuration
        config_path = os.path.join(agent_folder, "config.json")
        
        # Ensure file exists (it should from our mock setup)
        # If not, create it
        config_data = {}
        if os.path.exists(config_path):
            with open(config_path, "r") as f:
                try:
                    config_data = json.load(f)
                except:
                    config_data = {}
            
        # Inject Values
        config_data["TenantApiKey"] = tenant.ApiKey
        # Hardcoded for now or get from env. Request object unavailable? can use Starlette Request if needed.
        # Using the Docker Host IP or similar
        config_data["BackendUrl"] = "http://localhost:8000" 
            
        with open(config_path, "w") as f:
            json.dump(config_data, f, indent=2)
                
        # 5. Create Zip
        zip_path = os.path.join(base_path, "temp", f"payload_{temp_id}") # shutil adds .zip
        shutil.make_archive(zip_path, 'zip', agent_folder)
        final_zip = zip_path + ".zip"
        
        # 6. Return File
        # Note: In production, use BackgroundTasks to clean up temp files after sending.
        return FileResponse(final_zip, media_type="application/zip", filename="watch-sec-agent.zip")

    except Exception as e:
        import traceback
        traceback.print_exc()
        print(f"Error creating agent download: {e}")
        # Return exact error for debugging (remove in prod)
        raise HTTPException(status_code=500, detail=f"Failed: {str(e)}")
