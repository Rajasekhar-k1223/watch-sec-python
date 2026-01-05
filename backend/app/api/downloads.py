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

from fastapi import Request

@router.get("/agent/install")
async def download_agent(
    request: Request,
    os_type: str = "windows",
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
    
    base_path = "storage"
    template_path = os.path.join(base_path, "AgentTemplate", folder_name)
    
    if not os.path.exists(template_path):
        raise HTTPException(status_code=404, detail=f"Agent Template for {os_type} not found.")

    # 3. Prepare Temp Directory
    temp_id = str(uuid.uuid4())
    temp_path = os.path.join(base_path, "temp", temp_id)
    agent_folder = os.path.join(temp_path, "watch-sec-agent")
    
    try:
        os.makedirs(temp_path, exist_ok=True)
        shutil.copytree(template_path, agent_folder)
        
        # 4. Inject Configuration
        config_path = os.path.join(agent_folder, "config.json")
        config_data = {}
        if os.path.exists(config_path):
            with open(config_path, "r") as f:
                try:
                    config_data = json.load(f)
                except:
                    config_data = {}
            
        config_data["TenantApiKey"] = tenant.ApiKey
        
        # Dynamic Backend URL
        env_url = os.getenv("APP_BACKEND_URL")
        railway_url = os.getenv("RAILWAY_PUBLIC_DOMAIN")
        if env_url:
            backend_url = env_url
        elif railway_url:
             backend_url = f"https://{railway_url}"
        else:
             backend_url = str(request.base_url).rstrip("/")
        config_data["BackendUrl"] = backend_url 
            
        with open(config_path, "w") as f:
            json.dump(config_data, f, indent=2)
            
        # 5. OS Specific Packaging
        if os_type.lower() in ["linux", "mac"]:
            install_script = f"""#!/bin/bash
# WatchSec Installer
API_KEY="{tenant.ApiKey}"
BACKEND_URL="{backend_url}"

echo "Configuring Agent..."
mkdir -p ./watch-sec-agent
echo '{json.dumps(config_data)}' > ./watch-sec-agent/config.json

echo "Done. Run ./watch-sec-agent/agent to start."
"""
            script_path = os.path.join(base_path, "temp", f"install_{temp_id}.sh")
            with open(script_path, "w") as f:
                f.write(install_script)
            
            return FileResponse(script_path, media_type="application/x-sh", filename="watch-sec-install.sh")

        else:
            # Windows: EXE Overlay
            exe_name = "watch-sec-agent.exe"
            exe_path = os.path.join(agent_folder, exe_name)
            
            if not os.path.exists(exe_path):
                # Fallback search
                for f in os.listdir(agent_folder):
                    if f.endswith(".exe"):
                        exe_path = os.path.join(agent_folder, f)
                        break
            
            if os.path.exists(exe_path):
                payload = json.dumps(config_data).encode("utf-8")
                delimiter = b"\n<<<<WATCHSEC_CONFIG>>>>\n"
                final_exe_path = os.path.join(base_path, "temp", f"watch-sec-installer_{temp_id}.exe")
                
                with open(exe_path, "rb") as orig_f:
                     with open(final_exe_path, "wb") as new_f:
                         new_f.write(orig_f.read())
                         new_f.write(delimiter)
                         new_f.write(payload)
                
                return FileResponse(final_exe_path, media_type="application/vnd.microsoft.portable-executable", filename="watch-sec-installer-v2.exe")
            else:
                 # Debugging: Why is EXE missing?
                 files = os.listdir(agent_folder)
                 raise HTTPException(status_code=500, detail=f"Server Error: Could not find .exe in template. Scanned: {agent_folder}. Files found: {files}")

    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Failed: {str(e)}")
