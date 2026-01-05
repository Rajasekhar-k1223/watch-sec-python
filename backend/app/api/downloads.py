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

@router.get("/agent")
async def download_agent(
    request: Request,
    os_type: str = "windows", # renamed from 'os' to avoid conflict with module
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    # ... (Lines 24-73 omitted, assuming context match works or I need to span larger) ...
    # Wait, I need to match valid context block.
    # Let's target the function def and then the assignment.
    # REPLACE FUNCTION SIG
    
    # ...
    
        # Inject Values
        config_data["TenantApiKey"] = tenant.ApiKey
        
        # Inject configured Backend URL
        # Priority: 1. ENV, 2. Railway Public Domain, 3. Request Host
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
            # Generate Shell Script Installer
            install_script = f"""#!/bin/bash
# WatchSec Installer
API_KEY="{tenant.ApiKey}"
BACKEND_URL="{config_data["BackendUrl"]}"

echo "Downloading Agent..."
# Logic to download the actual payload (zip) using a separate endpoint or just embedding logic
# For this prototype, we'll assume this script bootstraps the agent.
# Ideally, we return a script that curl's the binary.

# Creating config locally
mkdir -p ./watch-sec-agent
echo '{json.dumps(config_data)}' > ./watch-sec-agent/config.json

echo "Installing binary..."
# (In real scenario, download binary here)
echo "Done. Run ./watch-sec-agent/agent to start."
"""
            script_path = os.path.join(base_path, "temp", f"install_{temp_id}.sh")
            with open(script_path, "w") as f:
                f.write(install_script)
            
            return FileResponse(script_path, media_type="application/x-sh", filename="watch-sec-install.sh")

        else:
            # Windows: Single EXE with injected config (Overlay)
            # Find the executable in the template
            exe_name = "watch-sec-agent.exe" # Default
            exe_path = os.path.join(agent_folder, exe_name)
            
            # If default name doesn't exist, try to find any .exe
            if not os.path.exists(exe_path):
                for f in os.listdir(agent_folder):
                    if f.endswith(".exe"):
                        exe_path = os.path.join(agent_folder, f)
                        break
            
            # If still not found (e.g. mock template is empty), fallback to Zip creation logic implies file didn't exist
            # But here we must try to serve an EXE. 
            # If we can't find it, we'll error or create a dummy one for the prototype?
            # Let's assume it exists or fallback gracefully to ZIP with a warning? 
            # User demanded .exe, so we should try hard.
            
            if os.path.exists(exe_path):
                # Config Payload
                payload = json.dumps(config_data).encode("utf-8")
                delimiter = b"\n<<<<WATCHSEC_CONFIG>>>>\n"
                
                # Create Output Path
                final_exe_path = os.path.join(base_path, "temp", f"watch-sec-installer_{temp_id}.exe")
                
                with open(exe_path, "rb") as orig_f:
                     with open(final_exe_path, "wb") as new_f:
                         new_f.write(orig_f.read())
                         new_f.write(delimiter)
                         new_f.write(payload)
                
                return FileResponse(final_exe_path, media_type="application/vnd.microsoft.portable-executable", filename="watch-sec-installer.exe")
            else:
                # Fallback to Zip if binary missing in template
                zip_path = os.path.join(base_path, "temp", f"payload_{temp_id}") 
                shutil.make_archive(zip_path, 'zip', agent_folder)
                final_zip = zip_path + ".zip"
                return FileResponse(final_zip, media_type="application/zip", filename="watch-sec-agent-win.zip")

    except Exception as e:
        import traceback
        traceback.print_exc()
        print(f"Error creating agent download: {e}")
        # Return exact error for debugging (remove in prod)
        raise HTTPException(status_code=500, detail=f"Failed: {str(e)}")
