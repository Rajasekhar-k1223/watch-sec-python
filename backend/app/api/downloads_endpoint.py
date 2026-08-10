import os
from fastapi import APIRouter, Depends, HTTPException, Response
from fastapi.responses import FileResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from app.db.session import get_db
from app.db.models import Tenant

router = APIRouter()
@router.get("/installer/exe")
async def get_installer_exe(key: str, db: AsyncSession = Depends(get_db)):
    # Serve the Generic Signed Installer but rename it so it contains the Key
    tenant_result = await db.execute(select(Tenant).where(Tenant.ApiKey == key))
    tenant = tenant_result.scalars().first()
    if not tenant:
        raise HTTPException(status_code=403, detail="Invalid Key")

    # Path to signed installer (Located in Storage Volume)
    # We moved it to storage/AgentTemplate/win-x64/monitorix-installer.exe
    installer_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../storage/AgentTemplate/win-x64/monitorix-installer.exe"))
    
    if not os.path.exists(installer_path):
        print(f"[Downloads] Installer missing at: {installer_path}")
        raise HTTPException(status_code=404, detail="Installer Not Available (File Missing)")
        
    filename = f"monitorix-installer-{tenant.ApiKey}.exe"
    
    return FileResponse(installer_path, media_type="application/vnd.microsoft.portable-executable", filename=filename)

@router.get("/public/agent")
async def get_public_agent_script(key: str, os_type: str, db: AsyncSession = Depends(get_db)):
    tenant_result = await db.execute(select(Tenant).where(Tenant.ApiKey == key))
    tenant = tenant_result.scalars().first()
    if not tenant and key != "guest":
        raise HTTPException(status_code=403, detail="Invalid Publisher Key")

    api_url = "https://agent-api.monitorix.co.in"

    if os_type.lower() == "windows":
        script_content = f"""# Monitorix Windows Agent Installation Script
$ErrorActionPreference = "Stop"
$InstallDir = "C:\\Program Files\\MonitorixAgent"
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null

Write-Host "Downloading Rust Agent..."
Invoke-WebRequest -Uri "https://monitorix.co.in/downloads/monitorix-agent-rust-windows-amd64.exe" -OutFile "$InstallDir\\monitorix-agent.exe"

Write-Host "Writing Configuration..."
$ConfigJson = @"
{{
    "BackendURL": "{api_url}",
    "ApiKey": "{key}"
}}
"@
Set-Content -Path "$InstallDir\\config.json" -Value $ConfigJson

Write-Host "Registering Windows Service..."
& sc.exe create "MonitorixAgent" binPath= "$InstallDir\\monitorix-agent.exe" start= auto
& sc.exe start "MonitorixAgent"

Write-Host "Installation Complete!"
"""
        return Response(content=script_content, media_type="text/plain")
        
    elif os_type.lower() in ["linux", "mac"]:
        script_content = f"""#!/bin/bash
# Monitorix Unix Agent Installation Script
set -e

INSTALL_DIR="/opt/monitorix-agent"
mkdir -p "$INSTALL_DIR"

echo "Downloading Rust Agent..."
if [ "$(uname)" = "Darwin" ]; then
    curl -sL "https://monitorix.co.in/downloads/monitorix-agent-rust-darwin-amd64" -o "$INSTALL_DIR/monitorix-agent"
else
    curl -sL "https://monitorix.co.in/downloads/monitorix-agent-rust-linux-amd64" -o "$INSTALL_DIR/monitorix-agent"
fi
chmod +x "$INSTALL_DIR/monitorix-agent"

echo "Writing Configuration..."
cat << EOF > "$INSTALL_DIR/config.json"
{{
    "BackendURL": "{api_url}",
    "ApiKey": "{key}"
}}
EOF

echo "Installation Complete! (Please configure systemd/launchd manually for now)"
"""
        return Response(content=script_content, media_type="text/plain")
        
    else:
        raise HTTPException(status_code=400, detail="Invalid os_type")
