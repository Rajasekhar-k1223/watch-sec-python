from fastapi import APIRouter, Depends, HTTPException, status, Response, Request
from fastapi.responses import FileResponse, StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
import shutil
import os
import io
import zipfile
import json
import uuid
import asyncio
from typing import Optional

from ..db.session import get_db
from ..db.models import Tenant, User
from .deps import get_current_user

router = APIRouter()

# --- Helper Logic ---

def _get_backend_url(request: Request) -> str:
    env_url = os.getenv("APP_BACKEND_URL")
    railway_url = os.getenv("RAILWAY_PUBLIC_DOMAIN")
    if env_url:
        return env_url
    elif railway_url:
        return f"https://{railway_url}"
    else:
        return str(request.base_url).rstrip("/")

def _serve_agent_package(os_type: str, tenant: Tenant, backend_url: str, serve_payload: bool = False, format_type: str = None):
    """
    Common logic to package and serve the agent.
    - Windows: Stream modified EXE (Zero Disk Write) OR Static Zip.
    - Linux/Mac: Serve generated Shell Script (Minimal Disk Write).
    """
    
    # 1. Prepare Config Data
    config_data = {
        "TenantApiKey": tenant.ApiKey,
        "BackendUrl": backend_url
    }
    
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

    # 2.2 Handle Static Zip (Pre-packaged Windows Agent)
    if os_type.lower() == "windows" and format_type == "zip":
        zip_path = os.path.join(template_path, "monitorix.zip")
        if os.path.exists(zip_path):
             def iterzip():
                with open(zip_path, "rb") as zf:
                    while chunk := zf.read(8 * 1024 * 1024): # 8MB Chunk
                        yield chunk
             return StreamingResponse(
                iterzip(),
                media_type="application/zip",
                headers={"Content-Disposition": 'attachment; filename="monitorix.zip"'}
             )

    # 2.5 Handle Payload Request (Zip Serving)
    if serve_payload:
        if os_type.lower() in ["linux", "mac"]:
            # On-the-fly Zip Generation
            zip_buffer = io.BytesIO()
            # Zip everything in template_path
            with zipfile.ZipFile(zip_buffer, "a", zipfile.ZIP_DEFLATED, False) as zip_file:
                for root, dirs, files in os.walk(template_path):
                    for file in files:
                        file_path = os.path.join(root, file)
                        arcname = os.path.relpath(file_path, template_path)
                        zip_file.write(file_path, arcname)
            
            zip_buffer.seek(0)
            filename = f"monitorix-agent-{os_type}.zip"
            return StreamingResponse(
                iter([zip_buffer.getvalue()]), 
                media_type="application/zip", 
                headers={"Content-Disposition": f'attachment; filename="{filename}"'}
            )

    # 3. Serve Installer (Script or EXE)
    temp_id = str(uuid.uuid4())

    if os_type.lower() in ["linux", "mac"]:
        # Bash Script Generation
        # Construct payload URL to download the zip we defined above
        payload_url = f"{backend_url}/api/downloads/public/agent?key={tenant.ApiKey}&os_type={os_type.lower()}&payload=true"

        install_script = f"""#!/bin/bash
# Monitorix Installer
API_KEY="{tenant.ApiKey}"
BACKEND_URL="{backend_url}"
PAYLOAD_URL="{payload_url}"

echo "--- Monitorix Agent Installer ---"

echo "[1/4] Creating Directory..."
mkdir -p ./monitorix-agent
dir_name="./monitorix-agent"

# Bear Animation Function
show_bear_progress() {{
    local pid=$1
    local delay=0.2
    local spin='(^-.-^) (o-o) (>.<) (^-^)'
    local frames=($spin)
    local i=0
    
    # Hide Cursor
    tput civis

    while ps -p $pid > /dev/null; do
        local frame=${{frames[$i]}}
        printf "\\r\\033[1;36m%s\\033[0m Downloading... " "$frame"
        i=$(( (i+1) % 4 ))
        sleep $delay
    done
    
    # Restore Cursor
    tput cnorm
    printf "\\r\\033[1;32m(^-^) Download Complete!   \\033[0m\\n"
}}

echo "[2/4] Downloading Agent Payload..."
if command -v curl &> /dev/null; then
    # Background curl, show animation
    curl -L "$PAYLOAD_URL" -o agent.zip -s &
    PID=$!
    show_bear_progress $PID
    wait $PID
elif command -v wget &> /dev/null; then
    wget -q "$PAYLOAD_URL" -O agent.zip &
    PID=$!
    show_bear_progress $PID
    wait $PID
else
    echo "Error: curl or wget is required."
    exit 1
fi

echo "[3/4] Extracting..."
if ! command -v unzip &> /dev/null; then
    echo "Error: unzip is required. Please install it (apt install unzip / yum install unzip)."
    exit 1
fi
unzip -o agent.zip -d "$dir_name" > /dev/null
rm agent.zip

echo "[4/4] Configuring..."
echo '{json.dumps(config_data)}' > "$dir_name/config.json"

# Make executable
chmod +x "$dir_name/monitorix" 2>/dev/null || true
chmod +x "$dir_name/src/main.py" 2>/dev/null || true

# Rename wrapper if needed (we renamed it on server, but just in case)
if [ -f "$dir_name/monitorix-agent" ]; then
    mv "$dir_name/monitorix-agent" "$dir_name/monitorix"
fi

# Create Systemd Service
SERVICE_FILE="/etc/systemd/system/monitorix.service"
if [ -d "/etc/systemd/system" ]; then
    echo "[5/4] Installing Service..."
    cat > $SERVICE_FILE <<EOF
[Unit]
Description=Monitorix Security Agent
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$dir_name
ExecStart=$dir_name/monitorix
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable monitorix
    systemctl restart monitorix
    echo "Service installed and started!"
else
    echo "Done! To start the agent manually:"
    echo "  cd $dir_name"
    echo "  ./monitorix"
fi
"""

        # We still write script to disk because it's tiny and simpler for FileResponse
        temp_dir = os.path.join(base_path, "temp")
        os.makedirs(temp_dir, exist_ok=True)
        script_path = os.path.join(temp_dir, f"install_{temp_id}.sh")
        
        with open(script_path, "w") as f:
            f.write(install_script)
        
        return FileResponse(script_path, media_type="application/x-sh", filename="monitorix-install.sh")

    else:
        # Windows: Streaming Response (Performance Optimization)
        # Priority 1: The New Standard Name
        exe_path = os.path.join(template_path, "monitorix.exe")
        
        # Priority 2: Legacy Names (Fallback)
        if not os.path.exists(exe_path):
             exe_path = os.path.join(template_path, "monitorix-agent.exe")
        
        # Priority 3: Any Exe
        if not os.path.exists(exe_path):
             for f in os.listdir(template_path):
                if f.endswith(".exe"):
                    exe_path = os.path.join(template_path, f)
                    break
        
        if not os.path.exists(exe_path):
             files = os.listdir(template_path)
             raise HTTPException(status_code=500, detail=f"Server Error: Could not find monitorix.exe in template. Found: {files}")

        # Prepare Payload
        payload = json.dumps(config_data).encode("utf-8")
        delimiter = b"\n<<<<WATCHSEC_CONFIG>>>>\n"
        
        # Generator for Streaming
        def iterfile():
            # 1. Stream Original EXE
            with open(exe_path, "rb") as original_exe:
                while chunk := original_exe.read(8 * 1024 * 1024):  # 8MB chunks
                    yield chunk
            # 2. Append Delimiter + Config
            yield delimiter
            yield payload
       
        # Default Windows Filename
        filename = "monitorix.exe"
        media_type = "application/vnd.microsoft.portable-executable"

        return StreamingResponse(
            iterfile(),
            media_type=media_type,
            headers={"Content-Disposition": f'attachment; filename="{filename}"'}
        )

# --- Endpoints ---

@router.get("/public/agent")
async def download_public_agent(
    request: Request,
    key: str,
    os_type: str = "windows",
    payload: bool = False,
    format: str = None,
    db: AsyncSession = Depends(get_db)
):
    # Public Endpoint (No Auth Header)
    tenant_result = await db.execute(select(Tenant).where(Tenant.ApiKey == key))
    tenant = tenant_result.scalars().first()
    if not tenant:
        raise HTTPException(status_code=401, detail="Invalid API Key")
        
    backend_url = _get_backend_url(request)
    return _serve_agent_package(os_type, tenant, backend_url, serve_payload=payload, format_type=format)

@router.get("/agent/install")
async def download_agent(
    request: Request,
    os_type: str = "windows",
    payload: bool = False,
    format: str = None,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    # Authenticated Endpoint
    if not current_user.TenantId:
        raise HTTPException(status_code=400, detail="User has no TenantId")
    
    tenant_result = await db.execute(select(Tenant).where(Tenant.Id == current_user.TenantId))
    tenant = tenant_result.scalars().first()
    if not tenant:
        raise HTTPException(status_code=401, detail="Tenant not found")

    backend_url = _get_backend_url(request)
    return _serve_agent_package(os_type, tenant, backend_url, serve_payload=payload, format_type=format)

@router.get("/public/payload")
async def get_payload_binary(key: str, db: AsyncSession = Depends(get_db)):
    # Serve the raw EXE (29MB or Split 106MB)
    tenant_result = await db.execute(select(Tenant).where(Tenant.ApiKey == key))
    tenant = tenant_result.scalars().first()
    if not tenant:
        raise HTTPException(status_code=401, detail="Invalid API Key")

    base_path = "storage"
    template_dir = os.path.join(base_path, "AgentTemplate", "win-x64")
    exe_path = os.path.join(template_dir, "monitorix-agent.exe")
    
    # 1. Check for Single File (Small Build)
    if os.path.exists(exe_path):
        return FileResponse(exe_path, media_type="application/vnd.microsoft.portable-executable", filename="monitorix-agent.exe")
    
    # 2. Check for Split Files (Large Build)
    part_0 = os.path.join(template_dir, "monitorix-agent.exe.part0")
    if os.path.exists(part_0):
        # Generator to stream parts sequentially
        def iterfile():
            part_num = 0
            while True:
                part_file = os.path.join(template_dir, f"monitorix-agent.exe.part{part_num}")
                if not os.path.exists(part_file):
                    break
                with open(part_file, "rb") as f:
                    while chunk := f.read(8 * 1024 * 1024): # 8MB Chunk
                        yield chunk
                part_num += 1
                
        return StreamingResponse(iterfile(), media_type="application/vnd.microsoft.portable-executable", headers={"Content-Disposition": "attachment; filename=monitorix-agent.exe"})

    raise HTTPException(status_code=404, detail="Agent Binary Not Found (Split or Single)")

@router.get("/script")
async def get_install_script(request: Request, key: str, db: AsyncSession = Depends(get_db)):
    # Helper to get the One-Liner Script (Stager)
    
    tenant_result = await db.execute(select(Tenant).where(Tenant.ApiKey == key))
    tenant = tenant_result.scalars().first()
    if not tenant:
        return Response(content="Write-Error 'Invalid API Key'", media_type="text/plain")

    backend_url = _get_backend_url(request)
    
    print(f"[Downloads] Generating Script for Key: {key}")
    print(f"[Downloads] Tenant Found: ID={tenant.Id}, API_KEY={tenant.ApiKey}")

    if not tenant.ApiKey:
        print("[Downloads] CRITICAL: Tenant has no API Key in DB!")

    # 1. Prepare Config Data
    config_data = {
        "TenantApiKey": tenant.ApiKey,
        "BackendUrl": backend_url
    }
    config_json = json.dumps(config_data)
    config_json_escaped = config_json.replace("'", "''")

    # 2. Generate PowerShell Stager
    payload_url = f"{backend_url}/api/downloads/public/payload?key={key}"
    
    ps_script = f"""
$ErrorActionPreference = 'Stop'
Write-Host "--- Monitorix Installer (Network Stager) ---" -ForegroundColor Cyan

# --- Configuration ---
$ConfigContent = '{config_json_escaped}'
$EulaAccepted = $true
$InstallDir = "$env:APPDATA\\Monitorix"
$ExeDest = "$InstallDir\\monitorix-agent.exe"

# --- Cleanup ---
Write-Host "Cleaning up old processes..." -ForegroundColor Gray
Stop-Process -Name "monitorix-agent", "monitorix", "watch-sec-agent" -Force -ErrorAction SilentlyContinue
if (Test-Path $InstallDir) {{ Remove-Item -Path $InstallDir -Recurse -Force -ErrorAction SilentlyContinue }}
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null

# --- Download Payload ---
# --- Download Payload with Animation ---
Write-Host "Initializing Secure Download..." -ForegroundColor Cyan

$Code = @"
using System;
using System.Net;
public class WebClientWithTimeout : WebClient {{
    protected override WebRequest GetWebRequest(Uri address) {{
        WebRequest w = base.GetWebRequest(address);
        w.Timeout = 10000; // Increased timeout
        return w;
    }}
}}
"@
Add-Type -TypeDefinition $Code -Language CSharp

$WebClient = New-Object WebClientWithTimeout
$WebClient.Headers.Add("User-Agent", "Monitorix-Installer")
$WebClient.Proxy = $null # Bypass Proxy Detection (Speed Boost)
$Uri = New-Object System.Uri("{payload_url}")

# Animation Frames (Running Bear / Spinner)
$BearFrames = @(
    " (^-.-^) ",
    " (^~.~^) ",
    " (o...o) ",
    " (>...<) "
)
$Frames = @("|", "/", "-", "\\")
$FrameIdx = 0

# Start Async Download
$DownloadTask = $WebClient.DownloadFileTaskAsync($Uri, $ExeDest)

Write-Host "Downloading Agent Package (High Performance)..." -NoNewline

while (-not $DownloadTask.IsCompleted) {{
    # Calculate simulated progress or just animate if total size unknown
    # Since we can't easily get TotalBytes in simple AsyncTask without handler event, 
    # we'll do a smart spinner with downloaded bytes check if file exists
    
    $Downloaded = 0
    if (Test-Path $ExeDest) {{ $Downloaded = (Get-Item $ExeDest).Length }}
    $MB = "{{0:N2}}" -f ($Downloaded / 1MB)
    
    # Update Status Line
    $Bear = $BearFrames[$FrameIdx % $BearFrames.Count]
    $Frame = $Frames[$FrameIdx % $Frames.Count]
    Write-Host "`r$Bear [$Frame] Downloading... $MB MB Received    " -NoNewline -ForegroundColor Yellow
    
    $FrameIdx++
    Start-Sleep -Milliseconds 100
}}

Write-Host "`r[v] Download Constants Verified.                   " -ForegroundColor Green

if ($DownloadTask.IsFaulted) {{
    Write-Error "Download Error: $($DownloadTask.Exception.InnerException.Message)"
    exit 1
}}


try {{
    # Move to Install Dir
    Move-Item -Path $ExeDest -Destination "$InstallDir\\monitorix-agent.exe" -Force
    
    # Write Config
    Write-Host "Applying Configuration..."
    $ConfigPath = "$InstallDir\\config.json"
    Set-Content -Path $ConfigPath -Value $ConfigContent -Encoding UTF8
    
    # Secure Config (Hide Indefinitely)
    (Get-Item $ConfigPath).Attributes = 'Hidden'

    # --- Persistence (Scheduled Task) ---
    Write-Host "Registering Startup Persistence..."
    $TaskName = "MonitorixAgent"
    $Action = New-ScheduledTaskAction -Execute "$InstallDir\\monitorix-agent.exe"
    $Trigger = New-ScheduledTaskTrigger -AtLogon
    $Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
    
    Register-ScheduledTask -Action $Action -Trigger $Trigger -Settings $Settings -TaskName $TaskName -Description "Monitorix Security Agent" -Force | Out-Null
    
    # Run Agent Immediately
    $ExePath = "$InstallDir\\monitorix-agent.exe"
    if (-not (Test-Path $ExePath)) {{ throw "Agent binary missing!" }}
    Start-Process -FilePath $ExePath -WindowStyle Hidden
    
    Write-Host "Starting Monitorix Agent..." -ForegroundColor Green
    # Start detached
    Start-Process -FilePath "$ExePath" -WorkingDirectory "$InstallDir"

}} catch {{
    Write-Error "Termination Error: $_"
    exit 1
}}

Write-Host "Done. Agent is running in background." -ForegroundColor Green
"""
    return Response(content=ps_script, media_type="text/plain")
