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

def _serve_agent_package(os_type: str, tenant: Tenant, backend_url: str, serve_payload: bool = False):
    """
    Common logic to package and serve the agent.
    - Windows: Stream modified EXE (Zero Disk Write).
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
        exe_name = "monitorix-agent.exe"
        exe_path = os.path.join(template_path, exe_name)
        
        # Fallback if specific name not found
        if not os.path.exists(exe_path):
             for f in os.listdir(template_path):
                if f.endswith(".exe"):
                    exe_path = os.path.join(template_path, f)
                    break
        
        if not os.path.exists(exe_path):
             # Try specific new name
             exe_path = os.path.join(template_path, "monitorix.exe")
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
                while chunk := original_exe.read(64 * 1024):  # 64KB chunks
                    yield chunk
            # 2. Append Delimiter + Config
            yield delimiter
            yield payload
        
        return StreamingResponse(
            iterfile(),
            media_type="application/vnd.microsoft.portable-executable",
            headers={"Content-Disposition": f'attachment; filename="monitorix.exe"'}
        )

# --- Endpoints ---

@router.get("/public/agent")
async def download_public_agent(
    request: Request,
    key: str,
    os_type: str = "windows",
    payload: bool = False,
    db: AsyncSession = Depends(get_db)
):
    # Public Endpoint (No Auth Header)
    tenant_result = await db.execute(select(Tenant).where(Tenant.ApiKey == key))
    tenant = tenant_result.scalars().first()
    if not tenant:
        raise HTTPException(status_code=401, detail="Invalid API Key")
        
    backend_url = _get_backend_url(request)
    return _serve_agent_package(os_type, tenant, backend_url, serve_payload=payload)

@router.get("/agent/install")
async def download_agent(
    request: Request,
    os_type: str = "windows",
    payload: bool = False,
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
    return _serve_agent_package(os_type, tenant, backend_url, serve_payload=payload)

@router.get("/script")
async def get_install_script(request: Request, key: str):
    # Helper to get the One-Liner Script
    
    backend_url = _get_backend_url(request)
    import time
    timestamp = int(time.time())
    # The script uses the PUBLIC endpoint to download the binary
    download_url = f"{backend_url}/api/downloads/public/agent?key={key}&os_type=windows&payload=false&t={timestamp}"
    
    ps_script = f"""
$ErrorActionPreference = 'Stop'
Write-Host "--- Monitorix Installer ---" -ForegroundColor Cyan
$Url = "{download_url}"
$Dest = "$env:TEMP\\monitorix-installer.exe"

Write-Host "Using Backend: {backend_url}" -ForegroundColor Yellow
Write-Host "Downloading Agent..."

# --- Animation Frames (Running Bear) ---
$BearFrames = @(
    " (^-.-^)  ", 
    " ( o-o )  ", 
    " ( >.< )  ", 
    " ( ^-^ )  "
)

# Custom Fast Downloader with Animated Progress
try {{
    $request = [System.Net.HttpWebRequest]::Create($Url)
    $request.Method = "GET"
    $request.UserAgent = "Monitorix-Installer"
    $response = $request.GetResponse()
    
    $totalBytes = $response.ContentLength
    $responseStream = $response.GetResponseStream()
    $targetStream = [System.IO.File]::Create($Dest)
    
    $buffer = New-Object byte[] 65536 # 64KB Chunk
    $totalRead = 0
    $lastUpdate = [System.Diagnostics.Stopwatch]::StartNew()
    $speedWatch = [System.Diagnostics.Stopwatch]::StartNew()
    $speedBytes = 0
    
    # Force Console to show progress
    $ProgressPreference = 'Continue'
    $frameIdx = 0
    
    # Hide Cursor
    try {{ [Console]::CursorVisible = $false }} catch {{}}

    Write-Host "Initializing Download..." -NoNewline
    
    while (($bytesRead = $responseStream.Read($buffer, 0, $buffer.Length)) -gt 0) {{
        $targetStream.Write($buffer, 0, $bytesRead)
        $totalRead += $bytesRead
        $speedBytes += $bytesRead
        
        # Update every 200ms for smoother animation
        if ($lastUpdate.ElapsedMilliseconds -gt 200) {{
            # Calculate Speed
            $seconds = $speedWatch.Elapsed.TotalSeconds
            $speed = 0
            if ($seconds -gt 0) {{ $speed = ($speedBytes / 1MB) / $seconds }}
            $speedWatch.Restart()
            $speedBytes = 0
            
            $lastUpdate.Restart()
            
            # Format Strings
            $mbRead = "{{0:N2}}" -f ($totalRead / 1MB)
            $mbTotal = "{{0:N2}}" -f ($totalBytes / 1MB)
            $speedStr = "{{0:N2}} MB/s" -f $speed
            
            # Get Current Frame
            $frame = $BearFrames[$frameIdx % $BearFrames.Count]
            $frameIdx++

            # Progress Bar Visual
            $percent = 0
            if ($totalBytes -gt 0) {{
                $percent = [math]::Round(($totalRead / $totalBytes) * 100)
            }}
            
            # Create Bar [====>...]
            $barWidth = 30
            $filled = [math]::Round(($percent / 100) * $barWidth)
            $empty = $barWidth - $filled
            $bar = "[" + ("=" * $filled) + ">" + (" " * $empty) + "]"

            # Construct Message
            $msg = "$frame $bar $percent% | $mbRead / $mbTotal MB @ $speedStr    "
            
            # Print (Carriage Return)
            try {{
                [Console]::CursorLeft = 0
                Write-Host $msg -NoNewline -ForegroundColor Cyan
            }} catch {{
                Write-Host $msg
            }}
        }}
    }}
    
    # Final
    try {{ [Console]::CursorVisible = $true }} catch {{}}
    Write-Host ""
    Write-Host "Download Complete!" -ForegroundColor Green
    
    $targetStream.Close()
    $responseStream.Close()
    $response.Close()
    
}} catch {{
    Write-Error "Download Failed: $_"
    exit 1
}}

Write-Host "Starting Monitorix Agent..."
Start-Process -FilePath $Dest

Write-Host "Done." -ForegroundColor Green
"""
    return Response(content=ps_script, media_type="text/plain")
