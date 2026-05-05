from fastapi import APIRouter, Depends, HTTPException, status, Response, Request # type: ignore
from fastapi.responses import FileResponse, StreamingResponse # type: ignore
from sqlalchemy.ext.asyncio import AsyncSession # type: ignore
from sqlalchemy.future import select # type: ignore
import shutil # type: ignore
import os # type: ignore
import io # type: ignore
import zipfile # type: ignore
import json # type: ignore
import uuid # type: ignore
import asyncio # type: ignore
import aiofiles # type: ignore
import subprocess # type: ignore
import re # type: ignore
import hashlib # type: ignore
from typing import Optional # type: ignore

from ..db.session import get_db # type: ignore
from ..db.models import Tenant, User # type: ignore
from .deps import get_current_user # type: ignore

router = APIRouter()

@router.get("/latest-binary")
async def get_latest_binary_for_audit(current_user: User = Depends(get_current_user)):
    """
    Forensics & Audit: Serves the current latest Windows binary for external analysis (Redrainbow/VirusTotal).
    """
    file_dir = os.path.dirname(os.path.abspath(__file__))
    base = os.path.normpath(os.path.join(file_dir, "../../storage/AgentTemplate/win-x64"))
    
    if not os.path.exists(base):
         raise HTTPException(status_code=404, detail="AgentTemplate volume not mounted.")

    # Priority Match: Standard Binary Name
    exe_path = os.path.join(base, "monitorixagent.exe")
    if not os.path.exists(exe_path):
        # Scan for ANY exe in the win-x64 folder
        for f in os.listdir(base):
            if f.endswith(".exe") and "vc_redist" not in f:
                exe_path = os.path.join(base, f)
                break
                
    if not exe_path or not os.path.exists(exe_path):
        raise HTTPException(status_code=404, detail="Latest binary not found on server.")

    return FileResponse(
        exe_path,
        media_type="application/vnd.microsoft.portable-executable",
        filename=os.path.basename(exe_path),
        headers={"Cache-Control": "no-cache"}
    )

# --- Helper Logic ---

def _get_backend_url(request: Request) -> str:
    # 1. Direct Env Var (Specific for Agent Gateway)
    env_url = os.getenv("AGENT_BACKEND_URL")
    if env_url:
        return env_url.rstrip("/")
    
    # 2. General Base URL (Standard across the app)
    base_url = os.getenv("MONITORIX_BASE_URL")
    if base_url:
        return base_url.rstrip("/")
    
    # 3. Fallback to current request domain (Robust)
    # Using request.url.scheme + netloc ensures it works behind proxies if ProxyHeadersMiddleware is active
    return f"{request.url.scheme}://{request.url.netloc}"

def _serve_agent_package(os_type: str, tenant: Tenant, backend_url: str, serve_payload: bool = False, format_type: Optional[str] = None):
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
        "linux-x64": "linux-x64",
        "linux-arm64": "linux-arm64",
        "mac-x64": "osx-x64",
        "mac-arm64": "osx-arm64",
        "windows-x64": "win-x64",
        "linux": "linux-x64", # Fallbacks
        "mac": "osx-x64",
        "windows": "win-x64"
    }
    
    # Try to match specific os-arch or fallback to os
    # format_type might be passed as architecture in future, but for now we look at os_type
    folder_name = template_folder_map.get(os_type.lower(), "win-x64")
    
    # [Updated] User requested AgentTemplate in backend/AgentTemplate
    # Resolve absolute path relative to this file (backend/app/api/downloads.py)
    # ../../../AgentTemplate -> backend/AgentTemplate
    file_dir = os.path.dirname(os.path.abspath(__file__))
    backend_root = os.path.join(file_dir, "..", "..") # app/api/../.. -> backend root
    base_path = os.path.join(backend_root, "storage", "AgentTemplate")
    
    # Correction: backend_root structure:
    # /app/backend/app/api/downloads.py
    # /app/backend/AgentTemplate
    # So: up 3 levels.
    
    template_path = os.path.join(base_path, folder_name)
    
    if not os.path.exists(template_path):
        raise HTTPException(status_code=404, detail=f"Agent Template for {os_type} not found at {template_path}")

    # 2.2 Handle Static Zip OR Generate Source Zip (Windows)
    if os_type.lower().startswith("windows") and format_type == "zip":
        # Check specific build artifact first (Source + Runtime Zip)
        zip_path = os.path.join(template_path, "monitorix.zip")
        
        # Fallback (Legacy)
        if not os.path.exists(zip_path):
             zip_path = os.path.join(template_path, "monitorix-windows.zip")

        if os.path.exists(zip_path):
             def iterzip():
                with open(zip_path, "rb") as zf:
                    while chunk := zf.read(8 * 1024 * 1024): # 8MB Chunk
                        yield chunk
             return StreamingResponse(
                iterzip(),
                media_type="application/zip",
                headers={"Content-Disposition": 'attachment; filename="monitorix-agent.zip"'}
             )
        else:
                 # STRICT SECURITY: Do NOT generate source zip.
                 print(f"[ERROR] Agent Binary/Zip Template Missing in {template_path}")
                 raise HTTPException(status_code=404, detail="Agent Binary Not Found. Please contact administrator.")

    # 2.5 Handle Payload Request (Zip Serving)
    if serve_payload:
        if os_type.lower().split("-")[0] in ["linux", "mac", "windows"]:
            # On-the-fly Zip Generation (from Template)
            zip_buffer = io.BytesIO()
            # Zip everything in template_path
            with zipfile.ZipFile(zip_buffer, "a", zipfile.ZIP_DEFLATED, False) as zip_file:
                for root, dirs, files in os.walk(template_path):
                    for file in files:
                        # Exclude Binaries and Parts from Source Zip to keep it small
                        if file.endswith(".part") or ".part" in file:
                            continue
                        if file.endswith(".exe") or file.endswith(".bin"):
                            continue
                        if file in ["monitorix-agent-linux", "monitorix-agent-mac", "monitorixagent.exe"]:
                            continue
                        
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

    if os_type.lower().split("-")[0] in ["linux", "mac"]:
        # Bash Script Generation
        
        # [Updated] Check if Binary Exists for Linux
        # If so, serve Binary Payload instead of Source Zip
        use_binary = False
        binary_name = "monitorix-agent-linux" if "linux" in os_type.lower() else "monitorix-agent-mac"
        
        # Check if parts or file exist in template
        check_path_part = os.path.join(template_path, f"{binary_name}.part0")
        check_path_full = os.path.join(template_path, binary_name)
        
        # [DEBUG]
        print(f"[DEBUG] Linux Binary Check in {template_path}: {check_path_full} ({os.path.exists(check_path_full)})")

        if os.path.exists(check_path_part) or os.path.exists(check_path_full):
             # Binary Available!
             use_binary = True
        
        if use_binary and "linux" in os_type.lower():
             payload_url = f"{backend_url}/api/downloads/public/payload?key={tenant.ApiKey}&os_type={os_type.lower()}"
        else:
             # Fallback to Source Zip
             use_binary = False
             payload_url = f"{backend_url}/api/downloads/public/agent?key={tenant.ApiKey}&os_type={os_type.lower()}&payload=true"

        install_script = f"""#!/bin/bash
# Monitorix Agent Installer (Self-Detecting Mode)
API_KEY="{tenant.ApiKey}"
BACKEND_URL="{backend_url}"
BINARY_NAME="{binary_name}"

echo "--- Monitorix Agent Installer (Cross-Platform) ---"

# Architecture Detection
ARCH=$(uname -m)
OS_TYPE=$(uname -s | tr '[:upper:]' '[:lower:]')

if [ "$OS_TYPE" = "darwin" ]; then
    OS_NAME="mac"
else
    OS_NAME="linux"
fi

if [[ "$ARCH" == "arm64" || "$ARCH" == "aarch64" ]]; then
    AGENT_ARCH="arm64"
else
    AGENT_ARCH="x64"
fi

# Detect Target Platform
TARGET_PLATFORM="${{OS_NAME}}-${{AGENT_ARCH}}"
echo "Detected Platform: ${{TARGET_PLATFORM}}"

# 1. Attempt Binary Download
PAYLOAD_URL="${{BACKEND_URL}}/api/downloads/public/payload?key=${{API_KEY}}&os_type=${{TARGET_PLATFORM}}"
echo "[1/5] Downloading Agent Binary package..."

IS_BINARY="false"
# Use a temp file for testing
if command -v curl &> /dev/null; then
    HTTP_CODE=$(curl -L -s -o agent.bin -w "%{{http_code}}" "$PAYLOAD_URL")
elif command -v wget &> /dev/null; then
    wget -q "$PAYLOAD_URL" -O agent.bin
    HTTP_CODE=$?
    if [ $HTTP_CODE -eq 0 ]; then HTTP_CODE=200; else HTTP_CODE=404; fi
fi

if [ "$HTTP_CODE" -eq 200 ]; then
    echo "✓ Binary payload found for ${{TARGET_PLATFORM}}"
    IS_BINARY="true"
else
    echo "Note: No pre-built binary for ${{TARGET_PLATFORM}} (Status: $HTTP_CODE). Falling back to Source mode..."
    rm -f agent.bin 2>/dev/null
    PAYLOAD_URL="${{BACKEND_URL}}/api/downloads/public/agent?key=${{API_KEY}}&os_type=${{TARGET_PLATFORM}}&payload=true"
    
    if command -v curl &> /dev/null; then
        curl -L -s -o agent.zip "$PAYLOAD_URL"
    else
        wget -q "$PAYLOAD_URL" -O agent.zip
    fi
fi

echo "[2/5] Creating Directory..."
mkdir -p ./monitorix-agent
dir_name="$(pwd)/monitorix-agent"

echo "[3/5] Extracting..."
if [ "$IS_BINARY" = "true" ]; then
    if [ -s agent.bin ]; then
        mv agent.bin "$dir_name/$BINARY_NAME"
        chmod +x "$dir_name/$BINARY_NAME"
    else
        echo "Error: Binary download was empty or failed. Falling back to source check..."
        IS_BINARY="false"
    fi
fi

if [ "$IS_BINARY" = "false" ]; then
    if ! command -v unzip &> /dev/null; then
        echo "Attempting to install unzip..."
        apt-get update && apt-get install -y unzip || yum install -y unzip
    fi
    if ! command -v unzip &> /dev/null; then
        echo "Error: unzip is required for source installation. Please install it manually."
        exit 1
    fi
    if [ -f agent.zip ]; then
        unzip -o agent.zip -d "$dir_name" > /dev/null
        rm agent.zip
    else
        echo "Error: agent.zip not found. Source download failed."
        exit 1
    fi
fi

echo "[4/5] Installing Dependencies..."
if [ "$IS_BINARY" = "false" ]; then
    if ! command -v python3 &> /dev/null; then
        if [ "$(uname)" = "Darwin" ]; then
             echo "Python 3 not found. Attempting to install..."
             if command -v brew &> /dev/null; then
                 brew install python > /dev/null 2>&1
             else
                 echo "Error: Python 3 is missing. Please run 'xcode-select --install' or install Python 3 manually."
                 exit 1
             fi
        fi
    fi

    if ! command -v pip3 &> /dev/null && ! python3 -m pip --version &> /dev/null; then
        echo "Installing python3-pip..."
        if [ "$(uname)" = "Darwin" ]; then
            python3 -m ensurepip --default-pip > /dev/null 2>&1 || echo "Warning: ensurepip failed. Please install pip manually."
        else
            {{
                apt-get update && apt-get install -y python3-pip || yum install -y python3-pip
            }} > /dev/null 2>&1
        fi
    fi

    if [ -f "$dir_name/requirements.txt" ]; then
        echo "Installing Python requirements (quiet mode)..."
        {{
            python3 -m pip install -r "$dir_name/requirements.txt" --break-system-packages || \
            python3 -m pip install -r "$dir_name/requirements.txt"
        }} > /dev/null 2>&1 || echo "Warning: Pip install failed. Agent might not start."
    else
        echo "Warning: requirements.txt not found."
    fi
else
    echo "Skipping non-binary dependencies (Binary Mode)."
fi

# 4.5 Binary Permission (Linux)
if [ "$IS_BINARY" = "true" ] && [ -f "$dir_name/$BINARY_NAME" ]; then
    echo "Setting execute permissions for binary..."
    chmod +x "$dir_name/$BINARY_NAME"
fi

echo "[5/5] Configuring..."
echo '{json.dumps(config_data)}' > "$dir_name/config.json"

# Create Systemd Service (Linux)
if [ "$(uname)" = "Linux" ] && [ -d "/etc/systemd/system" ]; then
    SERVICE_FILE="/etc/systemd/system/monitorix.service"
    echo "Installing Systemd Service..."
    
    if [ "$EUID" -ne 0 ]; then
        echo "Note: Service installation requires root. Your password may be requested for sudo."
        SUDO="sudo"
    else
        SUDO=""
    fi

    # Binary vs Source ExecStart
    if [ "$IS_BINARY" = "true" ] && [ -f "$dir_name/$BINARY_NAME" ]; then
        echo "Using Binary: $dir_name/$BINARY_NAME"
        EXEC_CMD="$dir_name/$BINARY_NAME"
    else
        echo "Using Source: $dir_name/src/main.py"
        PYTHON_PATH=$(which python3)
        # Check if src/main.py exists, otherwise use main.py in root (if it was zipped differently)
        if [ -f "$dir_name/src/main.py" ]; then
            EXEC_CMD="$PYTHON_PATH $dir_name/src/main.py"
        elif [ -f "$dir_name/main.py" ]; then
            EXEC_CMD="$PYTHON_PATH $dir_name/main.py"
        else
             EXEC_CMD="$PYTHON_PATH main.py"
        fi
    fi

    $SUDO bash -c "cat > $SERVICE_FILE" <<EOF
[Unit]
Description=Monitorix Security Agent
After=network.target

[Service]
Type=simple
User=$USER
WorkingDirectory=$dir_name
ExecStart=$EXEC_CMD
Restart=always
RestartSec=5
Environment=PYTHONUNBUFFERED=1
Environment=DISPLAY=:0
Environment=XAUTHORITY=/home/$USER/.Xauthority

[Install]
WantedBy=multi-user.target
EOF
    $SUDO systemctl daemon-reload 2>/dev/null
    $SUDO systemctl enable monitorix 2>/dev/null
    $SUDO systemctl restart monitorix 2>/dev/null
    echo -e "\033[0;32m[SUCCESS] Monitorix Agent v1.8.60 (Linux) is now running.\033[0m"

# Create LaunchAgent (macOS, Source Only)
elif [ "$(uname)" = "Darwin" ]; then
    if [ "$EUID" -ne 0 ]; then
        PLIST_DIR="$HOME/Library/LaunchAgents"
        BOOTSTRAP_DOMAIN="gui/$(id -u)"
    else
        PLIST_DIR="/Library/LaunchDaemons"
        BOOTSTRAP_DOMAIN="system"
    fi
    
    PLIST_FILE="$PLIST_DIR/com.monitorix.agent.plist"
    mkdir -p "$PLIST_DIR"
    
    # Binary vs Source ExecStart
    if [ "$IS_BINARY" = "true" ] && [ -f "$dir_name/$BINARY_NAME" ]; then
        EXEC_CMD_ARRAY="<string>$dir_name/$BINARY_NAME</string>"
    else
        PYTHON_PATH=$(which python3)
        if [ -f "$dir_name/src/main.py" ]; then
            MAIN_SCRIPT="$dir_name/src/main.py"
        elif [ -f "$dir_name/main.py" ]; then
            MAIN_SCRIPT="$dir_name/main.py"
        else
            MAIN_SCRIPT="main.py"
        fi
        EXEC_CMD_ARRAY="<string>$PYTHON_PATH</string><string>$MAIN_SCRIPT</string>"
    fi

    cat > "$PLIST_FILE" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.monitorix.agent</string>
    <key>ProgramArguments</key>
    <array>
        $EXEC_CMD_ARRAY
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>WorkingDirectory</key>
    <string>$dir_name</string>
    <key>StandardOutPath</key>
    <string>$dir_name/agent.log</string>
    <key>StandardErrorPath</key>
    <string>$dir_name/agent.err</string>
</dict>
</plist>
EOF
    
    SERVICE_STARTED=false
    echo "Installing Service..."
    # Try modern bootstrap, fallback to load
    if launchctl bootout $BOOTSTRAP_DOMAIN "$PLIST_FILE" 2>/dev/null; then
        sleep 1
    fi
    if launchctl bootstrap $BOOTSTRAP_DOMAIN "$PLIST_FILE" 2>/dev/null || launchctl load "$PLIST_FILE" 2>/dev/null; then
        echo "Agent started via launchctl!"
        SERVICE_STARTED=true
    else
        echo "Warning: Failed to start agent via launchctl."
    fi

    echo "--- Installation Complete ---"
    if [ "$SERVICE_STARTED" = "false" ]; then
        echo "Manual Start Required:"
        if [ "$IS_BINARY" = "true" ] && [ -f "$dir_name/$BINARY_NAME" ]; then
             echo "  cd $dir_name && sudo ./$BINARY_NAME"
        else
             echo "  cd $dir_name && sudo python3 $(basename $MAIN_SCRIPT)"
        fi
    else
        echo -e "\033[0;32m[SUCCESS] Monitorix Agent v1.8.60 (macOS) is now running.\033[0m"
    fi
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
        # Priority 1: The New NSIS Installer
        exe_path = os.path.join(template_path, "monitorix-setup-v3.exe")
        
        # Priority 2: Legacy/Standard Names
        if not os.path.exists(exe_path):
             exe_path = os.path.join(template_path, "monitorix.exe")
        
        if not os.path.exists(exe_path):
             exe_path = os.path.join(template_path, "monitorix-agent.exe")
        
        # Priority 3: Any Exe as absolute fallback
        if not os.path.exists(exe_path):
             for f in os.listdir(template_path):
                if f.endswith(".exe"):
                    exe_path = os.path.join(template_path, f)
                    break
        
        if not os.path.exists(exe_path):
             files = os.listdir(template_path)
             raise HTTPException(status_code=500, detail=f"Server Error: Could not find monitorix installer in {folder_name}. Found: {files}")

        # [SECURE] Serve Signed Binary Directly (No Config Injection)
        # Modifying a signed EXE breaks the signature.
        # Config is handled by passing /KEY to the installer or via config.json in zip.
        
        media_type = "application/vnd.microsoft.portable-executable"
        filename = "monitorix.exe"

        return FileResponse(exe_path, media_type=media_type, filename=filename)

# --- Endpoints ---

@router.get("/public/root_ca.crt")
async def download_root_ca():
    file_path = "storage/public/root_ca.crt"
    if os.path.exists(file_path):
        return FileResponse(file_path, media_type="application/x-x509-ca-cert", filename="root_ca.crt")
    raise HTTPException(status_code=404, detail="Root CA not found")

@router.api_route("/public/agent", methods=["GET", "HEAD"])
async def download_public_agent(
    request: Request,
    key: str,
    os_type: str = "windows",
    payload: bool = False,
    format: Optional[str] = None,
    db: AsyncSession = Depends(get_db)
):
    # Public Endpoint (No Auth Header)
    # NOTE: 'mode' param removed — Windows always uses standard binary installation.
    tenant_result = await db.execute(select(Tenant).where(Tenant.ApiKey == key))
    tenant = tenant_result.scalars().first()
    if not tenant:
        raise HTTPException(status_code=401, detail="Invalid API Key")
        
    backend_url = _get_backend_url(request)

    # If Windows and no payload requested, serve the PS1 Stager (always binary/standard mode)
    if os_type.lower().startswith("windows") and not payload:
        return await get_install_script(request, key, "binary", db)

    return _serve_agent_package(os_type, tenant, backend_url, serve_payload=payload, format_type=format)

@router.get("/agent/install")
async def download_agent(
    request: Request,
    os_type: str = "windows",
    payload: bool = False,
    format: Optional[str] = None,
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

import hashlib # type: ignore

@router.api_route("/public/payload", methods=["GET", "HEAD"])
async def get_payload_binary(key: str, os_type: str = "windows", part: Optional[int] = None, db: AsyncSession = Depends(get_db)):
    # Serve the raw Binary (Split or Single)
    tenant_result = await db.execute(select(Tenant).where(Tenant.ApiKey == key))
    tenant = tenant_result.scalars().first()
    if not tenant:
        raise HTTPException(status_code=401, detail="Invalid API Key")

    # Resolve absolute path relative to this file
    file_dir = os.path.dirname(os.path.abspath(__file__))
    # [FIX] Path is backend/app/api/downloads.py -> ..(api) -> ..(app) -> ..(backend)
    backend_root = os.path.join(file_dir, "..", "..")
    base_path = os.path.join(backend_root, "storage", "AgentTemplate")
    
    # OS Path Resolution
    template_folder_map = {
        "linux-x64": "linux-x64",
        "linux-arm64": "linux-arm64",
        "mac-x64": "osx-x64",
        "mac-arm64": "osx-arm64",
        "windows-x64": "win-x64",
        "linux": "linux-x64", # Fallbacks
        "mac": "osx-x64",
        "windows": "win-x64"
    }
    folder_name = template_folder_map.get(os_type.lower(), "win-x64")
    template_dir = os.path.join(base_path, folder_name)
    
    if not os.path.exists(template_dir):
         # If specific arch is requested but missing, we should NOT fallback to x64 here
         # as it will serve the wrong architecture binary.
         raise HTTPException(status_code=404, detail=f"Agent Template for {os_type} not found.")
    

    
    # --- Payload Resolution ---
    # The One-Liner and Worker scripts expect a ZIP package to extract.
    # We must ensure we serve the ZIP and NOT the NSIS installer here.
    
    binary_name = "monitorix.zip" # Default
    
    if "linux" in os_type.lower(): 
        binary_name = "monitorix-agent-linux"
    elif "mac" in os_type.lower() or "osx" in os_type.lower(): 
        binary_name = "monitorix-agent-mac"
    elif "windows" in os_type.lower():
        # Check for zip payload (Preferred for automated installation)
        if os.path.exists(os.path.join(template_dir, "monitorix.zip")):
             binary_name = "monitorix.zip"
        elif os.path.exists(os.path.join(template_dir, "monitorix-windows.zip")):
             binary_name = "monitorix-windows.zip"
        else:
             # Fallback to binary only if zip is missing (Legacy)
             if os.path.exists(os.path.join(template_dir, "monitorix-agent.exe")):
                  binary_name = "monitorix-agent.exe"
             elif os.path.exists(os.path.join(template_dir, "monitorixagent.exe")):
                  binary_name = "monitorixagent.exe"
             else:
                  binary_name = "monitorix.exe"
    
    binary_path = os.path.join(template_dir, binary_name)
    
    # 1.5 Check for Part Request
    if part is not None:
         part_name = f"{binary_name}.part{part}"
         part_path = os.path.join(template_dir, part_name)
         # If using -a 1 on split, suffix is 0, 1. If using default, 00, 01.
         # Our check above looked for .part0. 
         # Let's be flexible.
         if not os.path.exists(part_path):
             # Try padding?
             part_name_padded = f"{binary_name}.part{part:02d}"
             part_path_padded = os.path.join(template_dir, part_name_padded)
             if os.path.exists(part_path_padded):
                 part_path = part_path_padded
                 part_name = part_name_padded
         
         if os.path.exists(part_path):
             return FileResponse(part_path, media_type="application/octet-stream", filename=part_name)
         else:
             raise HTTPException(status_code=404, detail=f"Part {part} not found")

    # 1. Check for Single File (Full Download)
    if os.path.exists(binary_path):
        media_type = "application/octet-stream"
        if os_type.lower() == "windows": media_type = "application/vnd.microsoft.portable-executable"
        # If binary_name is monitorix.zip, type is zip
        if binary_name.endswith(".zip"): media_type = "application/zip"
        if binary_name.endswith(".zip"): media_type = "application/zip"
        
        # [v1.6.0 Checksum] Calculate SHA256
        sha256_hash = hashlib.sha256()
        with open(binary_path, "rb") as f:
            # Read in chunks to avoid memory issues
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        file_hash = sha256_hash.hexdigest()
        
        headers = {"X-Binary-SHA256": file_hash}
        
        return FileResponse(binary_path, media_type=media_type, filename=binary_name, headers=headers)
    
    # 2. Check for Split Files (Stream All)
    part_0 = os.path.join(template_dir, f"{binary_name}.part0")
    if os.path.exists(part_0):
        # Calculate Total Size
        total_size = 0
        p_idx = 0
        while True:
            p = os.path.join(template_dir, f"{binary_name}.part{p_idx}")
            if not os.path.exists(p):
                break
            total_size += os.path.getsize(p)
            p_idx += 1
            
        # [v1.8.1] Calculate SHA256 for Split Files
        sha256_hash = hashlib.sha256()
        p_idx_hash = 0
        while True:
            p_hash = os.path.join(template_dir, f"{binary_name}.part{p_idx_hash}")
            if not os.path.exists(p_hash):
                break
            with open(p_hash, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            p_idx_hash += 1
            
        file_hash = sha256_hash.hexdigest()

        # Generator to stream parts sequentially
        async def iterfile():
            part_num = 0
            while True:
                part_file = os.path.join(template_dir, f"{binary_name}.part{part_num}")
                if not os.path.exists(part_file):
                    break
                async with aiofiles.open(part_file, "rb") as f:
                    while chunk := await f.read(1024 * 1024): # 1MB Chunk
                        yield chunk
                part_num += 1
                
        headers = {
            "Content-Disposition": f'attachment; filename="{binary_name}"',
            "Content-Length": str(total_size),
            "X-Binary-SHA256": file_hash
        }
        return StreamingResponse(iterfile(), media_type="application/octet-stream", headers=headers)

    raise HTTPException(status_code=404, detail=f"Agent Binary Not Found in {folder_name}")

@router.get("/public/root-ca")
async def get_root_ca():
    """
    Returns the Root CA certificate for Windows trust establishment.
    """
    file_dir = os.path.dirname(os.path.abspath(__file__))
    backend_root = os.path.normpath(os.path.join(file_dir, "..", ".."))
    
    possible_paths = [
        os.path.join(backend_root, "storage", "AgentTemplate", "root_ca.crt"),
        os.path.join(backend_root, "AgentTemplate", "win-x64", "root_ca.crt"),
        os.path.join(backend_root, "..", "agent", "root_ca.crt")
    ]
    
    for p in possible_paths:
        if os.path.exists(p):
            return FileResponse(p, media_type="application/x-x509-ca-cert", filename="root_ca.crt")
            
    raise HTTPException(status_code=404, detail="Root CA certificate not found on server.")

@router.get("/script")
async def get_install_script(request: Request, key: str, mode: str = "binary", db: AsyncSession = Depends(get_db)):
    """
    Returns the PowerShell stager script for Windows agent installation.
    Always uses the standard binary installation method.
    The 'mode' param is kept for backwards-compat with direct /script calls but
    is no longer exposed via the public one-liner URL.
    """
    tenant_result = await db.execute(select(Tenant).where(Tenant.ApiKey == key))
    tenant = tenant_result.scalars().first()
    if not tenant:
        return Response(content="Write-Error 'Invalid Monitorix API Key. Please check the key in your dashboard.'", media_type="text/plain")

    backend_url = _get_backend_url(request)
    
    # Check Agent Limit BEFORE Generating Installer
    from sqlalchemy import func # type: ignore
    from ..db.models import Agent # type: ignore
    
    count_query = select(func.count()).select_from(Agent).where(Agent.TenantId == tenant.Id)
    count_res = await db.execute(count_query)
    current_count = count_res.scalar()
    
    if current_count >= tenant.AgentLimit:
        limit_script = f"""
Write-Host "--- Monitorix Installer ---" -ForegroundColor Cyan
Write-Error "INSTALLATION ABORTED: Agent Limit Reached ({current_count} / {tenant.AgentLimit})."
Write-Host "Please contact your administrator to upgrade your license." -ForegroundColor Gray
exit 1
"""
        return Response(content=limit_script.strip(), media_type="text/plain", headers={"Content-Disposition": 'attachment; filename="install.ps1"'})
    
    # Always use the standard binary installer template
    # Source mode is not exposed via the public one-liner but kept here for admin use.
    template_name = "install_agent_windows.ps1"
    if mode == "source":
        template_name = "install_agent_windows_source.ps1"

    file_dir = os.path.dirname(os.path.abspath(__file__))
    possible_paths = [
        os.path.normpath(os.path.join(file_dir, f"../../{template_name}")), # Backend Root
        os.path.normpath(os.path.join(file_dir, f"../../../agent/{template_name}")), # Agent Folder (Dev)
        f"/app/{template_name}"
    ]
    
    installer_script_path = None
    for p in possible_paths:
        if os.path.exists(p):
            installer_script_path = p
            break
            
    if not installer_script_path or not os.path.exists(str(installer_script_path)):
        # Fallback: always try standard binary template
        fallback = os.path.normpath(os.path.join(file_dir, "../../install_agent_windows.ps1"))
        if os.path.exists(fallback):
            installer_script_path = fallback
            print(f"[Downloads] Falling back to standard binary template.")
        else:
            return Response(content="Write-Error 'Monitorix Installer template not found on server. Contact support.'", media_type="text/plain")

    async with aiofiles.open(installer_script_path, mode='r') as f:
        full_script = await f.read()

    # Strip param(...) block — variables are injected below
    full_script = re.sub(r'(?si)param\s*\(.*?\)', '', full_script, count=1)

    # Build the EXE download URL (standard binary path)
    download_url = f"{backend_url}/api/downloads/exe/windows?key={tenant.ApiKey}"

    # Prepend all required variables so the script is fully self-contained
    variables = f"""
$DownloadUrl = "{download_url}"
$ApiKey = "{tenant.ApiKey}"
$BackendUrl = "{backend_url}"
$InstallDir = "C:\\Program Files\\Monitorix"
$ExeName = "monitorix-agent.exe"
$VersionCheckUrl = ""
"""
    
    # Insert variables after any #Requires directives and block comments
    lines = full_script.splitlines()
    insert_idx = 0
    for i, line in enumerate(lines):
        trimmed = line.strip()
        if not trimmed:
            continue
        if trimmed.startswith("<#") or trimmed.startswith("#Requires") or trimmed.startswith("#"):
            if trimmed.startswith("<#"):
                while i < len(lines) and "#>" not in lines[i]:
                    i += 1
            insert_idx = i + 1
            continue
        break
    
    final_script_lines = lines[:insert_idx] + [variables.strip()] + lines[insert_idx:]
    full_script = "\n".join(final_script_lines)

    return Response(content=full_script, media_type="text/plain")
    

@router.get("/python/windows")
async def get_python_windows():
    """
    Serves the portable Python (embedded) zip for source-based installations.
    """
    file_dir = os.path.dirname(os.path.abspath(__file__))
    # Path: backend/app/api/../../agent/python-3.11.9-embed-amd64.zip
    py_path = os.path.normpath(os.path.join(file_dir, "../../../agent/python-3.11.9-embed-amd64.zip"))
    
    if os.path.exists(py_path):
        return FileResponse(py_path, media_type="application/zip", filename="python-runtime.zip")
    
    # Fallback to backend/storage/AgentTemplate/win-x64 if moved
    py_path_alt = os.path.normpath(os.path.join(file_dir, "../../AgentTemplate/win-x64/python-3.11.9-embed-amd64.zip"))
    if os.path.exists(py_path_alt):
        return FileResponse(py_path_alt, media_type="application/zip", filename="python-runtime.zip")

    raise HTTPException(status_code=404, detail="Python runtime not found on server.")


@router.api_route("/exe/windows", methods=["GET", "HEAD"])
async def download_exe_windows(key: str, db: AsyncSession = Depends(get_db)):
    """
    Serves the raw monitorixagent.exe for clean PowerShell deployments.
    No ZIP, no certs exposed. The EXE reads its API key from config.json
    that the PowerShell script creates alongside it.
    """
    tenant_result = await db.execute(select(Tenant).where(Tenant.ApiKey == key))
    tenant = tenant_result.scalars().first()
    if not tenant:
        raise HTTPException(status_code=401, detail="Invalid API Key")

    # Resolve exe path  
    file_dir = os.path.dirname(os.path.abspath(__file__))
    base = os.path.normpath(os.path.join(file_dir, "../../storage/AgentTemplate/win-x64"))
    
    # Priority Match: Monolithic Hyphenated -> Legacy Compressed -> Standard
    exe_names = ["monitorix-agent.exe", "monitorixagent.exe", "monitorix.exe"]
    exe_path = None
    final_name = "monitorix-agent.exe"

    for name in exe_names:
        p = os.path.join(base, name)
        if os.path.exists(p):
            exe_path = p
            final_name = name
            break
    
    if not exe_path:
        # Final fallback: any exe in the folder
        for f in os.listdir(base):
            if f.endswith(".exe") and "vc_redist" not in f:
                exe_path = os.path.join(base, f)
                final_name = f
                break

    if not exe_path:
        raise HTTPException(status_code=404, detail="Agent binary not found on server.")
    
    # Serve the raw EXE - installer script will place config.json next to it
    return FileResponse(
        exe_path,
        media_type="application/vnd.microsoft.portable-executable",
        filename=final_name,
        headers={"Cache-Control": "no-cache"}
    )

@router.api_route("/installer/exe", methods=["GET", "HEAD"])
async def get_installer_exe(key: str, format: Optional[str] = None, db: AsyncSession = Depends(get_db)):
    # Serve the Generic Signed Installer but rename it so it contains the Key
    tenant_result = await db.execute(select(Tenant).where(Tenant.ApiKey == key))
    tenant = tenant_result.scalars().first()
    if not tenant:
        raise HTTPException(status_code=403, detail="Invalid Key")

    # Path to signed installer (Located in Storage Volume)
    # Path to signed installer (Located in AgentTemplate Root)
    # Priority: Standard Build Name -> Legacy V3 Name
    base_template = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../AgentTemplate/win-x64"))
    
    installer_path = os.path.join(base_template, "monitorix-agent.exe")
    if not os.path.exists(installer_path):
        installer_path = os.path.join(base_template, "monitorix-setup-v3.exe")
    
    if not os.path.exists(installer_path):
        # Fallback to any exe
        for f in os.listdir(base_template):
            if f.endswith(".exe") and "vc_redist" not in f:
                installer_path = os.path.join(base_template, f)
                break

    if not os.path.exists(installer_path):
        print(f"[Downloads] Installer missing in: {base_template}")
        raise HTTPException(status_code=404, detail="Installer Not Available (File Missing)")
        
    filename_exe = f"monitorix-installer-{tenant.ApiKey}.exe"

    if format == "zip":
        try:
            # Create a unique temp folder for this request
            request_id = str(uuid.uuid4())
            temp_dir = os.path.join("/tmp", f"mntx_{request_id}")
            os.makedirs(temp_dir, exist_ok=True)
            
            # Paths
            zip_filename = f"monitorix-installer-{tenant.ApiKey}.zip"
            zip_path = os.path.join(temp_dir, zip_filename)
            
            exe_src = installer_path
            exe_dest = os.path.join(temp_dir, filename_exe)
            
            # Correct path to root_ca.crt in storage/public
            cert_src = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../storage/public/root_ca.crt"))
            if not os.path.exists(cert_src):
                 # Fallback: check if it's in current dir (dev)
                 cert_src = "storage/public/root_ca.crt"

            cert_dest = os.path.join(temp_dir, "root_ca.crt")
            
            bat_path = os.path.join(temp_dir, "install.bat")

            # 1. Stage Files
            shutil.copy2(exe_src, exe_dest)
            if os.path.exists(cert_src):
                shutil.copy2(cert_src, cert_dest)
            
            # 2. Write Batch Script
            install_bat = f"""@echo off
:: Monitorix Enterprise Agent - Trusted Installer
:: This script installs the Root Certificate to avoid "Unknown Publisher" warnings
:: and then launches the agent installer.

echo [Monitorix] Requesting Administrative Privileges...
net session >nul 2>&1
if %errorLevel% == 0 (
    echo [Monitorix] Access Granted.
) else (
    echo [Monitorix] Elevating permissions...
    powershell -Command "Start-Process '%~dp0install.bat' -Verb RunAs"
    exit
)

echo [Monitorix] Trusting Enterprise Certificate...
certutil -addstore -f "Root" "%~dp0root_ca.crt" >nul
echo [Monitorix] Certificate Trusted.

echo [Monitorix] Launching Installer...
start "" "%~dp0{filename_exe}"
"""
            with open(bat_path, "w") as f:
                f.write(install_bat)

            # 3. Zip with Password (using system zip utility)
            # -j: junk paths (flatten), -P: password
            files_to_zip = [exe_dest, bat_path]
            if os.path.exists(cert_src):
                files_to_zip.append(cert_dest)
                
            cmd = ["zip", "-j", "-P", "monitorix", zip_path] + files_to_zip
            
            subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            # 4. Read Zip Content
            with open(zip_path, "rb") as f:
                zip_content = f.read()

            return StreamingResponse(
                iter([zip_content]), 
                media_type="application/zip", 
                headers={"Content-Disposition": f'attachment; filename="{zip_filename}"'}
            )
            
        except Exception as e:
            print(f"Error creating encrypted zip: {e}")
            raise HTTPException(status_code=500, detail="Failed to create installer package")
            
        finally:
            # Cleanup
            if os.path.exists(temp_dir):
                shutil.rmtree(temp_dir)

    # Default: Return EXE
    return FileResponse(installer_path, media_type="application/vnd.microsoft.portable-executable", filename=filename_exe)
