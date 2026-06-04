#!/bin/bash
# Monitorix Agent Installer (Self-Detecting Mode)
# Remove hardcoded key for security
API_KEY="${MONITORIX_API_KEY:-}"
if [ -z "$API_KEY" ]; then
    echo "Error: MONITORIX_API_KEY must be set in environment"
    exit 1
fi
BACKEND_URL="https://monitorix.co.in"
BINARY_NAME="monitorix-agent-linux"

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
TARGET_PLATFORM="${OS_NAME}-${AGENT_ARCH}"
echo "Detected Platform: ${TARGET_PLATFORM}"

# 1. Attempt Binary Download
PAYLOAD_URL="$https://monitorix.co.in/api/downloads/public/payload?key=$25005e1c-4dc5-459b-9599-db6ed09c9ad2&os_type=${TARGET_PLATFORM}"
echo "[1/5] Downloading Agent Binary package..."

IS_BINARY="false"
if command -v curl &> /dev/null; then
    HTTP_CODE=$(curl -L -s -o agent.bin -w "%{http_code}" "$PAYLOAD_URL")
elif command -v wget &> /dev/null; then
    wget -q "$PAYLOAD_URL" -O agent.bin
    HTTP_CODE=$?
    if [ $HTTP_CODE -eq 0 ]; then HTTP_CODE=200; else HTTP_CODE=404; fi
fi

if [ "$HTTP_CODE" -eq 200 ]; then
    echo "✓ Binary payload found for ${TARGET_PLATFORM}"
    IS_BINARY="true"
else
    echo "Note: No pre-built binary for ${TARGET_PLATFORM} (Status: $HTTP_CODE). Falling back to Source mode..."
    rm -f agent.bin 2>/dev/null
    PAYLOAD_URL="$https://monitorix.co.in/api/downloads/public/agent?key=$25005e1c-4dc5-459b-9599-db6ed09c9ad2&os_type=${TARGET_PLATFORM}&payload=true"
    
    if command -v curl &> /dev/null; then
        curl -L -s -o agent.zip "$PAYLOAD_URL"
    else
        wget -q "$PAYLOAD_URL" -O agent.zip
    fi
fi

echo "[2/5] Creating Directory..."
if [ "$EUID" -eq 0 ]; then
    dir_name="/opt/monitorix-agent"
else
    dir_name="$(pwd)/monitorix-agent"
fi
mkdir -p "$dir_name"

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
            {
                apt-get update && apt-get install -y python3-pip || yum install -y python3-pip
            } > /dev/null 2>&1
        fi
    fi

    if [ -f "$dir_name/requirements.txt" ]; then
        echo "Installing Python requirements (quiet mode)..."
        {
            python3 -m pip install -r "$dir_name/requirements.txt" --break-system-packages ||             python3 -m pip install -r "$dir_name/requirements.txt"
        } > /dev/null 2>&1 || echo "Warning: Pip install failed. Agent might not start."
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
echo '{"TenantApiKey": "25005e1c-4dc5-459b-9599-db6ed09c9ad2", "BackendUrl": "https://monitorix.co.in"}' > "$dir_name/config.json"

# Create Systemd Service (Linux)
if [ "$(uname)" = "Linux" ] && [ -d "/etc/systemd/system" ]; then
    SERVICE_FILE="/etc/systemd/system/monitorix-agent.service"
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
    $SUDO systemctl enable monitorix-agent 2>/dev/null
    $SUDO systemctl restart monitorix-agent 2>/dev/null
    echo -e "[0;32m[SUCCESS] Monitorix Agent v1.8.60 (Linux) is now running.[0m"

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
        echo -e "[0;32m[SUCCESS] Monitorix Agent v1.8.60 (macOS) is now running.[0m"
    fi
fi
