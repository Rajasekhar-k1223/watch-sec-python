#!/bin/bash
# Monitorix Agent Installer for Linux

set -e

INSTALL_DIR="/opt/monitorix"
BINARY_NAME="monitorix-agent-linux"
SERVICE_NAME="monitorix-agent"

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${GREEN}--- Monitorix Agent Installer (Linux) ---${NC}"

# 1. Check Root
if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}Error: Please run as root (sudo ./install_agent_linux.sh)${NC}"
  exit 1
fi

# 2. Detect Source Binary
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
# Check both dist_linux and root for the binary
if [ -f "$SCRIPT_DIR/dist_linux/$BINARY_NAME" ]; then
    SOURCE_BIN="$SCRIPT_DIR/dist_linux/$BINARY_NAME"
elif [ -f "$SCRIPT_DIR/$BINARY_NAME" ]; then
    SOURCE_BIN="$SCRIPT_DIR/$BINARY_NAME"
else
    echo -e "${RED}Error: Could not find binary '$BINARY_NAME' in '$SCRIPT_DIR' or '$SCRIPT_DIR/dist_linux'.${NC}"
    exit 1
fi

# 3. Install Files
echo "[*] Installing to $INSTALL_DIR..."
mkdir -p "$INSTALL_DIR"

# Stop service if running
systemctl stop $SERVICE_NAME 2>/dev/null || true

cp "$SOURCE_BIN" "$INSTALL_DIR/$BINARY_NAME"
chmod +x "$INSTALL_DIR/$BINARY_NAME"

# Copy Config if exists
if [ -f "$SCRIPT_DIR/config.json" ]; then
    cp "$SCRIPT_DIR/config.json" "$INSTALL_DIR/config.json"
    echo "    [+] Config installed from root."
elif [ -f "$SCRIPT_DIR/dist_linux/config.json" ]; then
    cp "$SCRIPT_DIR/dist_linux/config.json" "$INSTALL_DIR/config.json"
    echo "    [+] Config installed from dist_linux."
fi

# 4. Create Systemd Service
echo "[*] Creating Systemd Service..."
cat > /etc/systemd/system/$SERVICE_NAME.service <<EOF
[Unit]
Description=Monitorix Security Agent
After=network.target

[Service]
Type=simple
WorkingDirectory=$INSTALL_DIR
ExecStart=$INSTALL_DIR/$BINARY_NAME
Restart=always
RestartSec=10
Environment=PYTHONWARNINGS=ignore:pkg_resources
# Run as root for full monitoring capabilities
User=root
Group=root

[Install]
WantedBy=multi-user.target
EOF

# 5. Enable & Start
echo "[*] Starting Service..."
systemctl daemon-reload
systemctl enable $SERVICE_NAME
systemctl start $SERVICE_NAME

echo -e "${GREEN}[SUCCESS] Monitorix Agent v1.8.23 is now active.${NC}"
systemctl status $SERVICE_NAME --no-pager
