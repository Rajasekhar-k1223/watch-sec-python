#!/bin/bash
# Monitorix Agent Installer for macOS

set -e

INSTALL_DIR="/Applications/Monitorix"
BINARY_NAME="monitorix-agent-mac"
PLIST_NAME="com.monitorix.agent.plist"
PLIST_DEST="/Library/LaunchDaemons/$PLIST_NAME"

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${GREEN}--- Monitorix Agent Installer (macOS) ---${NC}"

# 1. Check Root
if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}Error: Please run as root (sudo ./install_agent_mac.sh)${NC}"
  exit 1
fi

# 2. Detect Source
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
SOURCE_BIN="$SCRIPT_DIR/$BINARY_NAME"

if [ ! -f "$SOURCE_BIN" ]; then
    echo -e "${RED}Error: Could not find binary '$BINARY_NAME'.${NC}"
    exit 1
fi

# 3. Install Files
echo "[*] Installing to $INSTALL_DIR..."
mkdir -p "$INSTALL_DIR"

# Stop existing
launchctl unload "$PLIST_DEST" 2>/dev/null || true

cp "$SOURCE_BIN" "$INSTALL_DIR/$BINARY_NAME"
chmod +x "$INSTALL_DIR/$BINARY_NAME"
# Remove Gatekeeper Quarantine (Fixes "Developer cannot be verified" error)
xattr -d com.apple.quarantine "$INSTALL_DIR/$BINARY_NAME" 2>/dev/null || true


if [ -f "$SCRIPT_DIR/config.json" ]; then
    cp "$SCRIPT_DIR/config.json" "$INSTALL_DIR/config.json"
fi

# 4. Create LaunchDaemon (System-wide, runs at boot as root)
echo "[*] Creating LaunchDaemon..."
cat > "$PLIST_DEST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.monitorix.agent</string>
    <key>ProgramArguments</key>
    <array>
        <string>$INSTALL_DIR/$BINARY_NAME</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>WorkingDirectory</key>
    <string>$INSTALL_DIR</string>
    <key>StandardOutPath</key>
    <string>$INSTALL_DIR/agent.log</string>
    <key>StandardErrorPath</key>
    <string>$INSTALL_DIR/agent.err</string>
</dict>
</plist>
EOF

# Fix permissions for LaunchDaemon
chown root:wheel "$PLIST_DEST"
chmod 644 "$PLIST_DEST"

# 5. Load
echo "[*] Loading Agent..."
launchctl load "$PLIST_DEST"

echo -e "${GREEN}[SUCCESS] Monitorix Agent v1.8.14 is now active.${NC}"
echo "Logs: $INSTALL_DIR/agent.log"
