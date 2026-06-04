#!/bin/bash
# ============================================================
# Monitorix Agent — macOS Installer
# Installs as a LaunchDaemon (system-wide, starts at boot)
# Supports: x64 (Intel) and arm64 (Apple Silicon / M-series)
# Usage: sudo ./install_agent_mac.sh [--api-key KEY] [--backend-url URL]
# ============================================================
set -e

GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

INSTALL_DIR="/Library/Application Support/Monitorix"
BINARY_NAME="monitorixagent"
PLIST_LABEL="com.monitorix.agent"
PLIST_DEST="/Library/LaunchDaemons/${PLIST_LABEL}.plist"
LOG_DIR="/Library/Logs/Monitorix"

# ── Parse Arguments ───────────────────────────────────────────────────────────
API_KEY=""
BACKEND_URL=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --backend-url) BACKEND_URL="$2"; shift 2 ;;
        *) shift ;;
    esac
done

if [ -z "$MONITORIX_API_KEY" ]; then
    echo -e "${YELLOW}Secure Installation: API Key not found in environment.${NC}"
    read -sp "Please enter your Tenant API Key: " MONITORIX_API_KEY
    echo ""
fi
API_KEY="$MONITORIX_API_KEY"

echo -e "${BLUE}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║   Monitorix Agent — macOS Installer              ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════╝${NC}"

# ── Root Check ────────────────────────────────────────────────────────────────
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Error: Run as root: sudo $0${NC}"
    exit 1
fi

# ── Architecture Detection ────────────────────────────────────────────────────
ARCH=$(uname -m)
if [[ "$ARCH" == "arm64" ]]; then
    ARCH_TAG="arm64"
else
    ARCH_TAG="x64"
fi
MACOS_VER=$(sw_vers -productVersion 2>/dev/null || echo "unknown")
echo -e "  Platform : macOS-${ARCH_TAG} (${MACOS_VER})"

# ── Locate Binary ─────────────────────────────────────────────────────────────
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

SOURCE_BIN=""
SEARCH_PATHS=(
    "$SCRIPT_DIR/dist/osx-${ARCH_TAG}/$BINARY_NAME"
    "$SCRIPT_DIR/$BINARY_NAME"
    "$SCRIPT_DIR/dist_mac/$BINARY_NAME"
)
for p in "${SEARCH_PATHS[@]}"; do
    if [ -f "$p" ]; then
        SOURCE_BIN="$p"
        break
    fi
done

if [ -z "$SOURCE_BIN" ]; then
    echo -e "${RED}Error: Binary '$BINARY_NAME' not found. Run build_mac.sh first.${NC}"
    echo "Searched:"
    for p in "${SEARCH_PATHS[@]}"; do echo "  $p"; done
    exit 1
fi
echo -e "  Binary   : $SOURCE_BIN"
echo -e "  Install  : $INSTALL_DIR/$BINARY_NAME"
echo ""

# ── Stop Existing Agent ───────────────────────────────────────────────────────
echo "[1/4] Stopping existing agent (if running)..."
launchctl bootout system "$PLIST_DEST" 2>/dev/null || \
    launchctl unload "$PLIST_DEST" 2>/dev/null || true

# ── Install Files ─────────────────────────────────────────────────────────────
echo "[2/4] Installing files..."
mkdir -p "$INSTALL_DIR"
mkdir -p "$LOG_DIR"

cp "$SOURCE_BIN" "$INSTALL_DIR/$BINARY_NAME"
chmod 750 "$INSTALL_DIR/$BINARY_NAME"
chown root:wheel "$INSTALL_DIR/$BINARY_NAME"

# Remove Gatekeeper quarantine
xattr -cr "$INSTALL_DIR/$BINARY_NAME" 2>/dev/null || true
echo "  ✓ Gatekeeper quarantine cleared"

# Install config
CONFIG_SOURCE=""
for cp_path in \
    "$SCRIPT_DIR/dist/osx-${ARCH_TAG}/config.json" \
    "$SCRIPT_DIR/config.json" \
    "$SCRIPT_DIR/dist_mac/config.json"; do
    if [ -f "$cp_path" ]; then CONFIG_SOURCE="$cp_path"; break; fi
done

if [ -n "$CONFIG_SOURCE" ]; then
    cp "$CONFIG_SOURCE" "$INSTALL_DIR/config.json"
    chmod 400 "$INSTALL_DIR/config.json"
    chown root:wheel "$INSTALL_DIR/config.json"
    echo "  ✓ config.json installed (read-only)"
fi

# Write config from CLI args
if [ -n "$API_KEY" ] && [ -n "$BACKEND_URL" ]; then
    chmod 600 "$INSTALL_DIR/config.json" 2>/dev/null || true
    cat > "$INSTALL_DIR/config.json" <<EOF
{
    "TenantApiKey": "$API_KEY",
    "BackendUrl": "$BACKEND_URL"
}
EOF
    chmod 400 "$INSTALL_DIR/config.json"
    chown root:wheel "$INSTALL_DIR/config.json"
    echo "  ✓ config.json written from CLI arguments"
fi

# Create data directories
mkdir -p "$INSTALL_DIR/data" "$INSTALL_DIR/data/logs" "$INSTALL_DIR/data/tmp"
chmod 700 "$INSTALL_DIR/data"
chown -R root:wheel "$INSTALL_DIR"

echo "  ✓ Files installed"

# ── Create LaunchDaemon Plist ─────────────────────────────────────────────────
echo "[3/4] Creating LaunchDaemon..."
cat > "$PLIST_DEST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>${PLIST_LABEL}</string>

    <key>ProgramArguments</key>
    <array>
        <string>${INSTALL_DIR}/${BINARY_NAME}</string>
    </array>

    <key>WorkingDirectory</key>
    <string>${INSTALL_DIR}</string>

    <!-- Run at system boot -->
    <key>RunAtLoad</key>
    <true/>

    <!-- Keep alive: restart if it exits -->
    <key>KeepAlive</key>
    <dict>
        <key>Crashed</key>
        <true/>
        <key>SuccessfulExit</key>
        <false/>
    </dict>

    <!-- Throttle restarts: wait 15s between attempts -->
    <key>ThrottleInterval</key>
    <integer>15</integer>

    <!-- Logs -->
    <key>StandardOutPath</key>
    <string>${LOG_DIR}/monitorix_agent.log</string>
    <key>StandardErrorPath</key>
    <string>${LOG_DIR}/monitorix_agent_error.log</string>

    <!-- Environment -->
    <key>EnvironmentVariables</key>
    <dict>
        <key>PYTHONWARNINGS</key>
        <string>ignore:pkg_resources</string>
        <key>PYTHONDONTWRITEBYTECODE</key>
        <string>1</string>
    </dict>

    <!-- Process priority -->
    <key>ProcessType</key>
    <string>Background</string>

    <!-- Nice value (lower = higher priority, 0 = normal) -->
    <key>Nice</key>
    <integer>-5</integer>
</dict>
</plist>
EOF

# Secure the plist — must be owned by root:wheel, mode 644
chown root:wheel "$PLIST_DEST"
chmod 644 "$PLIST_DEST"
echo "  ✓ LaunchDaemon plist created"

# ── Load & Start ──────────────────────────────────────────────────────────────
echo "[4/4] Loading LaunchDaemon..."

# Use bootstrap (macOS 10.15+) with launchctl fallback
if launchctl bootstrap system "$PLIST_DEST" 2>/dev/null; then
    echo "  ✓ Loaded via launchctl bootstrap"
else
    launchctl load -w "$PLIST_DEST"
    echo "  ✓ Loaded via launchctl load"
fi

sleep 2

# Check status
if launchctl list "$PLIST_LABEL" &>/dev/null 2>&1; then
    PID=$(launchctl list "$PLIST_LABEL" | awk 'NR==2 {print $1}')
    echo ""
    echo -e "${GREEN}✓ Monitorix Agent is running (PID: ${PID:-starting}).${NC}"
else
    echo -e "${YELLOW}⚠ Agent may still be starting. Check logs if issues persist.${NC}"
fi

echo ""
echo -e "${BLUE}Useful commands:${NC}"
echo "  launchctl list $PLIST_LABEL"
echo "  tail -f ${LOG_DIR}/monitorix_agent.log"
echo "  sudo launchctl bootout system $PLIST_DEST    # Stop"
echo "  sudo launchctl bootstrap system $PLIST_DEST  # Start"
