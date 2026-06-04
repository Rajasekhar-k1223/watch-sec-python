#!/bin/bash
# ============================================================
# Monitorix Agent — Linux Installer
# Installs as a hardened systemd service (root)
# Supports: x64 (amd64) and arm64 (aarch64)
# Usage: sudo ./install_agent_linux.sh [--api-key KEY] [--backend-url URL]
# ============================================================
set -e

GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

INSTALL_DIR="/var/lib/monitorix"
SERVICE_NAME="monitorix-agent"
BINARY_NAME="monitorixagent"

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
echo -e "${BLUE}║   Monitorix Agent — Linux Installer              ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════╝${NC}"

# ── Root Check ────────────────────────────────────────────────────────────────
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Error: Run as root: sudo $0${NC}"
    exit 1
fi

# ── Architecture Detection ────────────────────────────────────────────────────
ARCH=$(uname -m)
if [[ "$ARCH" == "arm64" || "$ARCH" == "aarch64" ]]; then
    ARCH_TAG="arm64"
else
    ARCH_TAG="x64"
fi
echo -e "  Platform : Linux-${ARCH_TAG}"

# ── Locate Binary ─────────────────────────────────────────────────────────────
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# Search order: dist/linux-<arch>/, current dir, parent dirs
SOURCE_BIN=""
SEARCH_PATHS=(
    "$SCRIPT_DIR/dist/linux-${ARCH_TAG}/$BINARY_NAME"
    "$SCRIPT_DIR/$BINARY_NAME"
    "$SCRIPT_DIR/dist_linux/$BINARY_NAME"
    "$SCRIPT_DIR/dist_lin_v1/$BINARY_NAME"
)
for p in "${SEARCH_PATHS[@]}"; do
    if [ -f "$p" ]; then
        SOURCE_BIN="$p"
        break
    fi
done

if [ -z "$SOURCE_BIN" ]; then
    echo -e "${RED}Error: Binary '$BINARY_NAME' not found. Run build_linux.sh first.${NC}"
    echo "Searched:"
    for p in "${SEARCH_PATHS[@]}"; do echo "  $p"; done
    exit 1
fi
echo -e "  Binary   : $SOURCE_BIN"
echo -e "  Install  : $INSTALL_DIR/$BINARY_NAME"
echo ""

# ── Stop existing service ─────────────────────────────────────────────────────
echo "[1/4] Stopping existing service (if running)..."
systemctl stop "$SERVICE_NAME" 2>/dev/null || true
systemctl disable "$SERVICE_NAME" 2>/dev/null || true

# ── Install Files ─────────────────────────────────────────────────────────────
echo "[2/4] Installing files..."
mkdir -p "$INSTALL_DIR"
cp "$SOURCE_BIN" "$INSTALL_DIR/$BINARY_NAME"
chmod 750 "$INSTALL_DIR/$BINARY_NAME"
chown root:root "$INSTALL_DIR/$BINARY_NAME"

# Install config if provided or available
CONFIG_SOURCE=""
for cp in \
    "$SCRIPT_DIR/dist/linux-${ARCH_TAG}/config.json" \
    "$SCRIPT_DIR/config.json" \
    "$SCRIPT_DIR/dist_linux/config.json" ; do
    if [ -f "$cp" ]; then CONFIG_SOURCE="$cp"; break; fi
done

if [ -n "$CONFIG_SOURCE" ]; then
    cp "$CONFIG_SOURCE" "$INSTALL_DIR/config.json"
    chmod 400 "$INSTALL_DIR/config.json"
    echo "  ✓ config.json installed (read-only)"
fi

# Write config from CLI arguments if provided
if [ -n "$API_KEY" ] && [ -n "$BACKEND_URL" ]; then
    chmod 600 "$INSTALL_DIR/config.json" 2>/dev/null || true
    cat > "$INSTALL_DIR/config.json" <<EOF
{
    "TenantApiKey": "$API_KEY",
    "BackendUrl": "$BACKEND_URL"
}
EOF
    chmod 400 "$INSTALL_DIR/config.json"
    echo "  ✓ config.json written from CLI arguments"
fi

# Create data dirs
mkdir -p "$INSTALL_DIR/data" "$INSTALL_DIR/data/logs" "$INSTALL_DIR/data/tmp"
chmod 700 "$INSTALL_DIR/data"

echo "  ✓ Files installed"

# ── Create Systemd Service ────────────────────────────────────────────────────
echo "[3/4] Creating systemd service..."
cat > "/etc/systemd/system/${SERVICE_NAME}.service" <<EOF
[Unit]
Description=Monitorix Enterprise Security Agent
Documentation=https://monitorix.co.in
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=300
StartLimitBurst=5

[Service]
Type=simple
WorkingDirectory=${INSTALL_DIR}
ExecStart=${INSTALL_DIR}/${BINARY_NAME}
ExecReload=/bin/kill -HUP \$MAINPID

# Auto-Restart
Restart=on-failure
RestartSec=15
TimeoutStartSec=30

# Security Hardening
User=root
Group=root
UMask=0077
Environment=PYTHONWARNINGS=ignore:pkg_resources
Environment=PYTHONDONTWRITEBYTECODE=1

# Resource Limits
LimitNOFILE=65536
LimitNPROC=512

# Filesystem Hardening (keeps write access to install dir only)
ProtectSystem=strict
ReadWritePaths=${INSTALL_DIR}
PrivateTmp=true
NoNewPrivileges=false

[Install]
WantedBy=multi-user.target
EOF

echo "  ✓ systemd unit created"

# ── Enable & Start ────────────────────────────────────────────────────────────
echo "[4/4] Enabling and starting service..."
systemctl daemon-reload
systemctl enable "$SERVICE_NAME"
systemctl start "$SERVICE_NAME"

sleep 2
echo ""
if systemctl is-active --quiet "$SERVICE_NAME"; then
    echo -e "${GREEN}✓ Monitorix Agent is now running as a systemd service.${NC}"
    systemctl status "$SERVICE_NAME" --no-pager -l | head -20
else
    echo -e "${YELLOW}⚠ Service started but may not be active yet. Checking...${NC}"
    systemctl status "$SERVICE_NAME" --no-pager -l | head -30
fi

echo ""
echo -e "${BLUE}Useful commands:${NC}"
echo "  systemctl status $SERVICE_NAME"
echo "  journalctl -u $SERVICE_NAME -f"
echo "  systemctl stop $SERVICE_NAME"
echo "  tail -f $INSTALL_DIR/monitorix_service.log"
