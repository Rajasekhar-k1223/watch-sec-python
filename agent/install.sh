#!/bin/bash
# [v2.6.0] Monitorix Enterprise Zero-Touch Provisioning (ZTP) Installer
# Usage: sudo ./install.sh --key <API_KEY> --url <BACKEND_URL> --cluster <CLUSTER_NAME>

set -e

echo "=========================================================="
echo "   Monitorix Enterprise Security - Autonomous Installer   "
echo "=========================================================="

# Default Values
API_KEY=""
BACKEND_URL=""
CLUSTER_NAME="Standalone"
INSTALL_DIR="/opt/monitorix-agent"

# Parse Arguments
while [[ "$#" -gt 0 ]]; do
    case $1 in
        --key) API_KEY="$2"; shift ;;
        --url) BACKEND_URL="$2"; shift ;;
        --cluster) CLUSTER_NAME="$2"; shift ;;
        *) echo "Unknown parameter: $1"; exit 1 ;;
    esac
    shift
done

if [ -z "$API_KEY" ] || [ -z "$BACKEND_URL" ]; then
    echo "Error: --key and --url are required."
    exit 1
fi

# 1. Environment Preparation
echo "[1/4] Preparing secure environment..."
mkdir -p "$INSTALL_DIR"
cp -r . "$INSTALL_DIR/"
cd "$INSTALL_DIR"

# 2. Setup Virtual Environment & Dependencies
echo "[2/4] Initializing Sovereign Runtime..."
python3 -m venv venv
./venv/bin/pip install --upgrade pip
./venv/bin/pip install -r requirements.txt

# 3. Provision Configuration
echo "[3/4] Provisioning Cluster Identity..."
cat <<EOF > config.json
{
    "TenantApiKey": "$API_KEY",
    "BackendUrl": "$BACKEND_URL",
    "ClusterName": "$CLUSTER_NAME",
    "AutoUpdateEnabled": true,
    "SovereignMode": true
}
EOF
chmod 600 config.json

# 4. System Service Registration (Linux systemd)
echo "[4/4] Registering Persistence Sentinel..."
if [ -d "/etc/systemd/system" ]; then
    cat <<EOF > /etc/systemd/system/monitorix.service
[Unit]
Description=Monitorix Enterprise Security Agent
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR
ExecStart=$INSTALL_DIR/venv/bin/python3 src/main.py
Restart=always
RestartSec=10
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable monitorix
    systemctl start monitorix
    echo "Monitorix service registered and started via systemd."
else
    echo "Warning: systemd not detected. Starting agent in background mode..."
    nohup ./venv/bin/python3 src/main.py > agent.log 2>&1 &
fi

echo "=========================================================="
echo "   INSTALLATION COMPLETE: Node is now protected.         "
echo "   Cluster: $CLUSTER_NAME                                "
echo "   Logs: tail -f $INSTALL_DIR/agent.log                  "
echo "=========================================================="
