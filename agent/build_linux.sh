#!/bin/bash
# Build standalone Linux binary for Monitorix Agent
# This binary will work without Python installed on the target system



echo "=== Monitorix Agent Linux Binary Build ==="
echo "Building standalone executable with PyInstaller..."

cd "$(dirname "$0")"

# [NEW] Sync version with backend
chmod +x sync_version.sh
./sync_version.sh

# Install build dependencies if needed
echo "[1/4] Installing build dependencies..."
#pip3 install -q -r requirements.txt

# Clean previous builds
echo "[2/4] Cleaning previous builds..."
rm -rf build_lin_v1 dist_lin_v1 __pycache__ *.spec

# Architecture Detection
ARCH=$(uname -m)
if [[ "$ARCH" == "arm64" || "$ARCH" == "aarch64" ]]; then
    AGENT_ARCH="arm64"
else
    AGENT_ARCH="x64"
fi
echo "Building for Architecture: ${AGENT_ARCH}"

# [3/4] Building binary with PyInstaller...
echo "[3/4] Building binary with PyInstaller..."
pyinstaller --clean --onefile \
    --workpath build_lin_v1 \
    --distpath dist_lin_v1 \
    --specpath build_lin_v1 \
    --name monitorix-agent-linux \
    --hidden-import=modules.activity_monitor \
    --hidden-import=modules.app_blocker \
    --hidden-import=modules.audit_logger \
    --hidden-import=modules.browser_enforcer \
    --hidden-import=modules.clipboard_monitor \
    --hidden-import=modules.data_queue \
    --hidden-import=modules.file_manager \
    --hidden-import=modules.file_monitor \
    --hidden-import=modules.fim \
    --hidden-import=modules.hardware \
    --hidden-import=modules.input_simulation \
    --hidden-import=modules.installer \
    --hidden-import=modules.keylogger \
    --hidden-import=modules.live_stream \
    --hidden-import=modules.location_monitor \
    --hidden-import=modules.mail_monitor \
    --hidden-import=modules.network \
    --hidden-import=modules.network_monitor \
    --hidden-import=modules.network_utils \
    --hidden-import=modules.power_monitor \
    --hidden-import=modules.printer_monitor \
    --hidden-import=modules.remote_shell \
    --hidden-import=modules.screenshots \
    --hidden-import=modules.security \
    --hidden-import=modules.shadow_monitor \
    --hidden-import=modules.speech_monitor \
    --hidden-import=modules.usb_control \
    --hidden-import=modules.usb_monitor \
    --hidden-import=modules.webrtc_stream \
    --hidden-import=modules.av_monitor \
    --hidden-import=agent_core.bandwidth_manager \
    --hidden-import=agent_core.remediation_handler \
    --hidden-import=agent_core.self_protection \
    --hidden-import=agent_core.session_monitor \
    --hidden-import=agent_core.utils \
    --hidden-import=agent_core.watchdog \
    --hidden-import=engineio.async_drivers.aiohttp \
    --hidden-import=cryptography.hazmat.backends.openssl.backend \
    --collect-all cryptography \
    --collect-all PIL \
    --collect-all watchdog \
    --collect-all aiortc \
    --collect-all av \
    --collect-all sounddevice \
    --hidden-import=pynput.keyboard._xorg \
    --hidden-import=pynput.keyboard._uinput \
    --hidden-import=pynput.mouse._xorg \
    --hidden-import=pynput.mouse._uinput \
    --exclude-module tkinter \
    --exclude-module PyQt5 \
    --exclude-module PyQt6 \
    --exclude-module PySide2 \
    --exclude-module PySide6 \
    --exclude-module matplotlib \
    --strip \
    --console \
    src/main.py

# Test the binary
echo "[4/4] Testing binary..."
if [ -f "dist_lin_v1/monitorix-agent-linux" ]; then
    chmod +x dist_lin_v1/monitorix-agent-linux
    SIZE=$(du -h dist_lin_v1/monitorix-agent-linux | cut -f1)
    echo "✓ Binary built successfully: $SIZE"
    echo "  Location: dist_lin_v1/monitorix-agent-linux"
    
    # Quick test
    timeout 2 dist_lin_v1/monitorix-agent-linux 2>&1 | head -n 5 || true
    
    echo ""
    echo "Next steps:"
    echo "1. Copy to backend: cp dist_lin_v1/monitorix-agent-linux ../backend/storage/AgentTemplate/linux-${AGENT_ARCH}/"
    echo "2. Remove .broken file: rm ../backend/storage/AgentTemplate/linux-${AGENT_ARCH}/monitorix-agent-linux.broken"
    echo "3. Restart backend: docker restart watch-sec-backend"
else
    echo "✗ Build failed - binary not found"
    exit 1
fi
