#!/bin/bash
# ============================================================
# Monitorix Agent — Linux Binary Build Script
# Produces a standalone binary (no Python required on target)
# Supports: x64 (amd64) and arm64 (aarch64)
# ============================================================
set -e

GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${BLUE}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║   Monitorix Agent — Linux Binary Build           ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════╝${NC}"

cd "$(dirname "$0")"

# ── Architecture Detection ────────────────────────────────────────────────────
ARCH=$(uname -m)
if [[ "$ARCH" == "arm64" || "$ARCH" == "aarch64" ]]; then
    ARCH_TAG="arm64"
else
    ARCH_TAG="x64"
fi
echo -e "  Platform : Linux-${ARCH_TAG}"

BINARY_NAME="monitorixagent"
DIST_DIR="dist/linux-${ARCH_TAG}"
BUILD_DIR="build/linux-${ARCH_TAG}"
TEMPLATE_DIR="../backend/storage/AgentTemplate/linux-${ARCH_TAG}"

echo -e "  Output   : ${DIST_DIR}/${BINARY_NAME}"
echo -e "  Template : ${TEMPLATE_DIR}/"
echo ""

# ── Step 1: Sync version ──────────────────────────────────────────────────────
if [ -f "sync_version.sh" ]; then
    echo "[1/4] Syncing version with backend..."
    chmod +x sync_version.sh
    ./sync_version.sh 2>/dev/null || echo "  (version sync skipped)"
else
    echo "[1/4] Skipping version sync (sync_version.sh not found)"
fi

# ── Step 2: Install build dependencies ───────────────────────────────────────
echo "[2/4] Checking build dependencies..."
python3 -m pip install -q pyinstaller>=6.3 2>/dev/null || pip3 install -q pyinstaller>=6.3 2>/dev/null || true

# ── Step 3: Clean ─────────────────────────────────────────────────────────────
echo "[3/4] Cleaning previous builds..."
rm -rf "$BUILD_DIR" "$DIST_DIR" build_staging *.spec 2>/dev/null || true

# ── Step 4: PyInstaller Build ─────────────────────────────────────────────────
echo "[4/4] Running PyInstaller..."
echo ""

# Auto-discover all module hidden imports
HIDDEN_IMPORTS=""
if [ -d "src/modules" ]; then
    for f in src/modules/*.py; do
        mod=$(basename "$f" .py)
        [ "$mod" = "__init__" ] && continue
        HIDDEN_IMPORTS="$HIDDEN_IMPORTS --hidden-import=modules.${mod}"
    done
fi
if [ -d "src/agent_core" ]; then
    for f in src/agent_core/*.py; do
        mod=$(basename "$f" .py)
        [ "$mod" = "__init__" ] && continue
        HIDDEN_IMPORTS="$HIDDEN_IMPORTS --hidden-import=agent_core.${mod}"
    done
fi

# Run PyInstaller
pyinstaller --clean --onefile \
    --workpath "$BUILD_DIR" \
    --distpath "$DIST_DIR" \
    --specpath "$BUILD_DIR" \
    --name "$BINARY_NAME" \
    \
    --hidden-import=cryptography \
    --hidden-import=cryptography.hazmat.backends.openssl.backend \
    --collect-all=cryptography \
    --hidden-import=socketio \
    --hidden-import=engineio \
    --hidden-import=engineio.client \
    --hidden-import=engineio.async_drivers \
    --hidden-import=engineio.async_drivers.aiohttp \
    --hidden-import=aiohttp \
    --hidden-import=psutil \
    --collect-all=psutil \
    --hidden-import=PIL \
    --hidden-import=PIL.Image \
    --collect-all=PIL \
    --hidden-import=mss \
    --hidden-import=requests \
    --hidden-import=urllib3 \
    \
    --hidden-import=aiortc \
    --collect-all=aiortc \
    --hidden-import=av \
    --collect-all=av \
    --hidden-import=sounddevice \
    --collect-all=sounddevice \
    --hidden-import=numpy \
    --hidden-import=wave \
    \
    --hidden-import=pyperclip \
    --hidden-import=pynput \
    --collect-all=pynput \
    --hidden-import=pynput.keyboard._xorg \
    --hidden-import=pynput.keyboard._uinput \
    --hidden-import=pynput.mouse._xorg \
    --hidden-import=pynput.mouse._uinput \
    --hidden-import=evdev \
    --hidden-import=Xlib \
    --hidden-import=Xlib.display \
    \
    --hidden-import=sqlite3 \
    --hidden-import=_sqlite3 \
    --collect-all=sqlite3 \
    --hidden-import=keyring \
    \
    --hidden-import=jaraco.text \
    --hidden-import=jaraco.classes \
    --hidden-import=jaraco.functools \
    --hidden-import=jaraco.context \
    --hidden-import=platformdirs \
    \
    --exclude-module=tkinter \
    --exclude-module=tcl \
    --exclude-module=PyQt5 \
    --exclude-module=PyQt6 \
    --exclude-module=PySide2 \
    --exclude-module=PySide6 \
    --exclude-module=matplotlib \
    --exclude-module=scipy \
    --exclude-module=pandas \
    --exclude-module=win32api \
    --exclude-module=win32con \
    --exclude-module=pythoncom \
    --exclude-module=wmi \
    --exclude-module=AppKit \
    --exclude-module=Quartz \
    \
    --strip \
    --console \
    $HIDDEN_IMPORTS \
    src/main.py

# ── Post-Build ────────────────────────────────────────────────────────────────
echo ""
if [ -f "${DIST_DIR}/${BINARY_NAME}" ]; then
    chmod +x "${DIST_DIR}/${BINARY_NAME}"
    SIZE=$(du -h "${DIST_DIR}/${BINARY_NAME}" | cut -f1)
    echo -e "${GREEN}✓ Build successful: ${DIST_DIR}/${BINARY_NAME} (${SIZE})${NC}"

    # Copy config.json
    if [ -f "config.json" ]; then
        cp "config.json" "${DIST_DIR}/config.json"
        echo "  ✓ config.json copied"
    fi

    # Deploy to AgentTemplate
    if [ -d "$(dirname "${TEMPLATE_DIR}")" ]; then
        mkdir -p "${TEMPLATE_DIR}"
        cp "${DIST_DIR}/${BINARY_NAME}" "${TEMPLATE_DIR}/${BINARY_NAME}"
        chmod +x "${TEMPLATE_DIR}/${BINARY_NAME}"
        echo -e "  ${GREEN}✓ Deployed to AgentTemplate: ${TEMPLATE_DIR}/${BINARY_NAME}${NC}"
        
        # Quick smoke test
        echo ""
        echo "Running quick smoke test (2s)..."
        timeout 2 "${DIST_DIR}/${BINARY_NAME}" 2>&1 | head -n 8 || true
    else
        echo -e "  ${YELLOW}Note: AgentTemplate path not found, skipping deploy.${NC}"
        echo -e "  Manually copy: cp ${DIST_DIR}/${BINARY_NAME} ${TEMPLATE_DIR}/"
    fi

    echo ""
    echo -e "${BLUE}Next steps:${NC}"
    echo "  sudo cp ${DIST_DIR}/${BINARY_NAME} /var/lib/monitorix/"
    echo "  sudo ./install_agent_linux.sh"
else
    echo -e "${RED}✗ Build FAILED — binary not found at ${DIST_DIR}/${BINARY_NAME}${NC}"
    exit 1
fi
