#!/bin/bash
set -e

AGENT_DIR="/opt/apps/monitorix/watch-sec-python/agent"
cd $AGENT_DIR

echo "=== Monitorix Agent ARM64 Binary Build (Cross-Compilation) ==="

# 1. Ensure QEMU handlers are registered
echo "[1/4] Registering QEMU binfmt handlers..."
docker run --rm --privileged multiarch/qemu-user-static --reset -p yes > /dev/null

# 2. Build the Docker Image for ARM64
echo "[2/4] Building ARM64 build environment (this may take a while)..."
docker build --platform linux/arm64 -t monitorix-agent-arm64-builder -f Dockerfile.arm64 .

# 3. Extract the binary
echo "[3/4] Extracting ARM64 binary..."
CONTAINER_ID=$(docker create --platform linux/arm64 monitorix-agent-arm64-builder)
mkdir -p dist_arm64
docker cp $CONTAINER_ID:/app/dist/monitorix-agent-linux ./dist_arm64/monitorix-agent-linux-arm64
docker rm $CONTAINER_ID

# 4. Cleanup
echo "[4/4] Cleanup..."
docker image rm monitorix-agent-arm64-builder

echo "✓ ARM64 Binary built successfully: dist_arm64/monitorix-agent-linux-arm64"
ls -lh dist_arm64/monitorix-agent-linux-arm64
