#!/bin/bash
# Synchronize Agent Version with Backend

AGENT_MAIN="src/main.py"
BACKEND_CONSTANTS="../backend/app/core/constants.py"
VERSION_INFO="version_info.txt"
WIN_INSTALLER="install_agent_windows.ps1"

if [ ! -f "$AGENT_MAIN" ]; then
    echo "Error: $AGENT_MAIN not found."
    exit 1
fi

if [ ! -f "$BACKEND_CONSTANTS" ]; then
    echo "Error: $BACKEND_CONSTANTS not found."
    exit 1
fi

# Extract version from main.py (e.g. "v1.8.63")
VERSION=$(grep "AGENT_VERSION =" "$AGENT_MAIN" | cut -d'"' -f2)

if [ -z "$VERSION" ]; then
    echo "Error: Could not extract AGENT_VERSION from $AGENT_MAIN."
    exit 1
fi

# Derive tuple form: "v1.8.63" -> "1, 8, 6, 3"
VERSION_CLEAN="${VERSION#v}"  # Strip leading 'v'
MAJOR=$(echo "$VERSION_CLEAN" | cut -d. -f1)
MINOR=$(echo "$VERSION_CLEAN" | cut -d. -f2)
PATCH=$(echo "$VERSION_CLEAN" | cut -d. -f3)
PATCH_A=$(echo "$PATCH" | cut -c1)
PATCH_B=$(echo "$PATCH" | cut -c2)
VERSION_TUPLE="${MAJOR}, ${MINOR}, ${PATCH_A}, ${PATCH_B}"

echo "Syncing Version: $VERSION (tuple: $VERSION_TUPLE) to Backend..."

# 1. Update backend constants.py
perl -i -pe "s/LATEST_AGENT_VERSION = os.getenv\(\"LATEST_AGENT_VERSION\", \".*?\"\)/LATEST_AGENT_VERSION = os.getenv(\"LATEST_AGENT_VERSION\", \"$VERSION\")/g" "$BACKEND_CONSTANTS"
echo "  ✓ Backend constants.py updated."

# 2. Update version_info.txt (Windows PE Metadata)
if [ -f "$VERSION_INFO" ]; then
    # Update tuple versions (filevers and prodvers)
    perl -i -pe "s/filevers=\(\d+, \d+, \d+, \d+\)/filevers=($VERSION_TUPLE)/g" "$VERSION_INFO"
    perl -i -pe "s/prodvers=\(\d+, \d+, \d+, \d+\)/prodvers=($VERSION_TUPLE)/g" "$VERSION_INFO"
    # Update string versions
    perl -i -pe "s/(FileVersion', u')[^']+/\${1}${VERSION_CLEAN}/g" "$VERSION_INFO"
    perl -i -pe "s/(ProductVersion', u')[^']+/\${1}${VERSION_CLEAN}/g" "$VERSION_INFO"
    echo "  ✓ version_info.txt updated."
fi

if [ -f "$WIN_INSTALLER" ]; then
    perl -i -pe "s/(Monitorix Agent )v[\d.]+( \([^)]+\))?( is now running)/\${1}${VERSION}\${3}/g" "$WIN_INSTALLER"
    # Ensure backend serves the updated version
    cp "$WIN_INSTALLER" ../backend/install_agent_windows.ps1
    echo "  ✓ install_agent_windows.ps1 updated and copied to backend."
fi

echo "✓ Backend updated successfully."
