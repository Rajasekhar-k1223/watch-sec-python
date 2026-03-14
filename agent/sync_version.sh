#!/bin/bash
# Synchronize Agent Version with Backend

AGENT_MAIN="src/main.py"
BACKEND_CONSTANTS="../backend/app/core/constants.py"

if [ ! -f "$AGENT_MAIN" ]; then
    echo "Error: $AGENT_MAIN not found."
    exit 1
fi

if [ ! -f "$BACKEND_CONSTANTS" ]; then
    echo "Error: $BACKEND_CONSTANTS not found."
    exit 1
fi

# Extract version from main.py
VERSION=$(grep "AGENT_VERSION =" "$AGENT_MAIN" | cut -d'"' -f2)

if [ -z "$VERSION" ]; then
    echo "Error: Could not extract AGENT_VERSION from $AGENT_MAIN."
    exit 1
fi

echo "Syncing Version: $VERSION to Backend..."

# Update backend constants.py
# Using perl for robust cross-platform in-place replacement
perl -i -pe "s/LATEST_AGENT_VERSION = os.getenv\(\"LATEST_AGENT_VERSION\", \".*?\"\)/LATEST_AGENT_VERSION = os.getenv(\"LATEST_AGENT_VERSION\", \"$VERSION\")/g" "$BACKEND_CONSTANTS"

echo "✓ Backend updated successfully."
