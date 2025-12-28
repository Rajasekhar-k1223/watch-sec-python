#!/bin/bash

# Define paths
BACKEND_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/backend" && pwd)"
VENV_DIR="$BACKEND_DIR/.venv"

echo "--- WatchSec Backend Launcher (Native) ---"

# Check Python3
if ! command -v python3 &> /dev/null; then
    echo "Error: Python3 not found."
    exit 1
fi

# Navigate to backend directory
cd "$BACKEND_DIR" || { echo "Error: backend directory not found at $BACKEND_DIR"; exit 1; }

# Create Virtual Environment if it doesn't exist
if [ ! -d "$VENV_DIR" ]; then
    echo "Creating virtual environment..."
    python3 -m venv "$VENV_DIR"
fi

# Activate Virtual Environment not strictly needed if we use direct paths, but good for shell
# source "$VENV_DIR/bin/activate"

echo "Installing Dependencies into virtual environment..."
"$VENV_DIR/bin/pip" install -r requirements.txt
if [ $? -ne 0 ]; then
    echo "Warning: Pip install failed. Trying to proceed anyway..."
fi

echo "Starting Server on Port 8000..."
echo "Connects to Railway Cloud DBs defined in .env"
echo ""

# Run uvicorn using the venv's python explicitly
"$VENV_DIR/bin/python" -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
