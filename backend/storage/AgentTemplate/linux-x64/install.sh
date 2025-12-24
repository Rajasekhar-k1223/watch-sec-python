#!/bin/bash
# WatchSec Agent Installer (Python)

echo "--- WatchSec Agent Installer ---"

# Detect OS
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    OS="linux"
elif [[ "$OSTYPE" == "darwin"* ]]; then
    OS="mac"
else
    echo "Unsupported OS: $OSTYPE"
    exit 1
fi

echo "Detected OS: $OS"

# 1. Check Python
if ! command -v python3 &> /dev/null; then
    echo "Error: Python 3 is required."
    exit 1
fi

# 2. Setup Venv
echo "Setting up virtual environment..."
python3 -m venv venv
source venv/bin/activate

# 3. Install Requirements
echo "Installing dependencies..."
pip install -r requirements.txt

# 4. Run Agent
# Ideally, setup a systemd service (Linux) or LaunchAgent (Mac)
echo "Starting Agent..."
nohup python3 src/main.py > agent.log 2>&1 &

echo "Agent installed and running (PID: $!)."
echo "Logs: agent.log"
