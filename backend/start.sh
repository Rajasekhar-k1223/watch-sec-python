#!/bin/bash
set -e

# Change to the directory of the script (ensure we are in /app or where files are)
cd "$(dirname "$0")"

echo "Current Directory: $(pwd)"
ls -la

# 1. Automatic Migrations (Self-Healing)
echo "Running Database Migrations..."
if ! alembic upgrade head; then
    echo "Migration Failed! Likely Ghost Migration detected."
    echo "Attempting Self-Healing (Resetting Database)..."
    python -m app.scripts.reset_db_force
    echo "Retrying Migrations..."
    alembic upgrade head
fi

# 2. Seed Initial Data (e.g. Admin User)
# "|| true" ensures server continues even if seed fails (e.g. duplicate user)
echo "Running Seed Script..."
python -m app.scripts.seed || true

# 3. Start Application
echo "Starting Uvicorn..."
uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}
