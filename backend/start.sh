#!/bin/bash
set -e

# 1. Automatic Migrations (Required for new Production DB)
echo "Running Database Migrations..."
alembic upgrade head

# 2. Seed Initial Data (e.g. Admin User)
# "|| true" ensures server continues even if seed fails (e.g. duplicate user)
echo "Running Seed Script..."
python -m app.scripts.seed || true

# 3. Start Application
echo "Starting Uvicorn..."
uvicorn app.main:app --host 0.0.0.0 --port $PORT
