#!/bin/bash
echo "Running Seed Script..."
python -m app.scripts.seed
echo "Starting Uvicorn..."
uvicorn app.main:app --host 0.0.0.0 --port $PORT
