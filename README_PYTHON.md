# WatchSec: Python Edition (Final)

This repository contains the fully ported **WatchSec** security platform, migrated from C# to Python.

## Project Structure
- `backend/`: FastAPI Backend (Port 8000).
- `agent/`: Python Agent (Source + Builder).
- `docker-compose.yml`: Orchestration for Backend, MySQL, Mongo.

## Prerequisites
- [Docker Desktop](https://www.docker.com/products/docker-desktop)
- [Python 3.10+](https://www.python.org/)

## Quick Start (Backend)
1.  Open Terminal in `watch-sec-python`.
2.  Run:
    ```powershell
    docker-compose up --build
    ```
3.  Access API: `https://api.monitorix.co.in/docs`
4.  Admin Login: `admin` / `admin` (or `admin123`)

## Quick Start (Agent)
To deploy the agent, you must first build the executable.

1.  Open Terminal in `watch-sec-python/agent`.
2.  Run `build_agent.bat` (Windows).
    - This will install dependencies (`mss`, `pyinstaller`).
    - Build `watch-sec-agent.exe`.
    - Automatically copy it to the Backend's `storage` folder.
3.  Now, download the agent from the Frontend ("Downloads" page).

## Features
- **Real-time Monitoring**: CPU, RAM, Network (Socket.IO).
- **Security**: File Integrity Monitor (FIM), Process Killer.
- **Visuals**: Screenshots, Remote Desktop (via Image Uploads).
- **Admin**: Tenant/User Management, Audits, Policies.

## Notes
- The default `seed.py` creates a "Default Tenant" and "admin" user.
- If you need to reset the DB, delete `docker-compose` volumes or run `docker-compose down -v`.

## Deployment

### Backend Deployment
1.  **Backend Host**: ensure your backend is running at `https://api.monitorix.co.in` or your own server.
2.  **Environment Variables**:
    - `DATABASE_URL`: Your MySQL Connection String (e.g. Railway or Local)
    - `APP_BACKEND_URL`: `https://api.monitorix.co.in`

### Agent Connection
1.  **Backend URL**: The agent connects to `https://api.monitorix.co.in`.
2.  **Update Config**:
    - Update `agent/config.json` locally or use the installer to auto-configure.
    ```json
    "BackendUrl": "https://api.monitorix.co.in"
    ```
3.  Rebuild/Run the agent.

### Data Migration
To sync your offline SQLite data to Production:
1.  Ensure `watch-sec.db` is present locally.
2.  Set `DATABASE_URL` env var to your Production URL.
3.  Run `python backend/app/scripts/sync_db.py`.
