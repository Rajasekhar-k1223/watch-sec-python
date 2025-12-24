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
3.  Access API: `http://localhost:8000/docs`
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
