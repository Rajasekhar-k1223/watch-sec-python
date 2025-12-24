@echo off
echo --- WatchSec Backend Launcher (Native) ---

rem Check Python
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo Error: Python not found.
    pause
    exit /b 1
)

cd backend

echo Installing Dependencies...
pip install -r requirements.txt
if %errorlevel% neq 0 (
    echo Warning: Pip install failed. Trying to proceed anyway...
)

echo Starting Server on Port 8000...
echo Connects to Railway Cloud DBs defined in .env
echo.
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload

pause
