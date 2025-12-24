@echo off
echo --- WatchSec Agent Builder ---

rem Check for Python
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo Error: Python not found. Please install Python 3.10+ and add to PATH.
    echo Download: https://www.python.org/downloads/
    pause
    exit /b 1
)

echo Installing Requirements...
pip install -r requirements.txt
if %errorlevel% neq 0 (
    echo Error: Failed to install requirements.
    pause
    exit /b 1
)

echo Building EXE...
python build.py
if %errorlevel% neq 0 (
    echo Error: Build failed.
    pause
    exit /b 1
)

echo.
echo Build Successful!
echo Artifact: dist\watch-sec-agent.exe
echo.
echo [Action Required] Copying to Backend Storage...
copy /Y "dist\watch-sec-agent.exe" "..\backend\storage\AgentTemplate\win-x64\"

echo Done.
pause
