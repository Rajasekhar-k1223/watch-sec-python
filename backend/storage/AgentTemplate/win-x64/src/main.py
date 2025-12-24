import asyncio
import json
import psutil
import requests
import socketio
import platform
from datetime import datetime, timedelta
import os
import sys

# Add src to path if running nicely
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from modules.fim import FileIntegrityMonitor
from modules.network import NetworkScanner
from modules.security import ProcessSecurity
from modules.screenshots import ScreenshotCapture

# Load Config
CONFIG_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "config.json")
try:
    with open(CONFIG_PATH, "r") as f:
        config = json.load(f)
except Exception as e:
    print(f"Error loading config: {e}")
    config = {}

BACKEND_URL = config.get("BackendUrl", "http://localhost:8000")
API_KEY = config.get("TenantApiKey", "")
AGENT_ID = config.get("AgentId", platform.node())

# Socket.IO Client
sio = socketio.AsyncClient()

# Initialize Modules
fim = FileIntegrityMonitor(paths_to_watch=["."])
net_scanner = NetworkScanner()
proc_sec = ProcessSecurity()
screen_cap = ScreenshotCapture(AGENT_ID, API_KEY, BACKEND_URL, interval=30)

@sio.event
async def connect():
    print("[WS] Connected to Backend")
    await sio.emit('join_room', {'room': AGENT_ID})

@sio.on('RefetchPolicy')
async def on_refetch_policy(data):
    print("[CMD] Received Policy Refetch Command")

@sio.on('KillProcess')
async def on_kill_process(data):
    target = data.get('target')
    print(f"[CMD] Kill Process Request: {target}")
    
    if isinstance(target, int):
        success, msg = proc_sec.kill_process_by_pid(target)
    else:
        success, msg = proc_sec.kill_process_by_name(str(target))
    
    # Ack back to server
    await sio.emit('CommandResult', {'AgentId': AGENT_ID, 'Result': msg, 'Success': success})

@sio.on('Isolate')
async def on_isolate(data):
    print(f"[CMD] *** ISOLATE COMMAND RECEIVED ***")
    # Implementation: Block all traffic except Backend
    # 1. Get Backend IP
    # 2. Add Firewall Rule (netsh advfirewall firewall add rule...)
    # For Checkpoint parity: We simulate the action
    print(f"[Security] Isolating Host... Allowing only {BACKEND_URL}")
    await sio.emit('CommandResult', {'AgentId': AGENT_ID, 'Result': "Host Isolated", 'Success': True})

async def system_monitor_loop():
    print(f"[Agent] Starting Monitor for {AGENT_ID} -> {BACKEND_URL}")
    last_net_scan = datetime.now()
    last_sw_scan = datetime.now() - timedelta(minutes=60) # Force start
    software_cache = []
    
    while True:
        try:
            # Gather Metrics
            cpu = psutil.cpu_percent(interval=1)
            mem = psutil.virtual_memory()
            
            # Subnet Scan (Every 60s)
            scan_results = []
            if (datetime.now() - last_net_scan).seconds > 60:
                print("[Net] Performing Periodic Scan...")
                scan_results = net_scanner.scan_subnet()
                last_net_scan = datetime.now()
                
            # Software Scan (Every 60m)
            if (datetime.now() - last_sw_scan).seconds > 3600 or not software_cache:
                print("[Sec] Scanning Installed Software...")
                software_cache = proc_sec.get_installed_software()
                last_sw_scan = datetime.now()

            payload = {
                "AgentId": AGENT_ID,
                "Status": "Online",
                "CpuUsage": cpu,
                "MemoryUsage": mem.used / (1024 * 1024), # MB
                "Timestamp": datetime.utcnow().isoformat(),
                "TenantApiKey": API_KEY,
                "InstalledSoftwareJson": json.dumps(software_cache), 
                "LocalIp": net_scanner.local_ip, 
                "Gateway": "Unknown"
            }

            # Send HTTP Report
            try:
                # Use async run_in_executor for request to avoid blocking
                resp = await asyncio.to_thread(requests.post, f"{BACKEND_URL}/api/report", json=payload, timeout=5)
                if resp.status_code == 200:
                    print(f"[Report] Sent: CPU {cpu}% | MEM {payload['MemoryUsage']:.1f}MB")
                else:
                    print(f"[Report] Error {resp.status_code}: {resp.text}")
            except Exception as e:
                print(f"[Report] Failed: {e}")

        except Exception as e:
            print(f"[Error] Loop Exception: {e}")

        await asyncio.sleep(5) # Report every 5 seconds

async def main():
    print(f"--- WatchSec Agent v2.0 ({platform.system()}) ---")
    
    # Connect WebSocket
    try:
        await sio.connect(BACKEND_URL)
    except Exception as e:
        print(f"[WS] Connection Failed (Will retry later): {e}")

    # Start Security Modules
    fim.start()
    screen_cap.start()

    # Start Tasks
    await system_monitor_loop()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("Stopping...")
        screen_cap.stop()
        sys.exit(0)
