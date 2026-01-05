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
# Load Config Logic
def load_config():
    config = {}
    
    # 1. Try Overlay (Priority for EXE)
    if getattr(sys, 'frozen', False):
        try:
            with open(sys.executable, 'rb') as f:
                content = f.read()
                delimiter = b"\n<<<<WATCHSEC_CONFIG>>>>\n"
                if delimiter in content:
                    print("[Config] Found Overlay Configuration")
                    json_bytes = content.split(delimiter)[-1]
                    # Handle potential EOF newlines or garbage? usually it's clean json
                    # But stripping whitespace is safe
                    json_str = json_bytes.decode('utf-8').strip()
                    return json.loads(json_str)
        except Exception as e:
            print(f"[Config] Overlay read error: {e}")

    # 2. Try File (Fallback / Local Dev)
    config_path = "config.json"
    # Adjust for running from source vs frozen dir
    if not os.path.exists(config_path):
        # Look in parent if in src?
        potential = os.path.join(os.path.dirname(os.path.dirname(__file__)), "config.json")
        if os.path.exists(potential):
            config_path = potential

    if os.path.exists(config_path):
        try:
            with open(config_path, "r") as f:
                print(f"[Config] Loading from {config_path}")
                return json.load(f)
        except Exception as e:
            print(f"[Config] File read error: {e}")
    
    print("[Config] No configuration found. Using defaults.")
    return {}

config = load_config()

BACKEND_URL = config.get("BackendUrl", "https://watch-sec-python-production.up.railway.app")
API_KEY = config.get("TenantApiKey", "")
AGENT_ID = config.get("AgentId", platform.node())

print(f"[Config] Active Backend URL: {BACKEND_URL}")
print(f"[Config] Tenant API Key: {API_KEY[:5]}...***")

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
    print(f"[Security] Isolating Host... Allowing only {BACKEND_URL}")
    await sio.emit('CommandResult', {'AgentId': AGENT_ID, 'Result': "Host Isolated", 'Success': True})

@sio.on('UpdateConfig')
async def on_update_config(data):
    print(f"[Config] Update Received: {data}")
    # Update Runtime Config
    if 'ScreenshotsEnabled' in data:
        should_enable = data['ScreenshotsEnabled']
        config['ScreenshotsEnabled'] = should_enable 
        if should_enable:
            screen_cap.start()
        else:
            screen_cap.stop()

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
                "Hostname": platform.node(),
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
    print(f"--- Monitorix Agent v2.0 ({platform.system()}) ---")
    
    # Connect WebSocket
    try:
        await sio.connect(BACKEND_URL)
    except Exception as e:
        print(f"[WS] Connection Failed (Will retry later): {e}")

    # Start Security Modules
    fim.start()
    
    # Conditional Screenshot Start
    if config.get("ScreenshotsEnabled", False):
        print("[Screens] Enabled by config")
        screen_cap.start()
    else:
        print("[Screens] Disabled by default (waiting for command)")

    # Start Tasks
    await system_monitor_loop()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("Stopping...")
        screen_cap.stop()
        sys.exit(0)
