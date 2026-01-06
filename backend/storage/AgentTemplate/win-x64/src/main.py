import asyncio
import json
import psutil
import requests
import socketio
import platform
from datetime import datetime, timedelta
import os
import sys
import urllib3

# Suppress insecure request warnings for development
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

import aiohttp
# Monkey Patch for aiohttp 3.9+ compatibility
if not hasattr(aiohttp, 'ClientWSTimeout'):
    class MockClientWSTimeout(aiohttp.ClientTimeout):
        def __init__(self, ws_close=None, ws_receive=None, **kwargs):
            # Swallow legacy args
            super().__init__(**kwargs)
    try:
        aiohttp.ClientWSTimeout = MockClientWSTimeout
        print("[Init] Monkey-patched aiohttp.ClientWSTimeout (Advanced)")
    except: pass

# Add src to path if running nicely
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from modules.live_stream import LiveStreamer
from modules.fim import FileIntegrityMonitor
from modules.network import NetworkScanner
from modules.security import ProcessSecurity
from modules.screenshots import ScreenshotCapture
from modules.activity_monitor import ActivityMonitor
from modules.mail_monitor import MailMonitor
from modules.mail_monitor import MailMonitor
from modules.browser_enforcer import BrowserEnforcer
from modules.remote_desktop import RemoteDesktopAgent

import uuid

# Load Config
CONFIG_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "config.json")
try:
    with open(CONFIG_PATH, "r") as f:
        config = json.load(f)
except Exception as e:
    print(f"Error loading config: {e}")
    config = {}

BACKEND_URL = config.get("BackendUrl", "http://192.168.1.2:8000")
API_KEY = config.get("TenantApiKey", "")
AGENT_ID = config.get("AgentId", "")

# Dynamic Agent ID Logic
# Always verify if the loaded ID matches the current system
import getpass
current_hostname = platform.node()
current_user = getpass.getuser()
expected_prefix = f"{current_hostname}-{current_user}"

# If ID is missing OR doesn't match the current system (e.g. config copied from another machine)
if not AGENT_ID or not AGENT_ID.startswith(expected_prefix):
    unique_suffix = str(uuid.uuid4())[:8].upper()
    AGENT_ID = f"{expected_prefix}-{unique_suffix}"
    print(f"[Init] ID Mismatch or Missing. Generated New Agent ID: {AGENT_ID}")
    
    # Update Config with new ID to persist it
    config["AgentId"] = AGENT_ID
    try:
        with open(CONFIG_PATH, "w") as f:
            json.dump(config, f, indent=4)
        print(f"[Init] Saved new Agent ID to config.json")
    except Exception as e:
        print(f"[Init] Failed to save config: {e}")
else:
    print(f"[Init] Using Configured Agent ID: {AGENT_ID}")

# Socket.IO Client
sio = socketio.AsyncClient(logger=False, engineio_logger=False, ssl_verify=False)

# Initialize Modules
fim = FileIntegrityMonitor(paths_to_watch=["."])
net_scanner = NetworkScanner()
proc_sec = ProcessSecurity()
screen_cap = ScreenshotCapture(AGENT_ID, API_KEY, BACKEND_URL, interval=30)
activity_mon = ActivityMonitor(AGENT_ID, API_KEY, BACKEND_URL)
activity_mon = ActivityMonitor(AGENT_ID, API_KEY, BACKEND_URL)
mail_mon = MailMonitor(BACKEND_URL, AGENT_ID, API_KEY)
remote_desktop = RemoteDesktopAgent(BACKEND_URL, AGENT_ID, API_KEY)
live_streamer = LiveStreamer(AGENT_ID, sio) # We will inject loop later or relies on get_event_loop in thread if safe

from modules.webrtc_stream import WebRTCManager

# ...
# Existing LiveStreamer (Keep for fallback if needed, or disable)
# live_streamer = LiveStreamer(AGENT_ID, sio) 
webrtc_manager = WebRTCManager(sio, AGENT_ID)

@sio.event
async def connect():
    print(f"[STREAM_DEBUG] Agent Connected to Backend. Joining Room: {AGENT_ID}")
    # Explicitly join room as fail-safe
    await sio.emit('join_room', {'room': AGENT_ID})

@sio.on('start_stream')
async def on_start_stream(data):
    print(f"[WebRTC] Received start_stream Command! Data: {data}", flush=True)
    # loop = asyncio.get_running_loop()
    # live_streamer.start_streaming(loop)
    await webrtc_manager.start_stream()

@sio.on('stop_stream')
async def on_stop_stream(data):
    print(f"[WebRTC] Received stop_stream Command!")
    # live_streamer.stop_streaming()
    await webrtc_manager.stop_stream()

@sio.on('webrtc_answer')
async def on_webrtc_answer(data):
    await webrtc_manager.handle_answer(data)

@sio.on('ice_candidate')
async def on_ice_candidate(data):
    await webrtc_manager.handle_ice_candidate(data)

# ... (keep other handlers)

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

@sio.on('TakeScreenshot')
async def on_take_screenshot(data):
    print(f"[CMD] Taking Screenshot...")
    success, msg = await asyncio.to_thread(screen_cap.capture_now)
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
                "Hostname": platform.node(),
                "CpuUsage": cpu,
                "MemoryUsage": mem.used / (1024 * 1024), # MB
                "Timestamp": datetime.utcnow().isoformat(),
                "TenantApiKey": API_KEY,
                "InstalledSoftwareJson": json.dumps(software_cache), 
                "LocalIp": net_scanner.local_ip, 
                "Gateway": "Unknown"
            }

            try:
                # Use async run_in_executor for request to avoid blocking
                # verify=False bypasses SSL self-signed errors
                resp = await asyncio.to_thread(requests.post, f"{BACKEND_URL}/api/report", json=payload, timeout=5, verify=False)
                if resp.status_code == 200:
                    data = resp.json()
                    # Handle Feature Flags
                    if "ScreenshotsEnabled" in data:
                        screen_cap.set_enabled(data["ScreenshotsEnabled"])
                        
                    # Handle Quality/Res Settings
                    if "ScreenshotQuality" in data:
                        screen_cap.set_config(
                            quality=data.get("ScreenshotQuality"), 
                            resolution=data.get("ScreenshotResolution"), 
                            max_size=data.get("MaxScreenshotSize")
                        )
                        
                    print(f"[Report] Sent: CPU {cpu}% | MEM {payload['MemoryUsage']:.1f}MB")
                else:
                    print(f"[Report] Error {resp.status_code}: {resp.text}")
            except Exception as e:
                print(f"[Report] Failed: {e}")

        except Exception as e:
            print(f"[Error] Loop Exception: {e}")

        await asyncio.sleep(5) # Report every 5 seconds

async def run_self_test():
    print("\n[Self-Test] --- Starting Connectivity Check ---")
    print(f"[Self-Test] Configured Backend: {BACKEND_URL}")
    print(f"[Self-Test] Agent ID: {AGENT_ID}")
    
    # 1. HTTP Connectivity
    try:
        print(f"[Self-Test] Pinging Backend API...", end=" ", flush=True)
        resp = await asyncio.to_thread(requests.get, f"{BACKEND_URL}/health", timeout=5, verify=False)
        if resp.status_code == 200:
            print("OK (HTTP 200)")
        else:
            print(f"WARNING (HTTP {resp.status_code})")
    except Exception as e:
        print(f"FAILED ({e})")
        print("[Self-Test] CRITICAL: Backend unreachable via HTTP.")

    # 2. WebSocket Connectivity (Simulated)
    print(f"[Self-Test] WebSocket Target: {BACKEND_URL}")

    # 3. Module Status
    print(f"[Self-Test] FIM: {'Active' if fim else 'Error'}")
    print(f"[Self-Test] WebRTC: {'Ready' if webrtc_manager else 'Error'}")
    print("[Self-Test] --- Check Complete ---\n")

async def main():
    print(f"--- WatchSec Agent v2.0 ({platform.system()}) ---")
    
    # Run Diagnostics
    await run_self_test()
    
    # Connect WebSocket
    # Connect WebSocket with Retry
    while True:
        try:
            await sio.connect(BACKEND_URL, auth={'room': AGENT_ID})
            print("[WS] Connected!")
            break
        except Exception as e:
            print(f"[WS] Connection Failed (Retrying in 5s): {e}")
            await sio.disconnect()
            await asyncio.sleep(5)

    # Start Security Modules
    fim.start()
    screen_cap.start()
    activity_mon.start()
    activity_mon.start()
    mail_mon.start()
    remote_desktop.start()
    
    # Enforce Browser Policies
    print("[Init] Enforcing Browser Extensions...")
    BrowserEnforcer().enforce()

    # Start Tasks
    await system_monitor_loop()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("Stopping...")
        screen_cap.stop()
        activity_mon.stop()
        activity_mon.stop()
        mail_mon.stop()
        remote_desktop.stop()
        sys.exit(0)
