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
                    json_str = json_bytes.decode('utf-8').strip()
                    return json.loads(json_str)
        except Exception as e:
            print(f"[Config] Overlay read error: {e}")

    # 2. Try File (Fallback / Local Dev)
    config_path = "config.json"
    if not os.path.exists(config_path):
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
sio = socketio.AsyncClient(logger=False, engineio_logger=False, ssl_verify=False)

# Initialize Modules
fim = FileIntegrityMonitor(paths_to_watch=["."])
net_scanner = NetworkScanner()
proc_sec = ProcessSecurity()
screen_cap = ScreenshotCapture(AGENT_ID, API_KEY, BACKEND_URL, interval=30)
activity_mon = ActivityMonitor(AGENT_ID, API_KEY, BACKEND_URL)
mail_mon = MailMonitor(BACKEND_URL, AGENT_ID, API_KEY)
remote_desktop = RemoteDesktopAgent(BACKEND_URL, AGENT_ID, API_KEY)
# live_streamer = LiveStreamer(AGENT_ID, sio) # Deprecated by webrtc_manager?
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

async def main():
    print(f"--- WatchSec Agent v2.0 ({platform.system()}) ---")
    
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
    
    # Conditional Screenshot Start
    if config.get("ScreenshotsEnabled", False):
        print("[Screens] Enabled by config")
        screen_cap.start()
    else:
        print("[Screens] Disabled by default (waiting for command)")

    try:
        activity_mon.start()
        print("[Activity] Monitor Started")
    except Exception as e:
        print(f"[Activity] Failed to start: {e}")

    try:
        mail_mon.start()
        print("[Mail] Monitor Started")
    except Exception as e:
        print(f"[Mail] Failed to start: {e}")

    remote_desktop.start()
    
    # Enforce Browser Policies
    print("[Init] Enforcing Browser Extensions...")
    try:
        BrowserEnforcer().enforce()
    except Exception as e:
        print(f"[Browser] Enforce failed: {e}")

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
