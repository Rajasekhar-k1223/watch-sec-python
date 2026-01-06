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
import warnings

# Suppress insecure request warnings & pkg_resources deprecation
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings("ignore", category=UserWarning, module='pkg_resources')

import aiohttp
# Monkey Patch for aiohttp 3.9+ compatibility
if not hasattr(aiohttp, 'ClientWSTimeout'):
    class MockClientWSTimeout(aiohttp.ClientTimeout):
        def __init__(self, ws_close=None, ws_receive=None, **kwargs):
            super().__init__(**kwargs)
    try:
        aiohttp.ClientWSTimeout = MockClientWSTimeout
        print("[Init] Monkey-patched aiohttp.ClientWSTimeout (Advanced)")
    except: pass

# Add src to path if running nicely
if getattr(sys, 'frozen', False):
    BASE_DIR = os.path.dirname(sys.executable)
else:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    sys.path.append(BASE_DIR)

# --- Import Modules ---
from modules.live_stream import LiveStreamer
from modules.fim import FileIntegrityMonitor
from modules.network import NetworkScanner
from modules.security import ProcessSecurity
from modules.screenshots import ScreenshotCapture
from modules.activity_monitor import ActivityMonitor
from modules.mail_monitor import MailMonitor
from modules.browser_enforcer import BrowserEnforcer
from modules.remote_desktop import RemoteDesktopAgent
from modules.webrtc_stream import WebRTCManager

import uuid
import getpass

# --- Configuration Loading ---
CONFIG_PATH = os.path.join(BASE_DIR, "config.json")
try:
    with open(CONFIG_PATH, "r") as f:
        config = json.load(f)
except Exception as e:
    print(f"Error loading config: {e}")
    config = {}

# Backend Configuration (User Defined Production URL)
BACKEND_URL = config.get("BackendUrl", "https://watch-sec-python-production.up.railway.app")
API_KEY = config.get("TenantApiKey", "")
AGENT_ID = config.get("AgentId", "")

# --- Dynamic Agent ID Logic ---
current_hostname = platform.node()
current_user = getpass.getuser()
expected_prefix = f"{current_hostname}-{current_user}"

print(f"[Init] Expected Agent ID Prefix: {expected_prefix}")
print(f"[Init] Loaded Agent ID: {AGENT_ID}")

# If ID is missing OR doesn't match the current system (e.g. config copied from another machine)
if not AGENT_ID or not AGENT_ID.startswith(expected_prefix):
    unique_suffix = str(uuid.uuid4())[:8].upper()
    AGENT_ID = f"{expected_prefix}-{unique_suffix}"
    print(f"[Init] ID Mismatch or Missing. Generated New Agent ID: {AGENT_ID}")
    
    # Update Config with new ID to persist it
    config["AgentId"] = AGENT_ID
    try:
        # Write Config
        with open(CONFIG_PATH, "w") as f:
            json.dump(config, f, indent=4)
        
        # Re-apply Hidden Attribute (Windows Security)
        if platform.system() == "Windows":
             import ctypes
             FILE_ATTRIBUTE_HIDDEN = 0x02
             ctypes.windll.kernel32.SetFileAttributesW(str(CONFIG_PATH), FILE_ATTRIBUTE_HIDDEN)

        print(f"[Init] Saved new Agent ID to config.json (Secure)")
    except Exception as e:
        print(f"[Init] Failed to save config: {e}")
else:
    print(f"[Init] Using Configured Agent ID: {AGENT_ID}")

# --- Socket.IO Client ---
sio = socketio.AsyncClient(logger=False, engineio_logger=False, ssl_verify=False)

# --- Remote Commands Handlers ---

@sio.on('uninstall')
async def on_uninstall(data):
    print("[Command] Received Remote Uninstall/Stop...")
    try:
        # 1. Remove Persistence (Scheduled Task)
        if platform.system() == "Windows":
             import subprocess
             print("[Uninstall] Removing Scheduled Task...")
             subprocess.run(["schtasks", "/Delete", "/TN", "MonitorixAgent", "/F"], capture_output=True)
        
        # 2. Stop Modules (Best Effort)
        try:
            screen_cap.stop()
            activity_mon.stop()
            mail_mon.stop()
            remote_desktop.stop()
        except: pass
        
        # 3. Exit
        print("[Command] Agent Stopping Permanently. Goodbye.")
        os._exit(0) # Force exit
    except Exception as e:
        print(f"[Command] Uninstall Failed: {e}")

# --- Initialize Modules ---
fim = FileIntegrityMonitor(paths_to_watch=["."])
net_scanner = NetworkScanner()
proc_sec = ProcessSecurity()
screen_cap = ScreenshotCapture(AGENT_ID, API_KEY, BACKEND_URL, interval=30)
activity_mon = ActivityMonitor(AGENT_ID, API_KEY, BACKEND_URL)
mail_mon = MailMonitor(BACKEND_URL, AGENT_ID, API_KEY)
remote_desktop = RemoteDesktopAgent(BACKEND_URL, AGENT_ID, API_KEY)
# live_streamer = LiveStreamer(AGENT_ID, sio) # Deprecated in favor of WebRTC
webrtc_manager = WebRTCManager(str(BACKEND_URL), str(AGENT_ID), sio)


async def system_monitor_loop():
    print("[Loop] Starting System Monitor Loop...")
    while True:
        try:
            cpu = psutil.cpu_percent(interval=1)
            mem = psutil.virtual_memory()
            
            # Periodic Software Scan (every hour approx)
            software_cache = []
            if datetime.now().minute == 0:
                print("[Sec] Scanning Installed Software...")
                software_cache = proc_sec.get_installed_software()

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
        resp = await asyncio.to_thread(requests.get, f"{BACKEND_URL}/api/health", timeout=5, verify=False)
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
    while True:
        try:
            # IMPORTANT: Auth dict with 'room' ensures backend routes us correctly
            await sio.connect(BACKEND_URL, auth={'room': AGENT_ID})
            print("[WS] Connected to Backend Socket!")
            break
        except Exception as e:
            print(f"[WS] Connection Failed (Retrying in 5s): {e}")
            try:
                await sio.disconnect()
            except: pass
            await asyncio.sleep(5)

    # Start Security Modules
    fim.start()
    screen_cap.start()
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
        if platform.system() == 'Windows':
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
        asyncio.run(main())
    except KeyboardInterrupt:
        print("Stopping...")
        screen_cap.stop()
        activity_mon.stop()
        mail_mon.stop()
        remote_desktop.stop()
        sys.exit(0)
    except Exception as e:
        print(f"\n[CRITICAL ERROR] Agent crashed: {e}")
        import traceback
        traceback.print_exc()
        input("Press Enter to Exit...") # Keep console open on crash
    finally:
        print("\n[EXIT] Process Terminated.")
