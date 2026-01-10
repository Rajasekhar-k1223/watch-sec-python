import asyncio
import json
import psutil
import requests
import socketio
import platform
from datetime import datetime, timedelta, timezone
import os
import sys
import urllib3
import warnings

# Suppress insecure request warnings & pkg_resources deprecation
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings("ignore", category=UserWarning, module='pkg_resources')

# Monkey Patch for aiohttp 3.9+ compatibility
import aiohttp 
if not hasattr(aiohttp, 'ClientWSTimeout'):
    class MockClientWSTimeout(aiohttp.ClientTimeout):
        def __init__(self, ws_close=None, ws_receive=None, **kwargs):
            super().__init__(**kwargs)
    try:
        aiohttp.ClientWSTimeout = MockClientWSTimeout
        print("[Init] Monkey-patched aiohttp.ClientWSTimeout (Advanced)")
    except: pass

# --- Setup Logging ---
# Log to file for debugging silent crashes on user machines
if getattr(sys, 'frozen', False):
    BASE_DIR = os.path.dirname(sys.executable)
else:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    sys.path.append(BASE_DIR)

LOG_FILE = os.path.join(BASE_DIR, "agent_debug.log")
def log_to_file(msg):
    try:
        with open(LOG_FILE, "a", encoding='utf-8') as f:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            f.write(f"[{timestamp}] {msg}\n")
    except: pass
    print(msg)

# Global Robust Session
http_session = requests.Session()
adapter = requests.adapters.HTTPAdapter(max_retries=3)
http_session.mount('https://', adapter)
http_session.mount('http://', adapter)

log_to_file("--- Agent Startup Initiated ---")
log_to_file(f"Platform: {platform.platform()}")
log_to_file(f"Base Dir: {BASE_DIR}")

# --- Import Modules ---
try:
    log_to_file("Importing Modules...")
    from modules.live_stream import LiveStreamer
    from modules.fim import FileIntegrityMonitor
    from modules.network import NetworkScanner
    from modules.security import ProcessSecurity
    from modules.screenshots import ScreenshotCapture
    from modules.activity_monitor import ActivityMonitor
    from modules.mail_monitor import MailMonitor
    from modules.browser_enforcer import BrowserEnforcer
    from modules.remote_desktop import RemoteDesktopAgent
    from modules.power_monitor import PowerMonitor
    from modules.webrtc_stream import WebRTCManager
    # DLP Modules (New)
    from modules.usb_monitor import UsbMonitor
    from modules.network_monitor import NetworkMonitor
    from modules.file_monitor import FileMonitor
    log_to_file("Modules Imported Successfully.")
except Exception as e:
    log_to_file(f"CRITICAL IMPORT ERROR: {e}")
    import traceback
    log_to_file(traceback.format_exc())

import uuid
import getpass

# --- Configuration Loading ---
CONFIG_PATH = os.path.join(BASE_DIR, "config.json")
try:
    if os.path.exists(CONFIG_PATH):
        if os.path.getsize(CONFIG_PATH) == 0:
             print("[Init] Config file found but is EMPTY (0 bytes). Re-initializing fresh config.")
             log_to_file("[Init] Warning: config.json is empty. Initializing empty.")
             config = {}
        else:
            with open(CONFIG_PATH, "r") as f:
                config = json.load(f)
    else:
        config = {}
        log_to_file("[Init] Warning: config.json not found. Initializing empty.")

    # Debug Config Content (Masking Key for security in logs, but printing existence)
    masked_config = config.copy()
    if "TenantApiKey" in masked_config:
        masked_config["TenantApiKey"] = masked_config["TenantApiKey"][:4] + "***" 
    log_to_file(f"[Init] Loaded Config: {masked_config}")
except Exception as e:
    msg = f"[CRITICAL] Config file exists at {CONFIG_PATH} but failed to load: {e}"
    print(msg)
    try:
        log_to_file(msg)
    except: pass
    print("Aborting to prevent configuration corruption. Please fix config.json syntax.")
    sys.exit(1)

# Backend Configuration (User Defined Production URL)
BACKEND_URL = config.get("BackendUrl", "https://api.monitorix.co.in")
API_KEY = config.get("TenantApiKey", "")
AGENT_ID = config.get("AgentId", "")

# --- Dynamic Agent ID Logic ---
current_hostname = platform.node()
current_user = getpass.getuser()
expected_prefix = f"{current_hostname}-{current_user}"

print(f"[Init] Expected Agent ID Prefix: {expected_prefix}")
print(f"[Init] Loaded Agent ID: {AGENT_ID}")

# If ID is missing OR doesn't match the current system (e.g. config copied from another machine)
def get_stable_id():
    try:
        if platform.system() == "Windows":
             import winreg
             key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography")
             guid, _ = winreg.QueryValueEx(key, "MachineGuid")
             return guid
        elif platform.system() == "Linux":
            with open("/etc/machine-id", "r") as f:
                return f.read().strip()
        elif platform.system() == "Darwin":
            import subprocess
            cmd = "ioreg -rd1 -c IOPlatformExpertDevice | grep IOPlatformUUID"
            result = subprocess.check_output(cmd, shell=True).decode()
            return result.split('"')[-2]
    except Exception as e:
        print(f"[Init] Failed to get stable ID: {e}")
        return str(uuid.uuid4()) # Fallback

if not AGENT_ID or not AGENT_ID.startswith(expected_prefix):
    # Use Hardware ID for stability across reinstalls
    machine_id = get_stable_id()
    # Create short hash of machine ID to keep Agent ID readable
    import hashlib
    machine_hash = hashlib.md5(machine_id.encode()).hexdigest()[:8].upper()
    
    AGENT_ID = f"{expected_prefix}-{machine_hash}"
    print(f"[Init] Stable ID Generated (Hardware Based): {AGENT_ID}")
    
    # Update Config with new ID to persist it
    config["AgentId"] = AGENT_ID
    try:
        # Prepare for Rewrite (Remove Hidden Attribute if exists)
        FILE_ATTRIBUTE_HIDDEN = 0x02
        FILE_ATTRIBUTE_NORMAL = 0x80
        if platform.system() == "Windows" and os.path.exists(CONFIG_PATH):
             import ctypes
             # Set to Normal first to allow write
             ctypes.windll.kernel32.SetFileAttributesW(str(CONFIG_PATH), FILE_ATTRIBUTE_NORMAL)

        # Write Config
        with open(CONFIG_PATH, "w") as f:
            json.dump(config, f, indent=4)
        
        # Re-apply Hidden Attribute (Windows Security)
        if platform.system() == "Windows":
             import ctypes
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
# Core Modules
screen_cap = ScreenshotCapture(AGENT_ID, API_KEY, BACKEND_URL, interval=30)
activity_mon = ActivityMonitor(AGENT_ID, API_KEY, BACKEND_URL)
proc_sec = ProcessSecurity()
mail_mon = MailMonitor(BACKEND_URL, AGENT_ID, API_KEY)
power_mon = PowerMonitor()
remote_desktop = RemoteDesktopAgent(BACKEND_URL, AGENT_ID, API_KEY)
webrtc_manager = WebRTCManager(sio, str(AGENT_ID))

from modules.network_monitor import NetworkMonitor
from modules.file_monitor import FileMonitor
from modules.location_monitor import LocationMonitor

# DLP Modules
fim_monitor = FileIntegrityMonitor(AGENT_ID, API_KEY, BACKEND_URL)
net_scanner = NetworkScanner(AGENT_ID, API_KEY, BACKEND_URL)
usb_ctrl = UsbMonitor(AGENT_ID, API_KEY, BACKEND_URL)
loc_mon = LocationMonitor()

# --- Start Threads ---
activity_mon.start()
screen_cap.start() 

# DLP Modules are started conditionally in the loop based on config, 
# but we can ensure they are ready. They don't block.

# Remote Desktop & WebRTC
remote_desktop.start()
loc_mon.start() 

print("[Main] All Monitoring Modules Initialized and Started.")


async def system_monitor_loop():
    print("[Loop] Starting System Monitor Loop...")
    while True:
        try:
            print("[Loop] System Monitor Loop...")
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
                "Timestamp": datetime.now(timezone.utc).isoformat(), # Fixed Deprecation
                "TenantApiKey": API_KEY,
                "InstalledSoftwareJson": json.dumps(software_cache), 
                "LocalIp": net_scanner.local_ip, 
                "Gateway": "Unknown",
                "Latitude": loc_mon.get_location()[0],
                "Longitude": loc_mon.get_location()[1],
                "Country": loc_mon.get_location()[2], 
                "PowerStatus": power_mon.get_status()
            }
            print("[Loop] Sending Heartbeat...")
            # Print valid JSON to confirm serialization is correct (Double Quotes)
            try:
                print(json.dumps(payload, default=str))
            except Exception as e:
                print(f"[Loop] JSON Serialization Log Error: {e}")
                print(payload)
            try:
                # Use async run_in_executor for request to avoid blocking
                # verify=False bypasses SSL self-signed errors
                # Use http_session for keep-alive and retries
                print( f"{BACKEND_URL}/api/agent/heartbeat")
                resp = await asyncio.to_thread(http_session.post, f"{BACKEND_URL}/api/agent/heartbeat", json=payload, timeout=10, verify=False)
                print(resp)
                if resp.status_code == 200:
                    data = resp.json()
                    
                    # Handle Feature Flags
                    config = data.get("config", {}) 

                    # Support both nested 'config' and direct fields logic
                    network_enabled = config.get("NetworkMonitoringEnabled", data.get("NetworkMonitoringEnabled", False))
                    file_dlp_enabled = config.get("FileDlpEnabled", data.get("FileDlpEnabled", False))
                    usb_blocking_enabled = config.get("UsbBlockingEnabled", data.get("UsbBlockingEnabled", False))
                    screenshot_enabled = config.get("ScreenshotsEnabled", data.get("ScreenshotsEnabled", False))
                    location_enabled = config.get("LocationTrackingEnabled", data.get("LocationTrackingEnabled", False))

                    if screenshot_enabled: screen_cap.set_enabled(True)
                    else: screen_cap.set_enabled(False)
                        
                    # [NET] Network Monitoring
                    if network_enabled and not net_scanner.is_running:
                        net_scanner.start()
                    elif not network_enabled and net_scanner.is_running:
                        net_scanner.stop()
                        
                    # [DLP] File Monitoring
                    if file_dlp_enabled and not fim_monitor.is_running:
                        fim_monitor.start()
                    elif not file_dlp_enabled and fim_monitor.is_running:
                        fim_monitor.stop()

                    # [LOCATION] Update Loop State 
                    if not location_enabled:
                         cached_location = {"lat": 0.0, "lon": 0.0, "country": "Unknown"}

                    # [DLP] USB Control
                    policy = "Block" if usb_blocking_enabled else "Allow"
                    usb_ctrl.set_policy(policy)
                    # success, msg = usb_ctrl.set_usb_write_protect(usb_blocking_enabled) 
                    # if not success and usb_blocking_enabled:
                         # [ERROR FEEDBACK] Report Failure to Backend
                         # try:
                         #     print(f"[DLP ERROR] USB Block Failed: {msg}")
                         #     err_payload = {
                         #         "AgentId": AGENT_ID,
                         #         "TenantApiKey": API_KEY,
                         #         "Type": "SystemError",
                         #         "Details": f"USB Blocking Failed: {msg}",
                         #         "Timestamp": datetime.utcnow().isoformat()
                         #     }
                         #     # Fire and forget error report
                         #     asyncio.create_task(asyncio.to_thread(http_session.post, f"{BACKEND_URL}/api/events/report", json=err_payload, timeout=5, verify=False))
                         # except: pass
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
        resp = await asyncio.to_thread(http_session.get, f"{BACKEND_URL}/api/health", timeout=10, verify=False)
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
    # 3. Module Status
    print(f"[Self-Test] FIM: {'Active' if fim_monitor.is_running else 'Inactive'}")
    print(f"[Self-Test] MailMonitor: {'Active' if mail_mon.running else 'Inactive'}")
    print(f"[Self-Test] UsbMonitor: {'Active' if usb_ctrl.running else 'Inactive'}")
    print(f"[Self-Test] ScreenCapture: {'Active' if screen_cap.running else 'Inactive'}")
    print(f"[Self-Test] ActivityMonitor: {'Active' if activity_mon.running else 'Inactive'}")
    print(f"[Self-Test] RemoteDesktop: {'Active' if remote_desktop.running else 'Inactive (Missing Dependency?)'}")
    print(f"[Self-Test] NetworkScanner: {'Active' if net_scanner.is_running else 'Inactive'}")
    print(f"[Self-Test] WebRTC: {'Ready' if webrtc_manager else 'Error'}")
    print("[Self-Test] --- Check Complete ---\n")

async def main():
    log_to_file(f"--- Monitorix Agent v2.0 ({platform.system()}) ---")
    
    # Run Diagnostics
    await run_self_test()
    
    # Connect WebSocket
    while True:
        try:
            # IMPORTANT: Auth dict with 'room' ensures backend routes us correctly
            log_to_file(f"Connecting WebSocket to {BACKEND_URL}...")
            # Try connecting with explicit namespace
            await sio.connect(BACKEND_URL, auth={'room': AGENT_ID, 'apiKey': API_KEY}, namespaces=['/'])
            log_to_file("[WS] Connected to Backend Socket!")
            break
        except Exception as e:
            log_to_file(f"[WS] Connection Failed (Retrying in 5s): {e}")
            try:
                await sio.disconnect()
            except: pass
            await asyncio.sleep(5)

    # Start Security Modules
    log_to_file("Starting Security Modules...")
    try:
        fim_monitor.start()
        screen_cap.start()
        activity_mon.start()
        mail_mon.start()
        usb_ctrl.start()
        remote_desktop.start()
        log_to_file("Modules Started.")
    except Exception as e:
        log_to_file(f"Error starting modules: {e}")
    
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
        log_to_file(f"[CRITICAL CRASH] Agent: {e}") # Debug Log
        import traceback
        traceback.print_exc()
        input("Press Enter to Exit...") # Keep console open on crash
    finally:
        log_to_file("[EXIT] Process Terminated.")
