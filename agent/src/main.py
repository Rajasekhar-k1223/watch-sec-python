import sys # type: ignore
import os # type: ignore

# --- Absolute Path Hardening ---
# We calculate the absolute path to the directory containing this script.
# This ensures we can find our modules regardless of where the script is called from.
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

if getattr(sys, 'frozen', False):
    # Running as compiled EXE
    BASE_DIR = os.path.dirname(os.path.abspath(sys.executable))
else:
    # If we are in src/main.py, BASE_DIR should be the root (one level up)
    if os.path.basename(SCRIPT_DIR).lower() == 'src':
        BASE_DIR = os.path.dirname(SCRIPT_DIR)
    else:
        BASE_DIR = SCRIPT_DIR
    
    # Add 'src' to sys.path if it exists to allow top-level imports of modules and agent_core
    SRC_PATH = os.path.join(BASE_DIR, "src")
    if os.path.exists(SRC_PATH) and SRC_PATH not in sys.path:
        sys.path.insert(0, SRC_PATH)
    
    # Also add BASE_DIR to allow imports like 'from src.modules import ...'
    if BASE_DIR not in sys.path:
        sys.path.append(BASE_DIR)

# Force CWD to the Application Directory for consistent local file access
try:
    os.chdir(BASE_DIR)
except Exception:
    pass

# Standard Libraries
import tempfile # type: ignore
import traceback # type: ignore
import platform # type: ignore
import subprocess # type: ignore
import time # type: ignore
import getpass # type: ignore
import json # type: ignore
import uuid # type: ignore
import asyncio # type: ignore
import signal # type: ignore
import warnings # type: ignore
import multiprocessing # type: ignore
import threading # type: ignore
import hashlib # type: ignore
import shutil # type: ignore
from datetime import datetime, timezone # type: ignore
from typing import List, Dict, Any, Union, Optional # type: ignore
from urllib.parse import urlparse # type: ignore

# Third-Party Libraries (External)
import socketio # type: ignore
import requests # type: ignore
import urllib3 # type: ignore

# Internal Modules (Core & Features)
from agent_core import AntiTamperMonitor, RemediationHandler, BandwidthManager, SessionMonitor # type: ignore
from modules.audit_logger import AuditLogger # type: ignore

# Milestone Version: 1.8.15
AGENT_VERSION = "v1.8.26"
IS_WINDOWS = platform.system() == "Windows"
IS_UPDATING = False # Global guard to prevent multiple update starts

# --- Cross-Platform Compatibility Stubs ---
if platform.system() != "Windows":
    if not hasattr(subprocess, "CREATE_NO_WINDOW"):
        setattr(subprocess, "CREATE_NO_WINDOW", 0)
    if not hasattr(subprocess, "DETACHED_PROCESS"):
        setattr(subprocess, "DETACHED_PROCESS", 0)
    
    # Mock winreg for Linux/Mac linting and runtime safety
    import types # type: ignore
    class WinregStub:
        HKEY_LOCAL_MACHINE = 0
        HKEY_CURRENT_USER = 0
        KEY_READ = 0
        KEY_WOW64_64KEY = 0
        KEY_WOW64_32KEY = 0
        @staticmethod
        def OpenKey(*a, **k): return 0
        @staticmethod
        def QueryValueEx(*a, **k): return ("", 0)
        @staticmethod
        def CloseKey(*a, **k): pass
    sys.modules["winreg"] = WinregStub() # type: ignore

try:
    import psutil # type: ignore
except ImportError:
    class PsutilStub:
        class VirtualMemoryProxy:
            percent = 0.0
        @staticmethod
        def cpu_percent(*a, **k): return 0.0
        @staticmethod
        def virtual_memory(*a, **k): return PsutilStub.VirtualMemoryProxy()
        @staticmethod
        def net_if_addrs(*a, **k): return {}
        @staticmethod
        def process_iter(*a, **k): return []
        @staticmethod
        def pid_exists(pid): return False
        @staticmethod
        def wait_procs(*a, **k): return ([], [])
        class NoSuchProcess(Exception): pass
        class AccessDenied(Exception): pass
        class Process:
            def __init__(self, pid): self.pid = pid
            def username(self): return "MOCK_USER"
            def kill(self): pass
            def terminate(self): pass
            def status(self): return "running"
    sys.modules["psutil"] = PsutilStub() # type: ignore
    psutil = sys.modules["psutil"]

# --- Windows Session Injection Helpers (Session 0 Support) ---
if IS_WINDOWS:
    import ctypes
    from ctypes import wintypes

    WTS_CURRENT_SERVER_HANDLE = 0
    WTS_CURRENT_SESSION = -1
    WTSUserName = 5
    WTSConnectState = 8
    WTSActive = 0

    class STARTUPINFO(ctypes.Structure):
        _fields_ = [
            ("cb", wintypes.DWORD),
            ("lpReserved", wintypes.LPWSTR),
            ("lpDesktop", wintypes.LPWSTR),
            ("lpTitle", wintypes.LPWSTR),
            ("dwX", wintypes.DWORD),
            ("dwY", wintypes.DWORD),
            ("dwXSize", wintypes.DWORD),
            ("dwYSize", wintypes.DWORD),
            ("dwXCountChars", wintypes.DWORD),
            ("dwYCountChars", wintypes.DWORD),
            ("dwFillAttribute", wintypes.DWORD),
            ("dwFlags", wintypes.DWORD),
            ("wShowWindow", wintypes.WORD),
            ("cbReserved2", wintypes.WORD),
            ("lpReserved2", ctypes.POINTER(ctypes.c_byte)),
            ("hStdInput", wintypes.HANDLE),
            ("hStdOutput", wintypes.HANDLE),
            ("hStdError", wintypes.HANDLE),
        ]

    class PROCESS_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("hProcess", wintypes.HANDLE),
            ("hThread", wintypes.HANDLE),
            ("dwProcessId", wintypes.DWORD),
            ("dwThreadId", wintypes.DWORD),
        ]

def get_active_session_id():
    if not IS_WINDOWS: return None
    try:
        # WTSGetActiveConsoleSessionId returns the session ID or 0xFFFFFFFF
        return ctypes.windll.kernel32.WTSGetActiveConsoleSessionId()
    except: return None

def get_hardware_id():
    """Generates a stable, hardware-based unique ID for the device."""
    try:
        # 1. Try Motherboard Serial Number (Windows)
        if platform.system() == "Windows":
            try:
                cmd = "wmic bios get serialnumber"
                output = subprocess.check_output(cmd, shell=True, timeout=5).decode().split('\n')
                serial = output[1].strip()
                if serial and serial.lower() not in ["unknown", "to be filled by o.e.m.", "0"]:
                    return hashlib.md5(serial.encode()).hexdigest()[:8].upper()
            except: pass
        
        # 2. Try DMI UUID (Linux)
        elif platform.system() == "Linux":
            try:
                if os.path.exists("/sys/class/dmi/id/product_uuid"):
                    with open("/sys/class/dmi/id/product_uuid", "r") as f:
                        uuid_str = f.read().strip()
                        if uuid_str:
                            return hashlib.md5(uuid_str.encode()).hexdigest()[:8].upper()
            except: pass

        # 3. Fallback to MAC (Most Stable)
        node = uuid.getnode()
        mac = ':'.join(list(reversed(['{:02x}'.format((node >> (i * 8)) & 0xff) for i in range(6)])))
        return hashlib.md5(mac.encode()).hexdigest()[:8].upper()
    except:
        return "DEV-ID"

def spawn_user_session_agent():
    """Spawns a child agent in the active user session if running as SYSTEM."""
    if not IS_WINDOWS or not HEADLESS_MODE: return
    
    session_id = get_active_session_id()
    if session_id is None or session_id == 0xFFFFFFFF: return
    
    # Check if a session agent is already running for this session
    try:
        my_exe = os.path.basename(sys.executable).lower()
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                if proc.info['name'] and proc.info['name'].lower() == my_exe:
                    # ONLY fetch environ for our own executables (saves massive CPU)
                    env = proc.environ()
                    if env and env.get("MONITORIX_SESSION_AGENT") == str(session_id):
                        return # Already active in this session
            except (psutil.NoSuchProcess, psutil.AccessDenied): continue
    except: pass

    log_to_file(f"[Session 0] Active user session detected: {session_id}. Spawning UI Agent...")
    
    try:
        h_token = wintypes.HANDLE()
        if not ctypes.windll.wtsapi32.WTSQueryUserToken(session_id, ctypes.byref(h_token)):
            return

        h_new_token = wintypes.HANDLE()
        # Duplicate token for Primary access
        if not ctypes.windll.advapi32.DuplicateTokenEx(h_token, 0x02000000, None, 2, 1, ctypes.byref(h_new_token)):
            ctypes.windll.kernel32.CloseHandle(h_token)
            return

        si = STARTUPINFO()
        si.cb = ctypes.sizeof(si)
        si.lpDesktop = "winsta0\\default"
        pi = PROCESS_INFORMATION()
        
        exe_path = sys.executable
        # Pass specialized flag and session env
        cmd = f'"{exe_path}" --session-agent'
        
        env = os.environ.copy()
        env["MONITORIX_SESSION_AGENT"] = str(session_id)
        
        # CreateProcessAsUserW
        if ctypes.windll.advapi32.CreateProcessAsUserW(
            h_new_token, exe_path, cmd, None, None, False, 
            0x00000010 | 0x00000200, # CREATE_NEW_CONSOLE | DETACHED_PROCESS
            None, None, ctypes.byref(si), ctypes.byref(pi)
        ):
            log_to_file(f"[Session 0] UI Agent spawned successfully (PID: {pi.dwProcessId})")
            ctypes.windll.kernel32.CloseHandle(pi.hProcess)
            ctypes.windll.kernel32.CloseHandle(pi.hThread)
        
        ctypes.windll.kernel32.CloseHandle(h_new_token)
        ctypes.windll.kernel32.CloseHandle(h_token)
    except Exception as e:
        log_to_file(f"[Session 0] Failed to spawn UI Agent: {e}")

# --- Global State ---
UPDATE_RETRY_COUNT: int = 0
LAST_UPDATE_TIME: float = 0
VERSION_HISTORY: List[str] = []
health_issues: List[str] = []
config: Dict[str, Any] = {}
API_KEY: str = ""
BACKEND_URL: str = ""
AGENT_ID: str = ""
running: bool = True
current_hostname: str = ""
sio_connected: bool = False
# Socket.IO Client Initialized at Module Level for Decorator Support
sio: Any = socketio.AsyncClient(ssl_verify=False, logger=False, engineio_logger=False)

# Monitors & Managers
hw_mon: Any = None
power_mon: Any = None
loc_mon: Any = None
tamper_mon: Any = None
screen_cap: Any = None
activity_mon: Any = None
keylogger: Any = None
clip_mon: Any = None
data_queue: Any = None
session_mon: Any = None
remediation: Any = None
app_blocker: Any = None
usb_ctrl: Any = None
shadow_mon: Any = None
net_mon: Any = None
file_mon: Any = None
mail_mon: Any = None
print_mon: Any = None
speech_mon: Any = None
bandwidth_manager: Any = None
webrtc_manager: Any = None
audit_logger: Any = None
installer: Any = None
file_manager: Any = None
remote_shell: Any = None
input_simulator: Any = None
browser_enforcer: Any = None
live_streamer: Any = None

live_streamer: Any = None
# HTTP Session Initialized at Module Level
http_session: Any = requests.Session()
http_session.mount('https://', requests.adapters.HTTPAdapter(max_retries=3))



# --- Configuration Path ---
CONFIG_PATH = os.path.join(BASE_DIR, "config.json")

def load_config():
    """Robust configuration loader with multi-encoding support."""
    cfg = {}
    if os.path.exists(CONFIG_PATH):
        success = False
        for enc in ['utf-8-sig', 'utf-16', 'utf-8']:
            try:
                with open(CONFIG_PATH, "r", encoding=enc) as f:
                    cfg = json.load(f)
                    log_to_file(f"Configuration loaded (Encoding: {enc})")
                    success = True
                    break
            except: continue
        if not success:
            log_to_file("ERROR: Found config.json but could not decode it.")
    else:
        log_to_file("WARNING: config.json not found!")
    return cfg

def save_config(new_config):
    try:
        # [v1.8.26] Mute Anti-Tamper for self-initiated config updates
        # Ensure we don't trigger the monitor we just started
        global tamper_mon
        if 'tamper_mon' in globals() and tamper_mon:
            try:
                tamper_mon.ignore_next_modification("config.json")
            except: pass

        if os.path.exists(CONFIG_PATH):
            os.chmod(CONFIG_PATH, 0o777) 
            if platform.system() == "Windows":
                import stat # type: ignore
                os.chmod(CONFIG_PATH, stat.S_IWRITE)

        with open(CONFIG_PATH, "w") as f:
            json.dump(new_config, f, indent=4)
        
        if platform.system() == "Windows":
             import stat # type: ignore
             os.chmod(CONFIG_PATH, stat.S_IREAD)
        else:
             # Linux: 400 (Read-only for owner/root)
             os.chmod(CONFIG_PATH, 0o400)
             
        log_to_file("Configuration updated and locked.")
    except Exception as e:
        log_to_file(f"Failed to save config: {e}")

def parse_version(ver_str):
    """Helper to compare version strings (v1.2.3 -> [1, 2, 3])"""
    try:
        return [int(x) for x in ver_str.lower().replace('v', '').split('.')]
    except:
        return [0, 0, 0]

def rotate_logs():
    """Log Rotation Policy: Delete log file if older than 10 days."""
    try:
        if os.path.exists(LOG_FILE):
            creation_time = os.path.getctime(LOG_FILE)
            file_age_days = (time.time() - creation_time) / (24 * 3600)
            
            if file_age_days > 10:
                log_to_file(f"Log Rotation: File is {file_age_days:.1f} days old. Recreating...")
                try:
                     os.remove(LOG_FILE)
                     log_to_file("Log file rotated.")
                except Exception as e:
                     log_to_file(f"Log Rotation Failed: {e}")
    except: pass

def sync_config_to_file(current_config, update_keys):
    """Persists specific keys from the remote config to the local config.json."""
    global API_KEY, config # Access global config
    changed = False
    for k in update_keys:
        if k in current_config:
            if config.get(k) != current_config[k]:
                config[k] = current_config[k]
                changed = True
                if k == "TenantApiKey":
                    API_KEY = current_config[k]
                    # Update global session headers
                    http_session.headers.update({"X-Tenant-Api-Key": API_KEY})
                    # Update SIO auth
                    if hasattr(sio, 'auth'):
                        if isinstance(sio.auth, dict):
                            sio.auth["apiKey"] = API_KEY
                        else:
                            sio.auth = {"apiKey": API_KEY}
    if changed:
        save_config(config)
        log_to_file("[Policy] Persistent configuration updated.")


# Unique log file per user/session context
current_user = getpass.getuser()
LOG_FILE = os.path.join(BASE_DIR, f"monitorix_test.log")

# [FIX] Force Windows Service (SYSTEM) to use a distinct log so User Agent can coexist
if platform.system() == "Windows":
    # Check for Service Environment (Session 0 or SYSTEM user)
    if current_user.upper() == "SYSTEM" or current_user.endswith("$"): 
            LOG_FILE = os.path.join(BASE_DIR, "monitorix_service.log")

def log_to_file(msg):
    global LOG_FILE, audit_logger
    try:
        # Try primary log
        with open(LOG_FILE, "a+", encoding='utf-8') as f:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            f.write(f"[{timestamp}] {msg}\n")
            f.flush()
        
        # Audit critical events
        if audit_logger:
            # Simple heuristic to identify audit-worthy events
            if any(k in msg for k in ["Started", "Stopped", "CRITICAL", "ERROR", "FATAL", "Update", "Policy"]):
                if "Heartbeat" not in msg: # Ignore heartbeat noise
                    audit_logger.log("System", msg)
    except:
        # Fallback to TEMP if primary is unwritable
        try:
            fallback_log = os.path.join(tempfile.gettempdir(), os.path.basename(LOG_FILE))
            with open(fallback_log, "a+", encoding='utf-8') as f:
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                f.write(f"[{timestamp}] (FALLBACK) {msg}\n")
                f.flush()
        except: pass
    try: print(msg)
    except: pass

log_to_file(f"--- Monitorix Agent v{AGENT_VERSION} Booting ---")
log_to_file(f"User Context: {current_user}")
log_to_file(f"System: {platform.system()} {platform.release()} ({platform.machine()})")
try:
    log_to_file(f"Binary Path: {sys.executable if getattr(sys, 'frozen', False) else __file__}")
except: pass
log_to_file(f"Base Directory: {BASE_DIR}")


# --- Global Error Handling (Suppress Popups) ---
def global_excepthook(exctype, value, tb):
    """Capture all unhandled exceptions and log them instead of showing a popup."""
    err_msg = "".join(traceback.format_exception(exctype, value, tb))
    log_to_file("!!! UNHANDLED EXCEPTION (GLOBAL HOOK) !!!")
    log_to_file(err_msg)
    # On Windows/Noconsole, this prevents the PyInstaller error dialog
    sys.exit(1)

sys.excepthook = global_excepthook

# --- Singleton Lock (Per User/Context) ---
def acquire_lock():
    # Allows User-Session Agent to override SYSTEM/Service Agent for GUI access.
    # [RDP Multi-User Fix v1.8.19] Use session-specific lock to allow concurrent users.
    if HEADLESS_MODE:
        lock_name = "monitorix.lock"
    else:
        user_slug = current_user.replace(" ", "_").replace(".", "_").upper()
        lock_name = f"monitorix_{user_slug}.lock"
        
    primary_lock_file = os.path.join(BASE_DIR, lock_name)
    fallback_dir = os.environ.get("LOCALAPPDATA") or tempfile.gettempdir()
    fallback_lock_file = os.path.join(fallback_dir, lock_name)
    
    lock_file = primary_lock_file
    is_system = current_user.upper() == "SYSTEM" or current_user.endswith("$")

    try:
        def remove_lock():
            try:
                for f_path in [primary_lock_file, fallback_lock_file]:
                    if os.path.exists(f_path):
                        with open(f_path, 'r') as f:
                            if f.read().strip() == str(os.getpid()):
                                os.remove(f_path)
            except: pass
        import atexit # type: ignore
        atexit.register(remove_lock) # type: ignore

        # --- Instance Management Logic ---
        def handle_existing_instance(target_lock):
            if os.path.exists(target_lock):
                try:
                    with open(target_lock, 'r') as f:
                        content = f.read().strip()
                        if content:
                            old_pid = int(content)
                            if psutil.pid_exists(old_pid):
                                old_user = "Unknown"
                                try:
                                    proc = psutil.Process(old_pid)
                                    old_user = proc.username()
                                    is_old_system = "SYSTEM" in old_user.upper() or old_user.endswith("$")
                                    
                                    if (not is_system and is_old_system) or (current_user == old_user):
                                        log_to_file(f"Terminating old instance (PID {old_pid}).")
                                        proc.terminate()
                                        # Wait a bit for termination
                                        for _ in range(10):
                                            if not psutil.pid_exists(old_pid): break
                                            time.sleep(0.5)
                                    else:
                                        log_to_file(f"Another instance is active (PID {old_pid} by {old_user}). Exiting.")
                                        sys.exit(0)
                                except psutil.NoSuchProcess:
                                    pass 
                                except psutil.AccessDenied:
                                    log_to_file(f"Access Denied to instance PID {old_pid} (Run by {old_user}). A higher-privileged instance likely exists. Exiting.")
                                    sys.exit(0)
                        else:
                            # Empty lock file
                            pass
                except Exception as e:
                    log_to_file(f"Lock Check Error: {e}")
            
            # 2. Acquire New Lock
            try:
                with open(target_lock, 'w') as f:
                    f.write(str(os.getpid()))
            except Exception as e:
                log_to_file(f"Critical: Failed to write lock file {target_lock}: {e}")
                sys.exit(1)
            lock_file = primary_lock_file

        handle_existing_instance(primary_lock_file)
        handle_existing_instance(fallback_lock_file)

    except Exception as e:
        log_to_file(f"Lock Error: {e}")
        if isinstance(e, SystemExit): raise

def spawn_watchdog():
    """Spawns a secondary process to monitor this agent's PID."""
    if os.environ.get("MONITORIX_WATCHDOG_RUNNING") == "1":
        return
        
    try:
        exe_path = sys.executable
        cmd = [exe_path]
        if not getattr(sys, 'frozen', False):
            cmd.append(os.path.abspath(__file__))
        
        cmd.extend(["--watchdog", str(os.getpid()), exe_path, BASE_DIR])
        log_to_file(f"Spawning Watchdog: {' '.join(cmd)}")
        
        env = os.environ.copy()
        env["MONITORIX_WATCHDOG_RUNNING"] = "1"
        
        if platform.system() == "Windows":
            subprocess.Popen(cmd, env=env,  creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0) | getattr(subprocess, "DETACHED_PROCESS", 0)) # type: ignore
        else:
            subprocess.Popen(cmd, env=env, start_new_session=True)
            
        log_to_file("Watchdog process launched successfully.")
    except Exception as e:
        log_to_file(f"Failed to spawn watchdog: {e}")

# --- Heavy Imports (Deferred) ---
def load_heavy_modules():
    """Initializes multiprocessing and other deferred startup tasks."""
    multiprocessing.freeze_support()
    # Modules are now imported at top-level for linting and architectural clarity.
    pass
# --- Detect Headless Environment ---
def is_headless():
    """Detect if running in a headless environment (no GUI/X server)"""
    if platform.system() == "Windows":
         # Service/System account is headless
         user = getpass.getuser().upper()
         if user == "SYSTEM" or user.endswith("$"):
             return True
         return False
    
    # Check if DISPLAY environment variable is set
    if platform.system() == "Darwin":
        return False
    if not os.environ.get('DISPLAY'):
        return True
    
    try:
        import subprocess # type: ignore
        result = subprocess.run(['xdpyinfo'], capture_output=True, timeout=2)
        return result.returncode != 0
    except:
        return True

HEADLESS_MODE = is_headless()
log_to_file(f"Headless Mode: {HEADLESS_MODE}")

def diagnose_platform_environment():
    """Performs additional platform-specific environment diagnostics."""
    issues = []
    sys_platform = platform.system()

    if sys_platform == "Windows":
        try:
            import ctypes # type: ignore
            windll = getattr(ctypes, "windll", None)
            if windll:
                session_id = ctypes.c_uint32()
                if windll.kernel32.ProcessIdToSessionId(os.getpid(), ctypes.byref(session_id)):
                    log_to_file(f"Windows Session ID: {session_id.value}")
                    if session_id.value == 0:
                        log_to_file("WARNING: Running in Session 0 (SYSTEM Service). GUI features (Screen Capture/Input Simulation) are restricted.")
                        issues.append("Windows Session 0 restriction")
        except Exception as e:
            log_to_file(f"Failed to diagnose Windows session: {e}")

    elif sys_platform == "Darwin":
        try:
            import ctypes # type: ignore
            # Load ApplicationServices for permission checks
            app_services = ctypes.cdll.LoadLibrary("/System/Library/Frameworks/ApplicationServices.framework/ApplicationServices")
            
            # AXIsProcessTrusted() checks for Accessibility
            if not app_services.AXIsProcessTrusted():
                log_to_file("WARNING: macOS Accessibility permission NOT granted.")
                issues.append("Missing macOS Accessibility permission")
            else:
                log_to_file("macOS Accessibility permission confirmed.")

            # CGPreflightScreenCaptureAccess() checks for Screen Recording (macOS 10.15+)
            try:
                core_graphics = ctypes.cdll.LoadLibrary("/System/Library/Frameworks/CoreGraphics.framework/CoreGraphics")
                if hasattr(core_graphics, "CGPreflightScreenCaptureAccess"):
                    if not core_graphics.CGPreflightScreenCaptureAccess():
                        log_to_file("WARNING: macOS Screen Recording permission NOT granted.")
                        issues.append("Missing macOS Screen Recording permission")
                    else:
                        log_to_file("macOS Screen Recording permission confirmed.")
            except: pass
        except Exception as e:
            log_to_file(f"Failed to diagnose macOS permissions: {e}")

    elif sys_platform == "Linux":
        session_type = os.environ.get("XDG_SESSION_TYPE", "").lower()
        display = os.environ.get("DISPLAY", "")
        
        if display:
            log_to_file(f"Linux Environment: Desktop (DISPLAY={display})")
            if session_type == "wayland":
                log_to_file("WARNING: Wayland detected. Traditional X11 capture and input simulation may be restricted.")
                issues.append("Wayland compatibility warning")
        else:
            log_to_file("Linux Environment: Server/Headless (No DISPLAY detected)")
            # Check for common desktop binaries as a hint
            has_x11 = any(os.path.exists(f"/usr/bin/{bin}") for bin in ["X", "Xorg"])
            if has_x11:
                log_to_file("Hint: X11 binaries found, but no active display for this process.")
            
        if session_type:
            log_to_file(f"Linux Session Type: {session_type}")

    return issues

# --- Import Security Modules ---
try:
    log_to_file("Importing Security Modules...")
    from modules.fim import FileIntegrityMonitor # type: ignore # type: ignore
    from modules.network import NetworkScanner # type: ignore # type: ignore
    from modules.security import ProcessSecurity # type: ignore # type: ignore
    
    # GUI-dependent modules - import conditionally
    LiveStreamer = None
    ScreenshotCapture = None
    ActivityMonitor = None
    Keylogger = None
    ClipboardMonitor = None
    
    # ActivityMonitor is special: it has a headless fallback (CPU-based tracking)
    try:
        from modules.activity_monitor import ActivityMonitor # type: ignore
        log_to_file("  ✓ ActivityMonitor loaded (with headless fallback)")
    except Exception as e:
        log_to_file(f"  ✗ ActivityMonitor failed to load: {e}")

    if not HEADLESS_MODE:
        try:
            from modules.live_stream import LiveStreamer # type: ignore
            log_to_file("  ✓ LiveStreamer loaded")
        except Exception as e:
            log_to_file(f"  ✗ LiveStreamer disabled: {e}")
        
        try:
            from modules.screenshots import ScreenshotCapture # type: ignore
            log_to_file("  ✓ ScreenshotCapture loaded")
        except Exception as e:
            log_to_file(f"  ✗ ScreenshotCapture disabled: {e}")
        
        try:
            from modules.keylogger import Keylogger # type: ignore
            log_to_file("  ✓ Keylogger loaded")
        except Exception as e:
            log_to_file(f"  ✗ Keylogger disabled: {e}")
        
        try:
            from modules.clipboard_monitor import ClipboardMonitor # type: ignore
            log_to_file("  ✓ ClipboardMonitor loaded")
        except Exception as e:
            log_to_file(f"  ✗ ClipboardMonitor disabled: {e}")
    else:
        log_to_file("  ⊘ Advanced GUI modules skipped (headless mode)")

    # Non-GUI modules - always import
    from modules.mail_monitor import MailMonitor # type: ignore
    from modules.browser_enforcer import BrowserEnforcer # type: ignore
    from modules.power_monitor import PowerMonitor # type: ignore
    from modules.webrtc_stream import WebRTCManager # type: ignore
    from modules.usb_monitor import UsbMonitor # type: ignore
    from modules.usb_control import UsbControl # type: ignore
    from modules.shadow_monitor import ShadowMonitor # type: ignore
    from modules.network_monitor import NetworkMonitor # type: ignore
    from modules.file_monitor import FileMonitor # type: ignore
    from modules.hardware import HardwareMonitor # type: ignore
    from modules.location_monitor import LocationMonitor # type: ignore
    from modules.network_utils import NetworkUtils # type: ignore
    from modules.speech_monitor import SpeechMonitor # type: ignore
    from modules.audit_logger import AuditLogger # type: ignore
    from modules.printer_monitor import PrinterMonitor # type: ignore
    from modules.app_blocker import AppBlocker # type: ignore
    from modules.remote_shell import RemoteShell # type: ignore
    from modules.file_manager import FileManager # type: ignore
    from modules.data_queue import DataQueue # type: ignore
    log_to_file("All available modules imported successfully.")

except Exception as e:
    log_to_file(f"CRITICAL MODULE IMPORT ERROR: {e}")
    log_to_file(traceback.format_exc())
    sys.exit(1)

# --- Application Startup ---
log_to_file("Bootstrapping core services...")

def apply_policy(config_src):
    """Applies configuration flags to enable/disable monitors."""
    try:
        log_to_file("[Policy] Applying configuration...")
        
        screenshots_enabled = config_src.get("ScreenshotsEnabled", False)
        if screen_cap:  # Only if GUI available
            if screenshots_enabled:
                screen_cap.start()
                screen_cap.set_enabled(True)
            else:
                screen_cap.stop()
                screen_cap.set_enabled(False)
            # [NEW] Sync screenshot settings (quality, resolution, max size, interval)
            screen_cap.set_config(
                config_src.get("ScreenshotQuality", 80),
                config_src.get("ScreenshotResolution", "Original"),
                config_src.get("MaxScreenshotSize", 0),
                config_src.get("ScreenshotInterval", 60)
            )
        
        if usb_ctrl:
            if not usb_ctrl.running:
                usb_ctrl.start()
            
            # [FIX] Debounce Logging: Only update if value changed
            target_usb_policy = "Block" if config_src.get("UsbBlockingEnabled") else "Allow"
            if getattr(usb_ctrl, 'last_policy', None) != target_usb_policy:
                usb_ctrl.set_policy(target_usb_policy)
                usb_ctrl.last_policy = target_usb_policy
        
        # [NEW] Full Feature Toggles
        if net_mon: net_mon.set_enabled(config_src.get("NetworkMonitoringEnabled", False))
        if file_mon: file_mon.set_enabled(config_src.get("FileDlpEnabled", False))
        if loc_mon: loc_mon.set_enabled(config_src.get("LocationTrackingEnabled", False))
        
        # [NEW] Remote Shell Toggle
        if remote_shell:
            remote_shell.set_enabled(config_src.get("RemoteShellEnabled", False))
            
        # [NEW] Apply Bandwidth Config (Policy Override)
        bw_config = config_src.get("BandwidthConfig")
        if bw_config and bandwidth_manager:
             log_to_file(f"[Policy] Applying Bandwidth Config: {bw_config}")
             bandwidth_manager.update_config(bw_config)
        
        # Core Modules with Start/Stop capability
        if "ActivityMonitorEnabled" in config_src and activity_mon:  # Only if GUI available
            if config_src["ActivityMonitorEnabled"]: 
                activity_mon.start()
            else: 
                activity_mon.stop()
        
        if "KeyloggerEnabled" in config_src and keylogger:
            if config_src["KeyloggerEnabled"]: 
                keylogger.start()
            else: 
                keylogger.stop()
            
        if "ClipboardMonitorEnabled" in config_src and clip_mon:
            if config_src["ClipboardMonitorEnabled"]: 
                clip_mon.start()
            else: 
                clip_mon.stop()
            
        if "AppBlockerEnabled" in config_src and app_blocker:
            if config_src["AppBlockerEnabled"]: 
                app_blocker.start()
            else: 
                app_blocker.stop()

        if "PrinterMonitorEnabled" in config_src and print_mon:
            if config_src["PrinterMonitorEnabled"]: 
                print_mon.start()
            else: 
                print_mon.stop()

        if "ShadowMonitorEnabled" in config_src and shadow_mon:
            if config_src["ShadowMonitorEnabled"]: 
                shadow_mon.start()
            else: 
                shadow_mon.stop()

        if "ShadowPaths" in config_src and shadow_mon:
            try:
                paths = config_src["ShadowPaths"]
                if isinstance(paths, str): paths = json.loads(paths)
                shadow_mon.set_watched_paths(paths)
            except: pass

        if "MailMonitorEnabled" in config_src and mail_mon:
            if config_src["MailMonitorEnabled"]: 
                mail_mon.start()
            else: 
                mail_mon.stop()

        if "BrowserEnforcerEnabled" in config_src and browser_enforcer:
            if config_src["BrowserEnforcerEnabled"]:
                browser_enforcer.enforce()
            else:
                browser_enforcer.stop()

        if "LiveStreamEnabled" in config_src:
            live_stream_enabled = config_src["LiveStreamEnabled"]
            if live_stream_enabled:
                if live_streamer and not live_streamer.running:
                    try:
                        print("[Policy] Starting Live Stream via Policy")
                        live_streamer.start_streaming(asyncio.get_event_loop())
                    except Exception as e:
                        print(f"[Policy] Live Stream Start Error: {e}")
            else:
                if live_streamer and live_streamer.running:
                    live_streamer.stop_streaming()

        if "SpeechMonitorEnabled" in config_src:
            if config_src["SpeechMonitorEnabled"]: 
                if speech_mon: speech_mon.start()
            else: 
                if speech_mon: speech_mon.stop()

        # [NEW] App Blocker JSON
        blocked_apps_str = config_src.get("BlockedApps", "[]") 
        if isinstance(blocked_apps_str, str) and app_blocker:
            try:
                app_blocker.set_blocked_apps(json.loads(blocked_apps_str))
            except: pass
        elif isinstance(blocked_apps_str, list) and app_blocker:
            app_blocker.set_blocked_apps(blocked_apps_str)
            
        # Persist important policy flags
        sync_config_to_file(config_src, [
            "ScreenshotsEnabled", "UsbBlockingEnabled", "NetworkMonitoringEnabled",
            "FileDlpEnabled", "ActivityMonitorEnabled", "KeyloggerEnabled",
            "ClipboardMonitorEnabled", "AppBlockerEnabled", "BrowserEnforcerEnabled",
            "PrinterMonitorEnabled", "ShadowMonitorEnabled", "LiveStreamEnabled",
            "SpeechMonitorEnabled", "VulnerabilityIntelligenceEnabled",
            "ShadowPaths", "TenantApiKey", "BandwidthConfig", "ScreenshotInterval",
            "ScreenshotQuality", "ScreenshotResolution", "MaxScreenshotSize"
        ])


    except Exception as e:
        log_to_file(f"Error applying policy: {e}")


def upload_update_log_to_backend():
    global BACKEND_URL, AGENT_ID
    """Uploads the local update debug log to the backend (Gap #7)."""
    try:
        update_log = os.path.join(tempfile.gettempdir(), "monitorix_update_debug.log")
        if os.path.exists(update_log):
            with open(update_log, 'r', encoding='utf-8', errors='ignore') as f:
                log_content = f.read()
            
            if log_content:
                log_to_file("Uploading update debug log to backend...")
                payload = {"AgentId": AGENT_ID, "Log": log_content}
                response = http_session.post(
                    f"{BACKEND_URL}/api/agents/{AGENT_ID}/update-log", 
                    json=payload, 
                    timeout=15, 
                    verify=False
                )
                if response.status_code == 200:
                    log_to_file("Update log uploaded successfully.")
                    # Move to avoid re-uploading every heartbeat
                    archived_log = update_log + ".uploaded"
                    if os.path.exists(archived_log): os.remove(archived_log)
                    os.rename(update_log, archived_log)
    except Exception as e:
        log_to_file(f"Failed to upload update log: {e}")

async def perform_update(update_url, target_ver):
    global IS_UPDATING, BACKEND_URL, AGENT_ID
    if IS_UPDATING:
        log_to_file("Update already in progress. Ignoring duplicate trigger.")
        return
        
    IS_UPDATING = True
    try:
        log_to_file(f"Starting remote update ({AGENT_VERSION} Robust) from: {update_url}")
        
        # [v1.8.1] Extract Backend URL for Failure Reporting
        try:
            parsed_url = urlparse(update_url)
            BACKEND_URL = f"{parsed_url.scheme}://{parsed_url.netloc}"
        except:
            BACKEND_URL = "http://localhost:8000" # Fallback
        
        temp_dir = tempfile.gettempdir()
        # Download as "monitorix_new.exe"
        update_fname = "monitorix_new.exe"
        update_path = os.path.join(temp_dir, update_fname)
        batch_path = os.path.join(temp_dir, "monitorix_updater.bat")
        lock_file = os.path.join(BASE_DIR, "monitorix.lock")
        
        # [v1.6.0] Retry Loop with Exponential Backoff
        max_retries = 3
        backoff_delay = 2
        download_success = False
        
        # [v1.7.0] Progress Tracking Helper
        loop = asyncio.get_running_loop()
        downloaded: int = 0
        
        def download_with_progress(url, dest_path):
            with http_session.get(url, stream=True, timeout=120, verify=False) as r:
                r.raise_for_status()
                total = int(r.headers.get('content-length') or 0)
                downloaded = 0
                last_emit = 0
                
                with open(dest_path, 'wb') as f:
                    for chunk in r.iter_content(chunk_size=8192):
                        if chunk:
                            # Use casting to satisfy strict Buffer linter
                            f.write(chunk) # type: ignore
                            cur_downloaded = int(downloaded)
                            new_total = cur_downloaded + len(chunk)
                            downloaded = int(new_total)
                            
                            if total > 0:
                                pct = int((downloaded / total) * 100)
                                if int(pct) - int(last_emit) >= 5:
                                    if bandwidth_manager:
                                        if not bandwidth_manager.check_network_availability():
                                            continue
                                        event_data = {'agentId': AGENT_ID, 'progress': pct}
                                        payload = bandwidth_manager.prepare_payload(event_data)
                                    else:
                                        payload = {'agentId': AGENT_ID, 'progress': pct}
                                    
                                    asyncio.run_coroutine_threadsafe(
                                        sio.emit('update_progress', payload),
                                        loop
                                    )
                                    last_emit = pct
                return r.headers

        for attempt in range(max_retries):
            try:
                log_to_file(f"Downloading update (Attempt {attempt+1}/{max_retries})...")
                
                # Run streaming download in thread
                headers = await asyncio.to_thread(download_with_progress, update_url, update_path)
                
                file_size = os.path.getsize(update_path)
                log_to_file(f"Update payload downloaded ({file_size} bytes).")
                
                # [v1.6.0 Checksum Verification]
                expected_hash = headers.get("X-Binary-SHA256")
                if expected_hash:
                    log_to_file(f"Verifying checksum... Expected: {expected_hash[:8]}...")
                    sha256_hash = hashlib.sha256()
                    with open(update_path, "rb") as f:
                        for byte_block in iter(lambda: f.read(4096), b""):
                            if byte_block:
                                sha256_hash.update(byte_block) # type: ignore
                    actual_hash = sha256_hash.hexdigest()
                    
                    if actual_hash.lower() != expected_hash.lower():
                        log_to_file(f"CRITICAL: Checksum Mismatch! Expected={expected_hash}, Actual={actual_hash}")
                        if os.path.exists(update_path):
                            os.remove(update_path)
                        raise Exception("Checksum Verification Failed")
                    else:
                        log_to_file(f"Checksum Verified ✅")
                else:
                    log_to_file("WARNING: No checksum header provided by backend. Proceeding (Legacy Mode).")
                    
                download_success = True
                break
                
            except Exception as e:
                log_to_file(f"Download Error (Attempt {attempt+1}): {e}")
                if attempt < max_retries - 1:
                    sleep_time = backoff_delay ** attempt
                    log_to_file(f"Retrying in {sleep_time}s...")
                    await asyncio.sleep(sleep_time)
        
        if not download_success:
             log_to_file("Aborting update due to persistent download/verify failure.")
             IS_UPDATING = False
             return

        # Detect Payload Type (Read Header)
        with open(update_path, "rb") as f:
            header_bytes = f.read(4)
        is_zip = header_bytes.startswith(b'PK')
        is_exe = header_bytes.startswith(b'MZ')
        
        log_to_file(f"Detection: is_zip={is_zip}, is_exe={is_exe}")

        if platform.system() == "Windows":
            current_exe = sys.executable
            target_dir = os.path.dirname(current_exe)
            target_exe_name = os.path.basename(current_exe)
            update_log = os.path.join(temp_dir, "monitorix_update_debug.log")

            payload_logic = ""
            if is_zip:
                payload_logic = f"""
echo [Batch] Extracting ZIP via PowerShell... >> "{update_log}"
powershell -Command "Expand-Archive -Path '{update_path}' -DestinationPath '{target_dir}' -Force" >> "{update_log}" 2>&1
"""
            else:
                payload_logic = f"""
echo [Batch] Moving Standalone EXE... >> "{update_log}"
move /y "{update_path}" "{current_exe}" >> "{update_log}" 2>&1
"""

            batch_content = f"""@echo off
setlocal enabledelayedexpansion

:: Define Log File
set "UPDATE_LOG=%~dp0monitorix_update_debug.log"
echo [Batch] Starting Robust Update Process ({AGENT_VERSION} -> {target_ver})... > "!UPDATE_LOG!"

:: 1. Wait for parent process to exit FIRST
echo [Batch] Waiting for PID {os.getpid()} to exit... >> "!UPDATE_LOG!"
set /a attempts=0
:wait_exit
C:\\Windows\\System32\\tasklist /FI "PID eq {os.getpid()}" 2>nul | C:\\Windows\\System32\\findstr /C:"{os.getpid()}" >nul 2>&1
if !ERRORLEVEL!==0 (
    set /a attempts+=1
    if !attempts! GTR 15 (
        echo [Batch] PID still active after 15s. Force killing... >> "!UPDATE_LOG!"
        C:\\Windows\\System32\\taskkill /F /PID {os.getpid()} >> "!UPDATE_LOG!" 2>&1
    )
    C:\\Windows\\System32\\ping 127.0.0.1 -n 2 > nul
    goto wait_exit
)

:: 2. NOW Disable Watchdog (after agent exits)
echo [Batch] Disabling Watchdog (MonitorixAgentLauncher)... >> "!UPDATE_LOG!"
C:\\Windows\\System32\\schtasks /query /tn "MonitorixAgentLauncher" >nul 2>&1
if !ERRORLEVEL!==0 (
    C:\\Windows\\System32\\schtasks /change /tn "MonitorixAgentLauncher" /disable >> "!UPDATE_LOG!" 2>&1
    echo [Batch] Watchdog disabled successfully. >> "!UPDATE_LOG!"
)

:: 3. Kill any other instances just in case
echo [Batch] Ensuring no other instances are running... >> "!UPDATE_LOG!"
C:\\Windows\\System32\\taskkill /F /IM "{target_exe_name}" >> "!UPDATE_LOG!" 2>nul
C:\\Windows\\System32\\ping 127.0.0.1 -n 4 > nul

:: 4. Swapping Files with Retries
echo [Batch] Swapping files... >> "!UPDATE_LOG!"
C:\\Windows\\System32\\attrib -r "{current_exe}" >> "!UPDATE_LOG!" 2>&1

set /a swap_attempts=0
:swap_retry
set /a swap_attempts+=1
echo [Batch] Swap attempt !swap_attempts!... >> "!UPDATE_LOG!"

:: [ROLLBACK PREP] Keep the .old file for safety!
if exist "{target_exe_name}.old" del /f /q "{target_exe_name}.old"
ren "{current_exe}" "{target_exe_name}.old" >> "!UPDATE_LOG!" 2>&1

if !ERRORLEVEL! NEQ 0 (
    if !swap_attempts! LSS 8 (
        echo [Batch] Rename failed (File locked?). Retrying in 2s... >> "!UPDATE_LOG!"
        C:\\Windows\\System32\\ping 127.0.0.1 -n 3 > nul
        goto swap_retry
    ) else (
        echo [Batch] CRITICAL: Failed to rename old EXE after 8 attempts. >> "!UPDATE_LOG!"
        goto abort
    )
)

:: 5. Cleanup Stale Lock BEFORE swapping
echo [Batch] Cleaning up stale lock... >> "!UPDATE_LOG!"
if exist "{lock_file}" del /f /q "{lock_file}" >> "!UPDATE_LOG!" 2>&1

:: 6. Install Payload
{payload_logic}

:: 7. Start New Agent with PROPER FLAGS & VERIFY
echo [Batch] Restarting Agent (Verification Mode)... >> "!UPDATE_LOG!"
start "Monitorix Agent" /B "{current_exe}"

:: [ROLLBACK] Verification Loop
echo [Batch] Verifying new agent startup (15s)... >> "!UPDATE_LOG!"
C:\\Windows\\System32\\ping 127.0.0.1 -n 16 > nul

:: Check if process is still running
C:\\Windows\\System32\\tasklist /FI "IMAGENAME eq {target_exe_name}" 2>nul | C:\\Windows\\System32\\findstr /I /C:"{target_exe_name}" >nul 2>&1
if !ERRORLEVEL!==0 (
    echo [Batch] SUCCESS: New agent is running stable. >> "!UPDATE_LOG!"
    if exist "{target_dir}\\rollback_marker.txt" del /f /q "{target_dir}\\rollback_marker.txt" >> "!UPDATE_LOG!" 2>&1
    
    :: 8. Re-enable Watchdog
    C:\\Windows\\System32\\schtasks /query /tn "MonitorixAgentLauncher" >nul 2>&1
    if !ERRORLEVEL!==0 (
        C:\\Windows\\System32\\schtasks /change /tn "MonitorixAgentLauncher" /enable >> "!UPDATE_LOG!" 2>&1
    ) else (
        echo [Batch] Watchdog missing. Creating Self-Healing Task... >> "!UPDATE_LOG!"
        C:\\Windows\\System32\\schtasks /create /tn "MonitorixAgentLauncher" /tr "\"{current_exe}\"" /sc MINUTE /mo 1 /ru SYSTEM /f >> "!UPDATE_LOG!" 2>&1
    )
    
    if exist "{target_exe_name}.old" del /f /q "{target_exe_name}.old"
    echo [Batch] Update Complete. >> "!UPDATE_LOG!"
    goto cleanup
) else (
    echo [Batch] CRITICAL: New agent failed to start! Initiating ROLLBACK... >> "!UPDATE_LOG!"
    goto abort
)

:abort
echo [Batch] UPDATE ABORTED. Restoring from backup... >> "!UPDATE_LOG!"
C:\\Windows\\System32\\taskkill /F /IM "{target_exe_name}" >nul 2>&1
if exist "{target_exe_name}.old" (
    if exist "{current_exe}" del /f /q "{current_exe}"
    ren "{target_exe_name}.old" "{target_exe_name}" >> "!UPDATE_LOG!" 2>&1
)
if exist "{lock_file}" del /f /q "{lock_file}" >> "!UPDATE_LOG!" 2>&1
C:\\Windows\\System32\\schtasks /query /tn "MonitorixAgentLauncher" >nul 2>&1
if !ERRORLEVEL!==0 (
    C:\\Windows\\System32\\schtasks /change /tn "MonitorixAgentLauncher" /enable >> "!UPDATE_LOG!" 2>&1
)
start "Monitorix Agent" /B "{current_exe}" >> "!UPDATE_LOG!" 2>&1
echo [Batch] Rollback completed. Agent restored. >> "!UPDATE_LOG!"

:cleanup
echo [Batch] Cleaning up temp files... >> "!UPDATE_LOG!"
if exist "{update_path}" del /f /q "{update_path}" >> "!UPDATE_LOG!" 2>&1
(goto) 2>nul & del "%~f0"
"""
            with open(batch_path, "w") as f:
                f.write(batch_content)
                
            log_to_file(f"Robust Batch script generated. Launching detached...")
            try:
                subprocess.Popen(
                    ["cmd.exe", "/c", batch_path],
                    creationflags=0x00000008 | 0x00000200 | 0x08000000,
                    close_fds=True,
                    start_new_session=True
                )
                log_to_file("Batch process launched successfully.")
            except Exception as le:
                log_to_file(f"Failed to launch batch: {le}")
            
            time.sleep(3)
            log_to_file("Exiting agent to allow update...")
            sys.exit(0)

        else:
            # [v1.8.15] Robust Linux Update with Rollback
            current_exe = sys.executable if getattr(sys, 'frozen', False) else __file__
            target_exe_name = os.path.basename(current_exe)
            update_sh = os.path.join(temp_dir, "monitorix_update.sh")
            update_log = os.path.join(temp_dir, "monitorix_update_debug.log")
            
            sh_content = f"""#!/bin/bash
# Monitorix Robust Linux Update Stager
LOG_FILE="{update_log}"
echo "[Stager] Starting update process ({AGENT_VERSION} -> {target_ver})..." > "$LOG_FILE"

# 1. Wait for parent PID {os.getpid()} to exit
echo "[Stager] Waiting for PID {os.getpid()} to exit..." >> "$LOG_FILE"
while kill -0 {os.getpid()} 2>/dev/null; do
    sleep 1
done

# 2. Kill any other instances (to avoid lock issues)
echo "[Stager] Ensuring no other instances are running..." >> "$LOG_FILE"
pkill -x "{target_exe_name}" >> "$LOG_FILE" 2>&1
sleep 2

# 3. Swap files
echo "[Stager] Swapping files..." >> "$LOG_FILE"
if [ -f "{current_exe}" ]; then
    mv -f "{current_exe}" "{current_exe}.old" >> "$LOG_FILE" 2>&1
fi
mv -f "{update_path}" "{current_exe}" >> "$LOG_FILE" 2>&1
chmod +x "{current_exe}" >> "$LOG_FILE" 2>&1

# 4. Start new agent
echo "[Stager] Restarting agent (Verification Mode)..." >> "$LOG_FILE"
nohup "{current_exe}" > /dev/null 2>&1 &
NEW_PID=$!

# 5. Verification Loop
echo "[Stager] Verifying new agent startup (15s)..." >> "$LOG_FILE"
sleep 15

# Check if new PID is still alive or if a process with same name exists
if kill -0 $NEW_PID 2>/dev/null || pgrep -x "{target_exe_name}" > /dev/null; then
    echo "[Stager] SUCCESS: New agent is running stable." >> "$LOG_FILE"
    rm -f "{current_exe}.old"
    echo "[Stager] Update Complete." >> "$LOG_FILE"
else
    echo "[Stager] CRITICAL: New agent failed to start! Initiating ROLLBACK..." >> "$LOG_FILE"
    if [ -f "{current_exe}.old" ]; then
        mv -f "{current_exe}.old" "{current_exe}" >> "$LOG_FILE" 2>&1
        chmod +x "{current_exe}" >> "$LOG_FILE" 2>&1
        nohup "{current_exe}" > /dev/null 2>&1 &
    fi
    
    # Notify backend of failure (using curl)
    curl -X POST -H "Content-Type: application/json" -d '{{"AgentId":"{AGENT_ID}", "Reason":"Rollback triggered during update"}}' "{BACKEND_URL}/api/agents/{AGENT_ID}/update-failed" >> "$LOG_FILE" 2>&1
    echo "[Stager] Rollback completed." >> "$LOG_FILE"
fi

# Cleanup stager
rm -- "$0"
"""
            try:
                with open(update_sh, "w") as f:
                    f.write(sh_content)
                os.chmod(update_sh, 0o755)
                log_to_file("Linux update stager generated. Launching detached...")
                subprocess.Popen(["/bin/bash", update_sh], start_new_session=True)
                time.sleep(2)
                log_to_file("Exiting agent to allow update...")
                sys.exit(0)
            except Exception as le:
                log_to_file(f"Linux Update Stager Failed: {le}")
                IS_UPDATING = False
        
        VERSION_HISTORY = []
        global UPDATE_RETRY_COUNT, LAST_UPDATE_TIME
        UPDATE_RETRY_COUNT = 0
        LAST_UPDATE_TIME = 0

    except Exception as e:
        log_to_file(f"Update Error: {e}")
        log_to_file(traceback.format_exc())
        IS_UPDATING = False
    IS_UPDATING = False

async def heartbeat_loop():
    global running, health_issues, API_KEY, BACKEND_URL, AGENT_ID
    global hw_mon, power_mon, loc_mon
    
    log_to_file("Heartbeat loop started.")
    # [RECOVERY] First heartbeat sends JustStarted flag
    first_heartbeat = True
    
    # [RECOVERY] Wait 5 seconds to ensure "Agent Started" event reaches backend 
    # to clear any stale IsPendingUninstall flags.
    await asyncio.sleep(5)
    while running:
        # [v1.8.21] Session 0 Support: Check for active user sessions to spawn UI Agent
        if IS_WINDOWS and HEADLESS_MODE:
            spawn_user_session_agent()
            
        try:
            # Gather Deep Telemetry (with defensive null checks)
            hw_specs = hw_mon.get_complete_specs() if hw_mon else {}
            power = power_mon.get_status() if power_mon else {}
            lat, lon, country = loc_mon.get_location() if loc_mon else (0, 0, "Unknown")
            
            payload = {
                "AgentId": AGENT_ID,
                "TenantApiKey": API_KEY,
                "Hostname": current_hostname,
                "Status": "Online",
                "Version": AGENT_VERSION,
                "CpuUsage": psutil.cpu_percent(),
                "MemoryUsage": psutil.virtual_memory().percent,
                "Timestamp": datetime.now(timezone.utc).isoformat(),
                "LocalIp": psutil.net_if_addrs().get('Ethernet', [])[0].address if 'Ethernet' in psutil.net_if_addrs() else "127.0.0.1",
                "PublicIp": NetworkUtils.get_public_ip(),
                "Ssid": NetworkUtils.get_wifi_ssid(),
                "Hardware": hw_specs,
                "PowerStatus": power,
                "Latitude": lat,
                "Longitude": lon,
                "Country": country,
                "InstalledSoftwareJson": json.dumps(hw_mon.get_installed_software()) if (hw_mon and config.get("VulnerabilityIntelligenceEnabled")) else "[]",
                "HealthIssues": json.dumps(health_issues),
                "JustStarted": first_heartbeat
            }
            resp = await asyncio.to_thread(http_session.post, f"{BACKEND_URL}/api/agent/heartbeat", json=payload, timeout=10, verify=False)
            if resp.status_code == 200:
                first_heartbeat = False # Succeed only on success
                data = resp.json()
                
                # [NEW] Check for Uninstall Command
                if data.get("Uninstall") is True:
                    log_to_file("!!! RECEIVED REMOTE UNINSTALL COMMAND !!!")
                    # Delegate to Installer Module
                    if installer:
                        installer.self_destruct()
                    else:
                        log_to_file("  ✗ Error: Installer module not loaded. Cannot self-destruct.")
                    sys.exit(0)

                # Apply remote flags
                config_src = data.get("config", data) # Robust fallback
                apply_policy(config_src)

                # Handle Remote Software Update
                target_ver = data.get("TargetVersion")
                if target_ver and target_ver != AGENT_VERSION:
                    # [SECURITY] Downgrade Protection
                    current_v = parse_version(AGENT_VERSION)
                    target_v = parse_version(target_ver)
                    
                    if target_v < current_v:
                        log_to_file(f"Update Ignored: Downgrade blocked (Current={AGENT_VERSION}, Target={target_ver})")
                    else:
                        log_to_file(f"REMOTE UPDATE TRIGGERED: Current={AGENT_VERSION}, Target={target_ver}")
                        update_url = data.get("UpdateUrl")
                        if update_url:
                            # [GAP #6] Implement Retry/Wait logic
                            global UPDATE_RETRY_COUNT, LAST_UPDATE_TIME
                            current_time = time.time()
                            
                            # Exponential backoff: 0, 5, 15, 30 mins
                            backoff_seconds = min(UPDATE_RETRY_COUNT * 300, 1800) 
                            
                            if current_time - LAST_UPDATE_TIME > backoff_seconds:
                                log_to_file(f"Triggering Update Attempt #{UPDATE_RETRY_COUNT + 1}...")
                                LAST_UPDATE_TIME = current_time
                                # Use a more explicit way to increment to satisfy strict linter if needed
                                new_retry_val = int(UPDATE_RETRY_COUNT) + 1
                                UPDATE_RETRY_COUNT = new_retry_val
                                asyncio.create_task(perform_update(update_url, target_ver))
                            else:
                                wait_remaining = int(backoff_seconds - (current_time - LAST_UPDATE_TIME))
                                log_to_file(f"Update suppressed (Retry Backoff): Next attempt in {wait_remaining}s")
                        else:
                            log_to_file("Error: Update triggered but no UpdateUrl provided.")
            else:
                log_to_file(f"Heartbeat Warning: Backend responded with {resp.status_code}")
        except Exception as e:
            log_to_file(f"Heartbeat Failed: {e}")
        
        # [GAP #7] Attempt log upload on every heartbeat if trace exists
        upload_update_log_to_backend()
        
        await asyncio.sleep(30) # [v1.8.19] Reduced to 30s for better real-time responsiveness

async def update_monitor_task():
    """Background task to handle periodic logic"""
    while True:
        try:
            if sio_connected:
                # [Bandwidth] Emit Real-Time Stats
                if bandwidth_manager:
                    stats = bandwidth_manager.get_stats()
                    await sio.emit('bandwidth_stats', stats)
        except Exception as e:
            log_to_file(f"[Bandwidth] Stats emit failed: {e}")
        
        await asyncio.sleep(30) # [v1.8.15] Bandwidth stats every 30s instead of 5s
    
# --- Socket.IO Event Handlers ---
# --- Bandwidth Management [NEW] ---
# bandwidth_manager already initialized globally

@sio.on('UpdateBandwidthConfig')
def on_update_bandwidth_config(data):
    log_to_file(f"[Bandwidth] Received config update: {data}")
    if bandwidth_manager:
        bandwidth_manager.update_config(data)

@sio.on('PauseUploads')
def on_pause_uploads(data):
    duration = data.get('duration_minutes', 60)
    reason = data.get('reason', 'Manual pause')
    log_to_file(f"[Bandwidth] Pausing uploads for {duration}m. Reason: {reason}")
    if bandwidth_manager:
        bandwidth_manager.pause_uploads(duration)

@sio.event
def connect():
    global sio_connected
    sio_connected = True
    log_to_file(f"[Socket.IO] Connected to {BACKEND_URL}")

@sio.event
def disconnect():
    global sio_connected
    sio_connected = False
    log_to_file("[Socket.IO] Disconnected from server")

@sio.event
def connect_error(data):
    log_to_file(f"[Socket.IO] Connection error: {data}")

@sio.on('TakeScreenshot')
async def on_take_screenshot(data):
    log_to_file("Manual Screenshot Triggered")
    if screen_cap:  # Only if GUI available
        screen_cap.capture_now()

@sio.on('UpdateConfig')
async def on_update_config(data):
    global config, live_streamer
    log_to_file(f"Config Update (Socket): {data}")
    
    if isinstance(data, dict):
        # Merge with RUNNING global config, not reload from disk
        for k, v in data.items():
            config[str(k)] = v
        
        # Apply Logic
        apply_policy(config)
        
        # Persist to disk so it survives restart
        save_config(config)
    else:
        log_to_file("Warning: Received non-dict UpdateConfig data.")


@sio.on('webrtc_answer')
async def on_webrtc_answer(data):
    log_to_file("Received WebRTC Answer")
    if webrtc_manager:
        await webrtc_manager.handle_answer(data)

@sio.on('webrtc_ice_candidate')
async def on_webrtc_ice_candidate(data):
    if webrtc_manager:
        await webrtc_manager.handle_ice_candidate(data)

@sio.on('StartStream')
async def on_start_stream(data):
    global live_streamer, webrtc_manager
    log_to_file("Live Stream Requested")
    # [FIX] Check both Config and global live_streamer/webrtc_manager
    if config.get("LiveStreamEnabled", True): # Default to True if not set to ensure better UX
        if webrtc_manager:
            await webrtc_manager.start_stream()
        
        if live_streamer:
            try:
                loop = asyncio.get_running_loop()
                live_streamer.start_streaming(loop, data)
                log_to_file("LiveStreamer (JPEG) started successfully")
            except Exception as e:
                log_to_file(f"Error starting LiveStreamer: {e}")
    else:
         log_to_file("Live Stream Blocked (Disabled in Policy)")

@sio.on('StopStream')
async def on_stop_stream(data):
    log_to_file("Live Stream Stop Requested")
    if webrtc_manager:
        await webrtc_manager.stop_stream()
    
    if live_streamer:
        live_streamer.stop_streaming()
    
    # Non-blocking execution of remediation
    if remediation:
        asyncio.create_task(remediation.handle_command(data))

@sio.on('RemoteInput')
async def on_remote_input(data):
    if input_simulator:
        input_simulator.handle_input(data)

@sio.on('FetchLocation')
async def on_fetch_location(data):
    log_to_file("Manual Location Fetch Triggered")
    if loc_mon:
        # Run in thread to avoid blocking the async event loop
        threading.Thread(target=loc_mon._check_location, daemon=True).start()
        # Wait a bit for the fetch to complete (primitive but works for this sync-ish module)
        await asyncio.sleep(3) 
        lat, lon, country = loc_mon.get_location()
        
        # Report back as a specific event
        if BACKEND_URL and AGENT_ID:
            payload = {
                "AgentId": AGENT_ID,
                "TenantApiKey": API_KEY,
                "Type": "LocationUpdate",
                "Details": f"Location manually fetched: {country} ({lat}, {lon})",
                "Timestamp": datetime.utcnow().isoformat()
            }
            try:
                requests.post(f"{BACKEND_URL}/api/events/report", json=payload, timeout=5, verify=False)
                log_to_file(f"Manual Location Reported: {lat}, {lon}")
            except: pass
        
async def ws_maintainer():
    log_to_file("WebSocket maintainer started.")
    retry_delay = 5  # Initial backoff delay
    max_delay = 60
    
    while running:
        if not sio.connected:
            try:
                # Check if already in a non-disconnected state
                if sio.eio.state != 'disconnected':
                    log_to_file("[Socket.IO] Client is busy (state: {}). Waiting...".format(sio.eio.state))
                else:
                    log_to_file(f"Connecting to {BACKEND_URL}...")
                    await sio.connect(BACKEND_URL, auth={'room': AGENT_ID, 'apiKey': API_KEY}, wait_timeout=10)
                    log_to_file("WebSocket Connected!")
                    retry_delay = 5  # Reset delay on success
            except Exception as e:
                if "not in a disconnected state" in str(e):
                    pass # Ignore redundant connect attempts
                elif "ClientWSTimeout" in str(e):
                    log_to_file("[Socket.IO] aiohttp timeout error (Legacy environment). Retrying simple connect...")
                    try:
                        await sio.connect(BACKEND_URL, auth={'room': AGENT_ID, 'apiKey': API_KEY})
                        retry_delay = 5
                    except: pass
                else:
                    log_to_file(f"WebSocket Connection Failed: {e}. Retrying in {retry_delay}s...")
                    # Exponential backoff
                    await asyncio.sleep(retry_delay)
                    retry_delay = float(min(retry_delay * 2, max_delay)) # type: ignore
        else:
            retry_delay = 5 # Always reset when connected
        await asyncio.sleep(10)


def harden_permissions():
    """
Security Hardening: Set all program files to Read-Only.
Allow Write only for database. Config and Logs are managed dynamically.
Optimized to skip non-essential and dev directories.
    """
    import stat # type: ignore
    try:
        log_to_file("Applying Security Hardening (File Permissions)...")
        
        # Identify current executable name to allow for self-updates
        exe_name = os.path.basename(sys.executable)
        
        # These files MUST be writable for the agent to function
        writable_files = {
            "events.db", "events.db-journal", "events.db-wal", "events.db-shm",
            "events_svc.db", "events_svc.db-journal", "events_svc.db-wal", "events_svc.db-shm",
            "events_user.db", "events_user.db-journal", "events_user.db-wal", "events_user.db-shm",
            "monitorix_service.log", "monitorix_RAJASEKHAR.log", "monitorix_watchdog.log",
            "monitorix.lock", "monitorix_RAJASEKHAR.lock",
            "agent_test_run.log", "agent_stdout.log",
            "monitorix_update.exe", "monitorix_update",
            "monitorix.lock", "monitorix_root.lock", 
            f"monitorix_{current_user.replace(' ', '_').replace('.', '_').upper()}.lock",
            exe_name, "MonitorixAgent.exe", "monitorixagent.exe"
        }
        
        # Skip architectural or large dev/dist directories
        skip_dirs = {"venv", ".git", "__pycache__", "build", "dist", "dist_mac", "build_mac", "build_staging"}
        
        for root, dirs, files in os.walk(BASE_DIR):
            # Efficiently skip directory branches
            dirs[:] = [d for d in dirs if d not in skip_dirs]
            
            for file in files:
                file_path = os.path.join(root, file)
                try:
                    current_mode = os.stat(file_path).st_mode
                    # Preserve execute bits for owner/group/others
                    exec_bits = current_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
                    
                    if file in writable_files:
                        # Make Writable (600 or 711)
                        os.chmod(file_path, stat.S_IRUSR | stat.S_IWUSR | exec_bits)
                    elif file == "config.json":
                        # Special case for config: 400 (Read-only for owner/root)
                        os.chmod(file_path, stat.S_IRUSR)
                    else:
                        # Make Read-Only (400 or 511)
                        os.chmod(file_path, stat.S_IRUSR | exec_bits)
                except:
                    pass # Best effort
        log_to_file("Security Hardening Applied.")
    except Exception as e:
        log_to_file(f"Security Hardening Warning: {e}")

async def perform_startup_health_check():
    log_to_file("--- STARTUP HEALTH CHECK ---")
    issues = []
    
    # 1. Verify Core Modules
    universal_mods = [
        "modules.app_blocker", "modules.audit_logger",
        "modules.browser_enforcer", "modules.data_queue",
        "modules.file_monitor", "modules.fim", "modules.hardware", "modules.installer",
        "modules.location_monitor", "modules.mail_monitor", "modules.network", 
        "modules.network_monitor", "modules.power_monitor", "modules.printer_monitor",
        "modules.remote_shell", "modules.security", "modules.shadow_monitor", 
        "modules.usb_control", "modules.usb_monitor", "modules.webrtc_stream",
        "modules.file_manager"
    ]
    
    gui_mods = [
        "modules.activity_monitor", "modules.clipboard_monitor", 
        "modules.keylogger", "modules.live_stream", "modules.screenshots"
    ]
    
    import importlib # type: ignore
    for mod in universal_mods:
        try:
            importlib.import_module(mod) # type: ignore
        except Exception as e:
            issues.append(f"Module Error: {mod} ({e})")
            
    if not HEADLESS_MODE:
        for mod in gui_mods:
            try:
                importlib.import_module(mod) # type: ignore
            except Exception as e:
                issues.append(f"GUI Module Error: {mod} ({e})")
    
    # 2. Verify Config Writability
    try:
        test_val = str(time.time())
        config_copy = config.copy()
        config_copy["_health_check"] = test_val
        # FIX: Use save_config which handles permission unlocking/locking
        save_config(config_copy)
        
        # reload and check
        with open(CONFIG_PATH, "r") as f:
            c = json.load(f)
            if c.get("_health_check") != test_val:
                issues.append("Config Writability Error: Save failed verification.")
    except Exception as e:
        issues.append(f"Config Error: {e}")
        
    # 3. Verify Watchdog Presence (Windows Only)
    if platform.system() == "Windows":
        try:
            # Use getattr to safely access subprocess attributes that might be missing on some platforms
            creation_flags = getattr(subprocess, 'CREATE_NO_WINDOW', 0) if platform.system() == "Windows" else 0
            proc = await asyncio.create_subprocess_shell(
                'schtasks /query /tn "MonitorixAgentLauncher"',
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                creationflags=creation_flags
            )
            await proc.communicate()
            if proc.returncode != 0:
                issues.append("Watchdog Warning: Scheduled Task 'MonitorixAgentLauncher' not found.")
        except:
            pass 
            
    # 4. Environment Diagnostics
    env_issues = diagnose_platform_environment()
    if env_issues:
        issues.extend(env_issues)

    if issues:
        log_to_file(f"HEALTH CHECK ISSUES FOUND: {len(issues)}")
        for issue in issues:
            log_to_file(f" - {issue}")
    else:
        log_to_file("HEALTH CHECK PASSED: All core components verified.")
    return issues

async def main():
    global config, sio, running, health_issues, API_KEY, BACKEND_URL, AGENT_ID
    global current_hostname, sio_connected
    global hw_mon, power_mon, loc_mon, tamper_mon, screen_cap, activity_mon, keylogger, clip_mon
    global data_queue, session_mon, remediation, app_blocker, usb_ctrl, shadow_mon, net_mon, file_mon, mail_mon, print_mon, speech_mon
    global bandwidth_manager, webrtc_manager, live_streamer, remote_shell, file_manager, browser_enforcer, input_simulator, installer, audit_logger
    
    # 1. Watchdog Entry Point (Handle before Lock/Heavy Imports)
    if "--watchdog" in sys.argv:
        try:
            from agent_core.watchdog import run_watchdog
            pid = int(sys.argv[2])
            exe = sys.argv[3]
            bdir = sys.argv[4]
            run_watchdog(pid, exe, bdir)
            sys.exit(0)
        except Exception as we:
            print(f"Watchdog Failure: {we}")
            sys.exit(1)

    # 1b. Session Agent Entry Point (v1.8.21)
    # Allows a UI process spawned from Session 0 Service to run GUI tasks.
    is_session_agent = "--session-agent" in sys.argv
    if is_session_agent:
        # Override headless mode so GUI modules are loaded
        global HEADLESS_MODE
        HEADLESS_MODE = False
        log_to_file("[Session Agent] Running in UI-enabled mode.")
    else:
        # 2. Singleton Lock (Skip for Session Agent to allow coexistence)
        acquire_lock()
    
    # 3. Spawn Watchdog (Skip for SYSTEM service as SCM handles recovery)
    if not HEADLESS_MODE:
        spawn_watchdog()
    else:
        log_to_file("Running in Headless/Service mode. Watchdog skipped (SCM recovery active).")

    # 3. Load heavy modules
    if "--watchdog" not in sys.argv:
        load_heavy_modules()
        
        # Suppress insecure request warnings
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        warnings.filterwarnings("ignore", category=UserWarning, module='pkg_resources')

    log_to_file(f"Monitorix Agent {AGENT_VERSION} starting...")
    
    # Initial Load
    config = load_config()
    
    # [ROBUST AUTH START]
    BACKEND_URL = config.get("BackendUrl", "https://agent-api.monitorix.co.in").strip()
    API_KEY = config.get("TenantApiKey", "").strip()
    
    # Windows Registry Auth
    if platform.system() == "Windows":
        try:
            import winreg # type: ignore
            access_flags = [winreg.KEY_READ | getattr(winreg, 'KEY_WOW64_64KEY', 0), 
                           winreg.KEY_READ | getattr(winreg, 'KEY_WOW64_32KEY', 0)]
            for flags in access_flags:
                try:
                    key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Monitorix", 0, flags)
                    val, _ = winreg.QueryValueEx(key, "TenantApiKey")
                    if val and str(val).strip():
                        API_KEY = str(val).strip()
                        config.update({"TenantApiKey": API_KEY})
                        log_to_file("API Key loaded from Registry (HKLM)")
                        winreg.CloseKey(key)
                        break
                    winreg.CloseKey(key)
                except: continue
            
            if not API_KEY:
                try:
                    key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"SOFTWARE\Monitorix", 0, winreg.KEY_READ)
                    val, _ = winreg.QueryValueEx(key, "TenantApiKey")
                    if val and str(val).strip():
                        API_KEY = str(val).strip()
                        config.update({"TenantApiKey": API_KEY})
                        log_to_file("Found API Key in HKCU Registry.")
                    winreg.CloseKey(key)
                except: pass
        except Exception as e:
            log_to_file(f"Registry Check Warning: {e}")

    # ID Generation
    import socket # type: ignore
    current_hostname = socket.gethostname().upper()
    if not API_KEY:
            # Fallback for dev/manual run
            API_KEY = os.environ.get("MONITORIX_API_KEY", "")
            if API_KEY:
                config.update({"TenantApiKey": API_KEY})
                save_config(config)
    
    # [v1.7.1] Set Mandatory Headers for hardening
    if API_KEY:
         http_session.headers.update({"X-Tenant-Api-Key": API_KEY})
         sio.auth = {"apiKey": API_KEY}

    # [v1.8.26] Hardware-Centric Identity (No Suffixes/No User/No IP)
    # This fulfills the request to avoid AgentId (volatile) and IP/Administrator checks.
    BASE_AGENT_ID = config.get("AgentId", "").strip()
    
    # 1. Generate Stable Hardware Hash
    hw_hash = get_hardware_id()
    # [v1.8.24] Privacy Hardening: Add random entropy if first-time or template match
    import random, string
    def get_entropy(length=4):
        return ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(length))

    # [v1.8.24] Blacklisted Template IDs
    BLACKLISTED_TEMPLATE_IDS = ["VMI3011362-ROOT-F39F2ABC", "vmi3011362-root-F39F2ABC"]
    
    stable_id = f"{current_hostname}-{hw_hash}"
    
    # 2. [v1.8.24] Migration / Unification:
    # If the stored ID matches the template or is invalid, force update with entropy
    is_template = BASE_AGENT_ID.upper() in BLACKLISTED_TEMPLATE_IDS
    if not BASE_AGENT_ID or is_template or "-ADMINISTRATOR" in BASE_AGENT_ID.upper() or (not is_template and BASE_AGENT_ID != stable_id and not BASE_AGENT_ID.startswith(stable_id)):
        entropy = get_entropy()
        new_fixed_id = f"{stable_id}-{entropy}"
        log_to_file(f"Identity Migration/Hardening: {BASE_AGENT_ID} -> {new_fixed_id} (Entropy Added)")
        BASE_AGENT_ID = new_fixed_id
        config.update({"AgentId": BASE_AGENT_ID})
        save_config(config)

    AGENT_ID = BASE_AGENT_ID
    
    log_to_file(f"Runtime Agent ID: {AGENT_ID} (Context: {'Service' if HEADLESS_MODE else 'User Session'})")

    # Health Check
    startup_issues = await perform_startup_health_check()
    health_issues.clear()
    if isinstance(startup_issues, list):
        health_issues.extend(startup_issues)
    rotate_logs()
    harden_permissions()

    # Managers
    global bandwidth_manager, audit_logger, data_queue, remediation, shadow_mon
    global usb_ctrl, loc_mon, hw_mon, power_mon, net_mon, file_mon, mail_mon
    global webrtc_manager, input_simulator, browser_enforcer, live_streamer
    global screen_cap, activity_mon, keylogger, clip_mon

    bandwidth_manager = BandwidthManager()
    audit_logger = AuditLogger(AGENT_ID, API_KEY, BACKEND_URL, http_session)
    
    # 4. Initialize core components
    log_to_file("Initializing DataQueue components...")
    # [v1.8.19] Differentiate DataQueue DB by session to prevent locking (RDP Multi-user)
    db_name = "events_svc.db" if HEADLESS_MODE else "events_user.db"
    db_path = os.path.join(BASE_DIR, db_name)
    
    try:
        data_queue = DataQueue(AGENT_ID, API_KEY, BACKEND_URL, bandwidth_manager=bandwidth_manager, db_path=db_path, logger=log_to_file)
        data_queue.start()
        log_to_file("  ✓ DataQueue started")
    except Exception as e:
        log_to_file(f"  ✗ DataQueue initialization FAILED: {e}")
        data_queue = None

    if bandwidth_manager and data_queue:
        bandwidth_manager.set_data_queue(data_queue)

    remediation = RemediationHandler(AGENT_ID)
    
    # GUI/Security workers
    shadow_mon = ShadowMonitor(AGENT_ID, API_KEY, BACKEND_URL)
    usb_ctrl = UsbMonitor(AGENT_ID, API_KEY, BACKEND_URL, data_queue=data_queue, on_mount=shadow_mon.start_watching_drive)
    
    # Telemetry
    loc_mon = LocationMonitor()
    hw_mon = HardwareMonitor()
    power_mon = PowerMonitor()
    
    # Networking & Shell
    net_mon = NetworkMonitor(AGENT_ID, API_KEY, BACKEND_URL, data_queue=data_queue)
    file_mon = FileMonitor(AGENT_ID, API_KEY, BACKEND_URL, data_queue=data_queue)
    try:
        mail_mon = MailMonitor(BACKEND_URL, AGENT_ID, API_KEY, data_queue=data_queue)
        log_to_file("  ✓ MailMonitor loaded")
    except Exception as e:
        log_to_file(f"  ✗ MailMonitor disabled: {e}")
        mail_mon = None
    
    # Managers
    webrtc_manager = WebRTCManager(sio, AGENT_ID)
    if not HEADLESS_MODE:
        try:
            from modules.input_simulation import InputSimulator # type: ignore
            input_simulator = InputSimulator()
            log_to_file("  ✓ InputSimulator loaded")
        except Exception as e:
            log_to_file(f"  ✗ InputSimulator disabled: {e}")
            input_simulator = None

        try:
            from modules.browser_enforcer import BrowserEnforcer # type: ignore
            browser_enforcer = BrowserEnforcer()
            log_to_file("  ✓ BrowserEnforcer loaded")
        except Exception as e:
            log_to_file(f"  ✗ BrowserEnforcer disabled: {e}")
            browser_enforcer = None
    else:
        input_simulator = None
        browser_enforcer = None
    
    # Initialize Live Streamer (if module loaded)
    if LiveStreamer:
        live_streamer = LiveStreamer(AGENT_ID, sio, log_to_file)
        log_to_file("  ✓ LiveStreamer initialized")
    
    # Conditionals
    if ScreenshotCapture: screen_cap = ScreenshotCapture(AGENT_ID, API_KEY, BACKEND_URL)
    if ActivityMonitor: activity_mon = ActivityMonitor(AGENT_ID, API_KEY, BACKEND_URL, data_queue=data_queue, logger=log_to_file)
    if Keylogger: keylogger = Keylogger(AGENT_ID, API_KEY, BACKEND_URL, data_queue=data_queue)
    if ClipboardMonitor: clip_mon = ClipboardMonitor(AGENT_ID, API_KEY, BACKEND_URL, data_queue=data_queue)
    
    # Session Monitor Callbacks
    def on_lock_detected():
        if screen_cap and screen_cap.enabled:
            log_to_file("[Session] Lock Detected. Taking final screenshot...")
            screen_cap.capture_now()
            screen_cap.set_paused(True)
    
    def on_unlock_detected():
        if screen_cap:
            log_to_file("[Session] Unlock Detected. Resuming screenshots...")
            screen_cap.set_paused(False)

    session_mon = SessionMonitor(on_lock=on_lock_detected, on_unlock=on_unlock_detected, logger=log_to_file)
    if platform.system() == "Windows":
        session_mon.start()

    # Anti-Tamper
    tamper_mon = AntiTamperMonitor(AGENT_ID, API_KEY, data_queue, BASE_DIR, log_to_file)
    tamper_mon.start()
    
    # Management
    from modules.remote_shell import RemoteShell # type: ignore
    from modules.file_manager import FileManager # type: ignore
    remote_shell = RemoteShell(sio, AGENT_ID)
    file_manager = FileManager(sio, AGENT_ID)
    
    # Persistence
    from modules.installer import AgentInstaller # type: ignore
    installer = AgentInstaller(BASE_DIR, sys.executable if getattr(sys, 'frozen', False) else sys.argv[0])
    installer.check_persistence()
    installer.check_browser_extension(AGENT_ID, API_KEY, BACKEND_URL)
    
    log_to_file("Core components initialized.")

    # [v1.6.0] Abort Notification (Check for Rollback Marker)
    marker_path = os.path.join(BASE_DIR, "rollback_marker.txt")
    if os.path.exists(marker_path):
        try:
            log_to_file("Found Rollback Marker! Reporting failure to backend...")
            with open(marker_path, "r") as f:
                fail_reason = f.read().strip()
            
            # Send High-Priority Alert
            if BACKEND_URL and AGENT_ID:
                 payload = {
                    "EventType": "UpdateFailed",
                    "Message": f"Rollback triggered. Reason: {fail_reason}",
                    "Timestamp": datetime.utcnow().isoformat()
                 }
                 try:
                     requests.post(
                         f"{BACKEND_URL}/api/agents/{AGENT_ID}/events", 
                         json=payload, 
                         timeout=10, 
                         verify=False
                     )
                     log_to_file("Abort Notification Sent successfully.")
                 except Exception as re:
                     log_to_file(f"Failed to send Abort Notification: {re}")
            
            # Cleanup marker
            os.remove(marker_path)
        except Exception as e:
            log_to_file(f"Error handling rollback marker: {e}")

    
    # [v1.8.21] Start monitoring automatically based on local policy
    try:
        apply_policy(config)
    except Exception as ap_err:
        log_to_file(f"Startup Policy Error: {ap_err}")

    try:
        await asyncio.gather(heartbeat_loop(), ws_maintainer(), update_monitor_task())
    finally:
        log_to_file("Stopping agent background workers...")
        # Cleanup local instances
        try:
            if 'screen_cap' in locals() and screen_cap: screen_cap.stop()
        except: pass
        try:
            if 'activity_mon' in locals() and activity_mon: activity_mon.stop()
        except: pass
        try:
            if 'usb_ctrl' in locals() and usb_ctrl: usb_ctrl.stop()
        except: pass
        try:
            if 'shadow_mon' in locals() and shadow_mon: shadow_mon.stop_all()
        except: pass
        try:
            if 'net_mon' in locals() and net_mon: net_mon.stop()
        except: pass
        try:
            if 'file_mon' in locals() and file_mon: file_mon.stop()
        except: pass
        try:
            if 'clip_mon' in locals() and clip_mon: clip_mon.stop()
        except: pass
        try:
            if 'app_blocker' in locals() and app_blocker: app_blocker.stop()
        except: pass
        try:
            if 'data_queue' in locals() and data_queue: data_queue.stop()
        except: pass
        try:
            if 'session_mon' in locals() and session_mon: session_mon.stop()
        except: pass
        try:
             loop = asyncio.get_event_loop()
             loop.run_until_complete(sio.disconnect())
        except: pass
        
        # [v1.8.2] Notify Shutdown to Backend
        try:
            if BACKEND_URL and AGENT_ID:
                log_to_file(f"Reporting Shutdown to {BACKEND_URL}...")
                import requests # type: ignore
                requests.post(
                    f"{BACKEND_URL}/api/agents/{AGENT_ID}/events",
                    json={
                        "EventType": "SystemShutdown",
                        "Message": "Agent process is shutting down (System Exit or Service Stop).",
                        "Timestamp": datetime.utcnow().isoformat()
                    },
                    timeout=5,
                    verify=False
                )
                log_to_file("Shutdown event reported.")
        except Exception as se:
            log_to_file(f"Failed to report shutdown: {se}")

        log_to_file("Agent background workers stopped.")

if __name__ == "__main__":
    try:
        if platform.system() == 'Windows':
            policy = getattr(asyncio, 'WindowsSelectorEventLoopPolicy', None)
            if policy:
                asyncio.set_event_loop_policy(policy())
        asyncio.run(main())
    except Exception as fatal_e:
        log_to_file(f"FATAL AGENT CRASH: {fatal_e}")
        log_to_file(traceback.format_exc())
        sys.exit(1)
    finally:
        log_to_file("Agent Process Terminating.")
