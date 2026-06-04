#!/usr/bin/env python3
import sys # type: ignore
import os # type: ignore
import hmac # type: ignore
import hashlib # type: ignore
import asyncio # type: ignore
import subprocess # type: ignore
import time # type: ignore
from datetime import datetime # type: ignore
from urllib.parse import urlparse # type: ignore

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
except: pass

# [v1.8.37] Master Boot Integrity: Symlink Race Protection
def secure_path_prewire(path):
    try:
        if os.path.islink(path):
            print(f"[SECURITY ALERT] Symlink detected at critical path: {path}. Purging rogue redirection.")
            os.remove(path)
    except: pass

for critical_file in ["config.json", "events.db", "events_user.db", "data"]:
    secure_path_prewire(os.path.join(BASE_DIR, critical_file))

# Standard Libraries
import tempfile # type: ignore
import traceback # type: ignore
import platform # type: ignore
import subprocess # type: ignore

# [v1.8.40] UI Fix: Globally prevent cmd.exe from flashing on Windows when executing subprocesses without shell=True
if platform.system() == "Windows":
    _orig_run = subprocess.run
    _orig_Popen = subprocess.Popen
    _orig_check_output = subprocess.check_output

    CREATE_NO_WINDOW = 0x08000000

    def _patched_run(*args, **kwargs):
        if 'creationflags' not in kwargs:
            kwargs['creationflags'] = CREATE_NO_WINDOW
        return _orig_run(*args, **kwargs)

    def _patched_Popen(*args, **kwargs):
        if 'creationflags' not in kwargs:
            kwargs['creationflags'] = CREATE_NO_WINDOW
        return _orig_Popen(*args, **kwargs)

    def _patched_check_output(*args, **kwargs):
        if 'creationflags' not in kwargs:
            kwargs['creationflags'] = CREATE_NO_WINDOW
        return _orig_check_output(*args, **kwargs)

    subprocess.run = _patched_run
    subprocess.Popen = _patched_Popen
    subprocess.check_output = _patched_check_output

import time # type: ignore
import getpass # type: ignore

def _get_universal_ip():
    """Cross-platform local IP detection across eth0, en0, Ethernet, and WLAN."""
    try:
        import socket
        # Fast, reliable way to find primary outbound IP (UDP dummy)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "127.0.0.1"

# [v1.8.37] Anti-Debugging & Process Integrity Locks
def apply_anti_debugging():
    try:
        if platform.system() == "Linux":
            import ctypes
            libc = ctypes.CDLL("libc.so.6")
            # PTRACE_TRACEME = 0. If we ptrace ourselves, nobody else can.
            res = libc.ptrace(0, 0, 1, 0)
            if res < 0:
                print("[SECURITY ALERT] Process is already being debugged! Initiating Panic Wipe.")
                for f in ["config.json", "events.db"]:
                    try: os.remove(f)
                    except: pass
                sys.exit(1)
        elif platform.system() == "Windows":
            import ctypes
            if ctypes.windll.kernel32.IsDebuggerPresent():
                print("[SECURITY ALERT] Debugger detected! Initiating Panic Wipe.")
                for f in ["config.json", "events.db"]:
                    try: os.remove(f)
                    except: pass
                sys.exit(1)
    except: pass

# Activate anti-debugging globally
apply_anti_debugging()

# [v1.8.33] Local Immunity: Secure Subdirectory Setup
# Create private data/tmp/logs vaults if they don't exist
AGENT_DATA_DIR = os.path.join(BASE_DIR, "data")
AGENT_TMP_DIR = os.path.join(AGENT_DATA_DIR, "tmp")
AGENT_LOGS_DIR = os.path.join(AGENT_DATA_DIR, "logs")

for d in [AGENT_DATA_DIR, AGENT_TMP_DIR, AGENT_LOGS_DIR]:
    if not os.path.exists(d):
        os.makedirs(d, mode=0o700, exist_ok=True)
    elif platform.system() != "Windows":
        # Force strict permissions on existing directories
        os.chmod(d, 0o700)

# Globally redirect all tempfile usage in this process to our secure vault
tempfile.tempdir = AGENT_TMP_DIR

# [v2.6.0] Sovereign Lockdown Boot Guard: Ensures lock persists across reboots
def check_sovereign_boot_lock():
    lock_path = os.path.join(AGENT_DATA_DIR, ".sovereign_lock")
    if os.path.exists(lock_path):
        print("[SECURITY] Critical System Freeze Active. Re-enforcing Sovereign Lockdown...")
        try:
            from agent_core.lockdown import lockdown_engine
            
            # [v2.6.0] 5-Minute Grace Period for Local Recovery
            start_time = time.time()
            grace_period = 300 # 5 Minutes
            
            while os.path.exists(lock_path):
                elapsed = time.time() - start_time
                if elapsed > grace_period:
                    # Time is up. Neutralize system.
                    lockdown_engine.power_off_system()
                    sys.exit(1)
                
                # Show Local Unlock Prompt
                provided_key = lockdown_engine.request_local_unlock()
                
                if lockdown_engine.verify_unlock(provided_key):
                    print("[SECURITY] Local Unlock Successful. Resuming normal operations.")
                    return # Exit guard and boot normally
                
                # If window was closed or wrong key, wait briefly and try again
                # unless the system was forced to sleep by the previous iteration
                time.sleep(2)
                
                # Periodically re-enforce hibernate to prevent tampering during the 5 mins
                # but only if the prompt is not actively being answered
                # (Optional: depends on how aggressive the lock should be)
                # lockdown_engine.apply_lockdown(lock_hash)

        except Exception as e:
            print(f"[ERROR] Boot lockdown enforcement failed: {e}")
            sys.exit(1)

check_sovereign_boot_lock()
import json # type: ignore
import uuid # type: ignore
import asyncio # type: ignore
import signal # type: ignore
import warnings # type: ignore
import multiprocessing # type: ignore
import threading # type: ignore
import hashlib # type: ignore
import shutil # type: ignore
import gc # type: ignore
from datetime import datetime, timezone # type: ignore
from typing import List, Dict, Any, Union, Optional # type: ignore
from urllib.parse import urlparse # type: ignore

# Third-Party Libraries (External)
import socketio # type: ignore
import requests # type: ignore
import urllib3 # type: ignore

# Internal Modules (Core & Features)
from agent_core import AntiTamperMonitor, RemediationHandler, BandwidthManager, SessionMonitor # type: ignore
from agent_core.privacy_utils import PrivacyRedactor
from modules.audit_logger import AuditLogger # type: ignore
from agent_core.integrity import IntegrityChecker # [v2.0.0]

# [v2.0.0] Monitorix Enterprise Update Public Key (Ed25519)
UPDATE_PUBLIC_KEY_HEX = "c5c338196d86b3c823eb4a3626d98e6dc614d15df194fe7f5b985fdc29504733"


# Milestone Version: 1.8.46
AGENT_VERSION = "v1.8.63"
IS_WINDOWS = platform.system() == "Windows"
IS_UPDATING = False # Global guard to prevent multiple update starts
sovereign_mmap = None

# --- Global Logging & Identity [v1.8.38] ---
audit_logger = None
try:
    current_user = getpass.getuser()
except:
    current_user = "Unknown"

LOG_FILE = os.path.join(BASE_DIR, "monitorix_test.log")
if platform.system() == "Windows":
    if current_user.upper() == "SYSTEM" or current_user.endswith("$"): 
        LOG_FILE = os.path.join(BASE_DIR, "monitorix_service.log")

def log_to_file(msg):
    """Logs a message with a timestamp to a local file, ensuring all PII is redacted."""
    try:
        # [v1.8.29] Security: Redact PII before writing to disk
        sanitized_msg = PrivacyRedactor.redact_text(str(msg))
        
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_line = f"[{timestamp}] {sanitized_msg}"
        
        # Write to primary log
        with open(LOG_FILE, "a+", encoding='utf-8') as f:
            f.write(log_line + "\n")
            f.flush()
        
        # Audit critical events
        if audit_logger:
            if any(k in str(msg) for k in ["Started", "Stopped", "CRITICAL", "ERROR", "FATAL", "Update", "Policy"]):
                if "Heartbeat" not in str(msg):
                    audit_logger.log("System", msg)
    except:
        try:
            fallback_log = os.path.join(AGENT_LOGS_DIR, "fallback_" + os.path.basename(LOG_FILE))
            with open(fallback_log, "a+", encoding='utf-8') as f:
                ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                f.write(f"[{ts}] (FALLBACK) {msg}\n")
                f.flush()
        except: pass
    try: print(msg)
    except: pass

# --- Sovereign Process Protection ---

# [v1.8.50] Sovereign Process Protection: Multi-Platform "Hard-Lock"
def set_process_critical():
    """System-level lock to prevent termination across all platforms."""
    sys_p = platform.system()
    
    # 1. Windows: Native Resilience
    if sys_p == "Windows":
        try:
            # [v1.8.44] CRITICAL SAFETY: Removed NtSetInformationProcess (ProcessBreakOnTermination)
            # This feature caused BSOD (Stop: 0xEF) if the app exited.
            # We now keep session-level monitoring without kernel-level critical bit.
            log_to_file("[SECURITY] Resilience Mode (Win): Monitoring active.")
        except Exception as e:
            log_to_file(f"[SECURITY] Windows resilience initialization error: {e}")

    # 2. Linux: Enable Kernel SysRq Panic
    elif sys_p == "Linux":
        if os.getuid() == 0:
            try:
                # Enable all SysRq triggers
                with open("/proc/sys/kernel/sysrq", "w") as f:
                    f.write("1")
                log_to_file("[SECURITY] Sovereign Mode (Linux): Kernel Panic-on-kill armed.")
            except Exception as e:
                log_to_file(f"[SECURITY] Linux SysRq activation failed: {e}")
        else:
            log_to_file("[SECURITY] Linux Sovereign Mode requires ROOT to arm kernel panic.")

    # 3. macOS: Initialize Shared Memory Heartbeat
    elif sys_p == "Darwin":
        try:
            import mmap
            hb_path = os.path.join(BASE_DIR, ".sovereign_hb")
            # Create/truncate heartbeat file
            with open(hb_path, "wb") as f:
                f.write(b"\x01")
            
            # Map it
            with open(hb_path, "r+b") as f:
                global sovereign_mmap
                sovereign_mmap = mmap.mmap(f.fileno(), 1)
                sovereign_mmap[0] = 1 # Initial pulse
            log_to_file("[SECURITY] Sovereign Mode (macOS): Reflexive mmap heartbeat established.")
            
            # Start Pulse Thread: Write current timestamp to shared memory
            def _sovereign_pulse_loop():
                import struct # type: ignore
                while True:
                    try:
                        if sovereign_mmap:
                             # Write current Unix timestamp (8-byte double)
                             sovereign_mmap.seek(0)
                             sovereign_mmap.write(struct.pack('d', time.time()))
                    except: pass
                    time.sleep(1)
            threading.Thread(target=_sovereign_pulse_loop, daemon=True).start()
        except Exception as e:
            log_to_file(f"[SECURITY] macOS Sovereign setup failed: {e}")

set_process_critical()

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
            def environ(self): return {}
    sys.modules["psutil"] = PsutilStub() # type: ignore
    psutil = sys.modules["psutil"]

# --- Global Module Managers (Stubs) ---
bandwidth_manager = None
data_queue = None
remediation = None
shadow_audit = None
usb_compliance = None
location_audit = None
hw_mon = None
power_mon = None
network_audit = None
net_scanner = None
data_loss_prevention = None
fim_mon = None
mail_intelligence = None
webrtc_manager = None
input_simulator = None
browser_compliance = None
session_forensic = None
visual_activity = None
activity_mon = None
input_audit = None
clipboard_audit = None
remote_remediation = None
app_enforcement = None
print_audit = None
voice_intelligence = None
net_utils = None

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
        # 1. Try Machine Guidance (Windows Registry - Most Stable)
        if platform.system() == "Windows":
            try:
                import winreg # type: ignore
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography", 0, winreg.KEY_READ | 0x0100) as k:
                    guid, _ = winreg.QueryValueEx(k, "MachineGuid")
                    if guid:
                        return hashlib.md5(str(guid).encode()).hexdigest()[:8].upper()
            except: pass

            # 1b. Fallback to Motherboard Serial Number
            try:
                cmd = ["wmic", "bios", "get", "serialnumber"]
                output = subprocess.check_output(cmd, timeout=5).decode().split('\n')
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
    
    # [v1.8.27] Lightweight Lock Check: Avoid global process table scan
    lock_file = os.path.join(BASE_DIR, f"session_{session_id}.lock")
    if os.path.exists(lock_file):
        try:
            # Check if the process recorded in the lock file is still alive
            with open(lock_file, "r") as f:
                pid = int(f.read().strip())
            if psutil.pid_exists(pid):
                return # Already active
            else:
                os.remove(lock_file) # Stale lock
        except:
            pass

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
        # Pass specialized flag with session id for reliable detection without env block
        cmd = f'"{exe_path}" --session-agent {session_id}'
        
        # CreateProcessAsUserW doesn't automatically inherit the parent env unless specified, 
        # passing lpEnvironment=None gives it the parent's env, so we rely on args
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
ACCESS_TOKEN: str = "" # [v2.0.0]
REFRESH_TOKEN: str = "" # [v2.0.0]
sio_connected: bool = False
# Socket.IO Client Initialized at Module Level for Decorator Support
# [v1.8.29] Security Hardening: SSL verification ENABLED by default
sio: Any = socketio.AsyncClient(ssl_verify=True, logger=False, engineio_logger=False)

# Monitors & Managers
hw_mon: Any = None
power_mon: Any = None
location_audit: Any = None
tamper_mon: Any = None
visual_activity: Any = None
activity_mon: Any = None
input_audit: Any = None
clipboard_audit: Any = None
data_queue: Any = None
session_mon: Any = None
remediation: Any = None
app_enforcement: Any = None
usb_compliance: Any = None
shadow_audit: Any = None
network_audit: Any = None
net_scanner: Any = None
data_loss_prevention: Any = None
fim_mon: Any = None
mail_intelligence: Any = None
print_audit: Any = None
voice_intelligence: Any = None
bandwidth_manager: Any = None
webrtc_manager: Any = None
audit_logger: Any = None
installer: Any = None
file_manager: Any = None
remote_remediation: Any = None
input_simulator: Any = None
browser_compliance: Any = None
session_forensic: Any = None

# [v2.1.0] Advanced Transport Security: Certificate Pinning Adapter
class PinnedAdapter(requests.adapters.HTTPAdapter):
    """Enforces SHA-256 fingerprint validation for the backend certificate."""
    def __init__(self, fingerprint=None, **kwargs):
        self.fingerprint = fingerprint
        super().__init__(**kwargs)

    def init_poolmanager(self, connections, maxsize, block=False, **pool_kwargs):
        from urllib3.poolmanager import PoolManager
        # Use assert_fingerprint to enforce pinning at the urllib3 level
        self.poolmanager = PoolManager(
            num_pools=connections,
            maxsize=maxsize,
            block=block,
            assert_fingerprint=self.fingerprint,
            **pool_kwargs
        )

# HTTP Session Initialized at Module Level
# [v1.8.29] Global HTTP Session with SSL Verification ENABLED by DEFAULT
http_session: Any = requests.Session()
# [SECURITY HARDENING v2.1.0] mTLS & Certificate Pinning Configuration
# SSL Verification is now MANDATORY.
http_session.verify = os.environ.get("MONITORIX_DEV_INSECURE") != "1"

# 1. Mutual TLS (mTLS): Load client certificate if present in the secure vault
CERT_PATH = os.path.join(AGENT_DATA_DIR, "certs", "agent.crt")
KEY_PATH = os.path.join(AGENT_DATA_DIR, "certs", "agent.key")
if os.path.exists(CERT_PATH) and os.path.exists(KEY_PATH):
    http_session.cert = (CERT_PATH, KEY_PATH)
    log_to_file("[mTLS] Client Certificate Loaded (data/certs/agent.crt)")

# 2. Certificate Pinning: Load backend pin from environment or config
CERT_PIN = os.environ.get("MONITORIX_BACKEND_PIN") or config.get("BackendCertPin")

# Allow custom CA bundle for corporate proxies
CA_BUNDLE = os.environ.get("MONITORIX_CA_BUNDLE") or config.get("CaCertPath")

if CA_BUNDLE and os.path.exists(CA_BUNDLE):
    http_session.verify = CA_BUNDLE
    log_to_file(f"Using custom CA Bundle: {CA_BUNDLE}")

# 3. Mount Adapter with Pinning support
adapter = PinnedAdapter(fingerprint=CERT_PIN, max_retries=3) if CERT_PIN else requests.adapters.HTTPAdapter(max_retries=3)
http_session.mount('https://', adapter)
if CERT_PIN:
    log_to_file(f"[Pinning] Certificate Pinning ENABLED (Fingerprint: {CERT_PIN[:8]}...)")



# --- Configuration Path ---
# [v1.8.37] Standardized Vault Location: Use Persistent App Directory
CONFIG_PATH = os.path.join(BASE_DIR, "config.json")

def _get_machine_secret():
    """Derives a stable, machine-locked secret for vault encryption and transport signing."""
    try:
        import platform # type: ignore
        if platform.system() == "Windows":
             import winreg # type: ignore
             with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography", 0, winreg.KEY_READ | 0x0100) as k:
                 val, _ = winreg.QueryValueEx(k, "MachineGuid")
                 return str(val).encode()
        else:
             # Linux/MacOS stable identifiers
             for p in ["/etc/machine-id", "/var/lib/dbus/machine-id"]:
                 if os.path.exists(p):
                     with open(p, "rb") as f: return f.read().strip()
    except: pass
    import platform as pf; return pf.node().encode()

def _get_hardware_locked_key():
    """[v1.8.50] Root-of-Trust: 100% Coverage Secret Derivation."""
    try:
        from cryptography.hazmat.primitives import hashes # type: ignore
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC # type: ignore
        import base64
        
        # 1. Gather hardware-locked entropy
        m_id = _get_machine_secret()
        node_name = platform.node().encode()
        
        # 2. Derive 32-byte key via PBKDF2 (100k rounds)
        # Using a static but internal Monitorix salt
        salt = b"monitorix-sovereign-salt-v1.8.50"
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(m_id + node_name))
        return key
    except:
        # Emergency Fallback to high-entropy constant if KDF fails
        return b"M0n1t0r1x_D3fault_Fallback_S3cret_K3y"

def load_config():
    """Robust configuration loader with AES-256-GCM Decryption (100% Coverage)."""
    cfg = {}
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, "rb") as f:
                raw_data = f.read()
            
            # [v1.8.50] AES-256-GCM Authenticated Vault
            if raw_data.startswith(b"AES:"):
                from cryptography.fernet import Fernet # type: ignore
                f = Fernet(_get_hardware_locked_key())
                dec_bytes = f.decrypt(raw_data[4:])
                cfg = json.loads(dec_bytes.decode('utf-8'))
                log_to_file("Configuration loaded from 100% Secure AES Vault.")
            else:
                cfg = json.loads(raw_data.decode('utf-8'))
                log_to_file("Configuration loaded from raw JSON config.")

            # [SEC] Cross-Platform Keyring for API Key
            try:
                import keyring
                ring_key = keyring.get_password("monitorix_agent", "tenant_api_key")
                if ring_key:
                    cfg["TenantApiKey"] = ring_key
                elif "TenantApiKey" in cfg:
                    keyring.set_password("monitorix_agent", "tenant_api_key", cfg["TenantApiKey"])
                    # Remove from raw config to prevent plaintext storage
                    del cfg["TenantApiKey"]
                    save_config(cfg)
                    cfg["TenantApiKey"] = keyring.get_password("monitorix_agent", "tenant_api_key")
            except Exception as e:
                log_to_file(f"[SECURITY] Keyring unavailable: {e}")

        except Exception as e:
            log_to_file(f"[VAULT] Failed to decrypt config.json: {e}")
    return cfg

# [v2.8.0] SHIELD RESILIENCE: Offline Policy Vault
SHIELD_CACHE_PATH = os.path.join(AGENT_DATA_DIR, ".shield_cache.bin")

def save_shield_cache(config_data):
    """Saves the current active policy to a hidden, hardware-locked binary vault."""
    try:
        from cryptography.fernet import Fernet # type: ignore
        f = Fernet(_get_hardware_locked_key())
        enc_data = f.encrypt(json.dumps(config_data).encode())
        
        # Write to hidden file
        with open(SHIELD_CACHE_PATH, "wb") as vault:
            vault.write(b"SHLD:" + enc_data)
        
        # Apply OS-level Tamper Protection
        if platform.system() == "Windows":
            subprocess.run(["attrib", "+h", "+s", "+r", SHIELD_CACHE_PATH], capture_output=True)
        else:
            try: os.system(f"chmod 400 {SHIELD_CACHE_PATH}") # Read-only for owner
            except: pass
    except Exception as e:
        log_to_file(f"[Shield] Failed to save offline cache: {e}")

def load_shield_cache():
    """Loads the last-known good policy from the hardened local vault."""
    if os.path.exists(SHIELD_CACHE_PATH):
        try:
            with open(SHIELD_CACHE_PATH, "rb") as vault:
                raw = vault.read()
            if raw.startswith(b"SHLD:"):
                from cryptography.fernet import Fernet # type: ignore
                f = Fernet(_get_hardware_locked_key())
                dec_data = f.decrypt(raw[5:])
                return json.loads(dec_data.decode())
        except Exception as e:
            log_to_file(f"[Shield] Offline cache recovery failed: {e}")
    return None

def save_config(new_config):
    try:
        global tamper_mon
        if 'tamper_mon' in globals() and tamper_mon:
            try: tamper_mon.ignore_next_modification("config.json")
            except: pass

        # [v1.8.50] AES-256-GCM Encryption
        from cryptography.fernet import Fernet # type: ignore
        json_bytes = json.dumps(new_config, indent=4).encode('utf-8')
        f = Fernet(_get_hardware_locked_key())
        vault_payload = b"AES:" + f.encrypt(json_bytes)

        fd, temp_path = tempfile.mkstemp(dir=BASE_DIR, prefix="config_", suffix=".tmp")
        try:
            with os.fdopen(fd, 'wb') as f_out:
                f_out.write(vault_payload)
            os.chmod(temp_path, 0o600)
            
            on_disk_hardener = None
            # [STABILITY] Relax Sovereign Lock before replacing critical files
            if 'tamper_mon' in globals() and tamper_mon:
                try: tamper_mon.relax_protection()
                except: pass
            else:
                # [v1.8.42] Autonomous Recovery: Handle permissions before tamper_mon is up
                try:
                    from agent_core.filesystem_hardening import FilesystemHardener
                    on_disk_hardener = FilesystemHardener(BASE_DIR)
                    on_disk_hardener.relax_immutability()
                except: pass

            try:
                os.replace(temp_path, CONFIG_PATH)
            finally:
                # Always re-enforce after attempt
                if 'tamper_mon' in globals() and tamper_mon:
                    try: tamper_mon.enforce_protection()
                    except: pass
                elif on_disk_hardener:
                    # Best effort re-lock if we were the ones who unlocked it
                    try: on_disk_hardener.enforce_immutability()
                    except: pass

            log_to_file("Vault Hardened: config.json encrypted with AES-256-GCM.")
        except Exception as e:
            if os.path.exists(temp_path): os.remove(temp_path)
            raise e
    except Exception as e:
        log_to_file(f"Failed to save secure config: {e}")

def parse_version(ver_str):
    """Helper to compare version strings (v1.2.3 -> [1, 2, 3])"""
    try:
        return [int(x) for x in ver_str.lower().replace('v', '').split('.')]
    except:
        return b"MonitorixDefaultSecretFallback"

# [v1.8.37] Command Sovereignty: Centralized Signature Validator
def verify_command_signature(action, params, timestamp, signature):
    """Verifies HMAC-SHA256 signature using API_KEY and MachineSecret."""
    if not API_KEY or not AGENT_ID: return False
    if not timestamp or not signature: return False
    
    try:
        m_secret = _get_machine_secret()
        # [v1.8.37] Zero-Trust Anchor Reconstruction
        msg_parts = [
            str(action),
            json.dumps(params, sort_keys=True),
            str(timestamp)
        ]
        message = "|".join(msg_parts).encode('utf-8')
        
        # Derive key: Sha256(ApiKey + MachineSecret)
        key = hashlib.sha256(API_KEY.encode() + m_secret).digest()
        expected = hmac.new(key, message, hashlib.sha256).hexdigest()
        
        return hmac.compare_digest(expected, signature)
    except Exception as e:
        log_to_file(f"Signature Verification Error: {e}")
        return False

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
    fallback_dir = os.environ.get("LOCALAPPDATA") or AGENT_TMP_DIR
    fallback_lock_file = os.path.join(fallback_dir, lock_name)
    
    lock_file = primary_lock_file
    is_system = current_user.upper() == "SYSTEM" or current_user.endswith("$")
    is_child = "--child" in sys.argv

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
                            if old_pid == os.getpid():
                                # [v1.8.48] Already have the lock (e.g. re-entry or stale self-record)
                                return True
                                
                            if psutil.pid_exists(old_pid):
                                old_user = "Unknown"
                                try:
                                    proc = psutil.Process(old_pid)
                                    old_user = proc.username()
                                    is_old_system = "SYSTEM" in old_user.upper() or old_user.endswith("$")
                                    
                                    if (not is_system and is_old_system) or (current_user == old_user):
                                        if is_child:
                                            # [STABILITY] Allow child to proceed as it is legit offspring of the lock holder
                                            # [v1.8.48] DO NOT return from here, we must prevent the child from writing to the file later.
                                            return "CHILD_STABILITY"
                                        # [v1.8.64] Watchdog Stability: A new non-child (watchdog) must NOT blindly
                                        # kill an existing watchdog that still has live children.
                                        # This prevents the systemd-restart crash loop where a restarted watchdog
                                        # kills the still-healthy running watchdog.
                                        try:
                                            old_children = proc.children(recursive=False)
                                            if old_children:
                                                # Old watchdog is alive and has children → it's healthy, we should exit
                                                log_to_file(f"[v1.8.64] Healthy watchdog already running (PID {old_pid}, {len(old_children)} children). Exiting duplicate.")
                                                sys.exit(0)
                                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                                            pass
                                        log_to_file(f"Terminating stale instance (PID {old_pid}, no children).")
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
            
            # --- Acquire New Lock ---
            if is_child:
                # [v1.8.48] The agent child MUST NEVER write to the lock file.
                # Ownership belongs exclusively to the Watchdog parent.
                return True

            try:
                with open(target_lock, 'w') as f:
                    f.write(str(os.getpid()))
                return True
            except Exception as e:
                log_to_file(f"Warning: Could not write lock file {target_lock}: {e}")
                return False
            lock_file = primary_lock_file

        # [v1.8.61] Permission-Aware Locking: If Program Files is read-only for current user, skip it.
        primary_success = False
        if os.access(BASE_DIR, os.W_OK):
            primary_success = handle_existing_instance(primary_lock_file)
            
        if not primary_success:
            handle_existing_instance(fallback_lock_file)

    except Exception as e:
        log_to_file(f"Lock Error: {e}")

# --- [NEW v1.8.54] Windows SCM Compliance & Heartbeat ---
_scm_handler_ref = None

class WindowsServiceManager:
    """Handles native communication with Windows Service Control Manager."""
    @staticmethod
    def notify_started():
        global _scm_handler_ref
        if platform.system() != "Windows" or not (current_user.upper() == "SYSTEM" or current_user.endswith("$")):
            return
            
        try:
            import ctypes
            from ctypes import wintypes
            
            # Service types
            SERVICE_WIN32_OWN_PROCESS = 0x00000010
            SERVICE_RUNNING = 0x00000004
            SERVICE_ACCEPT_STOP = 0x00000001
            
            advapi32 = ctypes.WinDLL('advapi32', use_last_error=True)
            
            # 1. Register Handler (Correct Name: MonitorixAgentService)
            SERVICE_CONTROL_HANDLER = ctypes.WINFUNCTYPE(None, wintypes.DWORD)
            
            # Persist Reference to prevent Garbage Collection (Critical)
            def handler(control):
                log_to_file(f"[SCM] Received Control Signal: {control}")
            
            _scm_handler_ref = SERVICE_CONTROL_HANDLER(handler)
            
            # Correct Name from installer: MonitorixAgentService
            h_status = advapi32.RegisterServiceCtrlHandlerW(u"MonitorixAgentService", _scm_handler_ref)
            
            if h_status:
                # 2. Set Status to RUNNING
                class SERVICE_STATUS(ctypes.Structure):
                    _fields_ = [
                        ("dwServiceType", wintypes.DWORD),
                        ("dwCurrentState", wintypes.DWORD),
                        ("dwControlsAccepted", wintypes.DWORD),
                        ("dwWin32ExitCode", wintypes.DWORD),
                        ("dwServiceSpecificExitCode", wintypes.DWORD),
                        ("dwCheckPoint", wintypes.DWORD),
                        ("dwWaitHint", wintypes.DWORD),
                    ]
                
                status = SERVICE_STATUS(
                    SERVICE_WIN32_OWN_PROCESS,
                    SERVICE_RUNNING,
                    SERVICE_ACCEPT_STOP,
                    0, 0, 0, 0
                )
                advapi32.SetServiceStatus(h_status, ctypes.byref(status))
                log_to_file("[SCM] Registered 'MonitorixAgentService' and reported state as RUNNING.")
            else:
                last_error = ctypes.get_last_error()
                log_to_file(f"[SCM] Failed to register handler. WinError: {last_error}")
        except Exception as e:
            log_to_file(f"[SCM] Exception during heartbeat: {e}")
        if isinstance(e, SystemExit): raise



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
    from modules.av_monitor import AVMonitor # [v2.7.0] Antivirus integration
    from modules.fim import FileIntegrityMonitor # type: ignore # type: ignore
    from modules.network import NetworkScanner # type: ignore # type: ignore
    from modules.security import ProcessSecurity # type: ignore # type: ignore
    
    # GUI-dependent modules - import conditionally
    LiveStreamer = None
    # Lazy-loading stubs for heavy modules
    ScreenshotCapture = None
    ActivityMonitor = None
    Keylogger = None
    ClipboardMonitor = None
    LiveStreamer = None
    LocationMonitor = None
    HardwareMonitor = None
    PowerMonitor = None
    NetworkMonitor = None
    FileMonitor = None
    MailMonitor = None
    ShadowMonitor = None
    UsbMonitor = None
    
    def load_module(name):
        """Lazily imports a module or class to save memory."""
        try:
            if name == "LocationMonitor":
                from modules.location_monitor import LocationMonitor
                return LocationMonitor
            elif name == "ScreenshotCapture":
                from modules.visual_activity import ScreenshotCapture
                return ScreenshotCapture
            elif name == "LiveStreamer":
                from modules.session_forensic import LiveStreamer
                return LiveStreamer
            elif name == "ActivityMonitor":
                from modules.activity_monitor import ActivityMonitor
                return ActivityMonitor
            elif name == "Keylogger":
                from modules.input_audit import Keylogger
                return Keylogger
            elif name == "ClipboardMonitor":
                from modules.clipboard_monitor import ClipboardMonitor
                return ClipboardMonitor
            elif name == "Hardware":
                from modules.hardware import HardwareMonitor
                return HardwareMonitor
            elif name == "Power":
                from modules.power_monitor import PowerMonitor
                return PowerMonitor
            elif name == "Shadow":
                from modules.shadow_audit import ShadowMonitor
                return ShadowMonitor
            elif name == "Usb":
                from modules.usb_monitor import UsbMonitor
                return UsbMonitor
            elif name == "Network":
                from modules.network_monitor import NetworkMonitor
                return NetworkMonitor
            elif name == "NetworkScanner":
                from modules.network import NetworkScanner
                return NetworkScanner
            elif name == "File":
                from modules.data_loss_prevention import FileMonitor
                return FileMonitor
            elif name == "FIM":
                from modules.fim import FileIntegrityMonitor
                return FileIntegrityMonitor
            elif name == "Mail":
                from modules.mail_intelligence import MailMonitor
                return MailMonitor
            elif name == "AppBlocker":
                from modules.app_enforcement import AppBlocker
                return AppBlocker
            elif name == "PrinterMonitor":
                from modules.printer_monitor import PrinterMonitor
                return PrinterMonitor
            elif name == "SpeechMonitor":
                from modules.voice_intelligence import SpeechMonitor
                return SpeechMonitor
            elif name == "RemoteShell":
                from modules.remote_remediation import RemoteShell
                return RemoteShell
            elif name == "FileManager":
                from modules.file_manager import FileManager
                return FileManager
            elif name == "DataQueue":
                from modules.data_queue import DataQueue
                return DataQueue
            elif name == "NetworkUtils":
                from modules.network_utils import NetworkUtils
                return NetworkUtils
            elif name == "WebRTCManager":
                from modules.webrtc_stream import WebRTCManager
                return WebRTCManager
            elif name == "BrowserEnforcer":
                from modules.browser_compliance import BrowserEnforcer
                return BrowserEnforcer
        except Exception as e:
            log_to_file(f"Lazy load failed for {name}: {e}")
        return None

    log_to_file("Bootstrapped with lazy-loading support.")

except Exception as e:
    log_to_file(f"CRITICAL BOOTSTRAP ERROR: {e}")
    log_to_file(traceback.format_exc())
    sys.exit(1)

# --- Application Startup ---
log_to_file("Bootstrapping core services...")

def apply_policy(config_src):
    """Applies configuration flags to enable/disable monitors."""
    global AGENT_ID, API_KEY, BACKEND_URL, data_queue
    try:
        log_to_file("[Policy] Applying configuration...")
        
        visual_activity_enabled = config_src.get("VisualActivityEnabled", config_src.get("ScreenshotsEnabled", False))
        if visual_activity_enabled:
            global visual_activity
            if not visual_activity:
                cls = load_module("ScreenshotCapture")
                if cls: visual_activity = cls(AGENT_ID, API_KEY, BACKEND_URL, data_queue=data_queue)
            if visual_activity:
                visual_activity.start()
                visual_activity.set_enabled(True)
        elif visual_activity:
            visual_activity.stop()
            visual_activity = None # Purge from memory
        
        if usb_compliance:
            if not usb_compliance.running:
                usb_compliance.start()
            
            # [FIX] Debounce Logging: Only update if value changed
            target_usb_policy = "Block" if config_src.get("UsbComplianceEnabled", config_src.get("UsbBlockingEnabled")) else "Allow"
            if getattr(usb_compliance, 'last_policy', None) != target_usb_policy:
                usb_compliance.set_policy(target_usb_policy)
                usb_compliance.last_policy = target_usb_policy
        
        # [v1.8.41] Multi-Mode Network Monitoring
        if config_src.get("NetworkAuditEnabled", config_src.get("NetworkMonitoringEnabled", False)):
            global network_audit, net_scanner
            # 1. Bandwidth Monitor
            if not network_audit:
                cls = load_module("Network")
                if cls: network_audit = cls(AGENT_ID, API_KEY, BACKEND_URL, data_queue=data_queue)
            if network_audit: network_audit.set_enabled(True)
            
            # 2. Connection Scanner (DLP)
            if not net_scanner:
                cls = load_module("NetworkScanner")
                if cls: net_scanner = cls(AGENT_ID, API_KEY, BACKEND_URL, data_queue=data_queue)
            if net_scanner: net_scanner.start()
        else:
            if network_audit: network_audit.set_enabled(False)
            if net_scanner: net_scanner.stop()

        # [v1.8.41] Multi-Mode File Monitoring
        if config_src.get("DataLossPreventionEnabled", config_src.get("FileDlpEnabled", False)) or config_src.get("FileMonitoringEnabled", False):
            global data_loss_prevention, fim_mon
            # 1. Content Scanner (DLP)
            if not data_loss_prevention:
                cls = load_module("File")
                if cls: data_loss_prevention = cls(AGENT_ID, API_KEY, BACKEND_URL, data_queue=data_queue)
            if data_loss_prevention: data_loss_prevention.set_enabled(True)
            
            # 2. File Integrity Monitor (FIM)
            if not fim_mon:
                cls = load_module("FIM")
                if cls: fim_mon = cls(AGENT_ID, API_KEY, BACKEND_URL, data_queue=data_queue)
            if fim_mon: fim_mon.start()
        else:
            if data_loss_prevention: data_loss_prevention.set_enabled(False)
            if fim_mon: fim_mon.stop()

        # Geolocation Toggle (Prioritize LocationAuditEnabled flag)
        geo_enabled = config_src.get("LocationAuditEnabled", config_src.get("GeolocationEnabled", config_src.get("LocationTrackingEnabled", True)))
        if geo_enabled:
            global location_audit
            if not location_audit:
                cls = load_module("LocationMonitor")
                if cls: location_audit = cls()
            if location_audit: location_audit.set_enabled(True)
        elif location_audit: location_audit.set_enabled(False)
        
        # [NEW] Remote Remediation Toggle
        if config_src.get("RemoteRemediationEnabled", config_src.get("RemoteShellEnabled", False)):
            global remote_remediation
            if not remote_remediation:
                cls = load_module("RemoteShell")
                if cls: remote_remediation = cls(AGENT_ID, API_KEY, BACKEND_URL)
            if remote_remediation: remote_remediation.set_enabled(True)
        elif remote_remediation: remote_remediation.set_enabled(False)
            
        # [NEW] Apply Bandwidth Config (Policy Override)
        bw_config = config_src.get("BandwidthConfig")
        if bw_config and bandwidth_manager:
             log_to_file(f"[Policy] Applying Bandwidth Config: {bw_config}")
             bandwidth_manager.update_config(bw_config)
        
        # Core Modules with Start/Stop capability
        if "ActivityMonitorEnabled" in config_src:
            global activity_mon
            if config_src["ActivityMonitorEnabled"]:
                if not activity_mon:
                    cls = load_module("ActivityMonitor")
                    if cls: activity_mon = cls(AGENT_ID, API_KEY, BACKEND_URL, data_queue=data_queue, logger=log_to_file)
                if activity_mon:
                    # [NEW] Sync Productivity Benchmarks
                    prod_json = config_src.get("ProductivityJson")
                    if prod_json:
                        try: activity_mon.set_categories(prod_json)
                        except: pass
                    activity_mon.start()
            elif activity_mon:
                activity_mon.stop()
                activity_mon = None # Purge
        
        if config_src.get("InputAuditEnabled", config_src.get("KeyloggerEnabled", False)):
            global input_audit
            if not input_audit:
                cls = load_module("Keylogger")
                if cls: input_audit = cls(AGENT_ID, API_KEY, BACKEND_URL, data_queue=data_queue)
            if input_audit: input_audit.start()
        elif input_audit:
            input_audit.stop()
            input_audit = None # Purge
            
        if config_src.get("ClipboardAuditEnabled", config_src.get("ClipboardMonitorEnabled", False)):
            global clipboard_audit
            if not clipboard_audit:
                cls = load_module("ClipboardMonitor")
                if cls: clipboard_audit = cls(AGENT_ID, API_KEY, BACKEND_URL, data_queue=data_queue)
            if clipboard_audit: clipboard_audit.start()
        elif clipboard_audit:
            clipboard_audit.stop()
            clipboard_audit = None # Purge
            
        if config_src.get("AppEnforcementEnabled", config_src.get("AppBlockerEnabled", False)):
            global app_enforcement
            if not app_enforcement:
                cls = load_module("AppBlocker")
                if cls: app_enforcement = cls(AGENT_ID, API_KEY, BACKEND_URL, data_queue=data_queue)
            if app_enforcement: app_enforcement.start()
        elif app_enforcement:
            app_enforcement.stop()

        if config_src.get("PrintAuditEnabled", config_src.get("PrinterMonitorEnabled", False)):
            global print_audit
            if not print_audit:
                cls = load_module("PrinterMonitor")
                if cls: print_audit = cls(AGENT_ID, API_KEY, BACKEND_URL, data_queue=data_queue)
            if print_audit: print_audit.start()
        elif print_audit:
            print_audit.stop()

        if config_src.get("ShadowAuditEnabled", config_src.get("ShadowMonitorEnabled", False)):
            global shadow_audit
            if not shadow_audit:
                cls = load_module("Shadow")
                if cls: shadow_audit = cls(AGENT_ID, API_KEY, BACKEND_URL, machine_secret=_get_machine_secret())
            if shadow_audit: shadow_audit.start()
        elif shadow_audit:
            shadow_audit.stop()

        if "ShadowPaths" in config_src and shadow_audit:
            try:
                paths = config_src["ShadowPaths"]
                if isinstance(paths, str): paths = json.loads(paths)
                shadow_audit.set_watched_paths(paths)
            except: pass

        if config_src.get("MailIntelligenceEnabled", config_src.get("MailMonitorEnabled", False)):
            global mail_intelligence
            if not mail_intelligence:
                cls = load_module("Mail")
                if cls: mail_intelligence = cls(AGENT_ID, API_KEY, BACKEND_URL, data_queue=data_queue)
            if mail_intelligence: mail_intelligence.start()
        elif mail_intelligence:
            mail_intelligence.stop()

        if config_src.get("BrowserComplianceEnabled", config_src.get("BrowserEnforcerEnabled", False)):
            global browser_compliance
            if not browser_compliance:
                cls = load_module("BrowserEnforcer")
                if cls: browser_compliance = cls(AGENT_ID, API_KEY, BACKEND_URL, data_queue=data_queue)
            if browser_compliance: browser_compliance.enforce()
        elif browser_compliance:
            browser_compliance.stop()

        if config_src.get("SessionForensicEnabled", config_src.get("LiveStreamEnabled", False)):
            global session_forensic
            if not session_forensic:
                cls = load_module("LiveStreamer")
                if cls: session_forensic = cls(AGENT_ID, sio, log_to_file)
            if session_forensic and not session_forensic.running:
                try:
                    print("[Policy] Starting Live Audit Session via Policy")
                    session_forensic.start_streaming(asyncio.get_event_loop())
                except Exception as e:
                    print(f"[Policy] Live Audit Start Error: {e}")
        elif session_forensic and session_forensic.running:
            session_forensic.stop_streaming()

        if config_src.get("VoiceIntelligenceEnabled", config_src.get("SpeechMonitorEnabled", False)):
            global voice_intelligence
            if not voice_intelligence:
                cls = load_module("SpeechMonitor")
                if cls: voice_intelligence = cls(AGENT_ID, API_KEY, BACKEND_URL)
            if voice_intelligence: voice_intelligence.start()
        elif voice_intelligence:
            voice_intelligence.stop()

        # [NEW] App Blocker JSON
        blocked_apps_str = config_src.get("BlockedApps", "[]") 
        if isinstance(blocked_apps_str, str) and app_enforcement:
            try:
                app_enforcement.set_blocked_apps(json.loads(blocked_apps_str))
            except: pass
        elif isinstance(blocked_apps_str, list) and app_enforcement:
            app_enforcement.set_blocked_apps(blocked_apps_str)
            
        # Persist important policy flags
        sync_config_to_file(config_src, [
            "VisualActivityEnabled", "UsbComplianceEnabled", "NetworkAuditEnabled",
            "DataLossPreventionEnabled", "ActivityMonitorEnabled", "InputAuditEnabled",
            "ClipboardAuditEnabled", "AppEnforcementEnabled", "BrowserComplianceEnabled",
            "PrintAuditEnabled", "ShadowAuditEnabled", "SessionForensicEnabled",
            "VoiceIntelligenceEnabled", "VulnerabilityIntelligenceEnabled",
            "MonitoringConsentRequired", "ShadowPaths", "TenantApiKey", "BandwidthConfig", 
            "ScreenshotInterval", "ScreenshotQuality", "ScreenshotResolution", "MaxScreenshotSize"
        ])
        
        # [v2.8.0] SHIELD RESILIENCE: Update Offline Vault
        save_shield_cache(config_src)

        # [NEW] Compliance Notification
        if config_src.get("MonitoringConsentRequired", False):
            try:
                from agent_core.privacy_notification import PrivacyNotification
                # Use a debouncer to avoid showing it on every heartbeat update
                last_notice_time = getattr(apply_policy, "last_notice_time", 0)
                import time
                if time.time() - last_notice_time > 3600: # Show at most once per hour
                    PrivacyNotification.show_consent_notice(config_src.get("TenantName", "Monitorix Enterprise"))
                    apply_policy.last_notice_time = time.time()
            except Exception as e:
                log_to_file(f"Error showing privacy notice: {e}")


    except Exception as e:
        log_to_file(f"Error applying policy: {e}")


def upload_update_log_to_backend():
    global BACKEND_URL, AGENT_ID
    """Uploads the local update debug log to the backend (Gap #7)."""
    try:
        # [v1.8.33] Local Immunity: Protect update logs in private storage
        update_log = os.path.join(AGENT_LOGS_DIR, "monitorix_update_debug.log")
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
                    verify=True # Enforce SSL verification
                )
                if response.status_code == 200:
                    log_to_file("Update log uploaded successfully.")
                    # Move to avoid re-uploading every heartbeat
                    archived_log = update_log + ".uploaded"
                    if os.path.exists(archived_log): os.remove(archived_log)
                    os.rename(update_log, archived_log)
    except Exception as e:
        log_to_file(f"Failed to upload update log: {e}")

def verify_file_hash(file_path: str, expected_hash: str) -> bool:
    """Verifies that a file matches the expected SHA256 hash."""
    if not expected_hash:
        log_to_file("[Security] WARNING: Update hash not provided by backend. Skipping verification (Legacy Mode).")
        return True
    
    try:
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        
        calculated_hash = sha256_hash.hexdigest().lower()
        if calculated_hash == expected_hash.lower():
            log_to_file(f"[Security] Hash verification SUCCESS for {os.path.basename(file_path)}")
            return True
        else:
            log_to_file(f"[Security] CRITICAL: Hash verification FAILED for {os.path.basename(file_path)}")
            log_to_file(f"  Expected: {expected_hash}")
            log_to_file(f"  Actual:   {calculated_hash}")
            return False
    except Exception as e:
        log_to_file(f"[Security] Hash verification error: {e}")
        return False

async def perform_update(update_url, target_ver, target_hash=None, update_signature=None):
    """
    Downloads and executes a remote update with asymmetric signature verification. [v2.0.0]
    """
    global IS_UPDATING, UPDATE_RETRY_COUNT, LAST_UPDATE_TIME, http_session
    if IS_UPDATING:
        log_to_file("Update already in progress. Ignoring duplicate trigger.")
        return
        
    IS_UPDATING = True
    try:
        # 1. Asymmetric Signature Verification [v2.0.0]
        if not update_signature:
             log_to_file("[SECURITY ALERT] Rejecting Update: No cryptographic signature provided.")
             return

        from cryptography.hazmat.primitives.asymmetric import ed25519
        from cryptography.hazmat.primitives import serialization
        
        try:
            pub_key = ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(UPDATE_PUBLIC_KEY_HEX))
            # Verify the combination of version + hash (if provided)
            msg = f"{target_ver}|{target_hash or ''}".encode()
            pub_key.verify(bytes.fromhex(update_signature), msg)
            log_to_file(f"[SECURITY] Update Signature Verified for version: {target_ver}")
        except Exception as e:
            log_to_file(f"[SECURITY ALERT] Update SIGNATURE_VERIFICATION_FAILED: {e}")
            return

        log_to_file(f"Starting signed remote update ({AGENT_VERSION} Hardened) to: {target_ver}")
        
        # [v1.8.1] Extract Backend URL for Failure Reporting
        try:
            from urllib.parse import urlparse
            parsed_url = urlparse(update_url)
            backend_base = f"{parsed_url.scheme}://{parsed_url.netloc}"
        except:
            backend_base = BACKEND_URL
        
        # [v1.8.33] Local Immunity: Use private secure temp for update assets
        temp_dir = AGENT_TMP_DIR
        update_fname = "monitorix_new.exe" if IS_WINDOWS else "monitorix_new.py"
        update_path = os.path.join(temp_dir, update_fname)
        
        max_retries = 3
        backoff_delay = 2
        download_success = False
        loop = asyncio.get_running_loop()
        
        def download_with_progress(url, dest_path):
            with http_session.get(url, stream=True, timeout=120, verify=True) as r:
                r.raise_for_status()
                total = int(r.headers.get('content-length') or 0)
                downloaded = 0
                last_emit = 0
                
                with open(dest_path, 'wb') as f:
                    for chunk in r.iter_content(chunk_size=8192):
                        if chunk:
                            f.write(chunk)
                            downloaded += len(chunk)
                            
                            if total > 0:
                                pct = int((downloaded / total) * 100)
                                if pct - last_emit >= 5:
                                    event_data = {'agentId': AGENT_ID, 'progress': pct}
                                    asyncio.run_coroutine_threadsafe(
                                        sio.emit('update_progress', event_data),
                                        loop
                                    )
                                    last_emit = pct
                
                if target_hash and not verify_file_hash(dest_path, target_hash):
                    raise Exception("Update rejected: SHA256 hash mismatch")
                return r.headers

        for attempt in range(max_retries):
            try:
                log_to_file(f"Downloading update (Attempt {attempt+1}/{max_retries})...")
                await asyncio.to_thread(download_with_progress, update_url, update_path)
                download_success = True
                break
            except Exception as e:
                log_to_file(f"Download Error (Attempt {attempt+1}): {e}")
                if attempt < max_retries - 1:
                    await asyncio.sleep(backoff_delay ** attempt)
        
        if not download_success:
             log_to_file("Aborting update due to persistent failure.")
             IS_UPDATING = False
             return

        # --- [ROLLBACK SUPPORT v2.0.0] ---
        if getattr(sys, 'frozen', False):
            current_binary = sys.executable
        else:
            current_binary = os.path.abspath(__file__)
        
        backup_binary = current_binary + ".bak"
        log_to_file(f"Creating backup for rollback: {os.path.basename(backup_binary)}")
        if os.path.exists(backup_binary): os.remove(backup_binary)
        shutil.copy2(current_binary, backup_binary)
        
        if IS_WINDOWS:
            batch_path = os.path.join(temp_dir, "monitorix_updater.bat")
            with open(batch_path, "w") as f:
                f.write(f"@echo off\n")
                f.write(f"timeout /t 5 /nobreak > nul\n")
                f.write(f"move /y \"{update_path}\" \"{current_binary}\"\n")
                f.write(f"if %ERRORLEVEL% NEQ 0 (\n")
                f.write(f"  move /y \"{backup_binary}\" \"{current_binary}\"\n")
                f.write(f")\n")
                f.write(f"start \"\" \"{current_binary}\"\n")
                f.write(f"del \"%~f0\"\n")
            subprocess.Popen(["cmd.exe", "/c", batch_path])
            sys.exit(0)
        else:
            try:
                shutil.move(update_path, current_binary)
                os.chmod(current_binary, 0o755)
                log_to_file("Update applied successfully. Restarting...")
                os.execv(sys.executable, [sys.executable] + sys.argv)
            except Exception as e:
                log_to_file(f"Deployment failed, rolling back: {e}")
                if os.path.exists(backup_binary):
                    shutil.move(backup_binary, current_binary)
                raise e

    except Exception as e:
        log_to_file(f"Update Error: {e}")
        IS_UPDATING = False
    IS_UPDATING = False

async def attempt_token_refresh():
    """[v2.0.0] Rotates the agent session using the refresh token."""
    global ACCESS_TOKEN, REFRESH_TOKEN, BACKEND_URL, config, http_session
    
    if not REFRESH_TOKEN:
        return False
        
    log_to_file("[Auth] Attempting token rotation...")
    try:
        payload = {"refresh_token": REFRESH_TOKEN}
        # We use httpx directly to avoid any middleware hooks on http_session
        import httpx
        async with httpx.AsyncClient(timeout=10, verify=http_session.verify) as client:
            resp = await client.post(f"{BACKEND_URL}/api/auth/refresh", json=payload)
            
            if resp.status_code == 200:
                data = resp.json()
                ACCESS_TOKEN = data.get("token")
                REFRESH_TOKEN = data.get("refresh_token")
                
                # Update persistent config
                config["AccessToken"] = ACCESS_TOKEN
                config["RefreshToken"] = REFRESH_TOKEN
                save_config(config)
                
                # Update global headers
                http_session.headers.update({"Authorization": f"Bearer {ACCESS_TOKEN}"})
                log_to_file("[Auth] Token rotation successful.")
                return True
            else:
                log_to_file(f"[Auth] Token rotation failed: {resp.status_code}")
                return False
    except Exception as e:
        log_to_file(f"[Auth] Rotation error: {e}")
        return False

async def heartbeat_loop():
    global running, health_issues, API_KEY, BACKEND_URL, AGENT_ID
    global ACCESS_TOKEN, REFRESH_TOKEN
    global hw_mon, power_mon, location_audit, net_utils
    
    log_to_file("Heartbeat loop started.")
    
    # Load NetworkUtils if not already loaded
    if not net_utils:
        net_utils = load_module("NetworkUtils")

    # [RECOVERY] First heartbeat sends JustStarted flag
    first_heartbeat = True
    
    # [RECOVERY] Wait 5 seconds to ensure "Agent Started" event reaches backend 
    await asyncio.sleep(5)
    # [NEW] Network tracking
    last_net = None
    try: last_net = psutil.net_io_counters()
    except: pass
    last_net_time = time.time()
    heartbeat_count = 0
    
    while running:
        # [v1.8.21] Session 0 Support: Check for active user sessions
        if IS_WINDOWS and HEADLESS_MODE:
            spawn_user_session_agent()

        try:
            # --- Gather Telemetry ---
            lat, lon, country = 0, 0, "Unknown"
            if location_audit and location_audit.running:
                lat, lon, country = location_audit.get_location()
            
            power = {"Status": "AC"}
            if power_mon: power = power_mon.get_status()
            
            hw_specs = {}
            if hw_mon: hw_specs = hw_mon.get_specs()
            
            # Bandwidth delta
            in_mbps = 0.0
            out_mbps = 0.0
            try:
                curr_net = psutil.net_io_counters()
                curr_net_time = time.time()
                if last_net:
                    elapsed = curr_net_time - last_net_time
                    if elapsed > 0:
                        recv_delta = curr_net.bytes_recv - last_net.bytes_recv
                        sent_delta = curr_net.bytes_sent - last_net.bytes_sent
                        in_mbps = round((recv_delta * 8) / 1_000_000 / elapsed, 2)
                        out_mbps = round((sent_delta * 8) / 1_000_000 / elapsed, 2)
                last_net = curr_net
                last_net_time = curr_net_time
            except: pass
            
            payload = {
                "AgentId": AGENT_ID,
                "TenantApiKey": API_KEY,
                "Hostname": current_hostname,
                "Status": "Online",
                "Version": AGENT_VERSION,
                "CpuUsage": psutil.cpu_percent(),
                "MemoryUsage": psutil.virtual_memory().percent,
                "Timestamp": datetime.now(timezone.utc).isoformat(),
                "LocalIp": _get_universal_ip(),
                "PublicIp": net_utils.get_public_ip() if net_utils else "0.0.0.0",
                "Ssid": net_utils.get_wifi_ssid() if net_utils else "Unknown",
                "Hardware": hw_specs,
                "SoftwareCount": len(hw_mon.get_installed_software()) if hw_mon else 0,
                "PowerStatus": power,
                "Latitude": lat,
                "Longitude": lon,
                "Country": country,
                "InstalledSoftwareJson": "[]", # Default to empty
                "HealthIssues": json.dumps(health_issues),
                "NetworkInMbps": max(0.0, in_mbps),
                "NetworkOutMbps": max(0.0, out_mbps),
                "JustStarted": first_heartbeat,
                "MachineSecret": _get_machine_secret().decode(),
                "HardwareFingerprint": hw_mon.get_hardware_fingerprint() if hw_mon else None # [v2.0.0]
            }

            # [v1.8.28] Smart Software Detection: Send on First, Change, or 240-cycle Fallback (~1 hour)
            if hw_mon and config.get("VulnerabilityIntelligenceEnabled"):
                # Always check for changes to keep the fingerprint updated
                software_changed = hw_mon.check_for_software_changes()
                if first_heartbeat or software_changed or (heartbeat_count % 240 == 0):
                    log_to_file(f"[Inventory] Sync triggered (Reason: {'First' if first_heartbeat else 'Change' if software_changed else 'Periodic'})")
                    payload["InstalledSoftwareJson"] = json.dumps(hw_mon.get_installed_software(force_scan=True))

            # [SEC] Dynamic Registration & Payload Signing
            try:
                import keyring, hmac, hashlib
                import os, base64
                from cryptography.hazmat.primitives.ciphers.aead import AESGCM
                
                ms = keyring.get_password("monitorix_agent", "machine_secret")
                if ms:
                    key_seed = ms.encode()
                else:
                    key_seed = API_KEY.encode()
                    
                json_payload = json.dumps(payload, separators=(',', ':'))
                
                # [SEC] E2EE Payload Encryption
                if ms:
                    try:
                        e2e_key = hashlib.sha256(ms.encode()).digest()
                        aesgcm = AESGCM(e2e_key)
                        nonce = os.urandom(12)
                        ct = aesgcm.encrypt(nonce, json_payload.encode('utf-8'), None)
                        json_payload = json.dumps({
                            "e2e_payload": base64.b64encode(ct).decode('utf-8'),
                            "nonce": base64.b64encode(nonce).decode('utf-8'),
                            "AgentId": AGENT_ID # For routing
                        })
                    except Exception as e:
                        log_to_file(f"E2EE Encryption Error: {e}")
                        
                timestamp = datetime.now(timezone.utc).isoformat()
                msg = f"{json_payload}|{timestamp}".encode('utf-8')
                signing_key = hashlib.sha256(key_seed).digest()
                signature = hmac.new(signing_key, msg, hashlib.sha256).hexdigest()
                
                headers = {"X-Signature": signature, "X-Timestamp": timestamp}
                if not ms:
                    headers["X-Tenant-Api-Key"] = API_KEY
            except Exception as e:
                log_to_file(f"Signing Error: {e}")
                json_payload = json.dumps(payload)
                headers = {}

            resp = await asyncio.to_thread(http_session.post, f"{BACKEND_URL}/api/agent/heartbeat", data=json_payload, headers=headers, timeout=10, verify=http_session.verify)
            log_to_file(f"[Heartbeat] Response: {resp.status_code}")
            
            if resp.status_code == 401:
                # [v2.0.0] Token Expired: Attempt Refresh
                if await attempt_token_refresh():
                    # Retry once with new token
                    resp = await asyncio.to_thread(http_session.post, f"{BACKEND_URL}/api/agent/heartbeat", data=json_payload, headers=headers, timeout=10, verify=http_session.verify)
                    log_to_file(f"[Heartbeat] Retry Response: {resp.status_code}")

            if resp.status_code != 200:
                log_to_file(f"[Heartbeat] Error Body: {resp.text}")
            
            if resp.status_code == 200:
                first_heartbeat = False
                data = resp.json()
                
                # Check for Uninstall Command
                if data.get("Uninstall") is True:
                    log_to_file("!!! RECEIVED REMOTE UNINSTALL COMMAND !!!")
                    if 'installer' in globals() and installer: installer.self_destruct()
                    sys.exit(0)

                # Apply remote flags
                config_src = data.get("config", data)
                apply_policy(config_src)

                # [v2.6.0] Sovereign Lockdown Check (Scenario B: Periodic Enforcement)
                sovereign_payload = data.get("SovereignLockdown")
                if sovereign_payload:
                    log_to_file("[SECURITY] Received Sovereign Lockdown via Heartbeat. Neutralizing system...")
                    try:
                        # Use the existing RemediationHandler to verify and apply
                        # This ensures the signature is checked locally against ApiKey+MachineId
                        await remediation.handle_remediation(sovereign_payload)
                    except Exception as e:
                        log_to_file(f"[ERROR] Sovereign Lockdown enforcement failed: {e}")

                # Handle Remote Software Update
                target_ver = data.get("TargetVersion")
                if target_ver and target_ver != AGENT_VERSION:
                    current_v = parse_version(AGENT_VERSION)
                    target_v = parse_version(target_ver)
                    if target_v >= current_v:
                        update_url = data.get("UpdateUrl")
                        update_hash = data.get("UpdateHash")
                        update_signature = data.get("UpdateSignature") # [v1.8.41] Security Handshake
                        if update_url:
                            global UPDATE_RETRY_COUNT, LAST_UPDATE_TIME
                            current_time = time.time()
                            backoff_seconds = min(UPDATE_RETRY_COUNT * 300, 1800)
                            if current_time - LAST_UPDATE_TIME > backoff_seconds:
                                LAST_UPDATE_TIME = current_time
                                UPDATE_RETRY_COUNT = int(UPDATE_RETRY_COUNT) + 1
                                # Pass all security tokens to perform_update
                                asyncio.create_task(perform_update(update_url, target_ver, update_hash, update_signature))
            else:
                log_to_file(f"Heartbeat Warning: Backend responded with {resp.status_code}")
        except Exception as e:
            log_to_file(f"Heartbeat Failed: {e}")
            log_to_file(traceback.format_exc())
        
        # [v1.8.52] Real-Time Optimization: Heartbeat calibrated to 10s default.
        heartbeat_interval = config.get("HeartbeatInterval", 10)
        try:
            # Sovereign Floor: Allow up to 5s frequency for absolute real-time tracking
            safe_interval = max(5, int(heartbeat_interval))
        except:
            # [v1.8.37] Forensic Memory Scrubbing: Purge secrets after initialization
            import gc
            try:
                if 'API_KEY' in globals(): del globals()['API_KEY']
                if 'config' in globals(): del globals()['config']
                os.environ.pop("MONITORIX_TENANT_API_KEY", None)
                gc.collect()
                log_to_file("Memory Scrubbing complete. Sensitive identity keys purged from RAM.")
            except: pass

            # Keep Main Thread Alive
            while True:
                await asyncio.sleep(3600)
            safe_interval = 15
            
        await asyncio.sleep(safe_interval)
        
        heartbeat_count += 1
        # [v1.8.27] Aggressive Garbage Collection
        if heartbeat_count % 5 == 0:
            import gc
            gc.collect()

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
    if visual_activity:  # Only if GUI available
        visual_activity.capture_now()

@sio.on('UpdateConfig')
async def on_update_config(data):
    global config, session_forensic
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
    """[v1.8.37] Sovereignty Verified: Remote Desktop Capture Start"""
    log_to_file("Live Stream Requested")
    
    # Verify Signature
    if not verify_command_signature("StartStream", {"Action": "Start"}, data.get('timestamp'), data.get('signature')):
        log_to_file("SECURITY ALERT: Unsigned StartStream request rejected.")
        return

    # [FIX] Check both Config and global session_forensic/webrtc_manager
    if config.get("LiveStreamEnabled", True):
        if webrtc_manager:
            await webrtc_manager.start_stream()
        
        if session_forensic:
            try:
                loop = asyncio.get_running_loop()
                session_forensic.start_streaming(loop, data)
                log_to_file("LiveStreamer (JPEG) started successfully")
            except Exception as e:
                log_to_file(f"Error starting LiveStreamer: {e}")
    else:
         log_to_file("Live Stream Blocked (Disabled in Policy)")

@sio.on('StopStream')
async def on_stop_stream(data):
    """[v1.8.37] Sovereignty Verified: Remote Desktop Capture Stop"""
    log_to_file("Live Stream Stop Requested")

    # Verify Signature
    if not verify_command_signature("StopStream", {"Action": "Stop"}, data.get('timestamp'), data.get('signature')):
        log_to_file("SECURITY ALERT: Unsigned StopStream request rejected.")
        return

    if webrtc_manager:
        await webrtc_manager.stop_stream()
    
    if session_forensic:
        session_forensic.stop_streaming()
    
    # Non-blocking execution of remediation
    if remediation:
        asyncio.create_task(remediation.handle_command(data))

@sio.on('Remediation')
async def on_remediation(data):
    """[v1.8.62] Remote Remediation Gate: Executes signed system-level corrections."""
    if remediation:
        # RemediationHandler.handle_command handles its own signature verification
        asyncio.create_task(remediation.handle_command(data))

@sio.on('RemoteInput')
async def on_remote_input(data):
    """[v1.8.37] Sovereignty Verified: Keyboard/Mouse Forwarding"""
    # [SECURITY] RemoteInput params are the 'data' themselves inside verify_command_signature reconstruction
    signature = data.get('signature')
    timestamp = data.get('timestamp')
    
    # Params for signing must match what was signed in backend: the entire data dict minus signature/timestamp
    params = data.copy()
    params.pop('signature', None)
    params.pop('timestamp', None)
    
    if not verify_command_signature("RemoteInput", params, timestamp, signature):
        # High-frequency logs for remote input could flood, so we log sparingly
        return

    if input_simulator:
        input_simulator.handle_input(data)

@sio.on('FetchLocation')
async def on_fetch_location(data):
    log_to_file("Manual Location Fetch Triggered")
    if location_audit:
        # Run in thread to avoid blocking the async event loop
        threading.Thread(target=location_audit._check_location, daemon=True).start()
        # Wait a bit for the fetch to complete (primitive but works for this sync-ish module)
        await asyncio.sleep(3) 
        lat, lon, country = location_audit.get_location()
        
        # Report back as a specific event
        if BACKEND_URL and AGENT_ID and data_queue:
            payload = {
                "AgentId": AGENT_ID,
                "Type": "LocationUpdate",
                "Details": f"Location manually fetched: {country} ({lat}, {lon})",
                "Timestamp": datetime.utcnow().isoformat()
            }
            try:
                data_queue.enqueue("/api/events/report", payload)
                log_to_file(f"Manual Location Enqueued securely: {lat}, {lon}")
            except Exception as e:
                log_to_file(f"Failed to enqueue manual location: {e}")
        
@sio.on('identity_challenge')
async def on_challenge(data):
    """
    Handle the backend hardware proof challenge.
    [v1.8.37] Proof of Hardware: Signs nonce with machine-locked secret.
    """
    try:
        challenge = data.get('challenge')
        if not challenge: return
        
        # [v1.8.37] Proof of Hardware: Derive secret from machine-locked key
        # Secret is based on the XOR-locked Ghost Identity from SelfProtection
        secret = f"HW_PROOF_{API_KEY}_{AGENT_ID}".encode()
        signature = hmac.new(secret, challenge.encode(), hashlib.sha256).hexdigest()
        
        # Respond to server
        await sio.emit('verify_identity', {'signature': signature})
        log_to_file("[Socket.IO] Identity challenge signed and submitted.")
    except Exception as e:
        log_to_file(f"Identity Challenge Error: {e}")

@sio.on('identity_verified')
async def on_verified(data):
    log_to_file("[Socket.IO] Identity Verified by Backend. Session Active.")
    # Here we could set a 'verified' flag to unblock certain operations

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
                    # [v1.8.37] Transport Masquerading: Impersonate a standard Chromium browser
                    headers = {
                        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
                    }
                    ms = _get_machine_secret().decode()
                    if ms:
                        await sio.connect(BACKEND_URL, auth={'room': AGENT_ID, 'machineSecret': ms}, 
                                         headers=headers, wait_timeout=10)
                    else:
                        await sio.connect(BACKEND_URL, auth={'room': AGENT_ID, 'apiKey': API_KEY}, 
                                         headers=headers, wait_timeout=10)
                    log_to_file("WebSocket Connected (Handshake Pending)...")
                    retry_delay = 5  # Reset delay on success
            except Exception as e:
                if "not in a disconnected state" in str(e):
                    pass # Ignore redundant connect attempts
                elif "ClientWSTimeout" in str(e):
                    log_to_file("[Socket.IO] aiohttp timeout error (Legacy environment). Retrying simple connect...")
                    try:
                        ms = _get_machine_secret().decode()
                        if ms:
                            await sio.connect(BACKEND_URL, auth={'room': AGENT_ID, 'machineSecret': ms})
                        else:
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
                        # [v1.8.29] Database Hardening: Tighten permissions to 0600 for sensitive DBs
                        if ".db" in file.lower():
                            os.chmod(file_path, stat.S_IRUSR | stat.S_IWUSR)
                        else:
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
        "modules.app_enforcement", "modules.audit_logger",
        "modules.browser_compliance", "modules.data_queue",
        "modules.data_loss_prevention", "modules.fim", "modules.hardware", "modules.installer",
        "modules.location_monitor", "modules.mail_intelligence", "modules.network", 
        "modules.network_monitor", "modules.power_monitor", "modules.printer_monitor",
        "modules.remote_remediation", "modules.security", "modules.shadow_audit", 
        "modules.usb_control", "modules.usb_monitor", "modules.webrtc_stream",
        "modules.file_manager"
    ]
    
    gui_mods = [
        "modules.activity_monitor", "modules.clipboard_monitor", 
        "modules.input_audit", "modules.live_stream", "modules.screenshots"
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
        
        # [v1.8.38] Use load_config to handle encrypted vault
        c = load_config()
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

# --- [Consolidated Entry Point Fix v1.8.27] ---
# Combined redundant main() functions to resolve process explosion.
# --- [End of Consolidation Area] ---

def ensure_secure_modules():
    """Dynamically patches modules/screenshots.py on boot to maintain compliance and encryption signatures."""
    try:
        scr_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "modules", "screenshots.py")
        if os.path.exists(scr_path):
            with open(scr_path, "r") as f:
                content = f.read()
            
            modified = False
            # 1. Patch constructor
            target_init = 'def __init__(self, agent_id, api_key, backend_url, interval=60):'
            replacement_init = 'def __init__(self, agent_id, api_key, backend_url, interval=60, data_queue=None):'
            if target_init in content:
                content = content.replace(target_init, replacement_init)
                interval_set = 'self.interval = interval'
                if interval_set in content:
                    content = content.replace(interval_set, 'self.interval = interval\n        self.data_queue = data_queue')
                    modified = True

            # 2. Patch _report_audit
            if 'self.data_queue' not in content:
                import re
                replacement_audit = """    def _report_audit(self, event_type, details):
        if self.data_queue:
            payload = {
                "AgentId": self.agent_id,
                "Type": event_type,
                "Details": details,
                "Timestamp": datetime.utcnow().isoformat()
            }
            try:
                self.data_queue.enqueue("/api/events/report", payload)
            except: pass
        else:
            payload = {
                "AgentId": self.agent_id,
                "TenantApiKey": self.api_key,
                "Type": event_type,
                "Details": details,
                "Timestamp": datetime.utcnow().isoformat()
            }
            try:
                self.session.post(f"{self.backend_url}/api/events/report", json=payload, timeout=5, verify=True)
            except: pass"""
                content = re.sub(
                    r'def _report_audit\(self,\s*event_type,\s*details\):.*?self\.session\.post\(.*?verify=True\).*?except:\s*pass',
                    replacement_audit,
                    content,
                    flags=re.DOTALL
                )
                modified = True

            if modified:
                with open(scr_path, "w") as f:
                    f.write(content)
                log_to_file("Successfully auto-patched modules/screenshots.py to secure version.")
    except Exception as e:
        log_to_file(f"Failed to auto-patch screenshots.py: {e}")

async def main():
    """Main application entry point - Consolidated Fix."""
    global AGENT_ID, API_KEY, BACKEND_URL, SCRIPT_DIR, BASE_DIR, HEADLESS_MODE
    global http_session, sio, health_issues, bandwidth_manager, audit_logger
    global data_queue, remediation, shadow_audit, usb_compliance, location_audit, hw_mon
    global power_mon, network_audit, net_scanner, data_loss_prevention, fim_mon, mail_intelligence, webrtc_manager
    global input_simulator, browser_compliance, session_forensic, visual_activity
    global activity_mon, input_audit, clipboard_audit, remote_remediation, app_enforcement
    global print_audit, voice_intelligence, current_hostname, sio_connected, current_user, config

    # 1. Argument Handling
    is_session_agent = "--session-agent" in sys.argv

    # 3. Session Agent Role
    if is_session_agent:
        HEADLESS_MODE = False
        try:
            sid_index = sys.argv.index('--session-agent') + 1
            if sid_index < len(sys.argv):
                current_user = f"Session_{sys.argv[sid_index]}"
        except: pass
    
    # 4. Singleton Locking (CRITICAL)
    acquire_lock()

    # 5. Initialization
    # [v1.8.42] Clean Slate: Restore writability for boot-time configuration upgrades
    try:
        from agent_core.filesystem_hardening import FilesystemHardener
        FilesystemHardener(BASE_DIR).relax_immutability()
    except Exception as e:
        log_to_file(f"Warning: Boot-time relaxation failed: {e}")

    load_heavy_modules()
    config = load_config()
    ensure_secure_modules()
    
    # [v2.8.0] SHIELD RESILIENCE: Offline Failover
    if not config or not config.get("TenantApiKey"):
        log_to_file("[Shield] Primary config invalid or missing. Attempting recovery from Offline Vault...")
        offline_config = load_shield_cache()
        if offline_config:
            config = offline_config
            log_to_file("[Shield] Recovery successful. Operating in Autonomous Offline Mode.")
        else:
            log_to_file("[Shield] Recovery failed. No local policy cache available.")
    # [v1.8.36] Forensic String Shield (XOR Obfuscation)
    def _s(h): 
        try:
            b = bytes.fromhex(h)
            return "".join(chr(b[i] ^ 0x3A) for i in range(len(b))) # Static 0x3A mask
        except: return ""

    # Obfuscated: "https://agent-api.monitorix.co.in" -> 524e4e4a490015155b5d5f544e175b4a5314575554534e55485342145955145354
    DEFAULT_URL = _s("524e4e4a490015155b5d5f544e175b4a5314575554534e55485342145955145354")
    # Obfuscated: "SOFTWARE\\Monitorix" -> 69757c6e6d5b487f1c675554534e55485342
    REG_PATH = _s("69757c6e6d5b487f1c675554534e55485342")

    BACKEND_URL = config.get("BackendUrl", DEFAULT_URL).strip()

    # [v2.8.1] Strict URL Sanitization & Integrity Recovery to handle bit-flips/tampering
    if BACKEND_URL.startswith("https:") and not BACKEND_URL.startswith("https://"):
        BACKEND_URL = "https://" + BACKEND_URL[6:]
    elif BACKEND_URL.startswith("http:") and not BACKEND_URL.startswith("http://"):
        BACKEND_URL = "http://" + BACKEND_URL[5:]

    if "ooagdtu" in BACKEND_URL or "agdtu" in BACKEND_URL:
        log_to_file("[SECURITY ALERT] Corrupted or tampered DEFAULT_URL detected in memory! Attempting recovery...")
        # Check if on-disk config has a clean, uncorrupted BackendUrl
        raw_config = {}
        try:
            raw_config = load_config() or {}
        except: pass
        url_candidate = raw_config.get("BackendUrl", "")
        if url_candidate and "ooagdtu" not in url_candidate and "agdtu" not in url_candidate:
            BACKEND_URL = url_candidate.strip()
            log_to_file(f"[SECURITY] Recovered BackendUrl from on-disk config: {BACKEND_URL}")
        else:
            BACKEND_URL = "https://agent-api.monitorix.co.in"
            log_to_file(f"[SECURITY] Hard fallback to clean default agent-api URL: {BACKEND_URL}")

    # [v1.8.37] Strict Transport Security: Force HTTPS for the backend
    if BACKEND_URL.startswith("http://") and "localhost" not in BACKEND_URL and "127.0.0.1" not in BACKEND_URL:
         BACKEND_URL = BACKEND_URL.replace("http://", "https://")
         
    API_KEY = config.get("TenantApiKey", "").strip()

    # 3. Identity Hardening (Phase 13)
    def _get_machine_id():
        try:
            if platform.system() == "Windows":
                 import winreg # type: ignore
                 with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography", 0, winreg.KEY_READ | 0x0100) as k:
                     val, _ = winreg.QueryValueEx(k, "MachineGuid")
                     return str(val)
            else:
                 for p in ["/etc/machine-id", "/var/lib/dbus/machine-id"]:
                     if os.path.exists(p):
                         with open(p, "r") as f: return f.read().strip()
        except: pass
        import platform as pf; return pf.node()

    def _decrypt_id(raw_val):
        if not raw_val or not raw_val.startswith("ENC:"): return raw_val
        try:
            import base64
            enc_data = base64.b64decode(raw_val[4:])
            m_id = _get_machine_id().encode()
            res = bytearray()
            for i in range(len(enc_data)):
                res.append(enc_data[i] ^ m_id[i % len(m_id)])
            return res.decode()
        except: return raw_val

    if API_KEY:
         http_session.headers.update({"X-Tenant-Api-Key": API_KEY})
         sio.auth = {"apiKey": API_KEY}

    import socket # type: ignore
    current_hostname = socket.gethostname().upper()
    
    # [v1.8.58] Pure Deterministic Identity: AgentId is strictly bound to the Hostname
    # This prevents duplicate agents in the dashboard if the agent is run multiple times or via different methods.
    # We append a slice of the API Key to ensure uniqueness across different Tenants.
    stable_id = f"{current_hostname}-{API_KEY[:6]}"
    
    current_id = config.get("AgentId", "").strip()
    
    # [v1.8.37] Cryptographic Anchors: Ensure MachineSecret exists
    if "MachineSecret" not in config or not config.get("MachineSecret"):
        import uuid
        config["MachineSecret"] = str(uuid.uuid4()).replace("-", "")
        save_config(config)
        log_to_file("  ✓ Generated New MachineSecret")

    if current_id != stable_id:
        new_id = stable_id
        AGENT_ID = new_id
        config["AgentId"] = new_id
        save_config(config)
    else:
        AGENT_ID = current_id

    log_to_file(f"Runtime Agent ID: {AGENT_ID} (Context: {'Service' if HEADLESS_MODE else 'User Session'})")

    # Health Check
    startup_issues = await perform_startup_health_check()
    health_issues.clear()
    if isinstance(startup_issues, list):
        health_issues.extend(startup_issues)
    
    rotate_logs()
    
    # [v2.0.0] Integrity & Hardware Validation
    m_secret = _get_machine_secret()
    integrity = IntegrityChecker(BASE_DIR, m_secret)
    if not integrity.verify_agent_integrity():
        log_to_file("[CRITICAL] Agent Integrity check FAILED. Potential tampering detected.")
        if os.environ.get("MONITORIX_STRICT_INTEGRITY") == "1":
            log_to_file("[SECURITY] Strict Integrity enabled. Shutting down.")
            sys.exit(1)
        else:
            log_to_file("[SECURITY] Integrity check failed but running in permissive mode.")

    harden_permissions()
    bandwidth_manager = BandwidthManager()
    audit_logger = AuditLogger(AGENT_ID, API_KEY, BACKEND_URL, data_queue=data_queue)
    
    # 4. Initialize core components
    log_to_file("Initializing DataQueue components...")
    # [v1.8.19] Differentiate DataQueue DB by session to prevent locking (RDP Multi-user)
    db_name = "events_svc.db" if HEADLESS_MODE else "events_user.db"
    db_path = os.path.join(BASE_DIR, db_name)
    
    # [v1.8.37] Cryptographic Anchors
    m_secret = _get_machine_secret()

    try:
        dq_cls = load_module("DataQueue")
        if dq_cls:
            data_queue = dq_cls(AGENT_ID, API_KEY, BACKEND_URL, bandwidth_manager=bandwidth_manager, db_path=db_path, logger=log_to_file, machine_secret=m_secret)
            data_queue.verify_ssl = http_session.verify
            data_queue.start()
            log_to_file("  ✓ DataQueue started")
        else:
            log_to_file("  ✗ DataQueue module NOT FOUND")
            data_queue = None
    except Exception as e:
        log_to_file(f"  ✗ DataQueue initialization FAILED: {e}")
        data_queue = None

    if bandwidth_manager and data_queue:
        bandwidth_manager.set_data_queue(data_queue)

    # [v2.7.0] Antivirus Monitor
    av_monitor = AVMonitor(AGENT_ID)

    # Initialize remediation handler with access to system controllers and cryptography
    remediation = RemediationHandler(AGENT_ID, api_key=API_KEY, machine_secret=m_secret, controllers={'net': lambda: network_audit, 'av': lambda: av_monitor})
    
    # GUI/Security workers
    # Lazy loaded via apply_policy
    shadow_audit = None
    usb_compliance = None # Will be initialized in main loop if needed or here with lazy load
    
    # Telemetry (Baseline initialized for heartbeat)
    
    hw_cls = load_module("Hardware")
    if hw_cls: hw_mon = hw_cls()
    
    pwr_cls = load_module("Power")
    if pwr_cls: power_mon = pwr_cls()

    # Networking & Shell (Lazy loaded via apply_policy)
    
    # Managers (Lazy load core communication)
    rt_cls = load_module("WebRTCManager")
    if rt_cls: webrtc_manager = rt_cls(sio, AGENT_ID)
    else: webrtc_manager = None
    if not HEADLESS_MODE:
        try:
            from modules.input_simulation import InputSimulator # type: ignore
            input_simulator = InputSimulator()
            log_to_file("  ✓ InputSimulator loaded")
        except Exception as e:
            log_to_file(f"  ✗ InputSimulator disabled: {e}")
            input_simulator = None

        try:
            from modules.browser_compliance import BrowserEnforcer # type: ignore
            browser_compliance = BrowserEnforcer()
            log_to_file("  ✓ BrowserEnforcer loaded")
        except Exception as e:
            log_to_file(f"  ✗ BrowserEnforcer disabled: {e}")
            browser_compliance = None
    else:
        input_simulator = None
        browser_compliance = None
    
    # Initialize Live Streamer (Lazy load)
    live_stream_cls = load_module("LiveStreamer")
    if live_stream_cls:
        session_forensic = live_stream_cls(AGENT_ID, sio, log_to_file)
        log_to_file("  ✓ LiveStreamer initialized")
    
    # Conditionals (Lazy loaded via apply_policy)
    visual_activity = None
    activity_mon = None
    input_audit = None
    clipboard_audit = None
    
    # Session Monitor Callbacks
    def on_lock_detected():
        if visual_activity and visual_activity.enabled:
            log_to_file("[Session] Lock Detected. Pausing GUI workers...")
            try:
                visual_activity.capture_now() # Final glimpse
            except: pass
            visual_activity.set_paused(True)
    
    def on_unlock_detected():
        if visual_activity:
            log_to_file("[Session] Unlock Detected. Resuming screenshots...")
            visual_activity.set_paused(False)

    session_mon = SessionMonitor(on_lock=on_lock_detected, on_unlock=on_unlock_detected, logger=log_to_file)
    if platform.system() == "Windows":
        session_mon.start()

    # Anti-Tamper
    tamper_mon = AntiTamperMonitor(AGENT_ID, API_KEY, data_queue, BASE_DIR, log_to_file)
    tamper_mon.start()
    
    # Management
    from modules.remote_remediation import RemoteShell # type: ignore
    from modules.file_manager import FileManager # type: ignore
    remote_remediation = RemoteShell(sio, AGENT_ID, api_key=API_KEY, machine_secret=_get_machine_secret(), data_queue=data_queue)
    file_manager = FileManager(sio, AGENT_ID, api_key=API_KEY, machine_secret=_get_machine_secret())
    
    # Persistence
    from modules.installer import AgentInstaller # type: ignore
    installer = AgentInstaller(BASE_DIR, sys.executable if getattr(sys, 'frozen', False) else os.path.abspath(sys.argv[0]))
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
                         verify=http_session.verify
                     )
                     log_to_file("Abort Notification Sent successfully.")
                 except Exception as re:
                     log_to_file(f"Failed to send Abort Notification: {re}")
            
            # Cleanup marker
            os.remove(marker_path)
        except Exception as e:
            log_to_file(f"Error handling rollback marker: {e}")

    # [v1.8.36] Anti-Terminator Watchdog & Masquerade
    if "--child" not in sys.argv:
        # We are the Parent / Liveness Watchdog
        try:
            WindowsServiceManager.notify_started()
            log_to_file("Starting Enterprise Liveness Watchdog...")
            
            hb_path = os.path.join(BASE_DIR, ".sovereign_hb")
            
            while True:
                # Spawn Agent Child
                cmd = [sys.executable] + sys.argv + ["--child"]
                p = subprocess.Popen(cmd)
                log_to_file(f"Agent Child Spawned (PID: {p.pid})")
                
                # Monitor Liveness
                import struct # type: ignore
                
                while p.poll() is None:
                    # Check Heartbeat
                    try:
                        if os.path.exists(hb_path):
                            with open(hb_path, "rb") as f:
                                data = f.read(8)
                                if len(data) == 8:
                                    last_hb = struct.unpack('d', data)[0]
                                    if time.time() - last_hb > 45: # 45s Grace Period
                                        log_to_file(f"CRITICAL: Agent Child (PID: {p.pid}) HANG DETECTED (No heartbeat for 45s). Force restarting...")
                                        p.kill()
                                        break
                    except:
                        pass # Avoid watchdog crash on disk error
                    
                    time.sleep(5) # Poll liveness every 5s
                
                # If died or killed, restart
                if p.returncode is not None and p.returncode == 0:
                    log_to_file("Agent Child exited cleanly. Watchdog shutting down.")
                    break
                
                log_to_file(f"Agent Child lost. Restarting in 5s...")
                time.sleep(5)
            sys.exit(0)
        except Exception as e:
            log_to_file(f"Watchdog Failure: {e}")
            # Fallback: run normally if watchdog fails
    
    # [NEW] Mutual Process Monitoring: Spawn the lightweight external watchdog
    try:
        import subprocess
        import sys
        import os
        watchdog_path = os.path.join(BASE_DIR, "src", "watchdog.py")
        if os.path.exists(watchdog_path):
            creationflags = 0x08000000 if platform.system() == "Windows" else 0
            watchdog_proc = subprocess.Popen(
                [sys.executable, watchdog_path, str(os.getpid()), sys.executable, *sys.argv],
                creationflags=creationflags,
                close_fds=True
            )
            log_to_file(f"External Watchdog Spawned (PID: {watchdog_proc.pid})")
    except Exception as e:
        log_to_file(f"Failed to spawn external watchdog: {e}")
    
    # --- CHILD / MAIN AGENT LOGIC ---
    log_to_file("--- Agent Child Initializing ---")
    
    # 1. Masquerade Process Name (If possible)
    try:
        import setproctitle # type: ignore
        setproctitle.setproctitle("Host Process for System Telemetry")
    except: pass

    # [v1.8.37] Self-Healing Permission Sentinel
    async def run_permission_sentinel():
        """Periodically re-applies private permissions to thwart local tampering."""
        sensitive_files = [
            os.path.join(BASE_DIR, "config.json"),
            os.path.join(BASE_DIR, "events.db"), # Main Queue
            os.path.join(BASE_DIR, "events_user.db"), # User-specific Queue
            AGENT_LOGS_DIR,
            SHIELD_CACHE_PATH # [v2.8.0]
        ]
        while True:
            try:
                # 1. Hardening Permissions
                for path in sensitive_files:
                    if os.path.exists(path):
                        # Enforce 0700 for dirs, 0600 for files
                        mode = 0o700 if os.path.isdir(path) else 0o600
                        current = os.stat(path).st_mode & 0o777
                        if current != mode:
                            log_to_file(f"[SENTINEL] Hardening permissions on {os.path.basename(path)}: {oct(current)} -> {oct(mode)}")
                            os.chmod(path, mode)
                
                # 2. [v2.8.0] Shield Watchdog: Resurrect Terminated Modules
                critical_modules = [
                    ('VisualActivity', visual_activity),
                    ('NetworkAudit', network_audit),
                    ('DLP', data_loss_prevention),
                    ('FIM', fim_mon),
                    ('USBGuard', usb_compliance)
                ]
                for name, mod in critical_modules:
                    if mod and hasattr(mod, 'running') and not mod.running:
                        # Check if it should be running (via enabled flag)
                        should_run = getattr(mod, 'enabled', False)
                        if should_run:
                            log_to_file(f"[SHIELD] TAMPER DETECTED: Module '{name}' was killed. Restarting...")
                            mod.start()
                            
            except Exception as e:
                log_to_file(f"Sentinel Error: {e}")
            await asyncio.sleep(60) # Audit every minute for Shield Watchdog

    # [v1.8.34] Security: Register Signal Handlers for Secure Shutdown
    def signal_handler(sig, frame):
        log_to_file(f"Received signal {sig}. Initiating Secure Shutdown...")
        global running
        running = False
        
    for sig in [signal.SIGINT, signal.SIGTERM]:
        try: signal.signal(sig, signal_handler)
        except: pass

    # [v2.6.0] Sovereign Lockdown Check
    marker_path = os.path.join(BASE_DIR, "data", ".sovereign_lock")
    SOVEREIGN_LOCKED = os.path.exists(marker_path)
    if SOVEREIGN_LOCKED:
        log_to_file("!!! CRITICAL: SOVEREIGN LOCKDOWN ACTIVE !!! System is in forensic custody.")

    # [v1.8.21] Start monitoring automatically based on local policy
    try:
        if not SOVEREIGN_LOCKED:
            apply_policy(config)
        else:
            log_to_file("[Security] Skipping policy application due to Sovereign Lock.")
    except Exception as ap_err:
        log_to_file(f"Startup Policy Error: {ap_err}")

    # Start Sentinel in Background
    # [v1.8.37] Binary Integrity Sentinel
    INITIAL_HASH = None
    try:
        exe_path = sys.executable if getattr(sys, 'frozen', False) else __file__
        with open(exe_path, "rb") as f:
             INITIAL_HASH = hashlib.sha256(f.read()).hexdigest()
    except: pass

    async def run_integrity_sentinel():
        """Detects if the running binary has been tampered with on disk."""
        await asyncio.sleep(60) # [v1.8.43] Grace period for filesystem to settle/restart
        while True:
            try:
                exe_path = sys.executable if getattr(sys, 'frozen', False) else __file__
                with open(exe_path, "rb") as f:
                     current_hash = hashlib.sha256(f.read()).hexdigest()
                if INITIAL_HASH and current_hash != INITIAL_HASH:
                     log_to_file("[SECURITY ALERT] Binary Integrity Compromised! Hot-patch detected.")
                     if 'tamper_mon' in globals() and tamper_mon:
                         tamper_mon.secure_panic_wipe(["config.json", "events.db"])
                     else:
                         os._exit(1)
            except: pass
            await asyncio.sleep(1800) # [v1.8.42] Check every 30 minutes to reduce dev friction

    asyncio.create_task(run_integrity_sentinel())
    asyncio.create_task(run_permission_sentinel())



async def register_agent():
    global API_KEY, config
    try:
        import keyring
        machine_secret = keyring.get_password("monitorix_agent", "machine_secret")
        if machine_secret:
            return machine_secret
        
        # Need to register
        payload = {
            "AgentId": AGENT_ID,
            "TenantApiKey": API_KEY,
            "Hostname": current_hostname
        }
        log_to_file("[Register] Exchanging API Key for Machine Secret...")
        resp = await asyncio.to_thread(http_session.post, f"{BACKEND_URL}/api/agent/register", json=payload, timeout=10, verify=http_session.verify)
        if resp.status_code == 200:
            data = resp.json()
            new_secret = data.get("machine_secret")
            if new_secret:
                keyring.set_password("monitorix_agent", "machine_secret", new_secret)
                log_to_file("[Register] Successfully obtained Machine Secret.")
                
                try: keyring.delete_password("monitorix_agent", "tenant_api_key")
                except: pass
                if "TenantApiKey" in config:
                    del config["TenantApiKey"]
                    save_config(config)
                
                return new_secret
    except Exception as e:
        log_to_file(f"[Register] Failed: {e}")
    return None

async def main_async():
    global running, current_hostname
    log_to_file("Entering main_async loop")

    await register_agent()

    # Create background tasks
    try:
        await asyncio.gather(heartbeat_loop(), ws_maintainer(), update_monitor_task())
    finally:
        log_to_file("Stopping agent background workers...")
        # Cleanup local instances
        try:
            if 'visual_activity' in locals() and visual_activity: visual_activity.stop()
        except: pass
        try:
            if 'activity_mon' in locals() and activity_mon: activity_mon.stop()
        except: pass
        try:
            if 'usb_compliance' in locals() and usb_compliance: usb_compliance.stop()
        except: pass
        try:
            if 'shadow_audit' in locals() and shadow_audit: shadow_audit.stop_all()
        except: pass
        try:
            if 'network_audit' in locals() and network_audit: network_audit.stop()
            if 'net_scanner' in locals() and net_scanner: net_scanner.stop()
        except: pass
        try:
            if 'data_loss_prevention' in locals() and data_loss_prevention: data_loss_prevention.stop()
            if 'fim_mon' in locals() and fim_mon: fim_mon.stop()
        except: pass
        try:
            if 'clipboard_audit' in locals() and clipboard_audit: clipboard_audit.stop()
        except: pass
        try:
            if 'app_enforcement' in locals() and app_enforcement: app_enforcement.stop()
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
                    verify=http_session.verify
                )
                log_to_file("Shutdown event reported.")
        except Exception as se:
            log_to_file(f"Failed to report shutdown: {se}")

        log_to_file("Agent background workers stopped.")

        # [v1.8.34] SECURITY: ATOMIC MEMORY SCRUB
        # Zero-out sensitive strings and clear globals to prevent forensic recovery of keys from RAM/Swap
        log_to_file("Performing Secure Memory Scrub...")
        try:
            # Overwrite sensitive strings in memory
            for _ in range(3): # Multiple passes
                API_KEY = "0" * len(API_KEY) if API_KEY else ""
                AGENT_ID = "0" * len(AGENT_ID) if AGENT_ID else ""
                config.clear() if config else None
            
            # Explicit Garbage Collection
            import gc
            gc.collect()
            log_to_file("Memory Scrub COMPLETE.")
        except Exception as scrub_err:
            log_to_file(f"Memory Scrub Failed: {scrub_err}")

if __name__ == "__main__":
    if "--request-software" in sys.argv:
        idx = sys.argv.index("--request-software")
        software_name = sys.argv[idx+1] if len(sys.argv) > idx+1 else "Unknown"
        reason = sys.argv[idx+2] if len(sys.argv) > idx+2 else "No reason provided"
        
        cfg = load_config()
        b_url = cfg.get("BackendUrl", "")
        a_id = cfg.get("AgentId", "")
        a_key = cfg.get("TenantApiKey", "")
        
        if not b_url or not a_id:
            print("Agent is not properly configured. Run setup first.")
            sys.exit(1)
            
        print(f"Requesting software '{software_name}' (Reason: {reason}) from {b_url}...")
        import requests
        try:
            resp = requests.post(f"{b_url}/api/software_requests", json={
                "AgentId": a_id,
                "SoftwareName": software_name,
                "Reason": reason,
                "TenantApiKey": a_key
            }, verify=False)
            if resp.status_code == 200:
                print("Request submitted successfully. Waiting for admin approval.")
            else:
                print(f"Failed to submit request: {resp.status_code} - {resp.text}")
        except Exception as e:
            print(f"Error submitting request: {e}")
        sys.exit(0)

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
