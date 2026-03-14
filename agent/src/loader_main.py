import os # type: ignore
import sys # type: ignore
import json # type: ignore
import base64 # type: ignore
import types # type: ignore
from datetime import datetime # type: ignore

# 1. Setup Robust Logging (World-Writable Directory)
if platform_system := os.environ.get('OS', ''): # Use env as a cheap way to check before platform import
    LOG_DIR = r"C:\ProgramData\Monitorix\Logs"
else:
    LOG_DIR = "/var/log/monitorix" # Linux fallback

if not os.path.exists(LOG_DIR):
    try: os.makedirs(LOG_DIR, exist_ok=True)
    except: LOG_DIR = os.getcwd()

LOG_FILE = os.path.join(LOG_DIR, "agent_loader.log")

def log(msg):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, "a") as f:
        f.write(f"[{ts}] [Loader] {msg}\n")
    print(f"[Loader] {msg}")

log("--- Monitorix Secure Loader Starting ---")

# 2. Get Bundle Path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PAYLOAD_PATH = os.path.join(BASE_DIR, "agent_payload.dat")

if not os.path.exists(PAYLOAD_PATH):
    log(f"CRITICAL: Payload not found at {PAYLOAD_PATH}")
    sys.exit(1)

try:
    # 3. Load Bundle
    with open(PAYLOAD_PATH, "r") as f:
        bundle = json.load(f)
    
    files = bundle.get("files", {})
    log(f"Unpacking {len(files)} components into memory...")

    # 4. Inject Modules into sys.modules
    # We sort them to ensure __init__.py files are handled or at least we follow a logical order
    for rel_path in sorted(files.keys()):
        if rel_path == "_real_main.py": continue
        
        # Convert path to module name
        # e.g. modules/activity_monitor.py -> modules.activity_monitor
        mod_name = rel_path.replace(".py", "").replace("/", ".").replace("\\", ".")
        
        # Decode and exec
        code = base64.b64decode(files[rel_path]).decode("utf-8")
        
        # Create module object
        module = types.ModuleType(mod_name)
        module.__file__ = os.path.join(BASE_DIR, rel_path)
        
        # Add to sys.modules BEFORE exec to support relative/circular imports
        sys.modules[mod_name] = module
        
        try:
            exec(code, module.__dict__)
        except Exception as e:
            log(f"Error loading module {mod_name}: {e}")

    log("Modules loaded. Launching real main...")

    # 5. Launch Real Main
    main_code = base64.b64decode(files["_real_main.py"]).decode("utf-8")
    
    # We run it in the current global context
    # But we want __name__ to be "__main__"
    globals_dict = {
        "__name__": "__main__",
        "__file__": os.path.join(BASE_DIR, "main.py"),
        "__loader__": None,
        "__package__": None,
    }
    # Update with current globals for builtins etc.
    globals_dict.update(globals())
    
    exec(main_code, globals_dict)

except Exception as e:
    log(f"CRITICAL LOADER ERROR: {e}")
    import traceback # type: ignore
    log(traceback.format_exc())
    sys.exit(1)
