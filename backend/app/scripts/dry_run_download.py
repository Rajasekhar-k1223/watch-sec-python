
import os
import json
import shutil
import uuid

# Configuration
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__))) # app/
BACKEND_DIR = os.path.dirname(BASE_DIR)
STORAGE_DIR = os.path.join(BACKEND_DIR, "storage")
TEMPLATE_DIR = os.path.join(STORAGE_DIR, "AgentTemplate", "win-x64")
EXE_NAME = "watch-sec-agent.exe"
TEMP_DIR = os.path.join(STORAGE_DIR, "temp", "dry_run")

print(f"--- Dry Run Download Test ---")
print(f"Root: {BACKEND_DIR}")
print(f"Template Dir: {TEMPLATE_DIR}")

# 1. Check Source
exe_path = os.path.join(TEMPLATE_DIR, EXE_NAME)
if not os.path.exists(exe_path):
    print(f"[FAIL] Source EXE not found at: {exe_path}")
    # List dir
    print(f"Contents of {TEMPLATE_DIR}:")
    try:
        print(os.listdir(TEMPLATE_DIR))
    except Exception as e:
        print(e)
    exit(1)

source_size = os.path.getsize(exe_path)
print(f"[PASS] Source EXE found. Size: {source_size} bytes")

# 2. Simulate Logic
try:
    os.makedirs(TEMP_DIR, exist_ok=True)
    
    # Config to inject
    config_data = {
        "TenantApiKey": "TEST-KEY-12345",
        "BackendUrl": "https://dry-run.test"
    }
    payload = json.dumps(config_data).encode("utf-8")
    delimiter = b"\n<<<<WATCHSEC_CONFIG>>>>\n"
    
    output_path = os.path.join(TEMP_DIR, "watch-sec-installer-dryrun.exe")
    
    print(f"Simulating Injection...")
    with open(exe_path, "rb") as orig_f:
         with open(output_path, "wb") as new_f:
             new_f.write(orig_f.read())
             new_f.write(delimiter)
             new_f.write(payload)
             
    if os.path.exists(output_path):
        out_size = os.path.getsize(output_path)
        print(f"[PASS] Output file created: {output_path}")
        print(f"Original Size: {source_size}")
        print(f"Output Size:   {out_size}")
        
        if out_size > source_size:
             print(f"[PASS] Injection successful (Size increased).")
        else:
             print(f"[FAIL] Size did not increase?")
             
    else:
        print(f"[FAIL] Output file not created.")
        
except Exception as e:
    import traceback
    traceback.print_exc()
    print(f"[FAIL] Exception: {e}")

print("--- End Test ---")
