
import os

target_path = "c:/Users/k.rajasekhar/Documents/watch-sec/watch-sec-python/backend/storage/AgentTemplate/win-x64/watch-sec-agent.exe"

# Create a 5MB dummy file
size_mb = 5
size_bytes = size_mb * 1024 * 1024

with open(target_path, "wb") as f:
    # Write a fake PE header (MZ...)
    f.write(b"MZ" + b"\x00" * 100)
    # Fill rest
    f.write(os.urandom(size_bytes))

print(f"Created dummy agent at {target_path} ({size_mb} MB)")
