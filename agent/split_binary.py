import os
import shutil

CHUNK_SIZE = 45 * 1024 * 1024 # 45MB
# Resolve paths relative to this script file (agent/split_binary.py)
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
# Going up from agent/ -> watch-sec-python/ -> dist/
SOURCE_DIR = os.path.join(SCRIPT_DIR, "..", "dist")
# Going up from agent/ -> watch-sec-python/ -> backend/storage/AgentTemplate
BASE_DEST_DIR = os.path.join(SCRIPT_DIR, "..", "backend", "storage", "AgentTemplate")

# Map Source filename -> (Dest Folder, Dest Filename)
PLATFORM_MAP = {
    "monitorix-agent.exe":      ("win-x64", "monitorix-agent.exe"),
    "watch-sec-agent.exe":      ("win-x64", "monitorix-agent.exe"), # Legacy support
    "monitorix-agent-linux":    ("linux-x64", "monitorix-agent-linux"),
    "monitorix-agent-mac":      ("osx-x64", "monitorix-agent-mac")
}

def split_file(source_path, dest_dir, dest_filename):
    if not os.path.exists(dest_dir):
        os.makedirs(dest_dir)

    # Clean old parts
    for f in os.listdir(dest_dir):
        if dest_filename in f and ".part" in f:
            os.remove(os.path.join(dest_dir, f))
            print(f"Removed old {f}")

    file_size = os.path.getsize(source_path)
    print(f"Splitting {source_path} ({file_size/1024/1024:.2f} MB)...")
    
    with open(source_path, 'rb') as src:
        part_num = 0
        while True:
            chunk = src.read(CHUNK_SIZE)
            if not chunk:
                break
            
            part_name = f"{dest_filename}.part{part_num}"
            dest_path = os.path.join(dest_dir, part_name)
            
            with open(dest_path, 'wb') as part:
                part.write(chunk)
            
            print(f"  Created {part_name} ({len(chunk)} bytes)")
            part_num += 1

    print(f"Done splitting {dest_filename}.")

def main():
    if not os.path.exists(SOURCE_DIR):
        print(f"Error: {SOURCE_DIR} directory not found.")
        return

    found_any = False
    for filename in os.listdir(SOURCE_DIR):
        if filename in PLATFORM_MAP:
            found_any = True
            source_path = os.path.join(SOURCE_DIR, filename)
            subfolder, dest_name = PLATFORM_MAP[filename]
            dest_dir = os.path.join(BASE_DEST_DIR, subfolder)
            
            split_file(source_path, dest_dir, dest_name)
    
    if not found_any:
        print("No matching binaries found in dist/. Expected one of: " + ", ".join(PLATFORM_MAP.keys()))

if __name__ == "__main__":
    main()
