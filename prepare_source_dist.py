import os
import shutil

# Resolve base paths
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
# agent/src is at ../agent/src relative to this script? 
# No, this script is in ./ (watch-sec-python root)
AGENT_SRC = os.path.join(SCRIPT_DIR, "agent", "src")
AGENT_REQS = os.path.join(SCRIPT_DIR, "agent", "requirements.txt")

STORAGE_BASE = os.path.join(SCRIPT_DIR, "backend", "storage", "AgentTemplate")
LINUX_DEST = os.path.join(STORAGE_BASE, "linux-x64")
MAC_DEST = os.path.join(STORAGE_BASE, "osx-x64")

def populate_source(dest_dir):
    if not os.path.exists(dest_dir):
        os.makedirs(dest_dir)
        
    # Clean existing
    for item in os.listdir(dest_dir):
        path = os.path.join(dest_dir, item)
        if os.path.isfile(path): os.remove(path)
        elif os.path.isdir(path): shutil.rmtree(path)

    print(f"Populating {dest_dir} with Source Code...")
    
    # Copy src folder
    shutil.copytree(AGENT_SRC, os.path.join(dest_dir, "src"))
    
    # Copy requirements
    shutil.copy2(AGENT_REQS, os.path.join(dest_dir, "requirements.txt"))
    
    print(f"Done: {dest_dir}")

def main():
    populate_source(LINUX_DEST)
    populate_source(MAC_DEST)

if __name__ == "__main__":
    main()
