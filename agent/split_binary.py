import os
import shutil

CHUNK_SIZE = 45 * 1024 * 1024 # 45MB
SOURCE_FILE = "dist/watch-sec-agent.exe"
DEST_DIR = "../backend/storage/AgentTemplate/win-x64/"

def split_file():
    if not os.path.exists(SOURCE_FILE):
        print(f"Error: {SOURCE_FILE} not found.")
        return

    # Clean destination of old parts
    for f in os.listdir(DEST_DIR):
        if "agent.exe.part" in f:
            os.remove(os.path.join(DEST_DIR, f))
            print(f"Removed old {f}")

    file_size = os.path.getsize(SOURCE_FILE)
    with open(SOURCE_FILE, 'rb') as src:
        part_num = 0
        while True:
            chunk = src.read(CHUNK_SIZE)
            if not chunk:
                break
            
            part_name = f"monitorix-agent.exe.part{part_num}" # Using legacy name as per previous file listing
            dest_path = os.path.join(DEST_DIR, part_name)
            
            with open(dest_path, 'wb') as part:
                part.write(chunk)
            
            print(f"Created {part_name} ({len(chunk)} bytes)")
            part_num += 1

    print("Split Complete.")

if __name__ == "__main__":
    split_file()
