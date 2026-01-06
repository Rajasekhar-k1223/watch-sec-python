
import os

CHUNK_SIZE = 45 * 1024 * 1024  # 45MB (Safe for GitHub 100MB Limit)
FILE_PATH = "dist/monitorix.exe"
DEST_DIR = "backend/storage/AgentTemplate/win-x64"

def split_file():
    if not os.path.exists(FILE_PATH):
        print("File not found.")
        return

    file_size = os.path.getsize(FILE_PATH)
    print(f"Splitting {FILE_PATH} ({file_size / 1024 / 1024:.2f} MB)...")

    with open(FILE_PATH, 'rb') as f:
        part_num = 0
        while True:
            chunk = f.read(CHUNK_SIZE)
            if not chunk:
                break
            
            part_name = f"monitorix-agent.exe.part{part_num}"
            part_path = os.path.join(DEST_DIR, part_name)
            
            with open(part_path, 'wb') as part_file:
                part_file.write(chunk)
            
            print(f"Created {part_name} ({len(chunk) / 1024 / 1024:.2f} MB)")
            part_num += 1

    print("Splitting complete.")
    # Remove original from destination if it exists (monitorix-agent.exe) to avoid confusion
    if os.path.exists(os.path.join(DEST_DIR, "monitorix-agent.exe")):
        os.remove(os.path.join(DEST_DIR, "monitorix-agent.exe"))
        print("Removed original single binary from destination.")

if __name__ == "__main__":
    if not os.path.exists(DEST_DIR):
        os.makedirs(DEST_DIR)
    split_file()
