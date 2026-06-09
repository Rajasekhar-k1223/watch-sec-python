import os
import sys
import subprocess
import platform

def main():
    print(f"[*] Starting Monitorix Agent compilation on {platform.system()}...")
    
    entry_point = os.path.join("src", "agent_entry.py")
    
    if not os.path.exists(entry_point):
        print(f"[!] Error: Cannot find {entry_point}")
        sys.exit(1)

    # PyInstaller arguments
    args = [
        "pyinstaller",
        "--noconfirm",
        "--onefile",                 # Create a single executable
        "--name", "monitorix-agent", # Name of the binary
        "--hidden-import", "psutil", 
        "--hidden-import", "cryptography",
        "--hidden-import", "websockets",
        "--hidden-import", "aiortc",
        "--hidden-import", "av",
        "--hidden-import", "sounddevice",
        "--hidden-import", "mss",
        "--hidden-import", "PIL",
        "--hidden-import", "numpy",
        "--hidden-import", "pyperclip",
        "--hidden-import", "pynput",
        "--clean"
    ]
    
    if platform.system() == "Darwin":
        # macOS specific fixes: build universal binary (Intel + Apple Silicon)
        args.extend(["--target-arch", "universal2"])
        # macOS doesn't support hidden-import for some windows specific modules
        # so we remove or ignore them if they fail, but universal2 fixes the arch issue
        
    args.append(entry_point)
    
    print(f"[*] Running command: {' '.join(args)}")
    
    try:
        subprocess.check_call(args)
        print("[*] Compilation successful!")
        
        # Determine output location
        if platform.system() == "Windows":
            bin_name = "monitorix-agent.exe"
        else:
            bin_name = "monitorix-agent"
            
        dist_path = os.path.join("dist", bin_name)
        if os.path.exists(dist_path):
            size_mb = os.path.getsize(dist_path) / (1024*1024)
            print(f"[*] Binary generated at: {dist_path}")
            print(f"[*] File size: {size_mb:.2f} MB")
            
            if size_mb < 1.0:
                print("[!] Error: Generated binary is suspiciously small (< 1MB). Build may be corrupted.")
                sys.exit(1)
            
            # Simulated Cross-Platform outputs (Prototype)
            import shutil
            win_path = os.path.join("dist", "monitorix-agent-simulated.exe")
            mac_path = os.path.join("dist", "monitorix-agent-simulated-mac")
            shutil.copy2(dist_path, win_path)
            shutil.copy2(dist_path, mac_path)
            print(f"[*] Simulated Cross-Platform Windows Build: {win_path}")
            print(f"[*] Simulated Cross-Platform macOS Build: {mac_path}")
            
        else:
            print("[!] Warning: Could not locate output binary in dist/")
            
    except subprocess.CalledProcessError as e:
        print(f"[!] Compilation failed with error code {e.returncode}")
        sys.exit(e.returncode)

if __name__ == "__main__":
    main()
